mod engine;
mod file_magic;
mod options;
mod progress;
mod report;
mod rules;
mod walk;

use crate::{die, load_packs, plugins};
use engine::{scan_files, ScanFile};
use options::{BinaryMode, ScanOpts};
use progress::ScanProgress;
use report::{print_report, report_json, ScanReport};
use std::io::Write;
use walk::collect_scan_roots;

pub(crate) fn cmd_scan(args: &[String]) {
    let opts = match ScanOpts::parse(args) {
        Ok(opts) => opts,
        Err(e) => die(e),
    };
    let explicit = plugins::collect_from_args(args).unwrap_or_else(|error| die(error));
    let active = plugins::active_from_specs(explicit, true).unwrap_or_else(|error| die(error));
    let _plugin_env = crate::EnvVarGuard::set_optional([
        (
            plugins::CONFIGS_ENV,
            active.config_env_value().unwrap_or_else(|error| die(error)),
        ),
        (
            plugins::BINARIES_ENV,
            active.binary_env_value().unwrap_or_else(|error| die(error)),
        ),
    ]);
    let report = match run_scan(args, &opts) {
        Ok(report) => report,
        Err(e) => die(e),
    };
    let mut labels = std::collections::BTreeMap::new();
    for file in &report.files {
        for (label, count) in &file.labels {
            *labels.entry(label.clone()).or_insert(0) += count;
        }
    }
    pentect_agent::record_scan_activity(report.files_scanned, report.findings, labels);
    let plugin_report = match dispatch_scan_plugins(args, &report) {
        Ok(report) => report,
        Err(error) => die(error),
    };
    if opts.json {
        println!("{plugin_report}");
    } else {
        print_report(&report);
    }
    let _ = std::io::stdout().flush();
    if report.findings > 0 && !opts.no_fail {
        std::process::exit(1);
    }
}

fn dispatch_scan_plugins(args: &[String], report: &ScanReport) -> Result<String, String> {
    let specs = plugins::collect_from_args(args).map_err(|error| error.to_string())?;
    let active = plugins::active_from_specs(specs, true).map_err(|error| error.to_string())?;
    let middleware =
        pentect_agent::PluginMiddleware::from_paths(active.binary_paths().iter().cloned())?;
    let mut payload: serde_json::Value =
        serde_json::from_str(&report_json(report)).map_err(|error| error.to_string())?;
    if let Some(files) = payload
        .get_mut("files")
        .and_then(serde_json::Value::as_array_mut)
    {
        for file in files {
            let run = middleware.run(
                pentect_agent::MiddlewareStage::Finding,
                file.take(),
                Some(serde_json::json!({"surface": "scan"})),
            )?;
            if run.stopped.is_some() {
                return Err(format!(
                    "scan blocked by plugin: {}",
                    run.message.unwrap_or_else(|| "finding blocked".to_string())
                ));
            }
            *file = run.payload;
        }
    }
    let run = middleware.run(
        pentect_agent::MiddlewareStage::Report,
        payload,
        Some(serde_json::json!({"surface": "scan"})),
    )?;
    if run.stopped.is_some() {
        return Err(format!(
            "scan blocked by plugin: {}",
            run.message.unwrap_or_else(|| "report blocked".to_string())
        ));
    }
    serde_json::to_string(&run.payload).map_err(|error| error.to_string())
}

fn run_scan(args: &[String], opts: &ScanOpts) -> Result<ScanReport, String> {
    let packs = load_packs(args)?;
    run_scan_with_engine(opts, packs, opts.json, scan_files)
}

#[cfg(test)]
fn run_scan_core_for_tests(args: &[String], opts: &ScanOpts) -> Result<ScanReport, String> {
    let packs = load_packs(args)?;
    run_scan_with_engine(opts, packs, true, engine::scan_files_core_for_tests)
}

fn run_scan_with_engine(
    opts: &ScanOpts,
    packs: Vec<pentect_core::Pack>,
    retain_skipped: bool,
    scanner: impl FnOnce(
        Vec<std::path::PathBuf>,
        Vec<pentect_core::Pack>,
        BinaryMode,
        ScanProgress,
        bool,
    ) -> Result<(Vec<ScanFile>, String), String>,
) -> Result<ScanReport, String> {
    let mut report = ScanReport {
        roots: opts.paths.clone(),
        engine: "pentect".to_string(),
        ..ScanReport::default()
    };
    let progress = ScanProgress::for_stderr();
    progress.start("walk", None);
    let files = match collect_scan_roots(
        &opts.paths,
        &opts.excludes,
        opts.use_gitignore,
        &mut report.skipped,
        &mut report.skipped_count,
        retain_skipped,
        &progress,
    ) {
        Ok(files) => files,
        Err(error) => {
            progress.finish();
            return Err(error);
        }
    };
    let scanned = scanner(files, packs, opts.binary, progress.clone(), retain_skipped);
    progress.finish();
    let (results, engine) = scanned?;
    report.engine = engine;
    for result in results {
        match result {
            ScanFile::Count {
                files_scanned,
                skipped,
            } => {
                report.files_scanned += files_scanned;
                report.skipped_count += skipped;
            }
            ScanFile::CleanPath(_) => {
                report.files_scanned += 1;
            }
            ScanFile::Finding(file) => {
                report.files_scanned += 1;
                report.findings += file.findings;
                report.warnings += file.warnings;
                report.files.push(file);
            }
            ScanFile::Skipped(skipped) => {
                report.skipped_count += 1;
                report.skipped.push(skipped);
            }
            ScanFile::Error(error) => return Err(error),
        }
    }
    report.files.sort_by(|a, b| a.path.cmp(&b.path));
    report.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::report::ScanScope;
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn scan_parse_defaults_to_current_dir() {
        let args = vec!["pentect".into(), "scan".into()];
        let opts = ScanOpts::parse(&args).unwrap();
        assert_eq!(opts.paths, vec![PathBuf::from(".")]);
        assert!(!opts.json);
        assert!(!opts.no_fail);
        assert!(opts.use_gitignore);
        assert_eq!(opts.binary, BinaryMode::Skip);
    }

    #[test]
    fn scan_parse_accepts_paths_and_automation_flags_only() {
        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--json".into(),
            "--no-fail".into(),
            "--no-gitignore".into(),
            "--binary".into(),
            "text".into(),
            "app.env".into(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        assert_eq!(opts.paths, vec![PathBuf::from("app.env")]);
        assert!(opts.json);
        assert!(opts.no_fail);
        assert!(!opts.use_gitignore);
        assert_eq!(opts.binary, BinaryMode::Text);
        assert!(opts.excludes.is_empty());
    }

    #[test]
    fn scan_parse_rejects_invalid_binary_mode() {
        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--binary".into(),
            "raw".into(),
        ];
        let err = ScanOpts::parse(&args).unwrap_err();
        assert!(err.contains("binary must be skip or text"), "{err}");
    }

    #[test]
    fn scan_parse_rejects_removed_gitignore_flag() {
        let args = vec!["pentect".into(), "scan".into(), "--gitignore".into()];
        let err = ScanOpts::parse(&args).unwrap_err();
        assert!(err.contains("unknown option"), "{err}");
    }

    #[test]
    fn scan_parse_rejects_core_mode() {
        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--core".into(),
            "app.env".into(),
        ];
        let err = ScanOpts::parse(&args).unwrap_err();
        assert!(err.contains("unknown option"), "{err}");
    }

    #[test]
    fn scan_parse_accepts_repeated_excludes() {
        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--exclude".into(),
            "package-lock.json".into(),
            "--exclude".into(),
            "fixtures/**".into(),
            "app.env".into(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        assert_eq!(opts.paths, vec![PathBuf::from("app.env")]);
        assert_eq!(opts.excludes, vec!["package-lock.json", "fixtures/**"]);
    }

    #[test]
    fn scan_parse_rejects_missing_exclude_value() {
        let args = vec!["pentect".into(), "scan".into(), "--exclude".into()];
        let err = ScanOpts::parse(&args).unwrap_err();
        assert!(err.contains("--exclude requires a value"), "{err}");
    }

    #[test]
    fn scan_rejects_profile_and_kind_flags() {
        for flag in ["--profile", "--kind"] {
            let args = vec![
                "pentect".into(),
                "scan".into(),
                flag.into(),
                "extra".into(),
                "app.env".into(),
            ];
            let err = ScanOpts::parse(&args).unwrap_err();
            assert!(err.contains("unknown option"), "{err}");
        }
    }

    #[test]
    fn scan_reports_findings_without_values() {
        let root = std::env::temp_dir().join(format!(
            "pentect-scan-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::write(
            root.join(".env"),
            "RUNPOD_API_KEY=rpa_FAKEPENTECTSCAN1234567890abcdef\nNOTE=hello\n",
        )
        .unwrap();
        std::fs::write(root.join("target").join("note.txt"), "plain text\n").unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();
        let rendered = report_json(&report);
        assert_eq!(report.files_scanned, 2);
        assert_eq!(report.files.len(), 1);
        assert!(report.findings >= 2, "{rendered}");
        assert!(rendered.contains(".env"), "{rendered}");
        assert!(!rendered.contains("rpa_FAKEPENTECTSCAN"), "{rendered}");
        assert!(!rendered.contains("hello"), "{rendered}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_applies_plugin_configs() {
        let root = temp_scan_root("pentect-scan-plugin-pack");
        let ext = root.join("ext");
        std::fs::create_dir(&ext).unwrap();
        std::fs::write(
            ext.join("config.toml"),
            r#"[[detector]]
pattern = 'ACME-[0-9]{8}'
category = "secret"
label = "ACME_CASE"
"#,
        )
        .unwrap();
        std::fs::write(root.join("note.txt"), "ticket ACME-12345678\n").unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--plugins".into(),
            ext.to_string_lossy().to_string(),
            root.join("note.txt").to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();
        let rendered = report_json(&report);
        assert_eq!(report.files_scanned, 1, "{rendered}");
        assert_eq!(report.findings, 1, "{rendered}");
        assert_eq!(report.files[0].labels.get("ACME_CASE"), Some(&1));
        assert!(!rendered.contains("ACME-12345678"), "{rendered}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_uses_native_credsweeper_without_python() {
        let root = temp_scan_root("pentect-scan-native-credsweeper");
        let token = format!("github_pat_{}", "A".repeat(80));
        std::fs::write(root.join("token.txt"), format!("token={token}\n")).unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan(&args, &opts).unwrap();
        let rendered = report_json(&report);

        assert_eq!(report.files_scanned, 1, "{rendered}");
        assert_eq!(report.files.len(), 1, "{rendered}");
        assert!(
            report.files[0].engines.contains_key("credsweeper"),
            "{rendered}"
        );
        assert!(!rendered.contains(&token), "{rendered}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn binary_text_mode_scans_magic_binary_files() {
        let root = temp_scan_root("pentect-scan-binary-text");
        let mut data = b"\x89PNG\r\n\x1A\n\0\0".to_vec();
        data.extend_from_slice(b"const PASSWORD: string = \"helloworld1234\";\n");
        std::fs::write(root.join("payload"), data).unwrap();

        let default_args = vec![
            "pentect".into(),
            "scan".into(),
            root.to_string_lossy().to_string(),
        ];
        let default_opts = ScanOpts::parse(&default_args).unwrap();
        let default_report = run_scan_core_for_tests(&default_args, &default_opts).unwrap();
        assert_eq!(0, default_report.files_scanned);
        assert_eq!(1, default_report.skipped.len());

        let text_args = vec![
            "pentect".into(),
            "scan".into(),
            "--binary".into(),
            "text".into(),
            root.to_string_lossy().to_string(),
        ];
        let text_opts = ScanOpts::parse(&text_args).unwrap();
        let text_report = run_scan_core_for_tests(&text_args, &text_opts).unwrap();
        let rendered = report_json(&text_report);
        assert_eq!(1, text_report.files_scanned, "{rendered}");
        assert_eq!(1, text_report.files.len(), "{rendered}");
        assert!(text_report.findings >= 1, "{rendered}");
        assert!(!rendered.contains("helloworld1234"), "{rendered}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn binary_skip_reports_nul_files_as_skipped_not_clean() {
        let root = temp_scan_root("pentect-scan-nul-skip");
        std::fs::write(
            root.join("payload.txt"),
            b"const PASSWORD: string = \"helloworld1234\";\0\n",
        )
        .unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();

        assert_eq!(0, report.files_scanned, "{}", report_json(&report));
        assert_eq!(1, report.skipped.len(), "{}", report_json(&report));
        assert_eq!("binary content", report.skipped[0].reason);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn binary_skip_reports_invalid_utf8_files_as_skipped_not_clean() {
        let root = temp_scan_root("pentect-scan-invalid-utf8-skip");
        let mut data = vec![0xFF, 0xFE];
        data.extend_from_slice(b"const PASSWORD: string = \"helloworld1234\";\n");
        std::fs::write(root.join("payload.txt"), data).unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();

        assert_eq!(0, report.files_scanned, "{}", report_json(&report));
        assert_eq!(1, report.skipped.len(), "{}", report_json(&report));
        assert_eq!("invalid utf-8", report.skipped[0].reason);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_skips_non_regular_paths_without_aborting() {
        let root = temp_scan_root("pentect-scan-non-regular-skip");
        let secret = root.join(".env");
        std::fs::write(
            &secret,
            "RUNPOD_API_KEY=rpa_FAKEPENTECTSCAN1234567890abcdef\n",
        )
        .unwrap();

        let (results, _) = engine::scan_files_core_for_tests(
            vec![root.clone(), secret.clone()],
            Vec::new(),
            BinaryMode::Skip,
            ScanProgress::disabled(),
            true,
        )
        .unwrap();
        let mut saw_skipped_dir = false;
        let mut saw_secret_finding = false;
        for result in results {
            match result {
                ScanFile::Skipped(skipped) if skipped.path == root => {
                    assert_eq!("not a regular file", skipped.reason);
                    saw_skipped_dir = true;
                }
                ScanFile::Finding(file) if file.path == secret => {
                    saw_secret_finding = true;
                }
                _ => {}
            }
        }
        assert!(saw_skipped_dir);
        assert!(saw_secret_finding);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_coalesces_clean_and_skipped_paths_when_details_are_not_requested() {
        let root = temp_scan_root("pentect-scan-coalesced-results");
        let mut paths = Vec::new();
        for index in 0..64 {
            let path = root.join(format!("clean-{index}.txt"));
            std::fs::write(&path, "ordinary text\n").unwrap();
            paths.push(path);
        }
        let binary = root.join("image.png");
        std::fs::write(&binary, b"\x89PNG\r\n\x1a\n").unwrap();
        paths.push(binary);

        let (results, _) = engine::scan_files_core_for_tests(
            paths,
            Vec::new(),
            BinaryMode::Skip,
            ScanProgress::disabled(),
            false,
        )
        .unwrap();
        let (mut scanned, mut skipped) = (0, 0);
        for result in results {
            match result {
                ScanFile::Count {
                    files_scanned,
                    skipped: skipped_count,
                } => {
                    scanned += files_scanned;
                    skipped += skipped_count;
                }
                ScanFile::CleanPath(path) => panic!("retained clean path: {}", path.display()),
                ScanFile::Skipped(file) => {
                    panic!("retained skipped path: {}", file.path.display())
                }
                ScanFile::Finding(file) => panic!("unexpected finding: {}", file.path.display()),
                ScanFile::Error(error) => panic!("unexpected scan error: {error}"),
            }
        }
        assert_eq!(64, scanned);
        assert_eq!(1, skipped);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn extensionless_text_starting_with_mz_is_scanned() {
        let root = temp_scan_root("pentect-scan-extensionless-mz");
        std::fs::write(
            root.join("payload"),
            "MZ\nconst PASSWORD: string = \"helloworld1234\";\n",
        )
        .unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();
        let rendered = report_json(&report);

        assert_eq!(1, report.files_scanned, "{rendered}");
        assert!(report.skipped.is_empty(), "{rendered}");
        assert_eq!(1, report.files.len(), "{rendered}");
        assert!(report.findings >= 1, "{rendered}");
        assert!(!rendered.contains("helloworld1234"), "{rendered}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_exclude_removes_files_from_scan_set() {
        let root = temp_scan_root("pentect-scan-exclude");
        std::fs::write(
            root.join(".env"),
            "RUNPOD_API_KEY=rpa_FAKEPENTECTSCAN1234567890abcdef\n",
        )
        .unwrap();
        std::fs::write(
            root.join("package-lock.json"),
            r#"{"env":"RUNPOD_API_KEY=rpa_FAKEPENTECTSCAN1234567890abcdef"}"#,
        )
        .unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--exclude".into(),
            "package-lock.json".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();

        assert_eq!(report.files_scanned, 1, "{}", report_json(&report));
        assert!(report
            .files
            .iter()
            .all(|file| file.path.file_name().unwrap() != "package-lock.json"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_pentectignore_removes_files_from_scan_set() {
        let root = temp_scan_root("pentect-scan-pentectignore");
        std::fs::write(root.join(".pentectignore"), "ignored.env\n").unwrap();
        std::fs::write(
            root.join(".env"),
            "RUNPOD_API_KEY=rpa_FAKEPENTECTSCAN1234567890abcdef\n",
        )
        .unwrap();
        std::fs::write(
            root.join("ignored.env"),
            "RUNPOD_API_KEY=rpa_IGNOREDPENTECTSCAN1234567890abcd\n",
        )
        .unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();

        assert_eq!(report.files_scanned, 2, "{}", report_json(&report));
        assert!(report
            .files
            .iter()
            .all(|file| file.path.file_name().unwrap() != "ignored.env"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_honors_gitignore_by_default() {
        let root = temp_scan_root("pentect-scan-gitignore");
        std::fs::write(root.join(".gitignore"), "ignored.env\n").unwrap();
        std::fs::write(
            root.join(".env"),
            "RUNPOD_API_KEY=rpa_FAKEPENTECTSCAN1234567890abcdef\n",
        )
        .unwrap();
        std::fs::write(
            root.join("ignored.env"),
            "RUNPOD_API_KEY=rpa_IGNOREDPENTECTSCAN1234567890abcd\n",
        )
        .unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();

        assert!(report
            .files
            .iter()
            .all(|file| file.path.file_name().unwrap() != "ignored.env"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_no_gitignore_includes_ignored_files() {
        let root = temp_scan_root("pentect-scan-gitignore-flag");
        std::fs::write(root.join(".gitignore"), "ignored.env\n").unwrap();
        std::fs::write(
            root.join(".env"),
            "RUNPOD_API_KEY=rpa_FAKEPENTECTSCAN1234567890abcdef\n",
        )
        .unwrap();
        std::fs::write(
            root.join("ignored.env"),
            "RUNPOD_API_KEY=rpa_IGNOREDPENTECTSCAN1234567890abcd\n",
        )
        .unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--no-gitignore".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();

        assert!(report
            .files
            .iter()
            .any(|file| file.path.file_name().unwrap() == "ignored.env"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_explicit_file_bypasses_ignore_files() {
        let root = temp_scan_root("pentect-scan-explicit-ignored-file");
        std::fs::write(root.join(".gitignore"), "ignored.env\n").unwrap();
        std::fs::write(root.join(".pentectignore"), "ignored.env\n").unwrap();
        let ignored = root.join("ignored.env");
        std::fs::write(
            &ignored,
            "RUNPOD_API_KEY=rpa_FAKEPENTECTSCAN1234567890abcdef\n",
        )
        .unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            ignored.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();

        assert_eq!(1, report.files_scanned, "{}", report_json(&report));
        assert!(report
            .files
            .iter()
            .any(|file| file.path.file_name() == ignored.file_name()));

        let excluded_args = vec![
            "pentect".into(),
            "scan".into(),
            "--exclude".into(),
            "ignored.env".into(),
            ignored.to_string_lossy().to_string(),
        ];
        let excluded_opts = ScanOpts::parse(&excluded_args).unwrap();
        let excluded_report = run_scan_core_for_tests(&excluded_args, &excluded_opts).unwrap();
        assert_eq!(
            0,
            excluded_report.files_scanned,
            "{}",
            report_json(&excluded_report)
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_no_gitignore_includes_vcs_dirs() {
        let root = temp_scan_root("pentect-scan-vcs-default");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(
            root.join(".git").join("config"),
            "RUNPOD_API_KEY=rpa_FAKEPENTECTSCAN1234567890abcdef\n",
        )
        .unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--no-gitignore".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();

        assert!(report
            .files
            .iter()
            .any(|file| has_path_segment(&file.path, ".git")));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_named_exclude_groups_can_be_restored() {
        let root = temp_scan_root("pentect-scan-vcs-restore");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(
            root.join(".git").join("config"),
            "RUNPOD_API_KEY=rpa_FAKEPENTECTSCAN1234567890abcdef\n",
        )
        .unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--exclude".into(),
            "~vcs".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();
        assert!(report
            .files
            .iter()
            .all(|file| !has_path_segment(&file.path, ".git")));

        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--exclude".into(),
            "~vcs".into(),
            "--exclude".into(),
            "!~vcs".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();
        assert!(report
            .files
            .iter()
            .any(|file| has_path_segment(&file.path, ".git")));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_nested_ignore_files_remove_files_from_walk() {
        let root = temp_scan_root("pentect-scan-nested-ignore");
        std::fs::create_dir_all(root.join("sub").join("child")).unwrap();
        std::fs::write(root.join("sub").join(".pentectignore"), "ignored.env\n").unwrap();
        std::fs::write(
            root.join("sub").join("child").join(".gitignore"),
            "also.env\n",
        )
        .unwrap();
        std::fs::write(
            root.join(".env"),
            "RUNPOD_API_KEY=rpa_FAKEPENTECTSCAN1234567890abcdef\n",
        )
        .unwrap();
        std::fs::write(
            root.join("sub").join("ignored.env"),
            "RUNPOD_API_KEY=rpa_IGNOREDPENTECTSCAN1234567890abcd\n",
        )
        .unwrap();
        std::fs::write(
            root.join("sub").join("child").join("also.env"),
            "RUNPOD_API_KEY=rpa_IGNOREDPENTECTSCAN2234567890abcd\n",
        )
        .unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();

        assert!(report
            .files
            .iter()
            .all(|file| file.path.file_name().unwrap() != "ignored.env"));
        assert!(report
            .files
            .iter()
            .all(|file| file.path.file_name().unwrap() != "also.env"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_reports_generated_files_as_explicit_scope() {
        let root = temp_scan_root("pentect-scan-generated-scope");
        std::fs::write(
            root.join("package-lock.json"),
            r#"{"env":"RUNPOD_API_KEY=rpa_FAKEPENTECTSCAN1234567890abcdef"}"#,
        )
        .unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();
        assert_eq!(report.files_scanned, 1);
        assert!(report.skipped.is_empty(), "{}", report_json(&report));
        assert_eq!(report.files.len(), 1, "{}", report_json(&report));
        assert_eq!(report.files[0].scope, ScanScope::Generated);
        assert!(report.files[0].findings >= 1, "{}", report_json(&report));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_uses_core_on_keywordless_entropy() {
        let root = temp_scan_root("pentect-scan-keywordless-entropy");
        let blob = "Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh";
        std::fs::write(root.join("plain.txt"), format!("blob {blob} end\n")).unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan_core_for_tests(&args, &opts).unwrap();
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.files.len(), 1);
        assert!(report.findings >= 1, "{}", report_json(&report));

        let _ = std::fs::remove_dir_all(&root);
    }

    fn temp_scan_root(prefix: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn has_path_segment(path: &Path, segment: &str) -> bool {
        path.components()
            .any(|component| component.as_os_str() == segment)
    }
}
