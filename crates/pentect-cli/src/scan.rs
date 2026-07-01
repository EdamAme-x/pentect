mod engine;
mod options;
mod report;
mod rules;
mod walk;

use crate::{die, load_packs};
use engine::{scan_files, ScanFile};
use options::ScanOpts;
use report::{print_report, report_json, ScanReport};
use std::io::Write;
use walk::collect_scan_roots;

pub(crate) fn cmd_scan(args: &[String]) {
    let opts = match ScanOpts::parse(args) {
        Ok(opts) => opts,
        Err(e) => die(e),
    };
    let report = match run_scan(args, &opts) {
        Ok(report) => report,
        Err(e) => die(e),
    };
    if opts.json {
        println!("{}", report_json(&report));
    } else {
        print_report(&report);
    }
    let _ = std::io::stdout().flush();
    if report.findings > 0 && !opts.no_fail {
        std::process::exit(1);
    }
}

fn run_scan(args: &[String], opts: &ScanOpts) -> Result<ScanReport, String> {
    let packs = load_packs(args)?;
    run_scan_with_engine(opts, packs, scan_files)
}

#[cfg(test)]
fn run_scan_core_for_tests(args: &[String], opts: &ScanOpts) -> Result<ScanReport, String> {
    let packs = load_packs(args)?;
    run_scan_with_engine(opts, packs, engine::scan_files_core_for_tests)
}

fn run_scan_with_engine(
    opts: &ScanOpts,
    packs: Vec<pentect_core::Pack>,
    scanner: impl FnOnce(
        Vec<std::path::PathBuf>,
        Vec<pentect_core::Pack>,
    ) -> Result<(Vec<ScanFile>, String), String>,
) -> Result<ScanReport, String> {
    let mut report = ScanReport {
        roots: opts.paths.clone(),
        engine: "pentect".to_string(),
        ..ScanReport::default()
    };
    let files = collect_scan_roots(
        &opts.paths,
        &opts.excludes,
        opts.gitignore,
        &mut report.skipped,
    )?;
    let (results, engine) = scanner(files, packs)?;
    report.engine = engine;
    for result in results {
        match result {
            ScanFile::Clean(path) => {
                let _ = path.as_os_str();
                report.files_scanned += 1;
            }
            ScanFile::Finding(file) => {
                report.files_scanned += 1;
                report.findings += file.findings;
                report.warnings += file.warnings;
                report.files.push(file);
            }
            ScanFile::Skipped(skipped) => report.skipped.push(skipped),
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
        assert!(!opts.gitignore);
    }

    #[test]
    fn scan_parse_accepts_paths_and_automation_flags_only() {
        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--json".into(),
            "--no-fail".into(),
            "--gitignore".into(),
            "app.env".into(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        assert_eq!(opts.paths, vec![PathBuf::from("app.env")]);
        assert!(opts.json);
        assert!(opts.no_fail);
        assert!(opts.gitignore);
        assert!(opts.excludes.is_empty());
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
        assert!(rendered.contains("RUNPOD_API_KEY"), "{rendered}");
        assert!(!rendered.contains("rpa_FAKEPENTECTSCAN"), "{rendered}");
        assert!(!rendered.contains("hello"), "{rendered}");

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
    fn scan_ignores_gitignore_by_default() {
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
            .any(|file| file.path.file_name().unwrap() == "ignored.env"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_gitignore_flag_removes_files_from_walk() {
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
            "--gitignore".into(),
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
    fn scan_includes_vcs_dirs_by_default() {
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
            "--gitignore".into(),
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
