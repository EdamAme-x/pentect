mod options;
mod report;
mod walk;

use crate::{die, infer_kind, load_packs};
use options::ScanOpts;
use pentect_core::{Category, Engine, Input, MaskedItem, Profile};
use report::{print_report, report_json, FileFinding, ScanReport, ScanScope, SkippedFile};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use walk::{collect_scan_roots, ignored_file_reason};

const MAX_SCAN_FILE_BYTES: u64 = 1024 * 1024;

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
    let mut report = ScanReport {
        roots: opts.paths.clone(),
        ..ScanReport::default()
    };
    let files = collect_scan_roots(&opts.paths, &mut report.skipped)?;
    for result in scan_files(files, packs)? {
        match result {
            ScanFile::Clean => report.files_scanned += 1,
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

enum ScanFile {
    Clean,
    Finding(FileFinding),
    Skipped(SkippedFile),
}

fn scan_files(
    files: Vec<PathBuf>,
    packs: Vec<pentect_core::Pack>,
) -> Result<Vec<ScanFile>, String> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(8)
        .min(files.len());
    let files = Arc::new(files);
    let next = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let files = Arc::clone(&files);
            let next = Arc::clone(&next);
            let packs = packs.clone();
            let tx = tx.clone();
            scope.spawn(move || {
                let mut worker = ScanWorker::new(packs);
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(path) = files.get(index) else {
                        break;
                    };
                    if tx.send(worker.scan_file(path)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);
        rx.into_iter().collect::<Result<Vec<_>, _>>()
    })
}

struct ScanWorker {
    packs: Option<Vec<pentect_core::Pack>>,
    engine: Option<Engine>,
}

impl ScanWorker {
    fn new(packs: Vec<pentect_core::Pack>) -> Self {
        Self {
            packs: Some(packs),
            engine: None,
        }
    }

    fn scan_file(&mut self, path: &Path) -> Result<ScanFile, String> {
        if let Some(reason) = ignored_file_reason(path) {
            return Ok(ScanFile::Skipped(SkippedFile::new(path, reason)));
        }
        let meta = match std::fs::metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ScanFile::Skipped(SkippedFile::new(path, "missing")));
            }
            Err(e) => return Err(format!("could not read '{}': {e}", path.display())),
        };
        if meta.len() > MAX_SCAN_FILE_BYTES {
            return Ok(ScanFile::Skipped(SkippedFile::new(path, "too large")));
        }
        let bytes =
            std::fs::read(path).map_err(|e| format!("could not read '{}': {e}", path.display()))?;
        if bytes.contains(&0) {
            return Ok(ScanFile::Skipped(SkippedFile::new(path, "binary content")));
        }
        let data = match String::from_utf8(bytes) {
            Ok(data) => data,
            Err(_) => return Ok(ScanFile::Skipped(SkippedFile::new(path, "non-utf8"))),
        };
        let kind = infer_kind(path);
        self.ensure_engine();
        let result = self.engine.as_ref().unwrap().analyze(Input {
            kind: kind.clone(),
            data,
        });
        let secret_items = result
            .items
            .iter()
            .filter(|item| item.category == Category::Secret)
            .collect::<Vec<_>>();
        let findings = secret_items.len();
        let warnings = result
            .residual
            .iter()
            .filter(|note| note.category == Category::Secret)
            .count();
        if findings == 0 && warnings == 0 {
            return Ok(ScanFile::Clean);
        }
        Ok(ScanFile::Finding(FileFinding {
            path: path.to_path_buf(),
            scope: ScanScope::classify(path),
            kind,
            findings,
            warnings,
            labels: label_counts(&secret_items),
            categories: category_counts(&secret_items),
            parser_fallback: result.parser_fallback,
        }))
    }

    fn ensure_engine(&mut self) {
        if self.engine.is_some() {
            return;
        }
        let packs = self.packs.take().unwrap_or_default();
        self.engine = Some(Engine::with_profile_and_packs(
            Profile::Strict,
            packs,
            false,
        ));
    }
}

fn label_counts(items: &[&MaskedItem]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for item in items {
        *out.entry(item.label.clone()).or_insert(0) += 1;
    }
    out
}

fn category_counts(items: &[&MaskedItem]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for item in items {
        *out.entry(format!("{:?}", item.category)).or_insert(0) += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_parse_defaults_to_current_dir() {
        let args = vec!["pentect".into(), "scan".into()];
        let opts = ScanOpts::parse(&args).unwrap();
        assert_eq!(opts.paths, vec![PathBuf::from(".")]);
        assert!(!opts.json);
        assert!(!opts.no_fail);
    }

    #[test]
    fn scan_parse_accepts_paths_and_automation_flags_only() {
        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--json".into(),
            "--no-fail".into(),
            "app.env".into(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        assert_eq!(opts.paths, vec![PathBuf::from("app.env")]);
        assert!(opts.json);
        assert!(opts.no_fail);
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
        std::fs::write(root.join("target").join("ignored.env"), "SECRET=ignored\n").unwrap();

        let args = vec![
            "pentect".into(),
            "scan".into(),
            root.to_string_lossy().to_string(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        let report = run_scan(&args, &opts).unwrap();
        let rendered = report_json(&report);
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.files.len(), 1);
        assert!(report.findings >= 2, "{rendered}");
        assert!(rendered.contains("RUNPOD_API_KEY"), "{rendered}");
        assert!(!rendered.contains("rpa_FAKEPENTECTSCAN"), "{rendered}");
        assert!(!rendered.contains("hello"), "{rendered}");

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
        let report = run_scan(&args, &opts).unwrap();
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
        let report = run_scan(&args, &opts).unwrap();
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
}
