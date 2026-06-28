use crate::{die, infer_kind, load_packs, parse_kind};
use pentect_core::{Category, Config, Engine, Input, Kind, MaskedItem, Profile};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};

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

#[derive(Clone, Debug)]
struct ScanOpts {
    paths: Vec<PathBuf>,
    kind: Option<Kind>,
    profile: Profile,
    json: bool,
    no_fail: bool,
}

#[derive(Clone, Debug, Default)]
struct ScanReport {
    roots: Vec<PathBuf>,
    files_scanned: usize,
    findings: usize,
    warnings: usize,
    skipped: Vec<SkippedFile>,
    files: Vec<FileFinding>,
}

#[derive(Clone, Debug)]
struct FileFinding {
    path: PathBuf,
    kind: Kind,
    findings: usize,
    warnings: usize,
    labels: BTreeMap<String, usize>,
    categories: BTreeMap<String, usize>,
    parser_fallback: bool,
}

#[derive(Clone, Debug)]
struct SkippedFile {
    path: PathBuf,
    reason: String,
}

impl ScanOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut paths = Vec::new();
        let mut kind = None;
        let mut profile = Profile::Balanced;
        let mut json = false;
        let mut no_fail = false;
        let mut i = 2usize;
        while i < args.len() {
            match args[i].as_str() {
                "--json" => {
                    json = true;
                    i += 1;
                }
                "--no-fail" => {
                    no_fail = true;
                    i += 1;
                }
                "--kind" => {
                    kind = Some(parse_kind(&required_value(args, &mut i, "--kind")?)?);
                }
                "--profile" => {
                    profile = required_value(args, &mut i, "--profile")?.parse()?;
                }
                "--pack" | "--pack-dir" | "--extensions" => {
                    let flag = args[i].clone();
                    let _ = required_value(args, &mut i, &flag)?;
                }
                flag if flag.starts_with("--") => {
                    return Err(format!("unknown option: {flag}"));
                }
                path => {
                    paths.push(PathBuf::from(path));
                    i += 1;
                }
            }
        }
        if paths.is_empty() {
            paths.push(PathBuf::from("."));
        }
        Ok(Self {
            paths,
            kind,
            profile,
            json,
            no_fail,
        })
    }
}

fn required_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    let Some(value) = args.get(*i + 1) else {
        return Err(format!("{flag} requires a value"));
    };
    if value.starts_with("--") {
        return Err(format!("{flag} requires a value"));
    }
    *i += 2;
    Ok(value.clone())
}

fn run_scan(args: &[String], opts: &ScanOpts) -> Result<ScanReport, String> {
    let packs = load_packs(args)?;
    let mut report = ScanReport {
        roots: opts.paths.clone(),
        ..ScanReport::default()
    };
    let mut files = Vec::new();
    for root in &opts.paths {
        if let Some(git_files) = git_files_for_root(root) {
            files.extend(git_files);
        } else {
            collect_files(root, &mut files, &mut report.skipped)?;
        }
    }
    files.sort();
    files.dedup();
    for result in scan_files(files, opts, packs)? {
        match result {
            ScanFile::Clean => {
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

enum ScanFile {
    Clean,
    Finding(FileFinding),
    Skipped(SkippedFile),
}

fn collect_files(
    path: &Path,
    out: &mut Vec<PathBuf>,
    skipped: &mut Vec<SkippedFile>,
) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        skipped.push(skip(path, "symlink"));
        return Ok(());
    }
    if meta.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }
    if !meta.is_dir() {
        skipped.push(skip(path, "not a regular file"));
        return Ok(());
    }
    if is_ignored_dir(path) {
        return Ok(());
    }
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(path)
        .map_err(|e| format!("could not read directory '{}': {e}", path.display()))?
    {
        let entry =
            entry.map_err(|e| format!("could not read directory '{}': {e}", path.display()))?;
        entries.push(entry.path());
    }
    entries.sort();
    for entry in entries {
        collect_files(&entry, out, skipped)?;
    }
    Ok(())
}

fn scan_file(
    engine: &Engine,
    cfg: &Config,
    opts: &ScanOpts,
    path: &Path,
) -> Result<ScanFile, String> {
    if is_ignored_file(path) {
        return Ok(ScanFile::Skipped(skip(path, "binary extension")));
    }
    let meta =
        std::fs::metadata(path).map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if meta.len() > MAX_SCAN_FILE_BYTES {
        return Ok(ScanFile::Skipped(skip(path, "too large")));
    }
    let bytes =
        std::fs::read(path).map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if bytes.contains(&0) {
        return Ok(ScanFile::Skipped(skip(path, "binary content")));
    }
    let data = match String::from_utf8(bytes) {
        Ok(data) => data,
        Err(_) => return Ok(ScanFile::Skipped(skip(path, "non-utf8"))),
    };
    if !looks_scan_relevant(path, &data) {
        return Ok(ScanFile::Clean);
    }
    let kind = opts.kind.clone().unwrap_or_else(|| infer_kind(path));
    let result = engine.mask(
        Input {
            kind: kind.clone(),
            data,
        },
        cfg,
    );
    let secret_items = result
        .items
        .iter()
        .filter(|item| item.category == Category::Secret)
        .collect::<Vec<_>>();
    let findings = secret_items.len();
    if findings == 0 {
        return Ok(ScanFile::Clean);
    }
    let warnings = result
        .summary
        .residual
        .iter()
        .filter(|note| note.category == Category::Secret)
        .count()
        + if findings > 0 {
            result.summary.collisions.len()
        } else {
            0
        };
    Ok(ScanFile::Finding(FileFinding {
        path: path.to_path_buf(),
        kind,
        findings,
        warnings,
        labels: label_counts(&secret_items),
        categories: category_counts(&secret_items),
        parser_fallback: result.summary.parser_fallback,
    }))
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

fn looks_scan_relevant(path: &Path, data: &str) -> bool {
    if infer_kind(path) == Kind::Env {
        return true;
    }
    if path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "pem" | "key" | "p8" | "p12" | "pfx" | "kdbx"
            )
        })
    {
        return true;
    }
    let lower = data.to_ascii_lowercase();
    [
        "api_key",
        "apikey",
        "authorization",
        "bearer ",
        "begin ec private key",
        "begin openssh private key",
        "begin private key",
        "begin rsa private key",
        "client_secret",
        "ghp_",
        "github_token",
        "id_token",
        "mnemonic",
        "openai_api_key",
        "otp=",
        "otp:",
        "password",
        "passwd",
        "private_key",
        "recovery phrase",
        "refresh_token",
        "rpa_",
        "runpod_api_key",
        "secret=",
        "secret:",
        "shared_secret",
        "sk-",
        "token=",
        "token:",
        "verification code",
        "webhook",
        "xoxb-",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || data.contains("AKIA")
}

fn scan_files(
    files: Vec<PathBuf>,
    opts: &ScanOpts,
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
    let opts = Arc::new(opts.clone());
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let files = Arc::clone(&files);
            let next = Arc::clone(&next);
            let opts = Arc::clone(&opts);
            let packs = packs.clone();
            let tx = tx.clone();
            scope.spawn(move || {
                let engine = Engine::with_profile_and_packs(opts.profile, packs, false);
                let cfg = Config::generate();
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(path) = files.get(index) else {
                        break;
                    };
                    if tx.send(scan_file(&engine, &cfg, &opts, path)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);
        rx.into_iter().collect::<Result<Vec<_>, _>>()
    })
}

fn git_files_for_root(root: &Path) -> Option<Vec<PathBuf>> {
    if root.is_file() {
        return None;
    }
    let top = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let top = PathBuf::from(String::from_utf8_lossy(&top.stdout).trim())
        .canonicalize()
        .ok()?;
    let root_abs = root.canonicalize().ok()?;
    let rel = root_abs.strip_prefix(&top).unwrap_or(Path::new(""));
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(&top).args([
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
    ]);
    if !rel.as_os_str().is_empty() {
        cmd.arg(rel);
    }
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let mut files = Vec::new();
    for raw in output.stdout.split(|b| *b == 0) {
        if raw.is_empty() {
            continue;
        }
        let rel = String::from_utf8_lossy(raw);
        files.push(top.join(rel.as_ref()));
    }
    Some(files)
}

fn is_ignored_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | ".pentect-agent"
            | "target"
            | "node_modules"
            | ".venv"
            | "venv"
            | "__pycache__"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".ruff_cache"
            | ".next"
            | "dist"
            | "build"
    ) || (name == "agent"
        && path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|parent| parent.to_str())
            == Some(".pentect"))
}

fn is_ignored_file(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "ico"
            | "pdf"
            | "zip"
            | "gz"
            | "xz"
            | "7z"
            | "rar"
            | "exe"
            | "dll"
            | "pdb"
            | "rlib"
            | "wasm"
            | "lock"
    )
}

fn skip(path: &Path, reason: &str) -> SkippedFile {
    SkippedFile {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    }
}

fn print_report(report: &ScanReport) {
    println!(
        "pentect scan findings={} files={} skipped={}",
        report.findings,
        report.files_scanned,
        report.skipped.len()
    );
    if report.files.is_empty() {
        println!("no findings");
        return;
    }
    println!("{:<48} {:>8} {:>8} labels", "file", "findings", "warnings");
    for file in &report.files {
        println!(
            "{:<48} {:>8} {:>8} {}",
            display_path(&file.path),
            file.findings,
            file.warnings,
            compact_counts(&file.labels)
        );
    }
}

fn report_json(report: &ScanReport) -> String {
    json!({
        "roots": report.roots.iter().map(|p| display_path(p)).collect::<Vec<_>>(),
        "summary": {
            "findings": report.findings,
            "files_scanned": report.files_scanned,
            "files_with_findings": report.files.len(),
            "warnings": report.warnings,
            "skipped": report.skipped.len(),
        },
        "files": report.files.iter().map(|file| json!({
            "path": display_path(&file.path),
            "kind": format!("{:?}", file.kind),
            "findings": file.findings,
            "warnings": file.warnings,
            "labels": file.labels,
            "categories": file.categories,
            "parser_fallback": file.parser_fallback,
        })).collect::<Vec<_>>(),
        "skipped": report.skipped.iter().map(|file| json!({
            "path": display_path(&file.path),
            "reason": file.reason,
        })).collect::<Vec<_>>(),
    })
    .to_string()
}

fn compact_counts(counts: &BTreeMap<String, usize>) -> String {
    counts
        .iter()
        .map(|(label, count)| format!("{label}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn display_path(path: &Path) -> String {
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|cwd| cwd.canonicalize().ok());
    let target = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let target = target.canonicalize().unwrap_or(target);
    let rel = cwd
        .as_deref()
        .and_then(|cwd| target.strip_prefix(cwd).ok())
        .unwrap_or(&target);
    rel.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_parse_defaults_to_current_dir_and_balanced() {
        let args = vec!["pentect".into(), "scan".into()];
        let opts = ScanOpts::parse(&args).unwrap();
        assert_eq!(opts.paths, vec![PathBuf::from(".")]);
        assert_eq!(opts.profile, Profile::Balanced);
        assert!(!opts.json);
        assert!(!opts.no_fail);
    }

    #[test]
    fn scan_parse_accepts_paths_and_automation_flags() {
        let args = vec![
            "pentect".into(),
            "scan".into(),
            "--json".into(),
            "--no-fail".into(),
            "--kind".into(),
            "env".into(),
            "--profile".into(),
            "balanced".into(),
            "app.env".into(),
        ];
        let opts = ScanOpts::parse(&args).unwrap();
        assert_eq!(opts.paths, vec![PathBuf::from("app.env")]);
        assert_eq!(opts.kind, Some(Kind::Env));
        assert_eq!(opts.profile, Profile::Balanced);
        assert!(opts.json);
        assert!(opts.no_fail);
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
}
