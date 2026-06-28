use pentect_core::Kind;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default)]
pub(super) struct ScanReport {
    pub(super) roots: Vec<PathBuf>,
    pub(super) files_scanned: usize,
    pub(super) findings: usize,
    pub(super) warnings: usize,
    pub(super) skipped: Vec<SkippedFile>,
    pub(super) files: Vec<FileFinding>,
}

#[derive(Clone, Debug)]
pub(super) struct FileFinding {
    pub(super) path: PathBuf,
    pub(super) kind: Kind,
    pub(super) findings: usize,
    pub(super) warnings: usize,
    pub(super) labels: BTreeMap<String, usize>,
    pub(super) categories: BTreeMap<String, usize>,
    pub(super) parser_fallback: bool,
}

#[derive(Clone, Debug)]
pub(super) struct SkippedFile {
    pub(super) path: PathBuf,
    pub(super) reason: String,
}

impl SkippedFile {
    pub(super) fn new(path: &Path, reason: &str) -> Self {
        Self {
            path: path.to_path_buf(),
            reason: reason.to_string(),
        }
    }
}

pub(super) fn print_report(report: &ScanReport) {
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

pub(super) fn report_json(report: &ScanReport) -> String {
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
