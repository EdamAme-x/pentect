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
    pub(super) scope: ScanScope,
    pub(super) kind: Kind,
    pub(super) findings: usize,
    pub(super) warnings: usize,
    pub(super) labels: BTreeMap<String, usize>,
    pub(super) categories: BTreeMap<String, usize>,
    pub(super) parser_fallback: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ScanScope {
    Runtime,
    ApplicationSource,
    DetectorSource,
    TestFixture,
    Evaluation,
    DocsExamples,
}

impl ScanScope {
    pub(super) fn classify(path: &Path) -> Self {
        let normalized = path.to_string_lossy().replace('\\', "/");
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if normalized.contains("/proptest-regressions/")
            || file_name == "tests.rs"
            || file_name.ends_with("_test.rs")
            || file_name.ends_with("_tests.rs")
            || file_name.starts_with("test_")
            || file_name.contains("fixture")
            || file_name == "bip39_english.txt"
        {
            return Self::TestFixture;
        }
        if normalized.contains("/src/detect/") || normalized.contains("/src/policy/guard.rs") {
            return Self::DetectorSource;
        }
        if normalized.starts_with("tools/")
            || normalized.contains("/tools/")
            || file_name.starts_with("eval_")
            || file_name.starts_with("bench_")
        {
            return Self::Evaluation;
        }
        if normalized.starts_with("docs/")
            || normalized.contains("/docs/")
            || normalized.starts_with("examples/")
            || normalized.contains("/examples/")
            || file_name.eq_ignore_ascii_case("README.md")
        {
            return Self::DocsExamples;
        }
        if is_source_file(path) {
            return Self::ApplicationSource;
        }
        Self::Runtime
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::ApplicationSource => "application_source",
            Self::DetectorSource => "detector_source",
            Self::TestFixture => "test_fixture",
            Self::Evaluation => "evaluation",
            Self::DocsExamples => "docs_examples",
        }
    }
}

fn is_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "rs" | "py"
                    | "js"
                    | "ts"
                    | "tsx"
                    | "jsx"
                    | "go"
                    | "java"
                    | "kt"
                    | "cs"
                    | "c"
                    | "cc"
                    | "cpp"
                    | "h"
                    | "hpp"
                    | "swift"
                    | "rb"
                    | "php"
                    | "toml"
                    | "yaml"
                    | "yml"
                    | "json"
            )
        })
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
    println!("scope summary: {}", compact_scope_counts(report));
    println!(
        "{:<48} {:<18} {:>8} {:>8} labels",
        "file", "scope", "findings", "warnings"
    );
    for file in &report.files {
        println!(
            "{:<48} {:<18} {:>8} {:>8} {}",
            display_path(&file.path),
            file.scope.as_str(),
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
            "scopes": scope_counts(report),
            "labels_by_scope": labels_by_scope(report),
        },
        "files": report.files.iter().map(|file| json!({
            "path": display_path(&file.path),
            "scope": file.scope.as_str(),
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

fn scope_counts(report: &ScanReport) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for file in &report.files {
        *counts.entry(file.scope.as_str().to_string()).or_insert(0) += file.findings;
    }
    counts
}

fn labels_by_scope(report: &ScanReport) -> BTreeMap<String, BTreeMap<String, usize>> {
    let mut scopes: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for file in &report.files {
        let labels = scopes.entry(file.scope.as_str().to_string()).or_default();
        for (label, count) in &file.labels {
            *labels.entry(label.clone()).or_insert(0) += count;
        }
    }
    scopes
}

fn compact_scope_counts(report: &ScanReport) -> String {
    scope_counts(report)
        .iter()
        .map(|(scope, count)| format!("{scope}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
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
