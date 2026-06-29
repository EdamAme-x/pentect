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
    Generated,
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
        let file_name_lower = file_name.to_ascii_lowercase();
        if is_generated_file(path) {
            return Self::Generated;
        }
        if normalized.contains("/proptest-regressions/")
            || file_name == "tests.rs"
            || file_name.ends_with("_test.rs")
            || file_name.ends_with("_tests.rs")
            || file_name.ends_with("_test.go")
            || file_name.starts_with("test_")
            || file_name_lower.ends_with(".test.js")
            || file_name_lower.ends_with(".test.jsx")
            || file_name_lower.ends_with(".test.ts")
            || file_name_lower.ends_with(".test.tsx")
            || file_name_lower.ends_with(".spec.js")
            || file_name_lower.ends_with(".spec.jsx")
            || file_name_lower.ends_with(".spec.ts")
            || file_name_lower.ends_with(".spec.tsx")
            || file_name_lower == "conftest.py"
            || file_name.contains("fixture")
            || path_has_segment(
                &normalized,
                &[
                    "test",
                    "tests",
                    "testdata",
                    "__tests__",
                    "__tests_dts__",
                    "playground",
                ],
            )
            || path_has_segment(
                &normalized,
                &["fixture", "fixtures", "snapshot", "snapshots"],
            )
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
            || normalized.starts_with("docs_src/")
            || normalized.contains("/docs_src/")
            || normalized.starts_with("examples/")
            || normalized.contains("/examples/")
            || normalized.starts_with("_examples/")
            || normalized.contains("/_examples/")
            || file_name.eq_ignore_ascii_case("README.md")
            || file_name.eq_ignore_ascii_case("CHANGELOG.md")
            || file_name.eq_ignore_ascii_case("CHANGES.md")
            || file_name.eq_ignore_ascii_case("CHANGES.rst")
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
            Self::Generated => "generated",
            Self::Runtime => "runtime",
            Self::ApplicationSource => "application_source",
            Self::DetectorSource => "detector_source",
            Self::TestFixture => "test_fixture",
            Self::Evaluation => "evaluation",
            Self::DocsExamples => "docs_examples",
        }
    }
}

fn is_generated_file(path: &Path) -> bool {
    has_file_name(
        path,
        &[
            "bun.lockb",
            "cargo.lock",
            "go.sum",
            "go.work.sum",
            "npm-shrinkwrap.json",
            "package-lock.json",
            "pipfile.lock",
            "pnpm-lock.yaml",
            "pnpm-lock.yml",
            "poetry.lock",
            "uv.lock",
            "yarn.lock",
        ],
    ) || has_extension(path, &["svg"])
}

fn has_file_name(path: &Path, names: &[&str]) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            names
                .iter()
                .any(|candidate| name.eq_ignore_ascii_case(candidate))
        })
}

fn has_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            extensions
                .iter()
                .any(|candidate| ext.eq_ignore_ascii_case(candidate))
        })
}

fn path_has_segment(path: &str, segments: &[&str]) -> bool {
    path.split('/').any(|part| {
        segments
            .iter()
            .any(|segment| part.eq_ignore_ascii_case(segment))
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_test_paths_are_test_fixture_scope() {
        for path in [
            "tests/unit/http.test.js",
            "test/res.location.js",
            "pkg/testdata/key.pem",
            "src/__tests__/client.spec.ts",
            "src/__tests_dts__/utils.ts",
            "playground/env/.env",
            "snapshots/register.bash",
        ] {
            assert_eq!(ScanScope::classify(Path::new(path)), ScanScope::TestFixture);
        }
    }

    #[test]
    fn generated_files_are_explicit_scope() {
        for path in [
            "package-lock.json",
            "pnpm-lock.yaml",
            "go.sum",
            "Cargo.lock",
            "docs/logo.svg",
        ] {
            assert_eq!(ScanScope::classify(Path::new(path)), ScanScope::Generated);
        }
    }

    #[test]
    fn common_docs_and_examples_are_docs_scope() {
        for path in [
            "README.md",
            "CHANGELOG.md",
            "_examples/rest/main.go",
            "docs_src/security/tutorial.py",
        ] {
            assert_eq!(
                ScanScope::classify(Path::new(path)),
                ScanScope::DocsExamples
            );
        }
    }
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
