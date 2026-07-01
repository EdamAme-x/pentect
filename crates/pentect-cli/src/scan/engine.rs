use super::report::{FileFinding, ScanScope, SkippedFile};
use super::walk::ignored_file_reason;
use crate::infer_kind;
use pentect_core::{ByteRange, Category, Engine, Input, Kind, Profile, Span};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, OnceLock};

const MAX_SCAN_FILE_BYTES: u64 = 1024 * 1024;
const CREDSWEEPER_BATCH_SIZE: usize = 128;
const CREDSWEEPER_JOBS: &str = "8";

pub(super) fn scan_files(
    files: Vec<PathBuf>,
    packs: Vec<pentect_core::Pack>,
    core_only: bool,
) -> Result<(Vec<ScanFile>, String), String> {
    let plan = ScanPlan::new(core_only);
    let mut out = Vec::new();
    let mut report = FindingSet::default();
    let mut scanned_paths = BTreeSet::new();

    if let Some(command) = plan.credsweeper_command.clone() {
        let mut eligible = Vec::new();
        for path in &files {
            match lightweight_precheck(path)? {
                Precheck::Eligible => {
                    scanned_paths.insert(path.clone());
                    eligible.push(path.clone());
                }
                Precheck::Skipped(skipped) => out.push(ScanFile::Skipped(skipped)),
            }
        }
        for file in CredSweeperRunner::new(command).scan(&eligible)? {
            report.merge_file(file);
        }
    }

    if plan.core {
        for file in scan_core_files(files, packs)? {
            match file {
                ScanFile::Finding(file) => {
                    scanned_paths.insert(file.path.clone());
                    report.merge_file(file);
                }
                ScanFile::Clean(path) => {
                    scanned_paths.insert(path);
                }
                ScanFile::Skipped(skipped) => {
                    if plan.credsweeper_command.is_none() {
                        out.push(ScanFile::Skipped(skipped));
                    }
                }
            }
        }
    }

    let finding_files = report.into_files();
    let finding_paths = finding_files
        .iter()
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>();
    for path in scanned_paths {
        if !finding_paths.contains(&path) {
            out.push(ScanFile::Clean(path));
        }
    }
    for file in finding_files {
        out.push(ScanFile::Finding(file));
    }
    Ok((out, plan.name.to_string()))
}

#[derive(Clone, Debug)]
pub(super) enum ScanFile {
    Clean(PathBuf),
    Finding(FileFinding),
    Skipped(SkippedFile),
}

#[derive(Clone, Debug)]
struct ScanPlan {
    name: &'static str,
    core: bool,
    credsweeper_command: Option<CredSweeperCommand>,
}

impl ScanPlan {
    fn new(core_only: bool) -> Self {
        if core_only {
            return Self {
                name: "core",
                core: true,
                credsweeper_command: None,
            };
        }
        let credsweeper_command = CredSweeperCommand::discover();
        Self {
            name: "pentect",
            core: true,
            credsweeper_command,
        }
    }
}

enum Precheck {
    Eligible,
    Skipped(SkippedFile),
}

fn lightweight_precheck(path: &Path) -> Result<Precheck, String> {
    if let Some(reason) = ignored_file_reason(path) {
        return Ok(Precheck::Skipped(SkippedFile::new(path, reason)));
    }
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Precheck::Skipped(SkippedFile::new(path, "missing")));
        }
        Err(e) => return Err(format!("could not read '{}': {e}", path.display())),
    };
    if meta.len() > MAX_SCAN_FILE_BYTES {
        return Ok(Precheck::Skipped(SkippedFile::new(path, "too large")));
    }
    Ok(Precheck::Eligible)
}

#[derive(Default)]
struct FindingSet {
    files: BTreeMap<PathBuf, FileAccumulator>,
}

impl FindingSet {
    fn merge_file(&mut self, file: FileFinding) {
        let path = file.path.clone();
        self.files
            .entry(path)
            .or_insert_with(|| FileAccumulator {
                path: file.path.clone(),
                scope: file.scope,
                kind: file.kind.clone(),
                warnings: 0,
                parser_fallback: false,
                hits: Vec::new(),
            })
            .merge(file);
    }

    fn into_files(self) -> Vec<FileFinding> {
        self.files
            .into_values()
            .filter_map(FileAccumulator::into_file)
            .collect()
    }
}

struct FileAccumulator {
    path: PathBuf,
    scope: ScanScope,
    kind: Kind,
    warnings: usize,
    parser_fallback: bool,
    hits: Vec<ScanHit>,
}

impl FileAccumulator {
    fn merge(&mut self, file: FileFinding) {
        self.warnings += file.warnings;
        self.parser_fallback |= file.parser_fallback;
        for hit in file.hits {
            self.push_hit(hit);
        }
    }

    fn push_hit(&mut self, hit: ScanHit) {
        if self.hits.iter().any(|existing| existing.overlaps(&hit)) {
            return;
        }
        self.hits.push(hit);
    }

    fn into_file(self) -> Option<FileFinding> {
        if self.hits.is_empty() && self.warnings == 0 {
            return None;
        }
        let mut labels = BTreeMap::new();
        let mut categories = BTreeMap::new();
        let mut engines = BTreeMap::new();
        for hit in &self.hits {
            *labels.entry(hit.label.clone()).or_insert(0) += 1;
            *categories.entry(hit.category.clone()).or_insert(0) += 1;
            *engines.entry(hit.engine.clone()).or_insert(0) += 1;
        }
        Some(FileFinding {
            path: self.path,
            scope: self.scope,
            kind: self.kind,
            findings: self.hits.len(),
            warnings: self.warnings,
            labels,
            categories,
            engines,
            parser_fallback: self.parser_fallback,
            hits: self.hits,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct ScanHit {
    pub(super) label: String,
    pub(super) category: String,
    pub(super) engine: String,
    range: SourceRange,
}

impl ScanHit {
    fn overlaps(&self, other: &Self) -> bool {
        self.range.overlaps(other.range)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceRange {
    line_start: usize,
    line_end: usize,
    col_start: usize,
    col_end: usize,
}

impl SourceRange {
    fn overlaps(self, other: SourceRange) -> bool {
        if self.line_end < other.line_start || other.line_end < self.line_start {
            return false;
        }
        if self.line_start == self.line_end && other.line_start == other.line_end {
            return self.col_start < other.col_end && other.col_start < self.col_end;
        }
        true
    }
}

#[derive(Clone, Debug)]
struct CredSweeperCommand {
    python: PathBuf,
}

impl CredSweeperCommand {
    fn discover() -> Option<Self> {
        static CACHE: OnceLock<Option<CredSweeperCommand>> = OnceLock::new();
        CACHE.get_or_init(Self::discover_uncached).clone()
    }

    fn discover_uncached() -> Option<Self> {
        let mut candidates = Vec::new();
        if let Some(path) = std::env::var_os("PENTECT_CREDSWEEPER_PYTHON") {
            candidates.push(PathBuf::from(path));
        }
        candidates.extend(bundled_venv_candidates());
        candidates.push(PathBuf::from("python"));
        candidates.push(PathBuf::from("python3"));
        candidates
            .into_iter()
            .find_map(|python| module_available(&python).then_some(Self { python }))
    }
}

fn bundled_venv_candidates() -> Vec<PathBuf> {
    let Some(root) = repo_root() else {
        return Vec::new();
    };
    let base = root.join("third_party").join("CredSweeper").join(".venv");
    if cfg!(windows) {
        vec![base.join("Scripts").join("python.exe")]
    } else {
        vec![base.join("bin").join("python")]
    }
}

fn repo_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join(".gitmodules").is_file() && dir.join("third_party").join("CredSweeper").exists()
        {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn module_available(python: &Path) -> bool {
    Command::new(python)
        .args(["-m", "credsweeper", "--version"])
        .output()
        .is_ok_and(|output| output.status.success())
}

struct CredSweeperRunner {
    command: CredSweeperCommand,
}

impl CredSweeperRunner {
    fn new(command: CredSweeperCommand) -> Self {
        Self { command }
    }

    fn scan(&self, files: &[PathBuf]) -> Result<Vec<FileFinding>, String> {
        if files.is_empty() {
            return Ok(Vec::new());
        }
        let mut by_file: BTreeMap<PathBuf, FileAccumulator> = BTreeMap::new();
        for (batch_index, batch) in files.chunks(CREDSWEEPER_BATCH_SIZE).enumerate() {
            let output_path = temp_json_path(batch_index);
            self.run_batch(batch, &output_path)?;
            for hit in parse_credsweeper_output(&output_path)? {
                let path = hit.path.clone();
                by_file
                    .entry(path.clone())
                    .or_insert_with(|| FileAccumulator {
                        path: path.clone(),
                        scope: ScanScope::classify(&path),
                        kind: infer_kind(&path),
                        warnings: 0,
                        parser_fallback: false,
                        hits: Vec::new(),
                    })
                    .push_hit_with_path(hit);
            }
            let _ = std::fs::remove_file(&output_path);
        }
        Ok(by_file
            .into_values()
            .filter_map(FileAccumulator::into_file)
            .collect())
    }

    fn run_batch(&self, files: &[PathBuf], output_path: &Path) -> Result<(), String> {
        let mut command = Command::new(&self.command.python);
        command
            .args(["-m", "credsweeper", "--jobs", CREDSWEEPER_JOBS])
            .arg("--save-json")
            .arg(output_path)
            .args([
                "--sort",
                "--subtext",
                "--no-stdout",
                "--no-color",
                "--hashed",
                "--no-error",
                "--path",
            ]);
        for file in files {
            command.arg(file);
        }
        let output = command
            .output()
            .map_err(|_| "failed to launch CredSweeper".to_string())?;
        if !output.status.success() {
            return Err("CredSweeper failed; check the Python environment and try `python -m credsweeper --version`".to_string());
        }
        Ok(())
    }
}

fn temp_json_path(batch_index: usize) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "pentect-credsweeper-{}-{nonce}-{batch_index}.json",
        std::process::id()
    ))
}

#[derive(Deserialize)]
struct CredSweeperItem {
    rule: String,
    #[serde(default)]
    line_data_list: Vec<CredSweeperLine>,
}

#[derive(Deserialize)]
struct CredSweeperLine {
    path: String,
    line_num: usize,
    value_start: Option<usize>,
    value_end: Option<usize>,
}

fn parse_credsweeper_output(path: &Path) -> Result<Vec<ScanHitWithPath>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read CredSweeper output: {e}"))?;
    let items: Vec<CredSweeperItem> = serde_json::from_str(&raw)
        .map_err(|e| format!("could not parse CredSweeper output: {e}"))?;
    let mut out = Vec::new();
    for item in items {
        let Some(first) = item.line_data_list.first() else {
            continue;
        };
        let last = item.line_data_list.last().unwrap_or(first);
        let Some(col_start) = first.value_start else {
            continue;
        };
        let Some(col_end) = last.value_end else {
            continue;
        };
        if first.line_num == last.line_num && col_end <= col_start {
            continue;
        }
        let path = normalize_path(&first.path);
        let label = normalize_label(&item.rule);
        out.push(ScanHitWithPath {
            path,
            label,
            category: "Secret".to_string(),
            engine: "credsweeper".to_string(),
            range: SourceRange {
                line_start: first.line_num,
                line_end: last.line_num,
                col_start,
                col_end,
            },
        });
    }
    Ok(out)
}

#[derive(Clone, Debug)]
struct ScanHitWithPath {
    path: PathBuf,
    label: String,
    category: String,
    engine: String,
    range: SourceRange,
}

impl From<ScanHitWithPath> for ScanHit {
    fn from(hit: ScanHitWithPath) -> Self {
        Self {
            label: hit.label,
            category: hit.category,
            engine: hit.engine,
            range: hit.range,
        }
    }
}

impl FileAccumulator {
    fn push_hit_with_path(&mut self, hit: ScanHitWithPath) {
        self.push_hit(hit.into());
    }
}

fn normalize_path(raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    path.canonicalize().unwrap_or(path)
}

fn normalize_label(rule: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;
    for ch in rule.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
            last_was_sep = false;
        } else if !last_was_sep {
            out.push('_');
            last_was_sep = true;
        }
    }
    let label = out.trim_matches('_');
    if label.is_empty() {
        "CREDSWEEPER".to_string()
    } else {
        label.to_string()
    }
}

fn scan_core_files(
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
                let mut worker = CoreWorker::new(packs);
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

struct CoreWorker {
    packs: Option<Vec<pentect_core::Pack>>,
    engine: Option<Engine>,
}

impl CoreWorker {
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
        let result = self.engine.as_ref().unwrap().analyze_spans(Input {
            kind: kind.clone(),
            data: data.clone(),
        });
        let line_index = LineIndex::new(&data);
        let hits = result
            .spans
            .iter()
            .filter(|span| span.category == Category::Secret)
            .filter_map(|span| hit_from_span(span, &line_index))
            .collect::<Vec<_>>();
        let warnings = result
            .residual
            .iter()
            .filter(|note| note.category == Category::Secret)
            .count();
        if hits.is_empty() && warnings == 0 {
            return Ok(ScanFile::Clean(path.to_path_buf()));
        }
        Ok(ScanFile::Finding(FileFinding {
            path: path.to_path_buf(),
            scope: ScanScope::classify(path),
            kind,
            findings: hits.len(),
            warnings,
            labels: label_counts(&hits),
            categories: category_counts(&hits),
            engines: engine_counts(&hits),
            parser_fallback: result.parser_fallback,
            hits,
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

fn hit_from_span(span: &Span, line_index: &LineIndex) -> Option<ScanHit> {
    Some(ScanHit {
        label: span.label.clone(),
        category: format!("{:?}", span.category),
        engine: "core".to_string(),
        range: line_index.range(span.range)?,
    })
}

fn label_counts(hits: &[ScanHit]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for hit in hits {
        *out.entry(hit.label.clone()).or_insert(0) += 1;
    }
    out
}

fn category_counts(hits: &[ScanHit]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for hit in hits {
        *out.entry(hit.category.clone()).or_insert(0) += 1;
    }
    out
}

fn engine_counts(hits: &[ScanHit]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for hit in hits {
        *out.entry(hit.engine.clone()).or_insert(0) += 1;
    }
    out
}

struct LineIndex<'a> {
    text: &'a str,
    starts: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    fn new(text: &'a str) -> Self {
        let mut starts = vec![0];
        for (i, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                starts.push(i + 1);
            }
        }
        Self { text, starts }
    }

    fn range(&self, range: ByteRange) -> Option<SourceRange> {
        if range.end > self.text.len() || range.start >= range.end {
            return None;
        }
        let line_start = self.line_for_offset(range.start)?;
        let line_end = self.line_for_offset(range.end.saturating_sub(1))?;
        let col_start = self.column_for_offset(line_start, range.start)?;
        let col_end = self.column_for_offset(line_end, range.end)?;
        Some(SourceRange {
            line_start,
            line_end,
            col_start,
            col_end,
        })
    }

    fn line_for_offset(&self, offset: usize) -> Option<usize> {
        let idx = self.starts.partition_point(|start| *start <= offset);
        (idx > 0).then_some(idx)
    }

    fn column_for_offset(&self, line: usize, offset: usize) -> Option<usize> {
        let start = *self.starts.get(line.checked_sub(1)?)?;
        if offset < start || offset > self.text.len() {
            return None;
        }
        Some(self.text[start..offset].chars().count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_sanitized() {
        assert_eq!(normalize_label("API Key"), "API_KEY");
        assert_eq!(normalize_label("OTP / 2FA Secret"), "OTP_2FA_SECRET");
    }

    #[test]
    fn source_ranges_overlap_on_same_line_columns() {
        let a = SourceRange {
            line_start: 1,
            line_end: 1,
            col_start: 4,
            col_end: 8,
        };
        let b = SourceRange {
            line_start: 1,
            line_end: 1,
            col_start: 6,
            col_end: 10,
        };
        let c = SourceRange {
            line_start: 1,
            line_end: 1,
            col_start: 8,
            col_end: 12,
        };
        assert!(a.overlaps(b));
        assert!(!a.overlaps(c));
    }
}
