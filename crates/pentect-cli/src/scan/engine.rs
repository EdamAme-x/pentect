use super::file_magic::{classify, FileMagic};
use super::options::BinaryMode;
use super::report::{FileFinding, ScanScope, SkippedFile};
use super::walk::ignored_file_reason;
use crate::infer_kind;
use memchr::memchr;
use pentect_core::{ByteRange, Category, Engine, Input, Kind, Profile, Span};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};

const ENGINE_NAME: &str = "pentect";
const MAX_SCAN_FILE_BYTES: u64 = 1024 * 1024;

pub(super) fn scan_files(
    files: Vec<PathBuf>,
    packs: Vec<pentect_core::Pack>,
    binary: BinaryMode,
) -> Result<(Vec<ScanFile>, String), String> {
    ScanPipeline::pentect(packs, binary)?.scan(files)
}

#[cfg(test)]
pub(super) fn scan_files_core_for_tests(
    files: Vec<PathBuf>,
    packs: Vec<pentect_core::Pack>,
    binary: BinaryMode,
) -> Result<(Vec<ScanFile>, String), String> {
    ScanPipeline::core_for_tests(packs, binary).scan(files)
}

#[derive(Clone, Debug)]
pub(super) enum ScanFile {
    Clean(PathBuf),
    Finding(FileFinding),
    Skipped(SkippedFile),
}

/// One detector backend inside the Pentect scan engine.
///
/// Adding a new engine should mean implementing this trait and appending it in
/// `ScanPipeline::pentect`. The pipeline owns path filtering, de-duplication,
/// value-free reporting, and final scan counts.
trait ScanBackend {
    fn name(&self) -> &'static str;
    fn binary_mode(&self) -> Option<BinaryMode> {
        None
    }
    fn scan(&mut self, files: &[PathBuf]) -> Result<Vec<FileFinding>, String>;
}

struct ScanPipeline {
    name: &'static str,
    backends: Vec<Box<dyn ScanBackend>>,
}

impl ScanPipeline {
    fn pentect(packs: Vec<pentect_core::Pack>, binary: BinaryMode) -> Result<Self, String> {
        Ok(Self {
            name: ENGINE_NAME,
            backends: vec![Box::new(CoreBackend::new(packs, binary))],
        })
    }

    #[cfg(test)]
    fn core_for_tests(packs: Vec<pentect_core::Pack>, binary: BinaryMode) -> Self {
        Self {
            name: "core",
            backends: vec![Box::new(CoreBackend::new(packs, binary))],
        }
    }

    fn scan(&mut self, files: Vec<PathBuf>) -> Result<(Vec<ScanFile>, String), String> {
        let (eligible, skipped) = precheck_files(&files, self.binary_mode())?;
        let mut out = skipped
            .into_iter()
            .map(ScanFile::Skipped)
            .collect::<Vec<_>>();
        let mut scanned_paths = eligible.iter().cloned().collect::<BTreeSet<_>>();
        let mut findings = FindingSet::default();

        for backend in &mut self.backends {
            let backend_name = backend.name();
            for file in backend
                .scan(&eligible)
                .map_err(|e| format!("{backend_name}: {e}"))?
            {
                scanned_paths.insert(file.path.clone());
                findings.merge_file(file);
            }
        }

        let finding_files = findings.into_files();
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
        Ok((out, self.name.to_string()))
    }

    fn binary_mode(&self) -> BinaryMode {
        self.backends
            .iter()
            .find_map(|backend| backend.binary_mode())
            .unwrap_or(BinaryMode::Skip)
    }
}

fn precheck_files(
    files: &[PathBuf],
    binary: BinaryMode,
) -> Result<(Vec<PathBuf>, Vec<SkippedFile>), String> {
    let mut eligible = Vec::new();
    let mut skipped = Vec::new();
    for path in files {
        if binary == BinaryMode::Skip {
            if let Some(reason) = ignored_file_reason(path) {
                skipped.push(SkippedFile::new(path, reason));
                continue;
            }
        }
        let meta = match std::fs::metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                skipped.push(SkippedFile::new(path, "missing"));
                continue;
            }
            Err(e) => return Err(format!("could not read '{}': {e}", path.display())),
        };
        if meta.len() > MAX_SCAN_FILE_BYTES {
            skipped.push(SkippedFile::new(path, "too large"));
            continue;
        }
        if binary == BinaryMode::Skip && should_sniff_magic(path) {
            if let Some(reason) = binary_magic_reason(path)? {
                skipped.push(SkippedFile::new(path, reason));
                continue;
            }
        }
        eligible.push(path.clone());
    }
    Ok((eligible, skipped))
}

fn should_sniff_magic(path: &Path) -> bool {
    path.extension().is_none()
}

fn binary_magic_reason(path: &Path) -> Result<Option<&'static str>, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    let mut buf = [0u8; 16];
    let len = file
        .read(&mut buf)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    match classify(&buf[..len]) {
        FileMagic::TextCandidate => Ok(None),
        FileMagic::Binary(reason) => Ok(Some(reason)),
    }
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

struct CoreBackend {
    packs: Option<Vec<pentect_core::Pack>>,
    engine: Option<Engine>,
    binary: BinaryMode,
}

impl CoreBackend {
    fn new(packs: Vec<pentect_core::Pack>, binary: BinaryMode) -> Self {
        Self {
            packs: Some(packs),
            engine: None,
            binary,
        }
    }

    fn scan_file(&mut self, path: &Path) -> Result<Option<FileFinding>, String> {
        let Some(data) = read_text_file(path, self.binary)? else {
            return Ok(None);
        };
        let kind = infer_kind(path);
        self.ensure_engine();
        let line_index = LineIndex::new(&data);
        let result = self.engine.as_ref().unwrap().analyze_spans(Input {
            kind: kind.clone(),
            data: data.clone(),
        });
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
            return Ok(None);
        }
        Ok(Some(FileFinding {
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
        self.engine = Some(Engine::secret_scan_with_profile_and_packs(
            Profile::Strict,
            packs,
        ));
    }
}

impl ScanBackend for CoreBackend {
    fn name(&self) -> &'static str {
        "core"
    }

    fn binary_mode(&self) -> Option<BinaryMode> {
        Some(self.binary)
    }

    fn scan(&mut self, files: &[PathBuf]) -> Result<Vec<FileFinding>, String> {
        if files.is_empty() {
            return Ok(Vec::new());
        }
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(8)
            .min(files.len());
        let files = Arc::new(files.to_vec());
        let next = Arc::new(AtomicUsize::new(0));
        let packs = self.packs.take().unwrap_or_default();
        let (tx, rx) = mpsc::channel();
        std::thread::scope(|scope| {
            for _ in 0..workers {
                let files = Arc::clone(&files);
                let next = Arc::clone(&next);
                let packs = packs.clone();
                let tx = tx.clone();
                let binary = self.binary;
                scope.spawn(move || {
                    let mut worker = CoreBackend::new(packs, binary);
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
            rx.into_iter()
                .collect::<Result<Vec<_>, _>>()
                .map(|items| items.into_iter().flatten().collect())
        })
    }
}

fn read_text_file(path: &Path, binary: BinaryMode) -> Result<Option<String>, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if binary == BinaryMode::Skip && memchr(0, &bytes).is_some() {
        return Ok(None);
    }
    match String::from_utf8(bytes) {
        Ok(data) => Ok(Some(data)),
        Err(e) if binary == BinaryMode::Text => {
            Ok(Some(String::from_utf8_lossy(e.as_bytes()).into_owned()))
        }
        Err(_) => Ok(None),
    }
}

fn hit_from_span(span: &Span, line_index: &LineIndex) -> Option<ScanHit> {
    Some(ScanHit {
        label: span.label.clone(),
        category: format!("{:?}", span.category),
        engine: span.source.as_str().to_string(),
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
    fn scan_engine_does_not_shell_out_to_credsweeper() {
        let source = include_str!("engine.rs");
        for forbidden in [
            concat!("PENTECT_", "CREDSWEEPER_", "PYTHON"),
            concat!("Cred", "Sweeper", "Command"),
            concat!("Command", "::", "new"),
            concat!("python", " -m ", "credsweeper"),
        ] {
            assert!(!source.contains(forbidden), "{forbidden}");
        }
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
