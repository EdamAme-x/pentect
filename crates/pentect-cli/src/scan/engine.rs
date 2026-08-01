use super::file_magic::{classify, FileMagic};
use super::options::BinaryMode;
use super::progress::ScanProgress;
use super::report::{FileFinding, ScanScope, SkippedFile};
use super::walk::ignored_file_reason;
use memchr::memchr;
use pentect_core::{
    infer_kind_with_content, ByteRange, Category, Context, DecodeConfig, Engine, Input, Kind,
    Profile, RegionKind, Span,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{mpsc, Condvar, Mutex};

const ENGINE_NAME: &str = "pentect";
const MAX_SCAN_FILE_BYTES: u64 = 16 * 1024 * 1024;
const RESULT_BATCH_SIZE: usize = 256;
const LARGE_FILE_BYTES: usize = 1024 * 1024;
const LARGE_FILE_CONCURRENCY: usize = 2;

pub(super) fn scan_files(
    files: Vec<PathBuf>,
    packs: Vec<pentect_core::Pack>,
    binary: BinaryMode,
    progress: ScanProgress,
    retain_skipped: bool,
) -> Result<(Vec<ScanFile>, String), String> {
    #[cfg(not(test))]
    let decode = pentect_agent::load_decode_config(Profile::Strict)?;
    #[cfg(test)]
    let decode = DecodeConfig::default();
    let plugins = pentect_agent::PluginMiddleware::from_env()?;
    ScanPipeline::pentect(packs, binary, decode, plugins)?.scan(files, &progress, retain_skipped)
}

#[cfg(test)]
pub(super) fn scan_files_core_for_tests(
    files: Vec<PathBuf>,
    packs: Vec<pentect_core::Pack>,
    binary: BinaryMode,
    progress: ScanProgress,
    retain_skipped: bool,
) -> Result<(Vec<ScanFile>, String), String> {
    ScanPipeline::core_for_tests(packs, binary).scan(files, &progress, retain_skipped)
}

#[derive(Clone, Debug)]
pub(super) enum ScanFile {
    Count {
        files_scanned: usize,
        skipped: usize,
    },
    CleanPath(PathBuf),
    Finding(FileFinding),
    Skipped(SkippedFile),
    Error(String),
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
    fn scan(
        &mut self,
        files: &[PathBuf],
        progress: &ScanProgress,
        retain_hits: bool,
        retain_skipped: bool,
    ) -> Result<Vec<ScanFile>, String>;
}

struct ScanPipeline {
    name: &'static str,
    backends: Vec<Box<dyn ScanBackend>>,
}

impl ScanPipeline {
    fn pentect(
        packs: Vec<pentect_core::Pack>,
        binary: BinaryMode,
        decode: DecodeConfig,
        plugins: pentect_agent::PluginMiddleware,
    ) -> Result<Self, String> {
        Ok(Self {
            name: ENGINE_NAME,
            backends: vec![Box::new(CoreBackend::new(packs, binary, decode, plugins))],
        })
    }

    #[cfg(test)]
    fn core_for_tests(packs: Vec<pentect_core::Pack>, binary: BinaryMode) -> Self {
        Self {
            name: "core",
            backends: vec![Box::new(CoreBackend::new(
                packs,
                binary,
                DecodeConfig::default(),
                pentect_agent::PluginMiddleware::default(),
            ))],
        }
    }

    fn scan(
        &mut self,
        files: Vec<PathBuf>,
        progress: &ScanProgress,
        retain_skipped: bool,
    ) -> Result<(Vec<ScanFile>, String), String> {
        progress.start("check", Some(files.len()));
        let (eligible, skipped, skipped_count) =
            precheck_files(files, self.binary_mode(), progress, retain_skipped);
        let mut out = skipped
            .into_iter()
            .map(ScanFile::Skipped)
            .collect::<Vec<_>>();
        if skipped_count > 0 {
            out.push(ScanFile::Count {
                files_scanned: 0,
                skipped: skipped_count,
            });
        }

        if self.backends.len() == 1 {
            let backend = &mut self.backends[0];
            progress.start("scan", Some(eligible.len()));
            out.extend(
                backend
                    .scan(&eligible, progress, false, retain_skipped)
                    .map_err(|e| format!("{}: {e}", backend.name()))?,
            );
            return Ok((out, self.name.to_string()));
        }

        let mut scanned_paths = BTreeSet::new();
        let mut skipped_paths = BTreeMap::new();
        let mut findings = FindingSet::default();

        for backend in &mut self.backends {
            let backend_name = backend.name();
            progress.start("scan", Some(eligible.len()));
            for result in backend
                .scan(&eligible, progress, true, true)
                .map_err(|e| format!("{backend_name}: {e}"))?
            {
                match result {
                    ScanFile::CleanPath(path) => {
                        skipped_paths.remove(&path);
                        scanned_paths.insert(path);
                    }
                    ScanFile::Count { .. } => {
                        return Err(format!("{backend_name}: pathless multi-engine result"));
                    }
                    ScanFile::Finding(file) => {
                        skipped_paths.remove(&file.path);
                        scanned_paths.insert(file.path.clone());
                        findings.merge_file(file);
                    }
                    ScanFile::Skipped(skipped) => {
                        if !scanned_paths.contains(&skipped.path) {
                            skipped_paths.entry(skipped.path.clone()).or_insert(skipped);
                        }
                    }
                    ScanFile::Error(error) => return Err(format!("{backend_name}: {error}")),
                }
            }
        }

        let finding_files = findings.into_files();
        let finding_paths = finding_files
            .iter()
            .map(|file| file.path.clone())
            .collect::<BTreeSet<_>>();
        for path in scanned_paths {
            if !finding_paths.contains(&path) {
                out.push(ScanFile::CleanPath(path));
            }
        }
        for file in finding_files {
            out.push(ScanFile::Finding(file));
        }
        out.extend(skipped_paths.into_values().map(ScanFile::Skipped));
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
    files: Vec<PathBuf>,
    binary: BinaryMode,
    progress: &ScanProgress,
    retain_skipped: bool,
) -> (Vec<PathBuf>, Vec<SkippedFile>, usize) {
    if files.is_empty() {
        return (Vec::new(), Vec::new(), 0);
    }
    let workers = worker_count(files.len());
    let next = AtomicUsize::new(0);
    let statuses = (0..files.len())
        .map(|_| AtomicU8::new(PRECHECK_PENDING))
        .collect::<Vec<_>>();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let next = &next;
            let statuses = &statuses;
            let files = &files;
            scope.spawn(move || loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(path) = files.get(index) else {
                    break;
                };
                statuses[index].store(precheck_file(path, binary), Ordering::Relaxed);
                progress.advance();
            });
        }
    });
    let mut eligible = Vec::new();
    let mut skipped = Vec::new();
    let mut skipped_count = 0;
    for (path, status) in files.into_iter().zip(statuses) {
        let status = status.load(Ordering::Relaxed);
        if status == PRECHECK_ELIGIBLE {
            eligible.push(path);
        } else if retain_skipped {
            skipped.push(SkippedFile::from_path_buf(path, precheck_reason(status)));
        } else {
            skipped_count += 1;
        }
    }
    (eligible, skipped, skipped_count)
}

const PRECHECK_PENDING: u8 = 0;
const PRECHECK_ELIGIBLE: u8 = 1;
const PRECHECK_BINARY_EXTENSION: u8 = 2;
const PRECHECK_MISSING: u8 = 3;
const PRECHECK_METADATA_ERROR: u8 = 4;
const PRECHECK_NOT_FILE: u8 = 5;
const PRECHECK_TOO_LARGE: u8 = 6;

fn precheck_file(path: &Path, binary: BinaryMode) -> u8 {
    if binary == BinaryMode::Skip && ignored_file_reason(path).is_some() {
        return PRECHECK_BINARY_EXTENSION;
    }
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return PRECHECK_MISSING;
        }
        Err(_) => return PRECHECK_METADATA_ERROR,
    };
    if !meta.is_file() {
        return PRECHECK_NOT_FILE;
    }
    if meta.len() > MAX_SCAN_FILE_BYTES {
        return PRECHECK_TOO_LARGE;
    }
    PRECHECK_ELIGIBLE
}

fn precheck_reason(status: u8) -> &'static str {
    match status {
        PRECHECK_BINARY_EXTENSION => "binary extension",
        PRECHECK_MISSING => "missing",
        PRECHECK_METADATA_ERROR => "metadata error",
        PRECHECK_NOT_FILE => "not a regular file",
        PRECHECK_TOO_LARGE => "too large",
        _ => "precheck error",
    }
}

fn worker_count(file_count: usize) -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(8)
        .min(file_count)
}

fn should_sniff_magic(path: &Path) -> bool {
    path.extension().is_none()
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
    decode: DecodeConfig,
    plugins: pentect_agent::PluginMiddleware,
}

impl CoreBackend {
    fn new(
        packs: Vec<pentect_core::Pack>,
        binary: BinaryMode,
        decode: DecodeConfig,
        plugins: pentect_agent::PluginMiddleware,
    ) -> Self {
        Self {
            packs: Some(packs),
            engine: None,
            binary,
            decode,
            plugins,
        }
    }

    fn ensure_engine(&mut self) {
        if self.engine.is_some() {
            return;
        }
        let packs = self.packs.take().unwrap_or_default();
        self.engine = Some(Engine::secret_scan_with_profile_packs_and_decode_config(
            Profile::Strict,
            packs,
            self.decode,
        ));
    }
}

fn scan_file_with_limits(
    engine: &Engine,
    plugins: &pentect_agent::PluginMiddleware,
    path: &Path,
    binary: BinaryMode,
    large_files: &LargeFileLimiter,
    retain_hits: bool,
    retain_skipped: bool,
) -> ScanFile {
    let data = match read_text_file(path, binary) {
        ReadTextFile::Text(data) => data,
        ReadTextFile::Skipped(reason) => {
            return if retain_skipped {
                ScanFile::Skipped(SkippedFile::new(path, reason))
            } else {
                ScanFile::Count {
                    files_scanned: 0,
                    skipped: 1,
                }
            };
        }
    };
    // Detectors can temporarily expand text several times. Keep small files
    // fully parallel while bounding the peak created by large inputs.
    let _large_file_permit = large_files.acquire(data.len());
    let kind = infer_kind_with_content(path, &data);
    let line_index = LineIndex::new(&data);
    let plugin_spans = if plugins.is_empty() {
        Vec::new()
    } else {
        let input = Input {
            kind: kind.clone(),
            data: data.clone(),
        };
        let plugin_context = Context {
            path: Some(path.to_string_lossy().into_owned()),
            key: None,
            hints: Vec::new(),
            kind: RegionKind::PlainText,
            format: kind.clone(),
        };
        match plugins.detect_spans(&input, Some(&plugin_context)) {
            Ok(run) => run.spans,
            Err(error) => return ScanFile::Error(format!("{}: {error}", path.display())),
        }
    };
    let result = engine.analyze_spans_with_path(
        Input {
            kind: kind.clone(),
            data,
        },
        path.to_string_lossy().into_owned(),
    );
    let mut spans = result
        .spans
        .into_iter()
        .filter(|span| span.category == Category::Secret)
        .map(|span| (span, true))
        .collect::<Vec<_>>();
    spans.extend(plugin_spans.into_iter().map(|span| (span, false)));
    spans.sort_by(|(left, left_is_core), (right, right_is_core)| {
        right_is_core
            .cmp(left_is_core)
            .then_with(|| right.cmp_strength(left))
    });
    let mut selected = Vec::<(Span, bool)>::new();
    for (span, is_core) in spans {
        if selected
            .iter()
            .all(|(existing, _)| !existing.range.overlaps(&span.range))
        {
            selected.push((span, is_core));
        }
    }
    selected.sort_by_key(|(span, _)| span.range.start);
    let hits = selected
        .iter()
        .filter_map(|(span, _)| hit_from_span(span, &line_index))
        .collect::<Vec<_>>();
    let warnings = result
        .residual
        .iter()
        .filter(|note| note.category == Category::Secret)
        .count();
    if hits.is_empty() && warnings == 0 {
        return if retain_hits {
            ScanFile::CleanPath(path.to_path_buf())
        } else {
            ScanFile::Count {
                files_scanned: 1,
                skipped: 0,
            }
        };
    }
    let findings = hits.len();
    let labels = label_counts(&hits);
    let categories = category_counts(&hits);
    let engines = engine_counts(&hits);
    let hits = if retain_hits { hits } else { Vec::new() };
    ScanFile::Finding(FileFinding {
        path: path.to_path_buf(),
        scope: ScanScope::classify(path),
        kind,
        findings,
        warnings,
        labels,
        categories,
        engines,
        parser_fallback: result.parser_fallback,
        hits,
    })
}

impl ScanBackend for CoreBackend {
    fn name(&self) -> &'static str {
        "core"
    }

    fn binary_mode(&self) -> Option<BinaryMode> {
        Some(self.binary)
    }

    fn scan(
        &mut self,
        files: &[PathBuf],
        progress: &ScanProgress,
        retain_hits: bool,
        retain_skipped: bool,
    ) -> Result<Vec<ScanFile>, String> {
        if files.is_empty() {
            return Ok(Vec::new());
        }
        let workers = worker_count(files.len());
        self.ensure_engine();
        let Some(engine) = self.engine.as_ref() else {
            return Err("engine unavailable".to_string());
        };
        let plugins = &self.plugins;
        let next = AtomicUsize::new(0);
        let large_files = LargeFileLimiter::new(LARGE_FILE_CONCURRENCY);
        let (tx, rx) = mpsc::channel();
        let out = std::thread::scope(|scope| {
            for _ in 0..workers {
                let next = &next;
                let tx = tx.clone();
                let binary = self.binary;
                let large_files = &large_files;
                scope.spawn(move || {
                    let mut batch = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(path) = files.get(index) else {
                            break;
                        };
                        batch.push(scan_file_with_limits(
                            engine,
                            plugins,
                            path,
                            binary,
                            large_files,
                            retain_hits,
                            retain_skipped,
                        ));
                        progress.advance();
                        if batch.len() >= RESULT_BATCH_SIZE
                            && tx.send(std::mem::take(&mut batch)).is_err()
                        {
                            return;
                        }
                    }
                    if !batch.is_empty() {
                        let _ = tx.send(batch);
                    }
                });
            }
            drop(tx);
            let mut out = Vec::new();
            let mut files_scanned = 0;
            let mut skipped = 0;
            for result in rx.into_iter().flatten() {
                match result {
                    ScanFile::Count {
                        files_scanned: count,
                        skipped: count_skipped,
                    } => {
                        files_scanned += count;
                        skipped += count_skipped;
                    }
                    ScanFile::Error(error) => return Err(error),
                    result => out.push(result),
                }
            }
            if files_scanned > 0 || skipped > 0 {
                out.push(ScanFile::Count {
                    files_scanned,
                    skipped,
                });
            }
            Ok(out)
        });
        out
    }
}

struct LargeFileLimiter {
    available: Mutex<usize>,
    ready: Condvar,
}

impl LargeFileLimiter {
    fn new(permits: usize) -> Self {
        Self {
            available: Mutex::new(permits.max(1)),
            ready: Condvar::new(),
        }
    }

    fn acquire(&self, bytes: usize) -> Option<LargeFilePermit<'_>> {
        if bytes < LARGE_FILE_BYTES {
            return None;
        }
        let mut available = self
            .available
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *available == 0 {
            available = self
                .ready
                .wait(available)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        *available -= 1;
        Some(LargeFilePermit { limiter: self })
    }
}

struct LargeFilePermit<'a> {
    limiter: &'a LargeFileLimiter,
}

impl Drop for LargeFilePermit<'_> {
    fn drop(&mut self) {
        let mut available = self
            .limiter
            .available
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *available += 1;
        self.limiter.ready.notify_one();
    }
}

enum ReadTextFile {
    Text(String),
    Skipped(&'static str),
}

fn read_text_file(path: &Path, binary: BinaryMode) -> ReadTextFile {
    let Ok(bytes) = std::fs::read(path) else {
        return ReadTextFile::Skipped("read error");
    };
    if binary == BinaryMode::Skip && should_sniff_magic(path) {
        if let FileMagic::Binary(reason) = classify(&bytes) {
            return ReadTextFile::Skipped(reason);
        }
    }
    if binary == BinaryMode::Skip && memchr(0, &bytes).is_some() {
        return ReadTextFile::Skipped("binary content");
    }
    match String::from_utf8(bytes) {
        Ok(data) => ReadTextFile::Text(data),
        Err(e) if binary == BinaryMode::Text => {
            ReadTextFile::Text(String::from_utf8_lossy(e.as_bytes()).into_owned())
        }
        Err(_) => ReadTextFile::Skipped("invalid utf-8"),
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

struct LineIndex {
    len: usize,
    starts: Vec<usize>,
    char_starts: Vec<usize>,
    ascii: bool,
}

impl LineIndex {
    fn new(text: &str) -> Self {
        let mut starts = vec![0];
        for (i, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                starts.push(i + 1);
            }
        }
        let ascii = text.is_ascii();
        let char_starts = if ascii {
            Vec::new()
        } else {
            text.char_indices().map(|(i, _)| i).collect()
        };
        Self {
            len: text.len(),
            starts,
            char_starts,
            ascii,
        }
    }

    fn range(&self, range: ByteRange) -> Option<SourceRange> {
        if range.end > self.len || range.start >= range.end {
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
        if offset < start || offset > self.len {
            return None;
        }
        if self.ascii {
            return Some(offset - start);
        }
        if offset != self.len && self.char_starts.binary_search(&offset).is_err() {
            return None;
        }
        let start_chars = self.char_starts.partition_point(|i| *i < start);
        let offset_chars = self.char_starts.partition_point(|i| *i < offset);
        Some(offset_chars - start_chars)
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

    #[test]
    fn line_index_counts_utf8_columns_without_borrowing_text() {
        let index = LineIndex::new("あb\nc");
        assert_eq!(
            index.range(ByteRange::new(0, "あ".len())),
            Some(SourceRange {
                line_start: 1,
                line_end: 1,
                col_start: 0,
                col_end: 1,
            })
        );
        assert_eq!(
            index.range(ByteRange::new("あ".len(), "あb".len())),
            Some(SourceRange {
                line_start: 1,
                line_end: 1,
                col_start: 1,
                col_end: 2,
            })
        );
    }
}
