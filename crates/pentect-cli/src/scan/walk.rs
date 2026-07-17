use super::progress::ScanProgress;
use super::report::SkippedFile;
use super::rules;
use ignore::{DirEntry, ParallelVisitor, ParallelVisitorBuilder, WalkBuilder, WalkState};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

const WALK_PROGRESS_BATCH: usize = 256;

pub(super) fn collect_scan_roots(
    roots: &[PathBuf],
    excludes: &[String],
    use_gitignore: bool,
    skipped: &mut Vec<SkippedFile>,
    skipped_count: &mut usize,
    retain_skipped: bool,
    progress: &ScanProgress,
) -> Result<Vec<PathBuf>, String> {
    let _heartbeat = WalkHeartbeat::start(progress);
    let mut files = Vec::new();
    for root in minimal_scan_roots(roots) {
        if root.is_file() {
            if !explicit_file_is_excluded(&root, excludes)? {
                files.push(root);
                progress.advance_by(1);
            }
            continue;
        }
        if use_gitignore {
            if let Some((base, walk_root, git_files)) = git_files_for_root(&root) {
                let filtered = filter_git_files(base, walk_root, git_files, excludes, progress)?;
                files.extend(filtered);
                continue;
            }
        }
        let mut builder = WalkBuilder::new(&root);
        configure_walker(&mut builder, &scan_base(&root), excludes, use_gitignore)?;
        collect_with_walker(
            builder,
            &mut files,
            skipped,
            skipped_count,
            retain_skipped,
            progress,
        )?;
    }
    files.sort_unstable();
    files.dedup();
    Ok(files)
}

fn explicit_file_is_excluded(path: &Path, excludes: &[String]) -> Result<bool, String> {
    let Some(overrides) = rules::build_overrides(&scan_base(path), excludes)? else {
        return Ok(false);
    };
    Ok(overrides.matched(path, false).is_ignore())
}

pub(super) fn ignored_file_reason(path: &Path) -> Option<&'static str> {
    has_extension(path, IGNORED_FILE_EXTENSIONS).then_some("binary extension")
}

const IGNORED_FILE_EXTENSIONS: &[&str] = &[
    "7z",
    "a",
    "arrow",
    "avi",
    "avif",
    "bin",
    "bmp",
    "br",
    "bz2",
    "class",
    "dat",
    "db",
    "db3",
    "dll",
    "dmg",
    "dylib",
    "eot",
    "exe",
    "feather",
    "flac",
    "gif",
    "gz",
    "heic",
    "ico",
    "iso",
    "jar",
    "jpeg",
    "jpg",
    "lib",
    "lz4",
    "mkv",
    "mov",
    "mp3",
    "mp4",
    "o",
    "obj",
    "ogg",
    "onnx",
    "otf",
    "parquet",
    "pdb",
    "pdf",
    "png",
    "pyc",
    "rar",
    "rlib",
    "safetensors",
    "so",
    "sqlite",
    "tar",
    "tgz",
    "tif",
    "tiff",
    "ttf",
    "war",
    "wasm",
    "wav",
    "webp",
    "woff",
    "woff2",
    "xz",
    "zip",
    "zst",
];

fn configure_walker(
    builder: &mut WalkBuilder,
    base: &Path,
    excludes: &[String],
    use_gitignore: bool,
) -> Result<(), String> {
    builder
        .hidden(false)
        .parents(true)
        .ignore(false)
        .git_ignore(use_gitignore)
        .git_global(use_gitignore)
        .git_exclude(use_gitignore)
        .require_git(false)
        .follow_links(false)
        .threads(walk_threads())
        .add_custom_ignore_filename(".pentectignore");
    if let Some(overrides) = rules::build_overrides(base, excludes)? {
        builder.overrides(overrides);
    }
    Ok(())
}

fn collect_with_walker(
    builder: WalkBuilder,
    files: &mut Vec<PathBuf>,
    skipped: &mut Vec<SkippedFile>,
    skipped_count: &mut usize,
    retain_skipped: bool,
    progress: &ScanProgress,
) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let mut visitor = WalkCollectorBuilder {
        tx,
        progress: progress.clone(),
        retain_skipped,
    };
    builder.build_parallel().visit(&mut visitor);
    drop(visitor);
    for batch in rx {
        if let Some(error) = batch.error {
            return Err(error);
        }
        files.extend(batch.files);
        skipped.extend(batch.skipped);
        *skipped_count += batch.skipped_count;
    }
    Ok(())
}

struct WalkCollectorBuilder {
    tx: mpsc::Sender<WalkBatch>,
    progress: ScanProgress,
    retain_skipped: bool,
}

impl<'s> ParallelVisitorBuilder<'s> for WalkCollectorBuilder {
    fn build(&mut self) -> Box<dyn ParallelVisitor + 's> {
        Box::new(WalkCollector {
            tx: self.tx.clone(),
            files: Vec::new(),
            skipped: Vec::new(),
            error: None,
            progress: self.progress.clone(),
            pending_progress: 0,
            skipped_count: 0,
            retain_skipped: self.retain_skipped,
        })
    }
}

struct WalkCollector {
    tx: mpsc::Sender<WalkBatch>,
    files: Vec<PathBuf>,
    skipped: Vec<SkippedFile>,
    error: Option<String>,
    progress: ScanProgress,
    pending_progress: usize,
    skipped_count: usize,
    retain_skipped: bool,
}

impl ParallelVisitor for WalkCollector {
    fn visit(&mut self, entry: Result<DirEntry, ignore::Error>) -> WalkState {
        match collect_entry(
            entry,
            &mut self.files,
            &mut self.skipped,
            &mut self.skipped_count,
            self.retain_skipped,
        ) {
            Ok(is_file) => {
                if is_file {
                    self.pending_progress += 1;
                    if self.pending_progress >= WALK_PROGRESS_BATCH {
                        self.progress.advance_by(self.pending_progress);
                        self.pending_progress = 0;
                    }
                }
                WalkState::Continue
            }
            Err(e) => {
                self.error = Some(e);
                WalkState::Quit
            }
        }
    }
}

impl Drop for WalkCollector {
    fn drop(&mut self) {
        self.progress.advance_by(self.pending_progress);
        let _ = self.tx.send(WalkBatch {
            files: std::mem::take(&mut self.files),
            skipped: std::mem::take(&mut self.skipped),
            skipped_count: self.skipped_count,
            error: self.error.take(),
        });
    }
}

struct WalkBatch {
    files: Vec<PathBuf>,
    skipped: Vec<SkippedFile>,
    skipped_count: usize,
    error: Option<String>,
}

fn collect_entry(
    entry: Result<DirEntry, ignore::Error>,
    files: &mut Vec<PathBuf>,
    skipped: &mut Vec<SkippedFile>,
    skipped_count: &mut usize,
    retain_skipped: bool,
) -> Result<bool, String> {
    let entry = entry.map_err(|e| e.to_string())?;
    let path = entry.path().to_path_buf();
    if let Some(err) = entry.error() {
        return Err(format!("could not walk '{}': {err}", path.display()));
    }
    if entry.path_is_symlink() {
        record_skipped(path, "symlink", skipped, skipped_count, retain_skipped);
        return Ok(false);
    }
    let Some(file_type) = entry.file_type() else {
        record_skipped(
            path,
            "not a regular file",
            skipped,
            skipped_count,
            retain_skipped,
        );
        return Ok(false);
    };
    if file_type.is_file() {
        files.push(path);
        return Ok(true);
    } else if !file_type.is_dir() {
        record_skipped(
            path,
            "not a regular file",
            skipped,
            skipped_count,
            retain_skipped,
        );
    }
    Ok(false)
}

fn record_skipped(
    path: PathBuf,
    reason: &str,
    skipped: &mut Vec<SkippedFile>,
    skipped_count: &mut usize,
    retain_skipped: bool,
) {
    *skipped_count += 1;
    if retain_skipped {
        skipped.push(SkippedFile::from_path_buf(path, reason));
    }
}

fn filter_git_files(
    base: PathBuf,
    walk_root: PathBuf,
    git_files: Vec<PathBuf>,
    excludes: &[String],
    progress: &ScanProgress,
) -> Result<Vec<PathBuf>, String> {
    if !has_pentectignore(&base, &git_files) {
        let Some(overrides) = rules::build_overrides(&base, excludes)? else {
            progress.advance_by(git_files.len());
            return Ok(git_files);
        };
        let filtered = git_files
            .into_iter()
            .filter(|path| !overrides.matched(path, false).is_ignore())
            .collect::<Vec<_>>();
        progress.advance_by(filtered.len());
        return Ok(filtered);
    }
    let mut builder = WalkBuilder::new(&walk_root);
    configure_walker(&mut builder, &base, excludes, true)?;
    let mut allowed = Vec::new();
    let mut skipped = Vec::new();
    let mut skipped_count = 0;
    collect_with_walker(
        builder,
        &mut allowed,
        &mut skipped,
        &mut skipped_count,
        false,
        &ScanProgress::disabled(),
    )?;
    allowed.sort_unstable();
    let mut filtered = Vec::with_capacity(git_files.len());
    for path in git_files {
        if allowed.binary_search(&path).is_ok() {
            filtered.push(path);
        }
    }
    progress.advance_by(filtered.len());
    Ok(filtered)
}

fn has_pentectignore(base: &Path, paths: &[PathBuf]) -> bool {
    if base.join(".pentectignore").is_file() {
        return true;
    }
    paths
        .iter()
        .any(|path| path.file_name().and_then(|name| name.to_str()) == Some(".pentectignore"))
}

fn has_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            extensions.binary_search(&ext).is_ok()
                || (ext.bytes().any(|byte| byte.is_ascii_uppercase())
                    && extensions
                        .iter()
                        .any(|candidate| ext.eq_ignore_ascii_case(candidate)))
        })
}

fn git_files_for_root(root: &Path) -> Option<(PathBuf, PathBuf, Vec<PathBuf>)> {
    let root_abs = root.canonicalize().ok()?;
    let git_cwd = if root_abs.is_file() {
        root_abs.parent()?
    } else {
        root_abs.as_path()
    };
    let top = Command::new("git")
        .arg("-C")
        .arg(git_cwd)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let top = PathBuf::from(String::from_utf8_lossy(&top.stdout).trim())
        .canonicalize()
        .ok()?;
    let rel = root_abs.strip_prefix(&top).ok()?;
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
        cmd.arg(git_pathspec(rel));
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
        push_git_regular_file(&top, rel.as_ref(), &mut files);
    }
    Some((top, root_abs, files))
}

struct WalkHeartbeat {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl WalkHeartbeat {
    fn start(progress: &ScanProgress) -> Option<Self> {
        if !progress.is_enabled() {
            return None;
        }
        let progress = progress.clone();
        let (stop, stopped) = mpsc::channel();
        let thread = std::thread::spawn(move || loop {
            match stopped.recv_timeout(Duration::from_secs(1)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => progress.pulse(),
            }
        });
        Some(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for WalkHeartbeat {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn push_git_regular_file(top: &Path, rel: &str, files: &mut Vec<PathBuf>) {
    let path = top.join(rel);
    if path.is_file() {
        files.push(path);
    }
}

fn git_pathspec(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn scan_base(root: &Path) -> PathBuf {
    if root.is_file() {
        root.parent()
            .map(Path::to_path_buf)
            .unwrap_or(root.to_path_buf())
    } else {
        root.to_path_buf()
    }
}

fn normalize_root(root: &Path) -> PathBuf {
    root.canonicalize().unwrap_or_else(|_| root.to_path_buf())
}

fn minimal_scan_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots = roots
        .iter()
        .map(|root| normalize_root(root))
        .collect::<Vec<_>>();
    roots.sort_unstable_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    let mut minimal = Vec::<PathBuf>::new();
    for root in roots {
        if minimal
            .iter()
            .any(|parent| parent.is_dir() && root.starts_with(parent))
        {
            continue;
        }
        minimal.push(root);
    }
    minimal
}

fn walk_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn git_listed_directories_are_not_scanned_as_files() {
        let root = temp_root("pentect-git-listed-dir");
        std::fs::create_dir_all(root.join("vendor-submodule")).unwrap();
        std::fs::write(root.join("tracked.txt"), "ok").unwrap();

        let mut files = Vec::new();
        push_git_regular_file(&root, "vendor-submodule", &mut files);
        push_git_regular_file(&root, "tracked.txt", &mut files);

        assert_eq!(vec![root.join("tracked.txt")], files);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn untracked_root_pentectignore_is_detected_for_git_filtering() {
        let root = temp_root("pentect-untracked-ignore");
        std::fs::write(root.join(".pentectignore"), "ignored.env\n").unwrap();
        assert!(has_pentectignore(&root, &[]));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ignored_extensions_are_sorted_and_case_insensitive() {
        assert!(IGNORED_FILE_EXTENSIONS.is_sorted());
        assert!(has_extension(
            Path::new("artifact.exe"),
            IGNORED_FILE_EXTENSIONS
        ));
        assert!(has_extension(
            Path::new("artifact.EXE"),
            IGNORED_FILE_EXTENSIONS
        ));
        assert!(!has_extension(
            Path::new("source.rs"),
            IGNORED_FILE_EXTENSIONS
        ));
    }

    #[test]
    fn nested_scan_roots_are_walked_once() {
        let root = temp_root("pentect-minimal-scan-roots");
        let nested = root.join("src");
        std::fs::create_dir(&nested).unwrap();
        let file = nested.join("main.rs");
        std::fs::write(&file, "fn main() {}\n").unwrap();

        assert_eq!(
            vec![normalize_root(&root)],
            minimal_scan_roots(&[nested, file, root.clone(), root.clone()])
        );

        let _ = std::fs::remove_dir_all(root);
    }
}
