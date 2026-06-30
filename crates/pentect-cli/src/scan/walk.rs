use super::report::SkippedFile;
use super::rules;
use ignore::{DirEntry, ParallelVisitor, ParallelVisitorBuilder, WalkBuilder, WalkState};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;

pub(super) fn collect_scan_roots(
    roots: &[PathBuf],
    excludes: &[String],
    use_gitignore: bool,
    skipped: &mut Vec<SkippedFile>,
) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for root in roots {
        if use_gitignore {
            if let Some((base, git_files)) = git_files_for_root(root) {
                let filtered = filter_git_files(base, git_files, excludes)?;
                files.extend(filtered);
                continue;
            }
        }
        let root = normalize_root(root);
        let mut builder = WalkBuilder::new(&root);
        configure_walker(&mut builder, &scan_base(&root), excludes, use_gitignore)?;
        collect_with_walker(builder, &mut files, skipped)?;
    }
    files.sort_unstable();
    files.dedup();
    Ok(files)
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
) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let mut visitor = WalkCollectorBuilder { tx };
    builder.build_parallel().visit(&mut visitor);
    drop(visitor);
    for batch in rx {
        if let Some(error) = batch.error {
            return Err(error);
        }
        files.extend(batch.files);
        skipped.extend(batch.skipped);
    }
    Ok(())
}

struct WalkCollectorBuilder {
    tx: mpsc::Sender<WalkBatch>,
}

impl<'s> ParallelVisitorBuilder<'s> for WalkCollectorBuilder {
    fn build(&mut self) -> Box<dyn ParallelVisitor + 's> {
        Box::new(WalkCollector {
            tx: self.tx.clone(),
            files: Vec::new(),
            skipped: Vec::new(),
            error: None,
        })
    }
}

struct WalkCollector {
    tx: mpsc::Sender<WalkBatch>,
    files: Vec<PathBuf>,
    skipped: Vec<SkippedFile>,
    error: Option<String>,
}

impl ParallelVisitor for WalkCollector {
    fn visit(&mut self, entry: Result<DirEntry, ignore::Error>) -> WalkState {
        match collect_entry(entry, &mut self.files, &mut self.skipped) {
            Ok(()) => WalkState::Continue,
            Err(e) => {
                self.error = Some(e);
                WalkState::Quit
            }
        }
    }
}

impl Drop for WalkCollector {
    fn drop(&mut self) {
        let _ = self.tx.send(WalkBatch {
            files: std::mem::take(&mut self.files),
            skipped: std::mem::take(&mut self.skipped),
            error: self.error.take(),
        });
    }
}

struct WalkBatch {
    files: Vec<PathBuf>,
    skipped: Vec<SkippedFile>,
    error: Option<String>,
}

fn collect_entry(
    entry: Result<DirEntry, ignore::Error>,
    files: &mut Vec<PathBuf>,
    skipped: &mut Vec<SkippedFile>,
) -> Result<(), String> {
    let entry = entry.map_err(|e| e.to_string())?;
    let path = entry.path().to_path_buf();
    if let Some(err) = entry.error() {
        return Err(format!("could not walk '{}': {err}", path.display()));
    }
    if entry.path_is_symlink() {
        skipped.push(SkippedFile::new(&path, "symlink"));
        return Ok(());
    }
    let Some(file_type) = entry.file_type() else {
        skipped.push(SkippedFile::new(&path, "not a regular file"));
        return Ok(());
    };
    if file_type.is_file() {
        files.push(path);
    } else if !file_type.is_dir() {
        skipped.push(SkippedFile::new(&path, "not a regular file"));
    }
    Ok(())
}

fn filter_git_files(
    base: PathBuf,
    git_files: Vec<PathBuf>,
    excludes: &[String],
) -> Result<Vec<PathBuf>, String> {
    if !has_pentectignore(&git_files) {
        let Some(overrides) = rules::build_overrides(&base, excludes)? else {
            return Ok(git_files);
        };
        return Ok(git_files
            .into_iter()
            .filter(|path| !overrides.matched(path, false).is_ignore())
            .collect());
    }
    let mut builder = WalkBuilder::new(&base);
    configure_walker(&mut builder, &base, excludes, true)?;
    let mut allowed = Vec::new();
    let mut skipped = Vec::new();
    collect_with_walker(builder, &mut allowed, &mut skipped)?;
    allowed.sort_unstable();
    let mut filtered = Vec::with_capacity(git_files.len());
    for path in git_files {
        if allowed.binary_search(&path).is_ok() {
            filtered.push(path);
        }
    }
    Ok(filtered)
}

fn has_pentectignore(paths: &[PathBuf]) -> bool {
    paths
        .iter()
        .any(|path| path.file_name().and_then(|name| name.to_str()) == Some(".pentectignore"))
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

fn git_files_for_root(root: &Path) -> Option<(PathBuf, Vec<PathBuf>)> {
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
        files.push(top.join(rel.as_ref()));
    }
    Some((top, files))
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

fn walk_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(8)
}
