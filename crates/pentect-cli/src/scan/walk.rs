use super::progress::ScanProgress;
use super::report::SkippedFile;
use super::rules;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::{DirEntry, Match, ParallelVisitor, ParallelVisitorBuilder, WalkBuilder, WalkState};
use std::collections::HashSet;
use std::ffi::OsString;
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
    if excludes.is_empty() {
        return Ok(false);
    }
    let base = filesystem_git_root(path).unwrap_or_else(|| scan_base(path));
    let Some(overrides) = rules::build_overrides(&base, excludes)? else {
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
    debug_assert!(walk_root.starts_with(&base));
    let custom_ignores = load_custom_ignores(&base, &git_files)?;
    let overrides = rules::build_overrides(&base, excludes)?;
    let mut filtered = Vec::with_capacity(git_files.len());
    for path in git_files {
        let custom_ignored = custom_ignores.iter().fold(false, |ignored, matcher| {
            if !path.starts_with(&matcher.root) {
                return ignored;
            }
            match matcher.matcher.matched_path_or_any_parents(&path, false) {
                Match::Ignore(_) => true,
                Match::Whitelist(_) => false,
                Match::None => ignored,
            }
        });
        let allowed = match overrides
            .as_ref()
            .map(|overrides| overrides.matched(&path, false))
        {
            Some(Match::Ignore(_)) => false,
            Some(Match::Whitelist(_)) => true,
            Some(Match::None) | None => !custom_ignored,
        };
        if allowed {
            filtered.push(path);
        }
    }
    progress.advance_by(filtered.len());
    Ok(filtered)
}

struct CustomIgnore {
    root: PathBuf,
    matcher: Gitignore,
}

fn load_custom_ignores(base: &Path, files: &[PathBuf]) -> Result<Vec<CustomIgnore>, String> {
    let mut visited = HashSet::new();
    let mut paths = Vec::new();
    for file in files {
        let mut current = file.parent();
        while let Some(dir) = current.filter(|dir| dir.starts_with(base)) {
            if !visited.insert(dir.to_path_buf()) {
                break;
            }
            let path = dir.join(".pentectignore");
            if path.is_file() {
                paths.push(path);
            }
            if dir == base {
                break;
            }
            current = dir.parent();
        }
    }
    paths.sort_unstable_by_key(|path| path.components().count());
    paths
        .into_iter()
        .map(|path| {
            let root = path
                .parent()
                .ok_or_else(|| format!("invalid .pentectignore path: {}", path.display()))?
                .to_path_buf();
            let mut builder = GitignoreBuilder::new(&root);
            if let Some(error) = builder.add(&path) {
                return Err(format!("could not load '{}': {error}", path.display()));
            }
            let matcher = builder
                .build()
                .map_err(|error| format!("could not load '{}': {error}", path.display()))?;
            Ok(CustomIgnore { root, matcher })
        })
        .collect()
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
    let context = git_context(root)?;
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(&context.top)
        .arg("--literal-pathspecs")
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
        ]);
    if !context.relative.as_os_str().is_empty() {
        cmd.arg(git_pathspec(&context.relative));
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
        let rel = git_path_from_bytes(raw)?;
        push_git_regular_file(&context.top, &rel, &mut files);
    }
    Some((context.top, context.root, files))
}

struct GitContext {
    top: PathBuf,
    root: PathBuf,
    relative: PathBuf,
}

fn git_context(root: &Path) -> Option<GitContext> {
    let root = root.canonicalize().ok()?;
    let git_cwd = if root.is_file() {
        root.parent()?
    } else {
        root.as_path()
    };
    let top = filesystem_git_root(&root).or_else(|| {
        let output = Command::new("git")
            .arg("-C")
            .arg(git_cwd)
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .ok()
            .filter(|output| output.status.success())?;
        git_path_from_bytes(trim_line_end(&output.stdout))?
            .canonicalize()
            .ok()
    })?;
    let relative = root.strip_prefix(&top).ok()?.to_path_buf();
    Some(GitContext {
        top,
        root,
        relative,
    })
}

fn filesystem_git_root(path: &Path) -> Option<PathBuf> {
    let start = if path.is_file() { path.parent()? } else { path };
    start
        .ancestors()
        .find(|ancestor| ancestor.join(".git").try_exists().ok() == Some(true))
        .map(Path::to_path_buf)
}

fn trim_line_end(mut bytes: &[u8]) -> &[u8] {
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(unix)]
fn git_path_from_bytes(bytes: &[u8]) -> Option<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    Some(PathBuf::from(OsStr::from_bytes(bytes)))
}

#[cfg(not(unix))]
fn git_path_from_bytes(bytes: &[u8]) -> Option<PathBuf> {
    String::from_utf8(bytes.to_vec()).ok().map(PathBuf::from)
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

fn push_git_regular_file(top: &Path, rel: &Path, files: &mut Vec<PathBuf>) {
    let path = top.join(rel);
    if path.is_file() {
        files.push(path);
    }
}

#[cfg(windows)]
fn git_pathspec(path: &Path) -> OsString {
    OsString::from(path.to_string_lossy().replace('\\', "/"))
}

#[cfg(not(windows))]
fn git_pathspec(path: &Path) -> OsString {
    path.as_os_str().to_os_string()
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
        if minimal.contains(&root)
            || (root.is_dir()
                && minimal
                    .iter()
                    .any(|parent| parent.is_dir() && root.starts_with(parent)))
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

    fn init_git(root: &Path) {
        let status = Command::new("git")
            .arg("init")
            .arg("--quiet")
            .arg(root)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn collect_test_roots(roots: &[PathBuf], excludes: &[String]) -> Vec<PathBuf> {
        let mut skipped = Vec::new();
        let mut skipped_count = 0;
        collect_scan_roots(
            roots,
            excludes,
            true,
            &mut skipped,
            &mut skipped_count,
            false,
            &ScanProgress::disabled(),
        )
        .unwrap()
    }

    #[test]
    fn git_listed_directories_are_not_scanned_as_files() {
        let root = temp_root("pentect-git-listed-dir");
        std::fs::create_dir_all(root.join("vendor-submodule")).unwrap();
        std::fs::write(root.join("tracked.txt"), "ok").unwrap();

        let mut files = Vec::new();
        push_git_regular_file(&root, Path::new("vendor-submodule"), &mut files);
        push_git_regular_file(&root, Path::new("tracked.txt"), &mut files);

        assert_eq!(vec![root.join("tracked.txt")], files);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn gitignored_pentectignore_is_detected_for_git_filtering() {
        let root = temp_root("pentect-gitignored-ignore");
        init_git(&root);
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join(".gitignore"), "**/.pentectignore\n").unwrap();
        std::fs::write(root.join("sub").join(".pentectignore"), "ignored.env\n").unwrap();
        let candidate = root.join("sub").join("ignored.env");
        std::fs::write(&candidate, "secret\n").unwrap();
        assert_eq!(1, load_custom_ignores(&root, &[candidate]).unwrap().len());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_file_is_kept_beside_parent_root() {
        let root = temp_root("pentect-explicit-file-root");
        init_git(&root);
        let ignored = root.join("ignored.env");
        std::fs::write(root.join(".gitignore"), "ignored.env\n").unwrap();
        std::fs::write(&ignored, "secret\n").unwrap();

        let files = collect_test_roots(&[root.clone(), ignored.clone()], &[]);
        assert!(files.contains(&ignored.canonicalize().unwrap()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_file_exclude_is_relative_to_git_root() {
        let root = temp_root("pentect-explicit-file-exclude");
        init_git(&root);
        let sub = root.join("sub");
        std::fs::create_dir(&sub).unwrap();
        let ignored = sub.join("ignored.env");
        std::fs::write(&ignored, "secret\n").unwrap();

        let files = collect_test_roots(&[ignored], &["sub/ignored.env".to_string()]);
        assert!(files.is_empty(), "{files:?}");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn git_subtree_honors_ancestor_pentectignore() {
        let root = temp_root("pentect-git-subtree-ignore");
        init_git(&root);
        let subtree = root.join("sub").join("child");
        std::fs::create_dir_all(&subtree).unwrap();
        std::fs::write(
            root.join("sub").join(".pentectignore"),
            "child/ignored.env\n",
        )
        .unwrap();
        let ignored = subtree.join("ignored.env");
        std::fs::write(&ignored, "secret\n").unwrap();

        let files = collect_test_roots(&[subtree], &[]);
        assert!(!files.contains(&ignored), "{files:?}");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn git_scan_honors_gitignored_pentectignore() {
        let root = temp_root("pentect-hidden-custom-ignore");
        init_git(&root);
        let sub = root.join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(root.join(".gitignore"), "**/.pentectignore\n").unwrap();
        std::fs::write(sub.join(".pentectignore"), "ignored.env\n").unwrap();
        let ignored = sub.join("ignored.env");
        std::fs::write(&ignored, "secret\n").unwrap();

        let files = collect_test_roots(std::slice::from_ref(&root), &[]);
        assert!(!files.contains(&ignored), "{files:?}");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn deeper_pentectignore_can_restore_a_parent_rule() {
        let root = temp_root("pentect-nested-custom-ignore");
        init_git(&root);
        let sub = root.join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(root.join(".pentectignore"), "*.env\n").unwrap();
        std::fs::write(sub.join(".pentectignore"), "!keep.env\n").unwrap();
        let keep = sub.join("keep.env");
        let drop = sub.join("drop.env");
        std::fs::write(&keep, "keep\n").unwrap();
        std::fs::write(&drop, "drop\n").unwrap();

        let files = collect_test_roots(std::slice::from_ref(&root), &[]);
        assert!(files.contains(&keep.canonicalize().unwrap()), "{files:?}");
        assert!(!files.contains(&drop.canonicalize().unwrap()), "{files:?}");

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn git_listing_preserves_non_utf8_paths() {
        use std::os::unix::ffi::OsStringExt;

        let root = temp_root("pentect-git-non-utf8");
        init_git(&root);
        let path = root.join(OsString::from_vec(b"secret-\xff.env".to_vec()));
        std::fs::write(&path, "secret\n").unwrap();

        let (_, _, files) = git_files_for_root(&root).unwrap();
        assert!(files.contains(&path), "{files:?}");

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
            vec![normalize_root(&root), normalize_root(&file)],
            minimal_scan_roots(&[nested, file, root.clone(), root.clone()])
        );

        let _ = std::fs::remove_dir_all(root);
    }
}
