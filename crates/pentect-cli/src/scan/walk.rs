use super::report::SkippedFile;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) fn collect_scan_roots(
    roots: &[PathBuf],
    excludes: &[String],
    skipped: &mut Vec<SkippedFile>,
) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for root in roots {
        if let Some((base, git_files)) = git_files_for_root(root) {
            let matcher = ExcludeMatcher::new(&base, excludes)?;
            let mut matchers_by_dir: BTreeMap<PathBuf, ExcludeMatcher> = BTreeMap::new();
            for path in git_files {
                let parent = path.parent().unwrap_or(&base).to_path_buf();
                let file_matcher = if let Some(cached) = matchers_by_dir.get(&parent) {
                    cached.clone()
                } else {
                    let built = matcher.with_ancestors(&path)?;
                    matchers_by_dir.insert(parent, built.clone());
                    built
                };
                if !file_matcher.is_excluded(&path, false) {
                    files.push(path);
                }
            }
        } else {
            let base = scan_base(root);
            let matcher = ExcludeMatcher::new(&base, excludes)?;
            collect_files(root, &mut files, skipped, &matcher)?;
        }
    }
    files.sort();
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

fn has_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            extensions
                .iter()
                .any(|candidate| ext.eq_ignore_ascii_case(candidate))
        })
}

fn collect_files(
    path: &Path,
    out: &mut Vec<PathBuf>,
    skipped: &mut Vec<SkippedFile>,
    matcher: &ExcludeMatcher,
) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        skipped.push(SkippedFile::new(path, "symlink"));
        return Ok(());
    }
    if meta.is_file() {
        if matcher.is_excluded(path, false) {
            return Ok(());
        }
        out.push(path.to_path_buf());
        return Ok(());
    }
    if !meta.is_dir() {
        skipped.push(SkippedFile::new(path, "not a regular file"));
        return Ok(());
    }
    if matcher.is_excluded(path, true) {
        return Ok(());
    }
    if is_ignored_dir(path) {
        return Ok(());
    }
    let matcher = matcher.with_directory(path)?;
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
        collect_files(&entry, out, skipped, &matcher)?;
    }
    Ok(())
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
    let absolute = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if absolute.is_file() {
        absolute.parent().map(Path::to_path_buf).unwrap_or(absolute)
    } else {
        absolute
    }
}

#[derive(Clone, Debug)]
struct ExcludeMatcher {
    root: PathBuf,
    layers: Vec<ExcludeLayer>,
    cli_layer: Option<ExcludeLayer>,
}

impl ExcludeMatcher {
    fn new(base: &Path, excludes: &[String]) -> Result<Self, String> {
        let root = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());
        let mut layers = Vec::new();
        if let Some(layer) = ExcludeLayer::from_directory(&root)? {
            layers.push(layer);
        }
        let cli_layer = ExcludeLayer::from_cli(&root, excludes)?;
        Ok(Self {
            root,
            layers,
            cli_layer,
        })
    }

    fn with_directory(&self, dir: &Path) -> Result<Self, String> {
        let mut next = self.clone();
        let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        if dir != self.root {
            next.push_directory(&dir)?;
        }
        Ok(next)
    }

    fn with_ancestors(&self, path: &Path) -> Result<Self, String> {
        let target = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let Some(parent) = target.parent() else {
            return Ok(self.clone());
        };
        let mut dirs = Vec::new();
        let mut current = Some(parent);
        while let Some(dir) = current {
            if !dir.starts_with(&self.root) {
                break;
            }
            if dir != self.root {
                dirs.push(dir.to_path_buf());
            }
            if dir == self.root {
                break;
            }
            current = dir.parent();
        }
        dirs.reverse();

        let mut next = self.clone();
        for dir in dirs {
            next.push_directory(&dir)?;
        }
        Ok(next)
    }

    fn push_directory(&mut self, dir: &Path) -> Result<(), String> {
        if let Some(layer) = ExcludeLayer::from_directory(dir)? {
            self.layers.push(layer);
        }
        Ok(())
    }

    fn is_excluded(&self, path: &Path, is_dir: bool) -> bool {
        let mut ignored = false;
        for layer in self.layers.iter().chain(self.cli_layer.iter()) {
            match layer.matched(path, is_dir) {
                Some(true) => ignored = true,
                Some(false) => ignored = false,
                None => {}
            }
        }
        ignored
    }
}

#[derive(Clone, Debug)]
struct ExcludeLayer {
    base: PathBuf,
    matcher: Gitignore,
}

impl ExcludeLayer {
    fn from_directory(base: &Path) -> Result<Option<Self>, String> {
        let mut builder = GitignoreBuilder::new(base);
        let mut loaded = false;
        for name in [".gitignore", ".pentectignore"] {
            let path = base.join(name);
            if path.is_file() {
                if let Some(err) = builder.add(&path) {
                    return Err(format!(
                        "could not read ignore file '{}': {err}",
                        path.display()
                    ));
                }
                loaded = true;
            }
        }
        if !loaded {
            return Ok(None);
        }
        Self::build(base, builder).map(Some)
    }

    fn from_cli(base: &Path, excludes: &[String]) -> Result<Option<Self>, String> {
        if excludes.is_empty() {
            return Ok(None);
        }
        let mut builder = GitignoreBuilder::new(base);
        for pattern in excludes {
            builder
                .add_line(None, pattern)
                .map_err(|e| format!("invalid exclude pattern '{pattern}': {e}"))?;
        }
        Self::build(base, builder).map(Some)
    }

    fn build(base: &Path, builder: GitignoreBuilder) -> Result<Self, String> {
        let matcher = builder
            .build()
            .map_err(|e| format!("could not build scan exclude matcher: {e}"))?;
        Ok(Self {
            base: base.to_path_buf(),
            matcher,
        })
    }

    fn matched(&self, path: &Path, is_dir: bool) -> Option<bool> {
        let target = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let rel = target.strip_prefix(&self.base).ok()?;
        let matched = self.matcher.matched_path_or_any_parents(rel, is_dir);
        if matched.is_ignore() {
            Some(true)
        } else if matched.is_whitelist() {
            Some(false)
        } else {
            None
        }
    }
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
