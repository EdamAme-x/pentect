use super::report::SkippedFile;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) fn collect_scan_roots(
    roots: &[PathBuf],
    skipped: &mut Vec<SkippedFile>,
) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for root in roots {
        if let Some(git_files) = git_files_for_root(root) {
            files.extend(git_files);
        } else {
            collect_files(root, &mut files, skipped)?;
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

pub(super) fn ignored_file_reason(path: &Path) -> Option<&'static str> {
    if has_file_name(path, GENERATED_LOCK_FILES) {
        return Some("generated lockfile");
    }
    if has_extension(path, GENERATED_ASSET_EXTENSIONS) {
        return Some("generated asset");
    }
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
    "lock",
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

const GENERATED_ASSET_EXTENSIONS: &[&str] = &["svg"];

const GENERATED_LOCK_FILES: &[&str] = &[
    "bun.lockb",
    "go.sum",
    "go.work.sum",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "pnpm-lock.yml",
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

fn has_file_name(path: &Path, names: &[&str]) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            names
                .iter()
                .any(|candidate| name.eq_ignore_ascii_case(candidate))
        })
}

fn collect_files(
    path: &Path,
    out: &mut Vec<PathBuf>,
    skipped: &mut Vec<SkippedFile>,
) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        skipped.push(SkippedFile::new(path, "symlink"));
        return Ok(());
    }
    if meta.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }
    if !meta.is_dir() {
        skipped.push(SkippedFile::new(path, "not a regular file"));
        return Ok(());
    }
    if is_ignored_dir(path) {
        return Ok(());
    }
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
        collect_files(&entry, out, skipped)?;
    }
    Ok(())
}

fn git_files_for_root(root: &Path) -> Option<Vec<PathBuf>> {
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
    Some(files)
}

fn git_pathspec(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_dependency_files_are_ignored() {
        for file in [
            "package-lock.json",
            "pnpm-lock.yaml",
            "go.sum",
            "go.work.sum",
            "bun.lockb",
        ] {
            assert_eq!(
                ignored_file_reason(Path::new(file)),
                Some("generated lockfile"),
                "{file}"
            );
        }
    }

    #[test]
    fn svg_assets_are_ignored() {
        assert_eq!(
            ignored_file_reason(Path::new("docs/logo.svg")),
            Some("generated asset")
        );
    }
}
