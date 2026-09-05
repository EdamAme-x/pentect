//! Crash-conservative Unix storage for generated Claude settings.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

const ROOT: &str = "claude-settings-v1";
const PREFIX: &str = "session-";
const SUFFIX: &str = "-v1";
const SETTINGS: &str = "settings.json";
const OWNER: &str = "owner.lock";
const RELEASED: &str = "released";
const ROOT_LOCK: &str = ".cleanup.lock";

#[derive(Debug)]
pub(crate) struct Session {
    directory: PathBuf,
    owner: File,
    released: bool,
}

impl Session {
    /// Called only in the already-running guardian. No settings bytes are
    /// written by the shell-facing wrapper.
    pub(crate) fn create(contents: &[u8]) -> Result<Self, String> {
        let runtime = pentect_agent::process_host_root()?;
        std::fs::create_dir_all(&runtime)
            .map_err(|error| format!("could not create Pentect runtime directory: {error}"))?;
        let runtime = std::fs::canonicalize(runtime)
            .map_err(|error| format!("could not resolve Pentect runtime directory: {error}"))?;
        let private = private_directory(&runtime.join("private"), "Pentect private runtime")?;
        let root = private_directory(&private.join(ROOT), "Claude settings recovery")?;
        let root_lock = root_lock(&root.join(ROOT_LOCK))?;
        cleanup_released(&root);

        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| format!("OS CSPRNG unavailable for Claude settings: {error}"))?;
        let directory = root.join(format!(
            "{PREFIX}{}{SUFFIX}",
            data_encoding::HEXLOWER.encode(&nonce)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|error| {
                format!("could not create protected Claude settings directory: {error}")
            })?;
        validate(&directory, true, "Claude settings directory")?;
        let owner = match locked_file(&directory.join(OWNER), true, "Claude settings owner lock") {
            Ok(owner) => owner,
            Err(error) => {
                let _ = std::fs::remove_dir(&directory);
                return Err(error);
            }
        };
        if let Err(error) = private_file(&directory.join(SETTINGS), contents, "Claude settings") {
            let _ = std::fs::remove_file(directory.join(OWNER));
            let _ = std::fs::remove_dir(&directory);
            return Err(error);
        }
        drop(root_lock);
        Ok(Self {
            directory,
            owner,
            released: false,
        })
    }

    pub(crate) fn settings_path(&self) -> PathBuf {
        self.directory.join(SETTINGS)
    }

    /// Marking is allowed only after the guardian has confirmed and reaped the
    /// actual Claude consumer. A crash before this point leaves conservative
    /// unreleased residue that future launches never remove.
    pub(crate) fn release(mut self) {
        let _ = private_file(
            &self.directory.join(RELEASED),
            b"",
            "Claude settings release marker",
        );
        self.released = true;
        cleanup_session(&self.directory);
    }

    /// Safe only before the client bootstrap has been released.
    pub(crate) fn abort(mut self) {
        self.released = true;
        cleanup_session(&self.directory);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Never infer release from process death. This intentionally preserves
        // bytes after an unexpected guardian/double kill.
        let _ = &self.owner;
        if self.released {
            cleanup_session(&self.directory);
        }
    }
}

fn cleanup_released(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !session_name(&entry.file_name())
            || validate(&path, true, "Claude settings directory").is_err()
        {
            continue;
        }
        let released = path.join(RELEASED);
        if validate(&released, false, "Claude settings release marker").is_err() {
            continue;
        }
        let Ok(owner) = locked_file(&path.join(OWNER), false, "Claude settings owner lock") else {
            continue;
        };
        cleanup_session(&path);
        drop(owner);
    }
}

fn cleanup_session(path: &Path) {
    if validate(path, true, "Claude settings directory").is_err() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        if !matches!(
            entry.file_name().to_str(),
            Some(SETTINGS | OWNER | RELEASED)
        ) {
            return;
        }
    }
    for name in [SETTINGS, RELEASED, OWNER] {
        let candidate = path.join(name);
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) if validate(&candidate, false, "Claude settings session file").is_err() => {
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return,
            Ok(_) => {}
        }
    }
    let _ = std::fs::remove_file(path.join(SETTINGS));
    let _ = std::fs::remove_file(path.join(RELEASED));
    let _ = std::fs::remove_file(path.join(OWNER));
    let _ = std::fs::remove_dir(path);
}

fn private_directory(path: &Path, purpose: &str) -> Result<PathBuf, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => validate(path, true, purpose)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => {}
                Err(create_error) if validate(path, true, purpose).is_err() => {
                    return Err(format!(
                        "could not create protected {purpose}: {create_error}"
                    ));
                }
                Err(_) => {}
            }
        }
        Err(error) => return Err(format!("could not inspect {purpose}: {error}")),
    }
    validate(path, true, purpose)?;
    std::fs::canonicalize(path).map_err(|error| format!("could not resolve {purpose}: {error}"))
}

fn private_file(path: &Path, contents: &[u8], purpose: &str) -> Result<File, String> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("could not create protected {purpose}: {error}"))?;
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("could not write protected {purpose}: {error}"));
    }
    if let Err(error) = validate_opened(&file, path, purpose) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(file)
}

fn root_lock(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("could not open Claude settings cleanup lock: {error}"))?;
    lock_bounded(file, path, "Claude settings cleanup lock")
}

fn locked_file(path: &Path, create_new: bool, purpose: &str) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    if create_new {
        options.create_new(true);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("could not open {purpose}: {error}"))?;
    lock(file, path, purpose)
}

fn lock(file: File, path: &Path, purpose: &str) -> Result<File, String> {
    validate_opened(&file, path, purpose)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == -1 {
        return Err(format!(
            "could not lock {purpose}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

fn lock_bounded(file: File, path: &Path, purpose: &str) -> Result<File, String> {
    validate_opened(&file, path, purpose)?;
    let started = std::time::Instant::now();
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock
            || started.elapsed() >= std::time::Duration::from_secs(2)
        {
            return Err(format!("could not lock {purpose}: {error}"));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn validate_opened(file: &File, path: &Path, purpose: &str) -> Result<(), String> {
    let opened = file
        .metadata()
        .map_err(|error| format!("could not inspect opened {purpose}: {error}"))?;
    validate(path, false, purpose)?;
    let named = std::fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {purpose}: {error}"))?;
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(format!("{purpose} changed while it was opened"));
    }
    Ok(())
}

fn session_name(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX))
        .is_some_and(|nonce| {
            nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn validate(path: &Path, directory: bool, purpose: &str) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {purpose}: {error}"))?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(format!("{purpose} ownership or permissions are unsafe"));
    }
    Ok(())
}
