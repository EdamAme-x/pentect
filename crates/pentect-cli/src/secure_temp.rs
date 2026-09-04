//! Short-lived, owner-only files used to inject client configuration.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
const CLAUDE_SETTINGS_ROOT: &str = "claude-settings-v1";
#[cfg(unix)]
const CLAUDE_SESSION_PREFIX: &str = "session-";
#[cfg(unix)]
const CLAUDE_SESSION_SUFFIX: &str = "-v1";
#[cfg(unix)]
const CLAUDE_OWNER_LOCK: &str = "owner.lock";
#[cfg(unix)]
const CLAUDE_SETTINGS_FILE: &str = "settings.json";
#[cfg(unix)]
const CLAUDE_ROOT_LOCK: &str = ".cleanup.lock";
#[cfg(all(unix, not(test)))]
const CLAUDE_ROOT_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
#[cfg(all(unix, test))]
const CLAUDE_ROOT_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
#[cfg(unix)]
const CLAUDE_ROOT_LOCK_RETRY: std::time::Duration = std::time::Duration::from_millis(10);

#[derive(Debug)]
pub(crate) struct SecureTempFile {
    path: PathBuf,
}

#[cfg(any(windows, test))]
#[derive(Debug)]
pub(crate) struct SecureTempDirectory {
    path: PathBuf,
}

/// Crash-recoverable private storage for Claude's generated settings copy.
/// SIGKILL residue is removed on the next real protected Claude launch, not
/// immediately when the killed process exits.
#[derive(Debug)]
#[cfg(unix)]
pub(crate) struct ClaudeSettingsSession {
    path: PathBuf,
    owner_lock: Option<std::fs::File>,
}

#[cfg(unix)]
impl ClaudeSettingsSession {
    pub(crate) fn create(contents: &[u8]) -> Result<Self, String> {
        let base = pentect_agent::process_host_root()?;
        std::fs::create_dir_all(&base)
            .map_err(|error| format!("could not create Pentect runtime directory: {error}"))?;
        let base = std::fs::canonicalize(&base)
            .map_err(|error| format!("could not resolve Pentect runtime directory: {error}"))?;
        let private = ensure_private_directory(&base.join("private"), "Pentect private runtime")?;
        let root = ensure_private_directory(
            &private.join(CLAUDE_SETTINGS_ROOT),
            "Claude settings recovery",
        )?;
        Self::create_in(&root, contents)
    }

    fn create_in(root: &Path, contents: &[u8]) -> Result<Self, String> {
        let root_lock = acquire_claude_root_lock(root)?;
        cleanup_stale_claude_sessions(root);
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| format!("OS CSPRNG unavailable for Claude settings: {error}"))?;
        let path = root.join(format!(
            "{CLAUDE_SESSION_PREFIX}{}{CLAUDE_SESSION_SUFFIX}",
            data_encoding::HEXLOWER.encode(&nonce)
        ));
        create_private_directory(&path, "Claude settings session")?;

        let lock_path = path.join(CLAUDE_OWNER_LOCK);
        let owner_lock = match create_private_file(&lock_path, b"", "Claude settings owner lock") {
            Ok(lock) => lock,
            Err(error) => {
                let _ = std::fs::remove_dir(&path);
                return Err(error);
            }
        };
        if let Err(error) = owner_lock.try_lock() {
            cleanup_owned_session_files(&path, Some(owner_lock), false);
            return Err(format!("could not lock Claude settings session: {error}"));
        }
        // Confidential bytes are written only after the lifetime lock is held.
        if let Err(error) = create_private_file(
            &path.join(CLAUDE_SETTINGS_FILE),
            contents,
            "Claude settings",
        ) {
            cleanup_owned_session_files(&path, Some(owner_lock), false);
            return Err(error);
        }
        drop(root_lock);
        Ok(Self {
            path,
            owner_lock: Some(owner_lock),
        })
    }

    pub(crate) fn settings_path(&self) -> PathBuf {
        self.path.join(CLAUDE_SETTINGS_FILE)
    }
}

#[cfg(unix)]
impl Drop for ClaudeSettingsSession {
    fn drop(&mut self) {
        cleanup_owned_session_files(&self.path, self.owner_lock.take(), false);
    }
}

#[cfg(unix)]
fn ensure_private_directory(path: &Path, purpose: &str) -> Result<PathBuf, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => validate_owned_private_path(path, true, purpose)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Err(create_error) = create_private_directory(path, purpose) {
                // Another launch may have won creation. Treat it as trusted
                // only after validation; never chmod a raced-in path first.
                if validate_owned_private_path(path, true, purpose).is_err() {
                    return Err(create_error);
                }
            }
        }
        Err(error) => return Err(format!("could not inspect {purpose} directory: {error}")),
    }
    validate_owned_private_path(path, true, purpose)?;
    std::fs::canonicalize(path).map_err(|error| format!("could not resolve {purpose}: {error}"))
}

#[cfg(unix)]
fn acquire_claude_root_lock(root: &Path) -> Result<std::fs::File, String> {
    let path = root.join(CLAUDE_ROOT_LOCK);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(&path)
        .map_err(|error| format!("could not open Claude settings cleanup lock: {error}"))?;
    restrict_to_current_user(&path)?;
    validate_owned_private_path(&path, false, "Claude settings cleanup lock")?;
    let started = std::time::Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock)
                if started.elapsed() < CLAUDE_ROOT_LOCK_TIMEOUT =>
            {
                std::thread::sleep(CLAUDE_ROOT_LOCK_RETRY);
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err("Claude settings recovery is busy; retry shortly".to_string());
            }
            Err(std::fs::TryLockError::Error(_)) => {
                return Err("could not lock Claude settings recovery root".to_string());
            }
        }
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path, purpose: &str) -> Result<(), String> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|error| format!("could not create protected {purpose} directory: {error}"))?;
    if let Err(error) = protect_private_directory(path, purpose) {
        let _ = std::fs::remove_dir(path);
        return Err(error);
    }
    Ok(())
}

#[cfg(unix)]
fn protect_private_directory(path: &Path, purpose: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("could not protect {purpose} directory: {error}"))?;
    }
    restrict_to_current_user(path)
}

#[cfg(unix)]
fn create_private_file(
    path: &Path,
    contents: &[u8],
    purpose: &str,
) -> Result<std::fs::File, String> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("could not create protected {purpose}: {error}"))?;
    if let Err(error) = restrict_to_current_user(path) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("could not write protected {purpose}: {error}"));
    }
    Ok(file)
}

#[cfg(unix)]
fn cleanup_stale_claude_sessions(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_claude_session_name(&entry.file_name())
            || validate_owned_private_path(&path, true, "Claude settings session").is_err()
        {
            continue;
        }
        let lock_path = path.join(CLAUDE_OWNER_LOCK);
        let Ok(owner_lock) = open_lock_without_links(&lock_path) else {
            continue;
        };
        match owner_lock.try_lock() {
            Ok(()) => cleanup_owned_session_files(&path, Some(owner_lock), true),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(_)) => {}
        }
    }
}

#[cfg(unix)]
fn is_claude_session_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(nonce) = name
        .strip_prefix(CLAUDE_SESSION_PREFIX)
        .and_then(|name| name.strip_suffix(CLAUDE_SESSION_SUFFIX))
    else {
        return false;
    };
    nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(unix)]
fn open_lock_without_links(path: &Path) -> Result<std::fs::File, String> {
    validate_owned_private_path(path, false, "Claude settings owner lock")?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|error| format!("could not inspect Claude settings owner lock: {error}"))
}

#[cfg(unix)]
fn cleanup_owned_session_files(path: &Path, owner_lock: Option<std::fs::File>, _stale: bool) {
    let _ = _stale;
    if validate_owned_private_path(path, true, "Claude settings session").is_err() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    let mut saw_lock = false;
    let mut saw_settings = false;
    for entry in entries {
        let Ok(entry) = entry else {
            return;
        };
        match entry.file_name().to_str() {
            Some(CLAUDE_OWNER_LOCK) => saw_lock = true,
            Some(CLAUDE_SETTINGS_FILE) => saw_settings = true,
            _ => return,
        }
    }
    if !saw_lock {
        return;
    }
    let lock_path = path.join(CLAUDE_OWNER_LOCK);
    let settings_path = path.join(CLAUDE_SETTINGS_FILE);
    if validate_owned_private_path(&lock_path, false, "Claude settings owner lock").is_err()
        || (saw_settings
            && validate_owned_private_path(&settings_path, false, "Claude settings").is_err())
    {
        return;
    }
    if saw_settings && std::fs::remove_file(&settings_path).is_err() {
        return;
    }

    // Unix permits unlinking the locked file, so the lock remains held through
    // every deletion.
    if std::fs::remove_file(&lock_path).is_err() || std::fs::remove_dir(path).is_err() {
        return;
    }
    drop(owner_lock);
}

#[cfg(unix)]
fn validate_owned_private_path(path: &Path, directory: bool, purpose: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {purpose}: {error}"))?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(format!("{purpose} ownership or permissions are unsafe"));
    }
    Ok(())
}

#[cfg(any(windows, test))]
impl SecureTempDirectory {
    pub(crate) fn create(prefix: &str, purpose: &str) -> Result<Self, String> {
        validate_name_part(prefix)?;
        let parent = std::env::temp_dir();
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| format!("OS CSPRNG unavailable for {purpose}: {error}"))?;
        let path = parent.join(format!(
            "{prefix}{}-{}",
            std::process::id(),
            data_encoding::HEXLOWER.encode(&nonce)
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).map_err(|error| {
            format!(
                "could not create protected {purpose} directory ({}): {error}",
                path.display()
            )
        })?;
        if let Err(error) = restrict_to_current_user(&path) {
            let _ = std::fs::remove_dir(&path);
            return Err(error);
        }
        Ok(Self { path })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(any(windows, test))]
impl Drop for SecureTempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

impl SecureTempFile {
    pub(crate) fn create(
        directory: &Path,
        prefix: &str,
        suffix: &str,
        contents: &[u8],
        purpose: &str,
    ) -> Result<Self, String> {
        validate_name_part(prefix)?;
        validate_name_part(suffix)?;
        cleanup_stale(directory, prefix, suffix);

        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| format!("OS CSPRNG unavailable for {purpose}: {error}"))?;
        let name = format!(
            "{prefix}{}-{}{suffix}",
            std::process::id(),
            data_encoding::HEXLOWER.encode(&nonce)
        );
        let path = directory.join(name);
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|error| {
            format!(
                "could not create protected {purpose} ({}): {error}",
                path.display()
            )
        })?;
        if let Err(error) = restrict_to_current_user(&path) {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&path);
            return Err(format!("could not write protected {purpose}: {error}"));
        }
        Ok(Self { path })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SecureTempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(any(windows, test))]
pub(crate) fn atomic_owner_only_write(
    path: &Path,
    contents: &[u8],
    purpose: &str,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{purpose} path has no parent"))?;
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| format!("OS CSPRNG unavailable for {purpose}: {error}"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{purpose} path has no valid file name"))?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        data_encoding::HEXLOWER.encode(&nonce)
    ));

    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("could not create protected {purpose}: {error}"))?;
    if let Err(error) = restrict_to_current_user(&temporary) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("could not write protected {purpose}: {error}"));
    }
    drop(file);

    if let Err(error) = atomic_replace(&temporary, path, purpose) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    sync_parent_directory(path, purpose)
}

#[cfg(windows)]
fn atomic_replace(temporary: &Path, path: &Path, purpose: &str) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let from = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let to = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both paths are NUL-terminated UTF-16 buffers that remain valid
    // for the duration of the call.
    let moved = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(format!(
            "could not atomically publish {purpose}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(all(not(windows), test))]
fn atomic_replace(temporary: &Path, path: &Path, purpose: &str) -> Result<(), String> {
    std::fs::rename(temporary, path)
        .map_err(|error| format!("could not atomically publish {purpose}: {error}"))
}

#[cfg(all(unix, test))]
fn sync_parent_directory(path: &Path, purpose: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{purpose} path has no parent"))?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("could not sync {purpose} directory: {error}"))
}

#[cfg(windows)]
fn sync_parent_directory(_: &Path, _: &str) -> Result<(), String> {
    Ok(())
}

fn validate_name_part(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 80
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
    {
        return Err("temporary file name component is invalid".to_string());
    }
    Ok(())
}

fn cleanup_stale(directory: &Path, prefix: &str, suffix: &str) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut candidates = Vec::new();
    for path in entries.filter_map(|entry| entry.ok().map(|entry| entry.path())) {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(stem) = name
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(suffix))
        else {
            continue;
        };
        // Early Pentect builds used only a 128-bit nonce and carried no PID.
        // It is impossible to distinguish their crash residue from a file
        // still owned by a concurrently running older Pentect, so leave that
        // shape untouched. Deleting it here could break the older process.
        if stem.len() == 32 && stem.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let Some((owner, nonce)) = stem.split_once('-') else {
            continue;
        };
        if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let Some(owner) = owner.parse::<u32>().ok() else {
            continue;
        };
        if owner != std::process::id() {
            candidates.push((path, sysinfo::Pid::from_u32(owner)));
        }
    }
    if candidates.is_empty() {
        return;
    }
    let pids = candidates.iter().map(|(_, pid)| *pid).collect::<Vec<_>>();
    let mut system = sysinfo::System::new();
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&pids),
        true,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    for (path, owner) in candidates {
        if system.process(owner).is_none() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(windows)]
pub(crate) fn restrict_to_current_user(path: &Path) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let identity = Command::new(crate::windows_system_executable("whoami.exe"))
        .args(["/user", "/fo", "csv", "/nh"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| format!("could not resolve the Windows account for ACL setup: {error}"))?;
    if !identity.status.success() {
        return Err("could not resolve the Windows account for ACL setup".to_string());
    }
    let sid = windows_sid_from_whoami_output(&identity.stdout)
        .ok_or_else(|| "could not parse the Windows account SID".to_string())?;
    let grant = format!("*{sid}:(F)");
    let status = Command::new(crate::windows_system_executable("icacls.exe"))
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("could not restrict temporary file ACL: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| "could not restrict temporary file ACL".to_string())
}

#[cfg(any(windows, test))]
fn windows_sid_from_whoami_output(output: &[u8]) -> Option<String> {
    for start in 0..output.len().saturating_sub(3) {
        if !output[start..].starts_with(b"S-1-") {
            continue;
        }
        let suffix_start = start + b"S-1-".len();
        let end = output[suffix_start..]
            .iter()
            .position(|byte| !byte.is_ascii_digit() && *byte != b'-')
            .map_or(output.len(), |length| suffix_start + length);
        let candidate = std::str::from_utf8(&output[start..end]).ok()?;
        if candidate.matches('-').count() >= 3 && !candidate.ends_with('-') {
            return Some(candidate.to_string());
        }
    }
    None
}

#[cfg(not(windows))]
pub(crate) fn restrict_to_current_user(_: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_owner_only_write_replaces_only_with_complete_contents() {
        let directory =
            SecureTempDirectory::create("pentect-atomic-write-", "atomic-write test").unwrap();
        let path = directory.path().join("journal");
        std::fs::write(&path, b"old").unwrap();

        atomic_owner_only_write(&path, b"complete new journal\n", "test journal").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"complete new journal\n");
        let entries = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, vec![std::ffi::OsString::from("journal")]);
    }

    #[test]
    fn atomic_owner_only_write_removes_temporary_file_when_publish_fails() {
        let directory =
            SecureTempDirectory::create("pentect-atomic-fail-", "atomic-write failure test")
                .unwrap();
        let path = directory.path().join("journal");
        std::fs::create_dir(&path).unwrap();

        let error = atomic_owner_only_write(&path, b"new journal\n", "test journal").unwrap_err();

        assert!(error.contains("could not atomically publish"), "{error}");
        let entries = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, vec![std::ffi::OsString::from("journal")]);
    }

    #[test]
    fn extracts_sid_without_decoding_the_account_name() {
        let output = b"\x8a\xc7\x97\x9d,\"S-1-5-21-123-456-789-1001\"\r\n";
        assert_eq!(
            windows_sid_from_whoami_output(output).as_deref(),
            Some("S-1-5-21-123-456-789-1001")
        );
    }

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pentect-secure-temp-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn file_is_unique_written_and_removed_on_drop() {
        let directory = directory();
        let file =
            SecureTempFile::create(&directory, ".pentect-test-", ".json", b"{}", "test").unwrap();
        let path = file.path().to_path_buf();
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        drop(file);
        assert!(!path.exists());
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let directory = directory();
        let file =
            SecureTempFile::create(&directory, ".pentect-test-", ".json", b"{}", "test").unwrap();
        assert_eq!(
            std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(file);
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn rejects_path_components() {
        let directory = directory();
        assert!(SecureTempFile::create(&directory, "../bad", ".json", b"", "test").is_err());
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn private_directory_is_removed_on_drop() {
        let directory = SecureTempDirectory::create("pentect-test-", "test").unwrap();
        let path = directory.path().to_path_buf();
        assert!(path.is_dir());
        drop(directory);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let directory = SecureTempDirectory::create("pentect-test-", "test").unwrap();
        assert_eq!(
            std::fs::metadata(directory.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn claude_cleanup_preserves_live_sessions_and_removes_released_residue() {
        let root = directory();
        let mut first = ClaudeSettingsSession::create_in(&root, b"first-confidential").unwrap();
        let second = ClaudeSettingsSession::create_in(&root, b"second-confidential").unwrap();
        let first_path = first.path.clone();
        let second_path = second.path.clone();

        cleanup_stale_claude_sessions(&root);
        assert!(first_path.exists());
        assert!(second_path.exists());

        let first_lock = first.owner_lock.take();
        std::mem::forget(first);
        drop(first_lock);
        cleanup_stale_claude_sessions(&root);
        assert!(!first_path.exists());
        assert!(second_path.exists());

        drop(second);
        assert!(!second_path.exists());
        std::fs::remove_file(root.join(CLAUDE_ROOT_LOCK)).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_claude_session_publication_is_serialized() {
        let root = directory();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads = (0..8)
            .map(|_| {
                let root = root.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let session = ClaudeSettingsSession::create_in(&root, b"concurrent").unwrap();
                    barrier.wait();
                    assert!(session.settings_path().is_file());
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        std::fs::remove_file(root.join(CLAUDE_ROOT_LOCK)).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn claude_root_lock_contention_is_bounded_and_preserves_the_live_lock() {
        let root = directory();
        let lock = acquire_claude_root_lock(&root).unwrap();
        let started = std::time::Instant::now();
        let error = ClaudeSettingsSession::create_in(&root, b"never-written").unwrap_err();
        assert_eq!(error, "Claude settings recovery is busy; retry shortly");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(root.join(CLAUDE_ROOT_LOCK).is_file());

        drop(lock);
        std::fs::remove_file(root.join(CLAUDE_ROOT_LOCK)).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_validation_does_not_chmod_a_symlink_target() {
        use std::os::unix::fs::PermissionsExt;

        let root = directory();
        let target = root.with_extension("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let raced = root.join("raced-private");
        std::os::unix::fs::symlink(&target, &raced).unwrap();

        assert!(ensure_private_directory(&raced, "test private path").is_err());
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );

        std::fs::remove_file(raced).unwrap();
        std::fs::remove_dir(target).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn claude_cleanup_accepts_safe_partial_creation_but_preserves_unexpected_entries() {
        let root = directory();
        let partial = root.join("session-00000000000000000000000000000000-v1");
        create_private_directory(&partial, "test session").unwrap();
        create_private_file(&partial.join(CLAUDE_OWNER_LOCK), b"", "test lock").unwrap();
        cleanup_stale_claude_sessions(&root);
        assert!(!partial.exists());

        let unexpected = root.join("session-11111111111111111111111111111111-v1");
        create_private_directory(&unexpected, "test session").unwrap();
        create_private_file(&unexpected.join(CLAUDE_OWNER_LOCK), b"", "test lock").unwrap();
        create_private_file(
            &unexpected.join("keep.txt"),
            b"keep",
            "unexpected test file",
        )
        .unwrap();
        cleanup_stale_claude_sessions(&root);
        assert!(unexpected.join("keep.txt").exists());
        std::fs::remove_file(unexpected.join("keep.txt")).unwrap();
        std::fs::remove_file(unexpected.join(CLAUDE_OWNER_LOCK)).unwrap();
        std::fs::remove_dir(unexpected).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn claude_cleanup_never_follows_links_or_touches_caller_files() {
        let root = directory();
        let caller = root.with_extension("caller-settings.json");
        std::fs::write(&caller, b"caller-confidential").unwrap();
        let linked = root.join("session-22222222222222222222222222222222-v1");
        std::os::unix::fs::symlink(caller.parent().unwrap(), &linked).unwrap();

        let session = root.join("session-33333333333333333333333333333333-v1");
        create_private_directory(&session, "test session").unwrap();
        create_private_file(&session.join(CLAUDE_OWNER_LOCK), b"", "test lock").unwrap();
        std::os::unix::fs::symlink(&caller, session.join(CLAUDE_SETTINGS_FILE)).unwrap();

        cleanup_stale_claude_sessions(&root);
        assert!(linked.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(session.exists());
        assert_eq!(std::fs::read(&caller).unwrap(), b"caller-confidential");

        std::fs::remove_file(session.join(CLAUDE_SETTINGS_FILE)).unwrap();
        std::fs::remove_file(session.join(CLAUDE_OWNER_LOCK)).unwrap();
        std::fs::remove_dir(session).unwrap();
        std::fs::remove_file(linked).unwrap();
        std::fs::remove_file(caller).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn claude_creation_errors_never_include_settings_bytes() {
        let missing = directory().join("missing");
        let confidential = b"synthetic-confidential-settings-value";
        let error = ClaudeSettingsSession::create_in(&missing, confidential).unwrap_err();
        assert!(!error.contains(std::str::from_utf8(confidential).unwrap()));
        std::fs::remove_dir(missing.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn claude_sigkill_residue_is_removed_on_next_creation() {
        const HELPER_ENV: &str = "PENTECT_TEST_CLAUDE_SETTINGS_SIGKILL_HELPER";
        const ROOT_ENV: &str = "PENTECT_TEST_CLAUDE_SETTINGS_ROOT";
        if std::env::var_os(HELPER_ENV).is_some() {
            let root = PathBuf::from(std::env::var_os(ROOT_ENV).unwrap());
            let session = ClaudeSettingsSession::create_in(&root, b"killed-confidential").unwrap();
            std::fs::write(
                root.join("ready"),
                session.path.to_string_lossy().as_bytes(),
            )
            .unwrap();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }

        let root = directory();
        struct KillOnDrop(std::process::Child);
        impl Drop for KillOnDrop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "secure_temp::tests::claude_sigkill_residue_is_removed_on_next_creation",
                "--nocapture",
            ])
            .env(HELPER_ENV, "1")
            .env(ROOT_ENV, &root)
            .spawn()
            .unwrap();
        let mut child = KillOnDrop(child);
        let ready = root.join("ready");
        for _ in 0..500 {
            if ready.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ready.exists());
        let stale = PathBuf::from(std::fs::read_to_string(&ready).unwrap());
        child.0.kill().unwrap();
        child.0.wait().unwrap();

        let next = ClaudeSettingsSession::create_in(&root, b"next-safe-value").unwrap();
        assert!(!stale.exists());
        drop(next);
        std::fs::remove_file(ready).unwrap();
        std::fs::remove_file(root.join(CLAUDE_ROOT_LOCK)).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
