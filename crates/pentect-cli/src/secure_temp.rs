//! Short-lived, owner-only files used to inject client configuration.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct SecureTempFile {
    path: PathBuf,
}

#[derive(Debug)]
pub(crate) struct SecureTempDirectory {
    path: PathBuf,
}

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

#[cfg(all(not(unix), test))]
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
}
