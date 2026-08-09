//! Short-lived, owner-only files used to inject client configuration.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct SecureTempFile {
    path: PathBuf,
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

    let identity = Command::new("whoami.exe")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| format!("could not resolve the Windows account for ACL setup: {error}"))?;
    if !identity.status.success() {
        return Err("could not resolve the Windows account for ACL setup".to_string());
    }
    let identity = String::from_utf8(identity.stdout)
        .map_err(|_| "Windows account name is not UTF-8".to_string())?;
    let identity = identity.trim();
    if identity.is_empty() {
        return Err("Windows account name is empty".to_string());
    }
    let grant = format!("{identity}:(F)");
    let status = Command::new("icacls.exe")
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

#[cfg(not(windows))]
pub(crate) fn restrict_to_current_user(_: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
