use serde::Deserialize;
use std::path::{Path, PathBuf};

pub(crate) const NPM_PACKAGE_ROOT_ENV: &str = "PENTECT_NPM_PACKAGE_ROOT";
pub(crate) const NPM_PROJECT_ROOT_ENV: &str = "PENTECT_NPM_PROJECT_ROOT";
pub(crate) const NPM_SCOPE_ENV: &str = "PENTECT_NPM_SCOPE";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NpmScope {
    Global,
    Local(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NpmInstallation {
    pub(crate) package_root: PathBuf,
    pub(crate) scope: NpmScope,
}

pub(crate) const INSTALL_MARKER: &str = ".pentect-managed-install.json";
const MAX_MARKER_BYTES: u64 = 4 * 1024;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct ManagedInstallation {
    #[serde(default = "default_manager")]
    pub(crate) manager: String,
    #[serde(default)]
    pub(crate) update: Option<String>,
    #[serde(default)]
    pub(crate) uninstall: Option<String>,
}

fn default_manager() -> String {
    "pentect".to_string()
}

impl ManagedInstallation {
    pub(crate) fn is_self_managed(&self) -> bool {
        self.manager == "pentect"
    }

    pub(crate) fn update_message(&self) -> String {
        instruction(
            &self.manager,
            "update",
            self.update.as_deref(),
            "the package manager that installed Pentect",
        )
    }

    pub(crate) fn uninstall_message(&self) -> String {
        instruction(
            &self.manager,
            "uninstall",
            self.uninstall.as_deref(),
            "the package manager that installed Pentect",
        )
    }
}

pub(crate) fn npm_installation() -> Result<NpmInstallation, String> {
    let package_root = absolute_env_path(NPM_PACKAGE_ROOT_ENV)?;
    if !package_root.join("package.json").is_file() {
        return Err("npm package root does not contain package.json".to_string());
    }
    let scope = match std::env::var(NPM_SCOPE_ENV).as_deref() {
        Ok("global") => NpmScope::Global,
        Ok("local") => {
            let project = absolute_env_path(NPM_PROJECT_ROOT_ENV)?;
            if !project.join("package.json").is_file() {
                return Err("npm project root does not contain package.json".to_string());
            }
            NpmScope::Local(project)
        }
        _ => {
            return Err(
                "npm installation scope is unavailable; reinstall the npm package".to_string(),
            )
        }
    };
    Ok(NpmInstallation {
        package_root,
        scope,
    })
}

fn absolute_env_path(name: &str) -> Result<PathBuf, String> {
    let path =
        PathBuf::from(std::env::var_os(name).ok_or_else(|| format!("{name} is unavailable"))?);
    if !path.is_absolute() {
        return Err(format!("{name} must be an absolute path"));
    }
    Ok(path)
}

fn instruction(manager: &str, action: &str, command: Option<&str>, fallback: &str) -> String {
    match command.filter(|value| !value.trim().is_empty()) {
        Some(command) => format!("Pentect is managed by {manager}; use `{command}` to {action} it"),
        None => format!("Pentect is managed by {manager}; use {fallback} to {action} it"),
    }
}

pub(crate) fn current_installation() -> Result<Option<ManagedInstallation>, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate the installed executable: {error}"))?;
    installation_for_executable(&executable)
}

pub(crate) fn installation_for_executable(
    path: &Path,
) -> Result<Option<ManagedInstallation>, String> {
    let mut candidates = Vec::with_capacity(2);
    push_marker_candidate(&mut candidates, path);
    if let Ok(canonical) = std::fs::canonicalize(path) {
        push_marker_candidate(&mut candidates, &canonical);
    }

    for marker in candidates {
        let metadata = match std::fs::symlink_metadata(&marker) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "could not inspect installation marker '{}': {error}",
                    marker.display()
                ));
            }
        };
        if !metadata.file_type().is_file() || metadata.len() > MAX_MARKER_BYTES {
            return Err(format!(
                "installation marker '{}' is not a small regular file",
                marker.display()
            ));
        }
        let bytes = std::fs::read(&marker).map_err(|error| {
            format!(
                "could not read installation marker '{}': {error}",
                marker.display()
            )
        })?;
        // Windows PowerShell 5.1 writes a UTF-8 BOM for `-Encoding utf8`.
        // Older official installers used that encoding for this marker, so the
        // reader must remain able to recover those existing installations.
        let json = bytes
            .strip_prefix(&[0xef, 0xbb, 0xbf])
            .unwrap_or(bytes.as_slice());
        let installation: ManagedInstallation = serde_json::from_slice(json).map_err(|error| {
            format!(
                "invalid installation marker '{}': {error}",
                marker.display()
            )
        })?;
        if !valid_installation(&installation) {
            return Err(format!(
                "installation marker '{}' contains invalid instructions",
                marker.display()
            ));
        }
        return Ok(Some(installation));
    }
    Ok(None)
}

fn valid_installation(installation: &ManagedInstallation) -> bool {
    !(installation.manager.is_empty()
        || installation.manager.len() > 32
        || !installation
            .manager
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        || installation
            .update
            .iter()
            .chain(installation.uninstall.iter())
            .any(|command| command.len() > 256 || command.chars().any(char::is_control)))
}

fn push_marker_candidate(candidates: &mut Vec<PathBuf>, executable: &Path) {
    let Some(parent) = executable.parent() else {
        return;
    };
    let marker = parent.join(INSTALL_MARKER);
    if !candidates.contains(&marker) {
        candidates.push(marker);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_manager_instructions() {
        let marker: ManagedInstallation = serde_json::from_str(
            r#"{"manager":"homebrew","update":"brew upgrade pentect","uninstall":"brew uninstall pentect"}"#,
        )
        .unwrap();
        assert!(!marker.is_self_managed());
        assert!(marker.update_message().contains("brew upgrade pentect"));
        assert!(marker
            .uninstall_message()
            .contains("brew uninstall pentect"));
    }

    #[test]
    fn accepts_the_direct_installer_marker() {
        let marker: ManagedInstallation =
            serde_json::from_str(r#"{"version":1,"path_added":false}"#).unwrap();
        assert!(marker.is_self_managed());
    }

    #[test]
    fn reads_a_utf8_bom_marker_written_by_windows_powershell() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pentect-installation-bom-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("pentect.exe");
        std::fs::write(&executable, b"fixture").unwrap();
        let mut marker = vec![0xef, 0xbb, 0xbf];
        marker.extend_from_slice(br#"{"version":1,"manager":"pentect","path_added":false}"#);
        std::fs::write(root.join(INSTALL_MARKER), marker).unwrap();

        let installation = installation_for_executable(&executable).unwrap().unwrap();
        assert!(installation.is_self_managed());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unsafe_marker_instructions() {
        let mut marker = ManagedInstallation {
            manager: "apt package".to_string(),
            update: None,
            uninstall: None,
        };
        assert!(!valid_installation(&marker));
        marker.manager = "apt".to_string();
        marker.update = Some("x".repeat(257));
        assert!(!valid_installation(&marker));
        marker.update = Some("apt\nupgrade pentect".to_string());
        assert!(!valid_installation(&marker));
    }
}
