use serde::Deserialize;
use std::path::{Path, PathBuf};

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

fn installation_for_executable(path: &Path) -> Result<Option<ManagedInstallation>, String> {
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
        let installation: ManagedInstallation =
            serde_json::from_slice(&bytes).map_err(|error| {
                format!(
                    "invalid installation marker '{}': {error}",
                    marker.display()
                )
            })?;
        if installation.manager.is_empty()
            || installation.manager.len() > 32
            || !installation
                .manager
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
            || installation
                .update
                .iter()
                .chain(installation.uninstall.iter())
                .any(|command| command.len() > 256 || command.chars().any(char::is_control))
        {
            return Err(format!(
                "installation marker '{}' contains invalid instructions",
                marker.display()
            ));
        }
        return Ok(Some(installation));
    }
    Ok(None)
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
}
