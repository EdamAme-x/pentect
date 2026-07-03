use std::fs;
use std::path::{Path, PathBuf};

const PENTECT_DIR: &str = ".pentect";
const CONFIG_FILE: &str = "config.toml";
const AUTO_APPROVE_ENV: &str = "PENTECT_AGENT_AUTO_APPROVE";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApprovalConfigState {
    pub(crate) project: ApprovalConfigScope,
    pub(crate) global: ApprovalConfigScope,
    pub(crate) effective_no_approve: bool,
    pub(crate) effective_source: ApprovalConfigSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApprovalConfigScope {
    pub(crate) display_path: String,
    pub(crate) no_approve: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApprovalConfigSource {
    Project,
    Global,
    Default,
}

pub(crate) fn approval_config_state() -> Result<ApprovalConfigState, String> {
    let project_path = project_config_path();
    let global_path = global_config_path()?;
    let project = read_approval_config_scope(project_path, project_config_display_path());
    let global = read_approval_config_scope(global_path, global_config_display_path());
    let project = project?;
    let global = global?;
    let (effective_no_approve, effective_source) = if let Some(value) = project.no_approve {
        (value, ApprovalConfigSource::Project)
    } else if let Some(value) = global.no_approve {
        (value, ApprovalConfigSource::Global)
    } else {
        (false, ApprovalConfigSource::Default)
    };
    Ok(ApprovalConfigState {
        project,
        global,
        effective_no_approve,
        effective_source,
    })
}

#[cfg(not(test))]
pub(crate) fn approval_bypassed_by_config() -> Result<bool, String> {
    let state = approval_config_state()?;
    Ok(approval_bypassed_with_state(
        &state,
        env_bool(AUTO_APPROVE_ENV),
    ))
}

#[cfg(test)]
pub(crate) fn approval_bypassed_by_config() -> Result<bool, String> {
    Ok(env_bool(AUTO_APPROVE_ENV))
}

fn approval_bypassed_with_state(state: &ApprovalConfigState, agent_auto_approve: bool) -> bool {
    if state.effective_no_approve {
        return true;
    }
    if state.effective_source != ApprovalConfigSource::Default {
        return false;
    }
    agent_auto_approve
}

pub(crate) fn set_approval_config(
    scope: &str,
    no_approve: Option<bool>,
) -> Result<PathBuf, String> {
    let path = match scope {
        "project" => project_config_path(),
        "global" => global_config_path()?,
        _ => return Err("unknown approval config scope".to_string()),
    };
    write_approval_config_value(&path, no_approve)?;
    Ok(path)
}

#[cfg(test)]
pub(crate) fn approval_bypassed_by_config_value(value: &toml::Value) -> Result<bool, String> {
    Ok(approval_config_override_value(value)?.unwrap_or(false))
}

fn read_approval_config_scope(
    path: PathBuf,
    display_path: String,
) -> Result<ApprovalConfigScope, String> {
    let no_approve = if path.exists() {
        let src = fs::read_to_string(&path)
            .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
        let value = src
            .parse::<toml::Value>()
            .map_err(|e| format!("could not parse '{}': {e}", path.display()))?;
        approval_config_override_value(&value)?
    } else {
        None
    };
    Ok(ApprovalConfigScope {
        display_path,
        no_approve,
    })
}

fn write_approval_config_value(path: &Path, no_approve: Option<bool>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("could not create '{}': {e}", parent.display()))?;
    }
    let mut value = if path.exists() {
        let src = fs::read_to_string(path)
            .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
        if src.trim().is_empty() {
            toml::Value::Table(toml::map::Map::new())
        } else {
            src.parse::<toml::Value>()
                .map_err(|e| format!("could not parse '{}': {e}", path.display()))?
        }
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    let Some(table) = value.as_table_mut() else {
        return Err(format!("'{}' must be a TOML table", path.display()));
    };
    match no_approve {
        Some(value) => {
            table.insert("no_approve".to_string(), toml::Value::Boolean(value));
        }
        None => {
            table.remove("no_approve");
            if let Some(approval) = table.get_mut("approval") {
                if let Some(approval_table) = approval.as_table_mut() {
                    approval_table.remove("no_approve");
                    approval_table.remove("required");
                    approval_table.remove("mode");
                    if approval_table.is_empty() {
                        table.remove("approval");
                    }
                } else {
                    table.remove("approval");
                }
            }
        }
    }
    let src = toml::to_string_pretty(&value)
        .map_err(|e| format!("could not serialize '{}': {e}", path.display()))?;
    fs::write(path, src).map_err(|e| format!("could not write '{}': {e}", path.display()))
}

fn approval_config_override_value(value: &toml::Value) -> Result<Option<bool>, String> {
    if let Some(raw) = value.get("no_approve") {
        return config_bool(raw, "no_approve").map(Some);
    }
    let Some(raw) = value.get("approval") else {
        return Ok(None);
    };
    if let Some(mode) = raw.as_str() {
        return Ok(Some(approval_mode_bypasses(mode)));
    }
    let Some(table) = raw.as_table() else {
        return Err("approval config approval must be a string or table".to_string());
    };
    if let Some(raw) = table.get("no_approve") {
        return config_bool(raw, "approval.no_approve").map(Some);
    }
    if let Some(raw) = table.get("required") {
        return config_bool(raw, "approval.required").map(|value| Some(!value));
    }
    if let Some(raw) = table.get("mode") {
        let Some(mode) = raw.as_str() else {
            return Err("approval config approval.mode must be a string".to_string());
        };
        return Ok(Some(approval_mode_bypasses(mode)));
    }
    Ok(None)
}

fn config_bool(value: &toml::Value, field: &str) -> Result<bool, String> {
    if let Some(value) = value.as_bool() {
        return Ok(value);
    }
    if let Some(value) = value.as_str() {
        return match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(format!("approval config {field} must be boolean-like")),
        };
    }
    Err(format!("approval config {field} must be a boolean"))
}

fn approval_mode_bypasses(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "none" | "off" | "bypass" | "no_approve" | "no-approve"
    )
}

fn env_bool(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on" | "no_approve" | "no-approve"
        )
    })
}

fn project_config_path() -> PathBuf {
    PathBuf::from(PENTECT_DIR).join(CONFIG_FILE)
}

fn project_config_display_path() -> String {
    format!("{PENTECT_DIR}\\{CONFIG_FILE}")
}

fn global_config_path() -> Result<PathBuf, String> {
    home_dir()
        .map(|home| home.join(PENTECT_DIR).join(CONFIG_FILE))
        .ok_or_else(|| "could not find a home directory for global Pentect config".to_string())
}

fn global_config_display_path() -> String {
    if cfg!(windows) {
        format!("%USERPROFILE%\\{PENTECT_DIR}\\{CONFIG_FILE}")
    } else {
        format!("$HOME/{PENTECT_DIR}/{CONFIG_FILE}")
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_config_accepts_no_approve_forms() {
        let value = "no_approve = true".parse::<toml::Value>().unwrap();
        assert!(approval_bypassed_by_config_value(&value).unwrap());

        let value = "approval = \"none\"".parse::<toml::Value>().unwrap();
        assert!(approval_bypassed_by_config_value(&value).unwrap());

        let value = "[approval]\nrequired = false"
            .parse::<toml::Value>()
            .unwrap();
        assert!(approval_bypassed_by_config_value(&value).unwrap());

        let value = "[approval]\nmode = \"required\""
            .parse::<toml::Value>()
            .unwrap();
        assert!(!approval_bypassed_by_config_value(&value).unwrap());
    }

    #[test]
    fn approval_config_detects_explicit_required() {
        let value = "no_approve = false".parse::<toml::Value>().unwrap();
        assert_eq!(approval_config_override_value(&value).unwrap(), Some(false));
    }

    #[test]
    fn agent_auto_approve_respects_explicit_required_config() {
        let explicit_required = ApprovalConfigState {
            project: ApprovalConfigScope {
                display_path: ".pentect/config.toml".to_string(),
                no_approve: Some(false),
            },
            global: ApprovalConfigScope {
                display_path: "$HOME/.pentect/config.toml".to_string(),
                no_approve: None,
            },
            effective_no_approve: false,
            effective_source: ApprovalConfigSource::Project,
        };
        assert!(!approval_bypassed_with_state(&explicit_required, true));

        let default_required = ApprovalConfigState {
            project: ApprovalConfigScope {
                display_path: ".pentect/config.toml".to_string(),
                no_approve: None,
            },
            global: ApprovalConfigScope {
                display_path: "$HOME/.pentect/config.toml".to_string(),
                no_approve: None,
            },
            effective_no_approve: false,
            effective_source: ApprovalConfigSource::Default,
        };
        assert!(approval_bypassed_with_state(&default_required, true));
    }
}
