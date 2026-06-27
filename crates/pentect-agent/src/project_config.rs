use std::path::{Path, PathBuf};

const PENTECT_DIR: &str = ".pentect";
const CONFIG_FILE: &str = "config.toml";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProjectConfig {
    pub(crate) approval_required: bool,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            approval_required: true,
        }
    }
}

pub(crate) fn load_project_config() -> Result<ProjectConfig, String> {
    load_project_config_from(&PathBuf::from(PENTECT_DIR).join(CONFIG_FILE))
}

pub(crate) fn set_approval_required(required: bool) -> Result<ProjectConfig, String> {
    let path = PathBuf::from(PENTECT_DIR).join(CONFIG_FILE);
    set_approval_required_at(&path, required)
}

fn load_project_config_from(path: &Path) -> Result<ProjectConfig, String> {
    if !path.exists() {
        return Ok(ProjectConfig::default());
    }
    let src = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    parse_project_config(&src).map_err(|e| format!("could not parse '{}': {e}", path.display()))
}

fn set_approval_required_at(path: &Path, required: bool) -> Result<ProjectConfig, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create '{}': {e}", parent.display()))?;
    }
    let mut value = if path.exists() {
        let src = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
        src.parse::<toml::Value>()
            .map_err(|e| format!("could not parse '{}': {e}", path.display()))?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    let Some(table) = value.as_table_mut() else {
        return Err(".pentect/config.toml must be a TOML table".to_string());
    };
    table.insert(
        "approval_required".to_string(),
        toml::Value::Boolean(required),
    );
    if let Some(approval) = table
        .get_mut("approval")
        .and_then(toml::Value::as_table_mut)
    {
        approval.insert("required".to_string(), toml::Value::Boolean(required));
    }
    std::fs::write(path, value.to_string())
        .map_err(|e| format!("could not write '{}': {e}", path.display()))?;
    Ok(ProjectConfig {
        approval_required: required,
    })
}

fn parse_project_config(src: &str) -> Result<ProjectConfig, String> {
    let value = src
        .parse::<toml::Value>()
        .map_err(|e| format!("invalid TOML: {e}"))?;
    let top_level = optional_bool(&value, "approval_required")?;
    let nested = value
        .get("approval")
        .map(|approval| optional_bool(approval, "required"))
        .transpose()?
        .flatten();
    if let (Some(a), Some(b)) = (top_level, nested) {
        if a != b {
            return Err("approval_required conflicts with approval.required".to_string());
        }
    }
    Ok(ProjectConfig {
        approval_required: top_level.or(nested).unwrap_or(true),
    })
}

fn optional_bool(value: &toml::Value, key: &str) -> Result<Option<bool>, String> {
    let Some(raw) = value.get(key) else {
        return Ok(None);
    };
    raw.as_bool()
        .map(Some)
        .ok_or_else(|| format!("{key} must be a boolean"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_requiring_approval() {
        assert!(parse_project_config("").unwrap().approval_required);
    }

    #[test]
    fn config_accepts_top_level_approval_required() {
        assert!(
            !parse_project_config("approval_required = false")
                .unwrap()
                .approval_required
        );
    }

    #[test]
    fn config_accepts_nested_approval_required() {
        assert!(
            !parse_project_config("[approval]\nrequired = false")
                .unwrap()
                .approval_required
        );
    }

    #[test]
    fn config_rejects_conflicting_approval_fields() {
        let err = parse_project_config("approval_required = true\n[approval]\nrequired = false")
            .unwrap_err();
        assert!(err.contains("conflicts"), "{err}");
    }

    #[test]
    fn config_setter_preserves_existing_keys() {
        let path = std::env::temp_dir().join(format!(
            "pentect-config-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        std::fs::write(&path, "extensions = [\"rules\"]\n").unwrap();

        let updated = set_approval_required_at(&path, false).unwrap();
        assert!(!updated.approval_required);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("approval_required = false"), "{text}");
        assert!(text.contains("extensions"), "{text}");
        let _ = std::fs::remove_file(path);
    }
}
