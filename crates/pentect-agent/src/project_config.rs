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

fn load_project_config_from(path: &Path) -> Result<ProjectConfig, String> {
    if !path.exists() {
        return Ok(ProjectConfig::default());
    }
    let src = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    parse_project_config(&src).map_err(|e| format!("could not parse '{}': {e}", path.display()))
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
}
