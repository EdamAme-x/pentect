use std::fs;
use std::path::{Path, PathBuf};

const PENTECT_DIR: &str = ".pentect";
const CONFIG_FILE: &str = "config.toml";
#[cfg(not(test))]
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
pub(crate) enum ImageOcrMode {
    Off,
    Auto,
    On,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnreadableImagePolicy {
    Allow,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ImageOcrConfig {
    pub(crate) mode: ImageOcrMode,
    pub(crate) max_pixels: u64,
    pub(crate) unreadable_images: UnreadableImagePolicy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ImageOcrConfigPartial {
    mode: Option<ImageOcrMode>,
    max_pixels: Option<u64>,
    unreadable_images: Option<UnreadableImagePolicy>,
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
    Ok(false)
}

pub(crate) fn require_pentect_agent_by_config() -> Result<bool, String> {
    let project = read_agent_require_pentect(project_config_path())?;
    let global = read_agent_require_pentect(global_config_path()?)?;
    Ok(require_pentect_agent_effective(project, global))
}

pub(crate) fn image_ocr_config() -> Result<ImageOcrConfig, String> {
    let project = read_image_ocr_config(project_config_path())?;
    let global = read_image_ocr_config(global_config_path()?)?;
    Ok(ImageOcrConfig {
        mode: project.mode.or(global.mode).unwrap_or(ImageOcrMode::Auto),
        max_pixels: project
            .max_pixels
            .or(global.max_pixels)
            .unwrap_or(4_000_000),
        unreadable_images: project
            .unreadable_images
            .or(global.unreadable_images)
            .unwrap_or(UnreadableImagePolicy::Allow),
    })
}

pub(crate) fn file_pointer_manager_save_enabled() -> Result<bool, String> {
    let project = read_file_pointer_manager_save(project_config_path())?;
    let global = read_file_pointer_manager_save(global_config_path()?)?;
    Ok(project.or(global).unwrap_or(true))
}

fn require_pentect_agent_effective(project: Option<bool>, global: Option<bool>) -> bool {
    project.unwrap_or(false) || global.unwrap_or(false)
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

fn read_agent_require_pentect(path: PathBuf) -> Result<Option<bool>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let src = fs::read_to_string(&path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if src.trim().is_empty() {
        return Ok(None);
    }
    let value = src
        .parse::<toml::Value>()
        .map_err(|e| format!("could not parse '{}': {e}", path.display()))?;
    agent_require_pentect_value(&value)
}

fn agent_require_pentect_value(value: &toml::Value) -> Result<Option<bool>, String> {
    if let Some(raw) = value.get("require_pentect") {
        return agent_config_bool(raw, "require_pentect").map(Some);
    }
    let Some(raw) = value.get("agent") else {
        return Ok(None);
    };
    let Some(table) = raw.as_table() else {
        return Err("agent config must be a table".to_string());
    };
    if let Some(raw) = table.get("require_pentect") {
        return agent_config_bool(raw, "agent.require_pentect").map(Some);
    }
    if let Some(raw) = table.get("required") {
        return agent_config_bool(raw, "agent.required").map(Some);
    }
    Ok(None)
}

fn read_image_ocr_config(path: PathBuf) -> Result<ImageOcrConfigPartial, String> {
    if !path.exists() {
        return Ok(ImageOcrConfigPartial::default());
    }
    let src = fs::read_to_string(&path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if src.trim().is_empty() {
        return Ok(ImageOcrConfigPartial::default());
    }
    let value = src
        .parse::<toml::Value>()
        .map_err(|e| format!("could not parse '{}': {e}", path.display()))?;
    image_ocr_config_value(&value)
}

fn image_ocr_config_value(value: &toml::Value) -> Result<ImageOcrConfigPartial, String> {
    let mut out = ImageOcrConfigPartial::default();
    if let Some(raw) = value.get("image_ocr") {
        out.mode = Some(image_ocr_mode(raw, "image_ocr")?);
    }
    let Some(raw) = value.get("image") else {
        return Ok(out);
    };
    let Some(table) = raw.as_table() else {
        return Err("image config must be a table".to_string());
    };
    if let Some(raw) = table.get("ocr") {
        out.mode = Some(image_ocr_mode(raw, "image.ocr")?);
    }
    if let Some(raw) = table.get("max_pixels") {
        out.max_pixels = Some(config_u64(raw, "image.max_pixels")?);
    }
    if let Some(raw) = table.get("unreadable_images") {
        out.unreadable_images = Some(unreadable_image_policy(raw, "image.unreadable_images")?);
    }
    Ok(out)
}

fn read_file_pointer_manager_save(path: PathBuf) -> Result<Option<bool>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let src = fs::read_to_string(&path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if src.trim().is_empty() {
        return Ok(None);
    }
    let value = src
        .parse::<toml::Value>()
        .map_err(|e| format!("could not parse '{}': {e}", path.display()))?;
    file_pointer_manager_save_value(&value)
}

fn file_pointer_manager_save_value(value: &toml::Value) -> Result<Option<bool>, String> {
    let Some(raw) = value.get("file_pointer_manager") else {
        return Ok(None);
    };
    if raw.is_bool() || raw.is_str() {
        return config_bool(raw, "file_pointer_manager").map(Some);
    }
    let Some(table) = raw.as_table() else {
        return Err("file_pointer_manager config must be a boolean or table".to_string());
    };
    let Some(raw) = table.get("save") else {
        return Ok(None);
    };
    config_bool(raw, "file_pointer_manager.save").map(Some)
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

fn image_ocr_mode(value: &toml::Value, field: &str) -> Result<ImageOcrMode, String> {
    if let Some(value) = value.as_bool() {
        return Ok(if value {
            ImageOcrMode::On
        } else {
            ImageOcrMode::Off
        });
    }
    let Some(value) = value.as_str() else {
        return Err(format!("{field} must be off, auto, or on"));
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "0" | "false" | "no" | "off" => Ok(ImageOcrMode::Off),
        "auto" => Ok(ImageOcrMode::Auto),
        "1" | "true" | "yes" | "on" => Ok(ImageOcrMode::On),
        _ => Err(format!("{field} must be off, auto, or on")),
    }
}

fn unreadable_image_policy(
    value: &toml::Value,
    field: &str,
) -> Result<UnreadableImagePolicy, String> {
    let Some(value) = value.as_str() else {
        return Err(format!("{field} must be allow or block"));
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "allow" => Ok(UnreadableImagePolicy::Allow),
        "block" => Ok(UnreadableImagePolicy::Block),
        _ => Err(format!("{field} must be allow or block")),
    }
}

fn config_u64(value: &toml::Value, field: &str) -> Result<u64, String> {
    let Some(value) = value.as_integer() else {
        return Err(format!("{field} must be an integer"));
    };
    u64::try_from(value).map_err(|_| format!("{field} must be positive"))
}

fn agent_config_bool(value: &toml::Value, field: &str) -> Result<bool, String> {
    if let Some(value) = value.as_bool() {
        return Ok(value);
    }
    if let Some(value) = value.as_str() {
        return match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(format!("agent config {field} must be boolean-like")),
        };
    }
    Err(format!("agent config {field} must be a boolean"))
}

fn approval_mode_bypasses(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "none" | "off" | "bypass" | "no_approve" | "no-approve"
    )
}

#[cfg(not(test))]
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

    #[test]
    fn agent_require_pentect_accepts_top_level_and_table_forms() {
        let value = "require_pentect = true".parse::<toml::Value>().unwrap();
        assert_eq!(agent_require_pentect_value(&value).unwrap(), Some(true));

        let value = "[agent]\nrequire_pentect = \"on\""
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(agent_require_pentect_value(&value).unwrap(), Some(true));

        let value = "[agent]\nrequired = false".parse::<toml::Value>().unwrap();
        assert_eq!(agent_require_pentect_value(&value).unwrap(), Some(false));
    }

    #[test]
    fn agent_require_pentect_is_monotonic_across_scopes() {
        assert!(require_pentect_agent_effective(Some(false), Some(true)));
        assert!(require_pentect_agent_effective(Some(true), Some(false)));
        assert!(require_pentect_agent_effective(Some(true), None));
        assert!(!require_pentect_agent_effective(Some(false), None));
        assert!(!require_pentect_agent_effective(None, Some(false)));
        assert!(!require_pentect_agent_effective(None, None));
    }

    #[test]
    fn image_ocr_config_accepts_mode_and_limit() {
        let value = "[image]\nocr = \"on\"\nmax_pixels = 1234\nunreadable_images = \"block\""
            .parse::<toml::Value>()
            .unwrap();
        let cfg = image_ocr_config_value(&value).unwrap();
        assert_eq!(cfg.mode, Some(ImageOcrMode::On));
        assert_eq!(cfg.max_pixels, Some(1234));
        assert_eq!(cfg.unreadable_images, Some(UnreadableImagePolicy::Block));

        let value = "image_ocr = false".parse::<toml::Value>().unwrap();
        let cfg = image_ocr_config_value(&value).unwrap();
        assert_eq!(cfg.mode, Some(ImageOcrMode::Off));
    }

    #[test]
    fn file_pointer_manager_save_config_accepts_table_and_bool() {
        let value = "[file_pointer_manager]\nsave = false"
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(
            file_pointer_manager_save_value(&value).unwrap(),
            Some(false)
        );

        let value = "file_pointer_manager = \"on\""
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(file_pointer_manager_save_value(&value).unwrap(), Some(true));
    }
}
