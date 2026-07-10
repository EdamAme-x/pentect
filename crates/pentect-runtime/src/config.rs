use std::fs;
use std::path::PathBuf;

const PENTECT_DIR: &str = ".pentect";
const CONFIG_FILE: &str = "config.toml";
const DEFAULT_IMAGE_OCR_MAX_EDGE: u32 = 2_048;
const DEFAULT_IMAGE_OCR_MAX_PIXELS: u64 = 64_000_000;
const DEFAULT_IMAGE_MAX_IMAGES: usize = 64;
const DEFAULT_IMAGE_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_IMAGE_MAX_SECONDS: u64 = 20;
const DEFAULT_IMAGE_MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_IMAGE_FETCH_SECONDS: u64 = 8;
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
    On,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnscannedImagePolicy {
    Allow,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImageRedactionStyle {
    Black,
    Blur,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ImageOcrConfig {
    pub(crate) mode: ImageOcrMode,
    pub(crate) redaction: ImageRedactionStyle,
    pub(crate) max_pixels: u64,
    pub(crate) max_edge: u32,
    pub(crate) max_images: usize,
    pub(crate) max_total_bytes: u64,
    pub(crate) max_seconds: u64,
    pub(crate) max_image_bytes: u64,
    pub(crate) fetch_seconds: u64,
    pub(crate) unscanned_images: UnscannedImagePolicy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ImageOcrConfigPartial {
    mode: Option<ImageOcrMode>,
    redaction: Option<ImageRedactionStyle>,
    max_pixels: Option<u64>,
    max_edge: Option<u32>,
    max_images: Option<usize>,
    max_total_bytes: Option<u64>,
    max_seconds: Option<u64>,
    max_image_bytes: Option<u64>,
    fetch_seconds: Option<u64>,
    unscanned_images: Option<UnscannedImagePolicy>,
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
    Ok(merge_image_ocr_config(project, global))
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
    let Some(raw) = value.get("image") else {
        return Ok(out);
    };
    let Some(table) = raw.as_table() else {
        return Err("image config must be a table".to_string());
    };
    if let Some(raw) = table.get("ocr") {
        out.mode = Some(image_ocr_mode(raw, "image.ocr")?);
    }
    if let Some(raw) = table.get("redaction") {
        out.redaction = Some(image_redaction_style(raw, "image.redaction")?);
    }
    if let Some(raw) = table.get("max_pixels") {
        out.max_pixels = Some(config_u64(raw, "image.max_pixels")?);
    }
    if let Some(raw) = table.get("max_edge") {
        out.max_edge = Some(config_u32(raw, "image.max_edge")?);
    }
    if let Some(raw) = table.get("max_images") {
        out.max_images = Some(config_usize(raw, "image.max_images")?);
    }
    if let Some(raw) = table.get("max_total_bytes") {
        out.max_total_bytes = Some(config_u64(raw, "image.max_total_bytes")?);
    }
    if let Some(raw) = table.get("max_seconds") {
        out.max_seconds = Some(config_u64(raw, "image.max_seconds")?);
    }
    if let Some(raw) = table.get("max_image_bytes") {
        out.max_image_bytes = Some(config_u64(raw, "image.max_image_bytes")?);
    }
    if let Some(raw) = table.get("fetch_seconds") {
        out.fetch_seconds = Some(config_u64(raw, "image.fetch_seconds")?);
    }
    if let Some(raw) = table.get("unscanned_images") {
        out.unscanned_images = Some(unscanned_image_policy(raw, "image.unscanned_images")?);
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
        return Err(format!("{field} must be off or on"));
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "0" | "false" | "no" | "off" => Ok(ImageOcrMode::Off),
        "1" | "true" | "yes" | "on" => Ok(ImageOcrMode::On),
        _ => Err(format!("{field} must be off or on")),
    }
}

fn unscanned_image_policy(
    value: &toml::Value,
    field: &str,
) -> Result<UnscannedImagePolicy, String> {
    let Some(value) = value.as_str() else {
        return Err(format!("{field} must be allow or block"));
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "allow" => Ok(UnscannedImagePolicy::Allow),
        "block" => Ok(UnscannedImagePolicy::Block),
        _ => Err(format!("{field} must be allow or block")),
    }
}

fn image_redaction_style(value: &toml::Value, field: &str) -> Result<ImageRedactionStyle, String> {
    let Some(value) = value.as_str() else {
        return Err(format!("{field} must be black or blur"));
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "black" => Ok(ImageRedactionStyle::Black),
        "blur" => Ok(ImageRedactionStyle::Blur),
        _ => Err(format!("{field} must be black or blur")),
    }
}

fn config_u64(value: &toml::Value, field: &str) -> Result<u64, String> {
    let value = config_positive_integer(value, field)?;
    u64::try_from(value).map_err(|_| format!("{field} must be positive"))
}

fn config_u32(value: &toml::Value, field: &str) -> Result<u32, String> {
    let value = config_positive_integer(value, field)?;
    u32::try_from(value).map_err(|_| format!("{field} must be positive"))
}

fn config_usize(value: &toml::Value, field: &str) -> Result<usize, String> {
    let value = config_positive_integer(value, field)?;
    usize::try_from(value).map_err(|_| format!("{field} must be positive"))
}

fn config_positive_integer(value: &toml::Value, field: &str) -> Result<i64, String> {
    let Some(value) = value.as_integer() else {
        return Err(format!("{field} must be an integer"));
    };
    if value <= 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(value)
}

fn merge_image_ocr_config(
    project: ImageOcrConfigPartial,
    global: ImageOcrConfigPartial,
) -> ImageOcrConfig {
    ImageOcrConfig {
        mode: project.mode.or(global.mode).unwrap_or(ImageOcrMode::On),
        redaction: project
            .redaction
            .or(global.redaction)
            .unwrap_or(ImageRedactionStyle::Black),
        max_pixels: project
            .max_pixels
            .or(global.max_pixels)
            .unwrap_or(DEFAULT_IMAGE_OCR_MAX_PIXELS),
        max_edge: project
            .max_edge
            .or(global.max_edge)
            .unwrap_or(DEFAULT_IMAGE_OCR_MAX_EDGE),
        max_images: project
            .max_images
            .or(global.max_images)
            .unwrap_or(DEFAULT_IMAGE_MAX_IMAGES),
        max_total_bytes: project
            .max_total_bytes
            .or(global.max_total_bytes)
            .unwrap_or(DEFAULT_IMAGE_MAX_TOTAL_BYTES),
        max_seconds: project
            .max_seconds
            .or(global.max_seconds)
            .unwrap_or(DEFAULT_IMAGE_MAX_SECONDS),
        max_image_bytes: project
            .max_image_bytes
            .or(global.max_image_bytes)
            .unwrap_or(DEFAULT_IMAGE_MAX_IMAGE_BYTES),
        fetch_seconds: project
            .fetch_seconds
            .or(global.fetch_seconds)
            .unwrap_or(DEFAULT_IMAGE_FETCH_SECONDS),
        unscanned_images: project
            .unscanned_images
            .or(global.unscanned_images)
            .unwrap_or(UnscannedImagePolicy::Allow),
    }
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
        let value = "\
[image]
ocr = \"on\"
redaction = \"blur\"
max_pixels = 1234
max_edge = 2048
max_images = 32
max_total_bytes = 268435456
max_seconds = 15
max_image_bytes = 33554432
fetch_seconds = 4
unscanned_images = \"block\""
            .parse::<toml::Value>()
            .unwrap();
        let cfg = image_ocr_config_value(&value).unwrap();
        assert_eq!(cfg.mode, Some(ImageOcrMode::On));
        assert_eq!(cfg.redaction, Some(ImageRedactionStyle::Blur));
        assert_eq!(cfg.max_pixels, Some(1234));
        assert_eq!(cfg.max_edge, Some(2048));
        assert_eq!(cfg.max_images, Some(32));
        assert_eq!(cfg.max_total_bytes, Some(268_435_456));
        assert_eq!(cfg.max_seconds, Some(15));
        assert_eq!(cfg.max_image_bytes, Some(33_554_432));
        assert_eq!(cfg.fetch_seconds, Some(4));
        assert_eq!(cfg.unscanned_images, Some(UnscannedImagePolicy::Block));

        let value = "[image]\nocr = false".parse::<toml::Value>().unwrap();
        let cfg = image_ocr_config_value(&value).unwrap();
        assert_eq!(cfg.mode, Some(ImageOcrMode::Off));
    }

    #[test]
    fn image_ocr_config_rejects_auto_mode() {
        let value = "[image]\nocr = \"auto\"".parse::<toml::Value>().unwrap();
        assert!(image_ocr_config_value(&value).is_err());
    }

    #[test]
    fn image_ocr_config_rejects_unknown_redaction() {
        let value = "[image]\nredaction = \"pixelate\""
            .parse::<toml::Value>()
            .unwrap();
        assert!(image_ocr_config_value(&value).is_err());
    }

    #[test]
    fn image_ocr_config_defaults_to_2k_ocr_edge() {
        let cfg = merge_image_ocr_config(
            ImageOcrConfigPartial::default(),
            ImageOcrConfigPartial::default(),
        );
        assert_eq!(cfg.mode, ImageOcrMode::On);
        assert_eq!(cfg.redaction, ImageRedactionStyle::Black);
        assert_eq!(cfg.max_edge, 2048);
        assert_eq!(cfg.max_pixels, 64_000_000);
        assert_eq!(cfg.max_images, 64);
        assert_eq!(cfg.max_total_bytes, 512 * 1024 * 1024);
        assert_eq!(cfg.max_seconds, 20);
        assert_eq!(cfg.max_image_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.fetch_seconds, 8);
    }

    #[test]
    fn image_ocr_config_rejects_zero_limits() {
        let value = "[image]\nmax_pixels = 0".parse::<toml::Value>().unwrap();
        assert!(image_ocr_config_value(&value).is_err());

        let value = "[image]\nmax_edge = 0".parse::<toml::Value>().unwrap();
        assert!(image_ocr_config_value(&value).is_err());

        let value = "[image]\nmax_images = 0".parse::<toml::Value>().unwrap();
        assert!(image_ocr_config_value(&value).is_err());

        let value = "[image]\nmax_total_bytes = 0"
            .parse::<toml::Value>()
            .unwrap();
        assert!(image_ocr_config_value(&value).is_err());

        let value = "[image]\nmax_seconds = 0".parse::<toml::Value>().unwrap();
        assert!(image_ocr_config_value(&value).is_err());

        let value = "[image]\nmax_image_bytes = 0"
            .parse::<toml::Value>()
            .unwrap();
        assert!(image_ocr_config_value(&value).is_err());

        let value = "[image]\nfetch_seconds = 0".parse::<toml::Value>().unwrap();
        assert!(image_ocr_config_value(&value).is_err());
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
