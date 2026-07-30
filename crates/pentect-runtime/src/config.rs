use hmac::{Hmac, Mac};
use pentect_core::{DecodeConfig, Profile};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const PENTECT_DIR: &str = ".pentect";
const CONFIG_FILE: &str = "config.toml";
const IDENTITY_KEY_FILE: &str = "handle-identity.key";
const DEFAULT_ENVIRONMENT_PREFIX: &str = "PENTECT_";
const MAX_ENVIRONMENT_PREFIX_BYTES: usize = 64;
const DEFAULT_IMAGE_OCR_MAX_EDGE: u32 = 2_048;
const DEFAULT_IMAGE_OCR_MAX_PIXELS: u64 = 64_000_000;
const DEFAULT_IMAGE_MAX_IMAGES: usize = 64;
const DEFAULT_IMAGE_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_IMAGE_MAX_SECONDS: u64 = 20;
const DEFAULT_IMAGE_MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_IMAGE_FETCH_SECONDS: u64 = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum HandleHashScope {
    #[default]
    Machine,
    Project,
    Session,
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn handle_identity_key() -> Result<[u8; 32], String> {
    let project = read_handle_hash_scope(project_config_path())?;
    let global = read_handle_hash_scope(global_config_path()?)?;
    match project.or(global).unwrap_or_default() {
        HandleHashScope::Machine => machine_identity_key(),
        HandleHashScope::Project => {
            let root = project_identity_root()?;
            Ok(derive_project_identity_key(&machine_identity_key()?, &root))
        }
        HandleHashScope::Session => random_identity_key(),
    }
}

#[cfg_attr(test, allow(dead_code))]
fn read_handle_hash_scope(path: PathBuf) -> Result<Option<HandleHashScope>, String> {
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
    handle_hash_scope_value(&value)
}

fn handle_hash_scope_value(value: &toml::Value) -> Result<Option<HandleHashScope>, String> {
    let Some(handles) = value.get("handles") else {
        return Ok(None);
    };
    let Some(table) = handles.as_table() else {
        return Err("handles config must be a table".to_string());
    };
    let Some(raw) = table.get("hash_scope") else {
        return Ok(None);
    };
    let Some(raw) = raw.as_str() else {
        return Err("handles.hash_scope must be a string".to_string());
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "machine" => Ok(Some(HandleHashScope::Machine)),
        "project" => Ok(Some(HandleHashScope::Project)),
        "session" => Ok(Some(HandleHashScope::Session)),
        _ => Err("handles.hash_scope must be machine, project, or session".to_string()),
    }
}

fn random_identity_key() -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| format!("OS CSPRNG unavailable: {e}"))?;
    Ok(key)
}

#[cfg_attr(test, allow(dead_code))]
fn machine_identity_key() -> Result<[u8; 32], String> {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    if let Some(key) = KEY.get() {
        return Ok(*key);
    }
    let key = load_or_create_identity_key(&machine_identity_key_path()?)?;
    let _ = KEY.set(key);
    Ok(*KEY.get().unwrap_or(&key))
}

#[cfg_attr(test, allow(dead_code))]
fn machine_identity_key_path() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = home_dir().map(|home| home.join("Library").join("Application Support"));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".local").join("state")));
    base.map(|base| base.join("pentect").join(IDENTITY_KEY_FILE))
        .ok_or_else(|| "could not find a local data directory for Pentect".to_string())
}

fn load_or_create_identity_key(path: &Path) -> Result<[u8; 32], String> {
    if !path.exists() {
        let parent = path
            .parent()
            .ok_or_else(|| format!("identity key path '{}' has no parent", path.display()))?;
        fs::create_dir_all(parent)
            .map_err(|e| format!("could not create '{}': {e}", parent.display()))?;
        let key = random_identity_key()?;
        let temporary = identity_key_temporary_path(path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(mut file) => {
                if let Err(error) = file.write_all(&key).and_then(|_| file.sync_data()) {
                    drop(file);
                    remove_identity_temporary(&temporary);
                    return Err(format!(
                        "could not write '{}': {error}",
                        temporary.display()
                    ));
                }
                drop(file);
                if let Err(error) = restrict_identity_file(&temporary) {
                    remove_identity_temporary(&temporary);
                    return Err(error);
                }
                let published = match fs::hard_link(&temporary, path) {
                    Ok(()) => true,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
                    Err(error) => {
                        remove_identity_temporary(&temporary);
                        return Err(format!(
                            "could not publish identity key '{}': {error}",
                            path.display()
                        ));
                    }
                };
                remove_identity_temporary(&temporary);
                if published {
                    restrict_identity_file(path)?;
                    return Ok(key);
                }
            }
            Err(error) => {
                return Err(format!(
                    "could not create temporary identity key '{}': {error}",
                    temporary.display()
                ));
            }
        }
    }
    restrict_identity_file(path)?;
    let bytes = fs::read(path).map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "identity key '{}' must contain exactly 32 bytes (found {})",
            path.display(),
            bytes.len()
        )
    })
}

fn identity_key_temporary_path(path: &Path) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_extension(format!("key.tmp-{}-{nonce}", std::process::id()))
}

fn remove_identity_temporary(path: &Path) {
    let _ = fs::remove_file(path);
    #[cfg(windows)]
    let _ = fs::remove_file(path.with_extension("acl-v1"));
}

#[cfg(windows)]
fn restrict_identity_file(path: &Path) -> Result<(), String> {
    let marker = path.with_extension("acl-v1");
    if marker.is_file() {
        return Ok(());
    }
    let identity = std::process::Command::new("whoami.exe")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
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
    let status = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &format!("{identity}:(F)")])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| format!("could not restrict identity key ACL: {error}"))?;
    if !status.success() {
        return Err("could not restrict identity key ACL".to_string());
    }
    fs::write(&marker, b"")
        .map_err(|error| format!("could not record identity key ACL setup: {error}"))
}

#[cfg(not(windows))]
fn restrict_identity_file(_: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg_attr(test, allow(dead_code))]
fn project_identity_root() -> Result<PathBuf, String> {
    let cwd =
        std::env::current_dir().map_err(|e| format!("could not read current directory: {e}"))?;
    let root = cwd
        .ancestors()
        .find(|candidate| candidate.join(".git").exists() || candidate.join(PENTECT_DIR).exists())
        .unwrap_or(&cwd);
    root.canonicalize()
        .map_err(|e| format!("could not canonicalize '{}': {e}", root.display()))
}

fn derive_project_identity_key(machine_key: &[u8; 32], root: &Path) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(machine_key).expect("fixed-size HMAC key");
    mac.update(b"pentect:handle-identity:project:v1\0");
    mac.update(root.to_string_lossy().as_bytes());
    mac.finalize().into_bytes().into()
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DecodeConfigPartial {
    enabled: Option<bool>,
    max_depth: Option<Option<usize>>,
    min_bytes: Option<usize>,
    max_bytes: Option<Option<usize>>,
    max_inflate_bytes: Option<Option<u64>>,
    mask_unknown: Option<bool>,
    unknown_min_bytes: Option<usize>,
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

#[cfg(not(test))]
pub(crate) fn environment_variable_prefix() -> Result<String, String> {
    let project = read_environment_variable_prefix(project_config_path())?;
    let global = read_environment_variable_prefix(global_config_path()?)?;
    Ok(effective_environment_variable_prefix(project, global))
}

#[cfg(test)]
pub(crate) fn environment_variable_prefix() -> Result<String, String> {
    Ok(DEFAULT_ENVIRONMENT_PREFIX.to_string())
}

#[cfg(not(test))]
pub(crate) fn decode_config(profile: Profile) -> Result<DecodeConfig, String> {
    let project = read_decode_config(project_config_path())?;
    let global = read_decode_config(global_config_path()?)?;
    merge_decode_config(profile, project, global).validate()
}

#[cfg(test)]
pub(crate) fn decode_config(profile: Profile) -> Result<DecodeConfig, String> {
    merge_decode_config(
        profile,
        DecodeConfigPartial::default(),
        DecodeConfigPartial::default(),
    )
    .validate()
}

pub(crate) fn file_pointer_manager_save_enabled() -> Result<bool, String> {
    let project = read_file_pointer_manager_save(project_config_path())?;
    let global = read_file_pointer_manager_save(global_config_path()?)?;
    Ok(project.or(global).unwrap_or(true))
}

pub(crate) fn log_share_enabled() -> Result<bool, String> {
    let project = read_log_share(project_config_path())?;
    let global = read_log_share(global_config_path()?)?;
    Ok(project.or(global).unwrap_or(true))
}

fn require_pentect_agent_effective(project: Option<bool>, global: Option<bool>) -> bool {
    project.unwrap_or(false) || global.unwrap_or(false)
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

fn read_decode_config(path: PathBuf) -> Result<DecodeConfigPartial, String> {
    if !path.exists() {
        return Ok(DecodeConfigPartial::default());
    }
    let src = fs::read_to_string(&path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if src.trim().is_empty() {
        return Ok(DecodeConfigPartial::default());
    }
    let value = src
        .parse::<toml::Value>()
        .map_err(|e| format!("could not parse '{}': {e}", path.display()))?;
    decode_config_value(&value)
}

fn decode_config_value(value: &toml::Value) -> Result<DecodeConfigPartial, String> {
    let mut out = DecodeConfigPartial::default();
    let Some(raw) = value.get("decode") else {
        return Ok(out);
    };
    let Some(table) = raw.as_table() else {
        return Err("decode config must be a table".to_string());
    };
    if let Some(raw) = table.get("enabled") {
        out.enabled = Some(config_bool(raw, "decode.enabled")?);
    }
    if let Some(raw) = table.get("max_depth") {
        out.max_depth = Some(config_optional_usize(raw, "decode.max_depth")?);
    }
    if let Some(raw) = table.get("min_bytes") {
        out.min_bytes = Some(config_usize(raw, "decode.min_bytes")?);
    }
    if let Some(raw) = table.get("max_bytes") {
        out.max_bytes = Some(config_optional_usize(raw, "decode.max_bytes")?);
    }
    if let Some(raw) = table.get("max_inflate_bytes") {
        out.max_inflate_bytes = Some(config_optional_u64(raw, "decode.max_inflate_bytes")?);
    }
    if let Some(raw) = table.get("mask_unknown") {
        out.mask_unknown = Some(config_bool(raw, "decode.mask_unknown")?);
    }
    if let Some(raw) = table.get("unknown_min_bytes") {
        out.unknown_min_bytes = Some(config_usize(raw, "decode.unknown_min_bytes")?);
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

fn read_environment_variable_prefix(path: PathBuf) -> Result<Option<String>, String> {
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
    environment_variable_prefix_value(&value)
}

fn environment_variable_prefix_value(value: &toml::Value) -> Result<Option<String>, String> {
    let Some(raw) = value.get("environment") else {
        return Ok(None);
    };
    let Some(table) = raw.as_table() else {
        return Err("environment config must be a table".to_string());
    };
    let Some(raw) = table.get("prefix") else {
        return Ok(None);
    };
    let Some(prefix) = raw.as_str() else {
        return Err("environment.prefix must be a string".to_string());
    };
    validate_environment_variable_prefix(prefix)?;
    Ok(Some(prefix.to_string()))
}

fn validate_environment_variable_prefix(prefix: &str) -> Result<(), String> {
    if prefix.len() > MAX_ENVIRONMENT_PREFIX_BYTES {
        return Err(format!(
            "environment.prefix must be at most {MAX_ENVIRONMENT_PREFIX_BYTES} ASCII bytes"
        ));
    }
    if prefix.is_empty() {
        return Ok(());
    }
    let bytes = prefix.as_bytes();
    if bytes[0].is_ascii_digit()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Err(
            "environment.prefix must be empty or an ASCII environment-name prefix".to_string(),
        );
    }
    Ok(())
}

fn effective_environment_variable_prefix(
    project: Option<String>,
    global: Option<String>,
) -> String {
    project
        .or(global)
        .unwrap_or_else(|| DEFAULT_ENVIRONMENT_PREFIX.to_string())
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

fn read_log_share(path: PathBuf) -> Result<Option<bool>, String> {
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
    log_share_value(&value)
}

fn log_share_value(value: &toml::Value) -> Result<Option<bool>, String> {
    let Some(raw) = value.get("log") else {
        return Ok(None);
    };
    let Some(table) = raw.as_table() else {
        return Err("log config must be a table".to_string());
    };
    let Some(raw) = table.get("share") else {
        return Ok(None);
    };
    config_bool(raw, "log.share").map(Some)
}

fn config_bool(value: &toml::Value, field: &str) -> Result<bool, String> {
    if let Some(value) = value.as_bool() {
        return Ok(value);
    }
    if let Some(value) = value.as_str() {
        return match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(format!("{field} must be boolean-like")),
        };
    }
    Err(format!("{field} must be a boolean"))
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

fn config_optional_usize(value: &toml::Value, field: &str) -> Result<Option<usize>, String> {
    if value
        .as_str()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("unlimited"))
    {
        return Ok(None);
    }
    config_usize(value, field).map(Some)
}

fn config_optional_u64(value: &toml::Value, field: &str) -> Result<Option<u64>, String> {
    if value
        .as_str()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("unlimited"))
    {
        return Ok(None);
    }
    config_u64(value, field).map(Some)
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
            .unwrap_or(UnscannedImagePolicy::Block),
    }
}

fn merge_decode_config(
    profile: Profile,
    project: DecodeConfigPartial,
    global: DecodeConfigPartial,
) -> DecodeConfig {
    let knobs = profile.knobs();
    let defaults = DecodeConfig {
        mask_unknown: knobs.mask_unknown_codec,
        unknown_min_bytes: knobs.min_opaque_run,
        ..DecodeConfig::default()
    };
    let min_bytes = project
        .min_bytes
        .or(global.min_bytes)
        .unwrap_or(defaults.min_bytes);
    let mask_unknown = project
        .mask_unknown
        .or(global.mask_unknown)
        .unwrap_or(defaults.mask_unknown);
    let unknown_min_bytes = project
        .unknown_min_bytes
        .or(global.unknown_min_bytes)
        .unwrap_or_else(|| defaults.unknown_min_bytes.max(min_bytes));
    DecodeConfig {
        enabled: project
            .enabled
            .or(global.enabled)
            .unwrap_or(defaults.enabled),
        max_depth: project
            .max_depth
            .or(global.max_depth)
            .unwrap_or(defaults.max_depth),
        min_bytes,
        max_bytes: project
            .max_bytes
            .or(global.max_bytes)
            .unwrap_or(defaults.max_bytes),
        max_inflate_bytes: project
            .max_inflate_bytes
            .or(global.max_inflate_bytes)
            .unwrap_or(defaults.max_inflate_bytes),
        mask_unknown,
        unknown_min_bytes,
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

fn project_config_path() -> PathBuf {
    PathBuf::from(PENTECT_DIR).join(CONFIG_FILE)
}

fn global_config_path() -> Result<PathBuf, String> {
    home_dir()
        .map(|home| home.join(PENTECT_DIR).join(CONFIG_FILE))
        .ok_or_else(|| "could not find a home directory for global Pentect config".to_string())
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pentect-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn handle_hash_scope_accepts_all_scopes_and_rejects_unknown_values() {
        for (raw, expected) in [
            ("machine", HandleHashScope::Machine),
            ("project", HandleHashScope::Project),
            ("session", HandleHashScope::Session),
        ] {
            let value = format!("[handles]\nhash_scope = {raw:?}")
                .parse::<toml::Value>()
                .unwrap();
            assert_eq!(handle_hash_scope_value(&value).unwrap(), Some(expected));
        }
        let value = "[handles]\nhash_scope = \"daily\""
            .parse::<toml::Value>()
            .unwrap();
        assert!(handle_hash_scope_value(&value).is_err());
    }

    #[test]
    fn machine_identity_key_is_stable_and_invalid_files_fail_closed() {
        let root = temp_test_dir("handle-identity-key");
        let path = root.join(IDENTITY_KEY_FILE);
        let first = load_or_create_identity_key(&path).unwrap();
        let second = load_or_create_identity_key(&path).unwrap();
        assert_eq!(first, second);
        assert_eq!(std::fs::read(&path).unwrap().len(), 32);

        let invalid = root.join("invalid.key");
        std::fs::write(&invalid, b"short").unwrap();
        assert!(load_or_create_identity_key(&invalid).is_err());
        assert_eq!(std::fs::read(&invalid).unwrap(), b"short");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn concurrent_identity_key_creation_publishes_one_complete_key() {
        let root = temp_test_dir("concurrent-handle-identity-key");
        let path = std::sync::Arc::new(root.join(IDENTITY_KEY_FILE));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let workers = (0..4)
            .map(|_| {
                let path = std::sync::Arc::clone(&path);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create_identity_key(&path).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let keys = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();

        assert!(keys.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(std::fs::read(path.as_ref()).unwrap().len(), 32);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn project_identity_key_is_stable_but_project_scoped() {
        let machine = [42u8; 32];
        let a = derive_project_identity_key(&machine, Path::new("project-a"));
        assert_eq!(
            a,
            derive_project_identity_key(&machine, Path::new("project-a"))
        );
        assert_ne!(
            a,
            derive_project_identity_key(&machine, Path::new("project-b"))
        );
        assert_ne!(
            a,
            derive_project_identity_key(&[43u8; 32], Path::new("project-a"))
        );
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
    fn decode_config_accepts_numeric_and_unlimited_limits() {
        let value = r#"
[decode]
enabled = true
max_depth = "unlimited"
min_bytes = 8
max_bytes = 1048576
max_inflate_bytes = "unlimited"
mask_unknown = true
unknown_min_bytes = 32
"#
        .parse::<toml::Value>()
        .unwrap();
        let partial = decode_config_value(&value).unwrap();
        assert_eq!(partial.enabled, Some(true));
        assert_eq!(partial.max_depth, Some(None));
        assert_eq!(partial.min_bytes, Some(8));
        assert_eq!(partial.max_bytes, Some(Some(1_048_576)));
        assert_eq!(partial.max_inflate_bytes, Some(None));
        assert_eq!(partial.mask_unknown, Some(true));
        assert_eq!(partial.unknown_min_bytes, Some(32));
    }

    #[test]
    fn environment_prefix_accepts_namespaced_and_empty_values() {
        let value = "[environment]\nprefix = \"SAFE_\""
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(
            environment_variable_prefix_value(&value).unwrap(),
            Some("SAFE_".to_string())
        );

        let value = "[environment]\nprefix = \"\""
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(
            environment_variable_prefix_value(&value).unwrap(),
            Some(String::new())
        );
    }

    #[test]
    fn environment_prefix_rejects_invalid_environment_names() {
        let too_long = "A".repeat(MAX_ENVIRONMENT_PREFIX_BYTES + 1);
        for prefix in ["9SAFE_", "SAFE-", "秘密_", &too_long] {
            let value = format!("[environment]\nprefix = {prefix:?}")
                .parse::<toml::Value>()
                .unwrap();
            assert!(environment_variable_prefix_value(&value).is_err());
        }
    }

    #[test]
    fn environment_prefix_prefers_project_then_global_then_default() {
        assert_eq!(
            effective_environment_variable_prefix(
                Some("PROJECT_".to_string()),
                Some("GLOBAL_".to_string())
            ),
            "PROJECT_"
        );
        assert_eq!(
            effective_environment_variable_prefix(None, Some("GLOBAL_".to_string())),
            "GLOBAL_"
        );
        assert_eq!(
            effective_environment_variable_prefix(None, None),
            "PENTECT_"
        );
        assert_eq!(
            effective_environment_variable_prefix(Some(String::new()), Some("GLOBAL_".to_string())),
            ""
        );
    }

    #[test]
    fn environment_prefix_reads_config_file() {
        let root = std::env::temp_dir().join(format!(
            "pentect-environment-prefix-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.toml");
        std::fs::write(&path, "[environment]\nprefix = \"SAFE_\"\n").unwrap();
        assert_eq!(
            read_environment_variable_prefix(path).unwrap(),
            Some("SAFE_".to_string())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn decode_config_reads_config_file() {
        let root = std::env::temp_dir().join(format!(
            "pentect-decode-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.toml");
        std::fs::write(
            &path,
            "[decode]\nmax_depth = \"unlimited\"\nmax_bytes = 999999\n",
        )
        .unwrap();
        let config = read_decode_config(path).unwrap();
        assert_eq!(config.max_depth, Some(None));
        assert_eq!(config.max_bytes, Some(Some(999_999)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn project_decode_config_overrides_global_including_unlimited() {
        let project = DecodeConfigPartial {
            max_depth: Some(None),
            max_bytes: Some(Some(2_000_000)),
            ..DecodeConfigPartial::default()
        };
        let global = DecodeConfigPartial {
            max_depth: Some(Some(9)),
            min_bytes: Some(24),
            max_bytes: Some(None),
            ..DecodeConfigPartial::default()
        };
        let merged = merge_decode_config(Profile::Strict, project, global);
        assert_eq!(merged.max_depth, None);
        assert_eq!(merged.min_bytes, 24);
        assert_eq!(merged.max_bytes, Some(2_000_000));
    }

    #[test]
    fn decode_config_rejects_invalid_limits_without_capping_valid_values() {
        let zero = "[decode]\nmax_depth = 0".parse::<toml::Value>().unwrap();
        assert!(decode_config_value(&zero).is_err());

        let project = DecodeConfigPartial {
            max_depth: Some(Some(100_000)),
            ..DecodeConfigPartial::default()
        };
        let merged = merge_decode_config(Profile::Strict, project, DecodeConfigPartial::default())
            .validate()
            .unwrap();
        assert_eq!(merged.max_depth, Some(100_000));
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
        assert_eq!(cfg.unscanned_images, UnscannedImagePolicy::Block);
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

    #[test]
    fn log_share_config_is_explicit_and_defaults_elsewhere() {
        let value = "[log]\nshare = false".parse::<toml::Value>().unwrap();
        assert_eq!(log_share_value(&value).unwrap(), Some(false));

        let value = "[log]\nshare = \"on\"".parse::<toml::Value>().unwrap();
        assert_eq!(log_share_value(&value).unwrap(), Some(true));

        let value = "log = true".parse::<toml::Value>().unwrap();
        assert!(log_share_value(&value).is_err());
    }
}
