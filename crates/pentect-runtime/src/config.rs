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
const DEFAULT_IMAGE_OCR_MAX_EDGE: u32 = 2_048;
const DEFAULT_IMAGE_OCR_MAX_PIXELS: u64 = 64_000_000;
const DEFAULT_IMAGE_MAX_IMAGES: usize = 64;
const DEFAULT_IMAGE_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_IMAGE_MAX_SECONDS: u64 = 20;
const DEFAULT_IMAGE_MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_IMAGE_FETCH_SECONDS: u64 = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum HandleScope {
    #[default]
    Device,
    Project,
    Session,
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn handle_identity_key() -> Result<[u8; 32], String> {
    let project = read_handle_scope(project_config_path())?;
    let global = read_handle_scope(global_config_path()?)?;
    match project.or(global).unwrap_or_default() {
        HandleScope::Device => machine_identity_key(),
        HandleScope::Project => {
            let root = project_root()?;
            Ok(derive_project_identity_key(&machine_identity_key()?, &root))
        }
        HandleScope::Session => random_identity_key(),
    }
}

#[cfg_attr(test, allow(dead_code))]
fn read_handle_scope(path: PathBuf) -> Result<Option<HandleScope>, String> {
    parse_config_file(&path)?.map_or(Ok(None), |value| handle_scope_value(&value))
}

fn parse_config_file(path: &Path) -> Result<Option<toml::Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let src = fs::read_to_string(path)
        .map_err(|error| format!("could not read '{}': {error}", path.display()))?;
    if src.trim().is_empty() {
        return Ok(None);
    }
    src.parse::<toml::Value>()
        .map(Some)
        .map_err(|error| format!("could not parse '{}': {error}", path.display()))
}

pub(crate) fn validate_config_file(path: &Path) -> Result<(), String> {
    let Some(value) = parse_config_file(path)? else {
        return Ok(());
    };
    validate_config_value(&value)
}

fn validate_config_value(value: &toml::Value) -> Result<(), String> {
    handle_scope_value(value)?;
    agent_require_pentect_value(value)?;
    image_ocr_config_value(value)?;
    let decode = decode_config_value(value)?;
    merge_decode_config_unchecked(Profile::Strict, decode, DecodeConfigPartial::default())
        .validate()?;
    files_remember_value(value)?;
    activity_share_value(value)?;
    metrics_enabled_value(value)?;
    update_check_value(value)?;
    output_restore_value(value)?;
    unknown_format_policy_value(value)?;
    reject_removed_environment_value(value)
}

fn handle_scope_value(value: &toml::Value) -> Result<Option<HandleScope>, String> {
    let Some(handles) = value.get("handles") else {
        return Ok(None);
    };
    let Some(table) = handles.as_table() else {
        return Err("handles config must be a table".to_string());
    };
    if table.contains_key("hash_scope") {
        return Err("handles.hash_scope was removed; use handles.scope = \"device\"".to_string());
    }
    let raw = table.get("scope");
    let Some(raw) = raw else {
        return Ok(None);
    };
    let Some(raw) = raw.as_str() else {
        return Err("handles.scope must be device, project, or session".to_string());
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "device" => Ok(Some(HandleScope::Device)),
        "project" => Ok(Some(HandleScope::Project)),
        "session" => Ok(Some(HandleScope::Session)),
        _ => Err("handles.scope must be device, project, or session".to_string()),
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
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    path.with_extension(format!("key.tmp-{}-{nonce}-{sequence}", std::process::id()))
}

fn remove_identity_temporary(path: &Path) {
    let _ = fs::remove_file(path);
    #[cfg(windows)]
    let _ = fs::remove_file(identity_acl_marker_path(path));
}

#[cfg(windows)]
fn restrict_identity_file(path: &Path) -> Result<(), String> {
    let marker = identity_acl_marker_path(path);
    let expected_marker = identity_acl_marker(path)?;
    if fs::metadata(&marker).is_ok_and(|metadata| metadata.len() == expected_marker.len() as u64)
        && fs::read(&marker).is_ok_and(|stored| stored == expected_marker.as_bytes())
    {
        return Ok(());
    }
    let system32 = windows_system32()?;
    let identity = std::process::Command::new(system32.join("whoami.exe"))
        .args(["/user", "/fo", "csv", "/nh"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|error| format!("could not resolve the Windows account for ACL setup: {error}"))?;
    if !identity.status.success() {
        return Err("could not resolve the Windows account for ACL setup".to_string());
    }
    let sid = windows_sid_from_whoami_output(&identity.stdout)
        .ok_or_else(|| "could not parse the Windows account SID".to_string())?;
    let status = std::process::Command::new(system32.join("icacls.exe"))
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &format!("*{sid}:(F)")])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| format!("could not restrict identity key ACL: {error}"))?;
    if !status.success() {
        return Err("could not restrict identity key ACL".to_string());
    }
    fs::write(&marker, expected_marker)
        .map_err(|error| format!("could not record identity key ACL setup: {error}"))
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

#[cfg(windows)]
fn identity_acl_marker_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    path.with_file_name(format!("{name}.acl-v1"))
}

#[cfg(windows)]
fn identity_acl_marker(path: &Path) -> Result<String, String> {
    let key: [u8; 32] = fs::read(path)
        .map_err(|error| format!("could not read '{}': {error}", path.display()))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            format!(
                "identity key '{}' must contain exactly 32 bytes (found {})",
                path.display(),
                bytes.len()
            )
        })?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("fixed-size HMAC key");
    mac.update(b"pentect:windows-acl-marker:v1\0");
    mac.update(path.as_os_str().to_string_lossy().as_bytes());
    Ok(data_encoding::HEXLOWER.encode(&mac.finalize().into_bytes()))
}

#[cfg(windows)]
fn windows_system32() -> Result<PathBuf, String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

    let mut buffer = [0u16; 32_768];
    // SAFETY: `buffer` is writable for the advertised length and remains alive
    // for the duration of the Win32 call.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err("could not resolve the Windows system directory".to_string());
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length as usize])).join("System32"))
}

#[cfg(not(windows))]
fn restrict_identity_file(_: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn project_root() -> Result<PathBuf, String> {
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
pub(crate) enum UnknownFormatPolicy {
    Ignore,
    Error,
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
    merge_image_ocr_config(project, global)
}

#[cfg(not(test))]
pub(crate) fn environment_variable_prefix() -> Result<String, String> {
    reject_removed_environment_config(project_config_path())?;
    reject_removed_environment_config(global_config_path()?)?;
    Ok(DEFAULT_ENVIRONMENT_PREFIX.to_string())
}

#[cfg(test)]
pub(crate) fn environment_variable_prefix() -> Result<String, String> {
    Ok(DEFAULT_ENVIRONMENT_PREFIX.to_string())
}

#[cfg(not(test))]
pub(crate) fn decode_config(profile: Profile) -> Result<DecodeConfig, String> {
    let project = read_decode_config(project_config_path())?;
    let global = read_decode_config(global_config_path()?)?;
    merge_decode_config(profile, project, global)?.validate()
}

#[cfg(test)]
pub(crate) fn decode_config(profile: Profile) -> Result<DecodeConfig, String> {
    merge_decode_config(
        profile,
        DecodeConfigPartial::default(),
        DecodeConfigPartial::default(),
    )?
    .validate()
}

pub(crate) fn remember_files_enabled() -> Result<bool, String> {
    let project = read_files_remember(project_config_path())?;
    let global = read_files_remember(global_config_path()?)?;
    Ok(project.or(global).unwrap_or(true))
}

pub(crate) fn activity_share_enabled() -> Result<bool, String> {
    let project = read_activity_share(project_config_path())?;
    let global = read_activity_share(global_config_path()?)?;
    Ok(local_privacy_setting_enabled(project, global))
}

pub(crate) fn metrics_enabled() -> Result<bool, String> {
    let project = read_metrics_enabled(project_config_path())?;
    let global = read_metrics_enabled(global_config_path()?)?;
    Ok(local_privacy_setting_enabled(project, global))
}

fn local_privacy_setting_enabled(project: Option<bool>, global: Option<bool>) -> bool {
    // A repository may narrow local event sharing and metrics visibility, but
    // it must not re-enable either after the user disabled it globally.
    global.unwrap_or(true) && project.unwrap_or(true)
}

pub(crate) fn update_check_enabled() -> Result<bool, String> {
    let project = read_update_check(project_config_path())?;
    let global = read_update_check(global_config_path()?)?;
    Ok(project.or(global).unwrap_or(true))
}

pub(crate) fn output_restore_enabled() -> Result<bool, String> {
    let project = read_output_restore(project_config_path())?;
    let global = read_output_restore(global_config_path()?)?;
    Ok(output_restore_effective(project, global))
}

fn output_restore_effective(project: Option<bool>, global: Option<bool>) -> bool {
    // User-facing assistant output is local and restores known handles by
    // default. Either the user policy or a project policy may narrow that
    // boundary; a project cannot override a user-level opt-out.
    global.unwrap_or(true) && project.unwrap_or(true)
}

pub(crate) fn unknown_formats_should_block() -> Result<bool, String> {
    let project = read_unknown_format_policy(project_config_path())?;
    let global = read_unknown_format_policy(global_config_path()?)?;
    unknown_formats_should_block_effective(project, global)
}

fn unknown_formats_should_block_effective(
    project: Option<UnknownFormatPolicy>,
    global: Option<UnknownFormatPolicy>,
) -> Result<bool, String> {
    if project == Some(UnknownFormatPolicy::Ignore) {
        return Err(
            "compatibility.unknown_formats = \"ignore\" may only be set in the user config at ~/.pentect/config.toml"
                .to_string(),
        );
    }
    Ok(project == Some(UnknownFormatPolicy::Error)
        || global.unwrap_or(UnknownFormatPolicy::Error) == UnknownFormatPolicy::Error)
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
    if value.get("require_pentect").is_some() {
        return Err("require_pentect was removed; use agent.required".to_string());
    }
    let agent = value.get("agent").map(|raw| {
        raw.as_table()
            .ok_or_else(|| "agent config must be a table".to_string())
    });
    let agent = agent.transpose()?;
    let required = agent.and_then(|table| table.get("required"));
    if agent.is_some_and(|table| table.contains_key("require_pentect")) {
        return Err("agent.require_pentect was removed; use agent.required".to_string());
    }
    required
        .map(|raw| agent_config_bool(raw, "agent.required"))
        .transpose()
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
    if table.contains_key("unscanned_images") {
        return Err(
            "image.unscanned_images was removed; use image.unscanned = \"block\"".to_string(),
        );
    }
    if let Some(raw) = table.get("unscanned") {
        out.unscanned_images = Some(unscanned_image_policy(raw, "image.unscanned")?);
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

fn read_files_remember(path: PathBuf) -> Result<Option<bool>, String> {
    parse_config_file(&path)?.map_or(Ok(None), |value| files_remember_value(&value))
}

fn read_update_check(path: PathBuf) -> Result<Option<bool>, String> {
    parse_config_file(&path)?.map_or(Ok(None), |value| update_check_value(&value))
}

fn update_check_value(value: &toml::Value) -> Result<Option<bool>, String> {
    let Some(raw) = value.get("update") else {
        return Ok(None);
    };
    let Some(table) = raw.as_table() else {
        return Err("update config must be a table".to_string());
    };
    table
        .get("check")
        .map(|raw| config_bool(raw, "update.check"))
        .transpose()
}

fn read_output_restore(path: PathBuf) -> Result<Option<bool>, String> {
    parse_config_file(&path)?.map_or(Ok(None), |value| output_restore_value(&value))
}

fn output_restore_value(value: &toml::Value) -> Result<Option<bool>, String> {
    let Some(raw) = value.get("output") else {
        return Ok(None);
    };
    let Some(table) = raw.as_table() else {
        return Err("output config must be a table".to_string());
    };
    table
        .get("restore")
        .map(|raw| config_bool(raw, "output.restore"))
        .transpose()
}

fn reject_removed_environment_config(path: PathBuf) -> Result<(), String> {
    let Some(value) = parse_config_file(&path)? else {
        return Ok(());
    };
    reject_removed_environment_value(&value)
}

fn reject_removed_environment_value(value: &toml::Value) -> Result<(), String> {
    if value.get("environment").is_some() {
        return Err(
            "environment.prefix was removed; handle variables always start with PENTECT_"
                .to_string(),
        );
    }
    Ok(())
}

fn files_remember_value(value: &toml::Value) -> Result<Option<bool>, String> {
    if value.get("file_pointer_manager").is_some() {
        return Err("file_pointer_manager was removed; use files.remember = true".to_string());
    }
    if let Some(raw) = value.get("files") {
        let Some(table) = raw.as_table() else {
            return Err("files config must be a table".to_string());
        };
        if let Some(raw) = table.get("remember") {
            return config_bool(raw, "files.remember").map(Some);
        }
    }
    Ok(None)
}

fn read_activity_share(path: PathBuf) -> Result<Option<bool>, String> {
    parse_config_file(&path)?.map_or(Ok(None), |value| activity_share_value(&value))
}

fn read_metrics_enabled(path: PathBuf) -> Result<Option<bool>, String> {
    parse_config_file(&path)?.map_or(Ok(None), |value| metrics_enabled_value(&value))
}

fn read_unknown_format_policy(path: PathBuf) -> Result<Option<UnknownFormatPolicy>, String> {
    parse_config_file(&path)?.map_or(Ok(None), |value| unknown_format_policy_value(&value))
}

fn unknown_format_policy_value(value: &toml::Value) -> Result<Option<UnknownFormatPolicy>, String> {
    let Some(raw) = value.get("compatibility") else {
        return Ok(None);
    };
    let Some(table) = raw.as_table() else {
        return Err("compatibility config must be a table".to_string());
    };
    let Some(raw) = table.get("unknown_formats") else {
        return Ok(None);
    };
    let Some(raw) = raw.as_str() else {
        return Err("compatibility.unknown_formats must be error, block, or ignore".to_string());
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "ignore" => Ok(Some(UnknownFormatPolicy::Ignore)),
        "error" | "block" => Ok(Some(UnknownFormatPolicy::Error)),
        _ => Err("compatibility.unknown_formats must be error, block, or ignore".to_string()),
    }
}

fn activity_share_value(value: &toml::Value) -> Result<Option<bool>, String> {
    if value.get("log").is_some() {
        return Err("log.share was removed; use activity.share = true".to_string());
    }
    if let Some(raw) = value.get("activity") {
        let Some(table) = raw.as_table() else {
            return Err("activity config must be a table".to_string());
        };
        if let Some(raw) = table.get("share") {
            return config_bool(raw, "activity.share").map(Some);
        }
    }
    Ok(None)
}

fn metrics_enabled_value(value: &toml::Value) -> Result<Option<bool>, String> {
    let Some(raw) = value.get("metrics") else {
        return Ok(None);
    };
    let Some(table) = raw.as_table() else {
        return Err("metrics config must be a table".to_string());
    };
    table
        .get("enabled")
        .map(|raw| config_bool(raw, "metrics.enabled"))
        .transpose()
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
) -> Result<ImageOcrConfig, String> {
    let baseline = merge_image_ocr_config_unchecked(ImageOcrConfigPartial::default(), global);
    let merged = merge_image_ocr_config_unchecked(project, global);
    ensure_project_image_ocr_not_weaker(&baseline, &merged)?;
    Ok(merged)
}

fn merge_image_ocr_config_unchecked(
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

fn ensure_project_image_ocr_not_weaker(
    baseline: &ImageOcrConfig,
    merged: &ImageOcrConfig,
) -> Result<(), String> {
    if baseline.unscanned_images == UnscannedImagePolicy::Block
        && merged.unscanned_images == UnscannedImagePolicy::Allow
    {
        return Err(
            "image.unscanned = \"allow\" may only be set in the user config at ~/.pentect/config.toml"
                .to_string(),
        );
    }
    if baseline.mode == ImageOcrMode::On && merged.mode == ImageOcrMode::Off {
        return Err(
            "image.ocr = \"off\" may only be set in the user config at ~/.pentect/config.toml"
                .to_string(),
        );
    }
    if baseline.mode == ImageOcrMode::Off {
        return Ok(());
    }
    for (field, weaker) in [
        ("image.max_pixels", merged.max_pixels < baseline.max_pixels),
        ("image.max_edge", merged.max_edge < baseline.max_edge),
        ("image.max_images", merged.max_images < baseline.max_images),
        (
            "image.max_total_bytes",
            merged.max_total_bytes < baseline.max_total_bytes,
        ),
        (
            "image.max_seconds",
            merged.max_seconds < baseline.max_seconds,
        ),
        (
            "image.max_image_bytes",
            merged.max_image_bytes < baseline.max_image_bytes,
        ),
        (
            "image.fetch_seconds",
            merged.fetch_seconds < baseline.fetch_seconds,
        ),
    ] {
        if weaker {
            return Err(project_image_limit_error(field));
        }
    }
    Ok(())
}

fn project_image_limit_error(field: &str) -> String {
    format!(
        "{field} may not reduce image inspection coverage in project config; set the weaker limit in ~/.pentect/config.toml"
    )
}

fn merge_decode_config(
    profile: Profile,
    project: DecodeConfigPartial,
    global: DecodeConfigPartial,
) -> Result<DecodeConfig, String> {
    let baseline = merge_decode_config_unchecked(profile, DecodeConfigPartial::default(), global);
    let merged = merge_decode_config_unchecked(profile, project, global);
    ensure_project_decode_not_weaker(&baseline, &merged)?;
    Ok(merged)
}

fn merge_decode_config_unchecked(
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
        limit_reporter: Some(record_decode_limit),
    }
}

fn ensure_project_decode_not_weaker(
    baseline: &DecodeConfig,
    merged: &DecodeConfig,
) -> Result<(), String> {
    if baseline.enabled && !merged.enabled {
        return Err(
            "decode.enabled = false may only be set in the user config at ~/.pentect/config.toml"
                .to_string(),
        );
    }
    // Enabling a decoder disabled by the user is a strict project policy. Its
    // subordinate limits cannot weaken a decoder that was not running.
    if !baseline.enabled {
        return Ok(());
    }
    if !optional_limit_is_at_least(merged.max_depth, baseline.max_depth) {
        return Err(project_decode_limit_error("decode.max_depth"));
    }
    if merged.min_bytes > baseline.min_bytes {
        return Err(project_decode_limit_error("decode.min_bytes"));
    }
    if !optional_limit_is_at_least(merged.max_bytes, baseline.max_bytes) {
        return Err(project_decode_limit_error("decode.max_bytes"));
    }
    if !optional_limit_is_at_least(merged.max_inflate_bytes, baseline.max_inflate_bytes) {
        return Err(project_decode_limit_error("decode.max_inflate_bytes"));
    }
    if baseline.mask_unknown && !merged.mask_unknown {
        return Err(project_decode_limit_error("decode.mask_unknown"));
    }
    if baseline.mask_unknown
        && merged.mask_unknown
        && merged.unknown_min_bytes > baseline.unknown_min_bytes
    {
        return Err(project_decode_limit_error("decode.unknown_min_bytes"));
    }
    Ok(())
}

fn optional_limit_is_at_least<T: Ord>(candidate: Option<T>, baseline: Option<T>) -> bool {
    match (candidate, baseline) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(candidate), Some(baseline)) => candidate >= baseline,
    }
}

fn project_decode_limit_error(field: &str) -> String {
    format!(
        "{field} may not reduce decode coverage in project config; set the weaker limit in ~/.pentect/config.toml"
    )
}

fn record_decode_limit(reason: pentect_core::DecodeLimitReason) {
    crate::activity_log::record_diagnostic(
        "decode",
        reason.as_str(),
        Some("limit"),
        None,
        None,
        None,
        None,
        None,
    );
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

    #[test]
    fn extracts_sid_without_decoding_the_account_name() {
        let output = b"\x8a\xc7\x97\x9d,\"S-1-5-21-123-456-789-1001\"\r\n";
        assert_eq!(
            windows_sid_from_whoami_output(output).as_deref(),
            Some("S-1-5-21-123-456-789-1001")
        );
    }

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
    fn handle_scope_accepts_all_scopes_and_rejects_old_or_unknown_values() {
        for (raw, expected) in [
            ("device", HandleScope::Device),
            ("project", HandleScope::Project),
            ("session", HandleScope::Session),
        ] {
            let value = format!("[handles]\nscope = {raw:?}")
                .parse::<toml::Value>()
                .unwrap();
            assert_eq!(handle_scope_value(&value).unwrap(), Some(expected));
        }
        let value = "[handles]\nscope = \"daily\""
            .parse::<toml::Value>()
            .unwrap();
        assert!(handle_scope_value(&value).is_err());

        let value = "[handles]\nhash_scope = \"machine\""
            .parse::<toml::Value>()
            .unwrap();
        assert!(handle_scope_value(&value).is_err());
    }

    #[test]
    fn machine_identity_key_is_stable_and_invalid_files_fail_closed() {
        let root = temp_test_dir("handle-identity-key");
        let path = root.join(IDENTITY_KEY_FILE);
        let first = load_or_create_identity_key(&path).unwrap();
        let second = load_or_create_identity_key(&path).unwrap();
        assert_eq!(first, second);
        assert_eq!(std::fs::read(&path).unwrap().len(), 32);
        #[cfg(windows)]
        {
            let marker = identity_acl_marker_path(&path);
            assert_eq!(
                marker.file_name().and_then(|name| name.to_str()),
                Some("handle-identity.key.acl-v1")
            );
            std::fs::write(&marker, "forged").unwrap();
            restrict_identity_file(&path).unwrap();
            assert_eq!(
                std::fs::read_to_string(marker).unwrap(),
                identity_acl_marker(&path).unwrap()
            );
        }

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
    fn agent_required_accepts_only_the_canonical_key() {
        let value = "[agent]\nrequired = false".parse::<toml::Value>().unwrap();
        assert_eq!(agent_require_pentect_value(&value).unwrap(), Some(false));

        let value = "require_pentect = true".parse::<toml::Value>().unwrap();
        assert!(agent_require_pentect_value(&value).is_err());

        let value = "[agent]\nrequire_pentect = \"on\""
            .parse::<toml::Value>()
            .unwrap();
        assert!(agent_require_pentect_value(&value).is_err());
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
    fn unknown_formats_block_by_default_and_only_global_config_can_relax() {
        assert!(unknown_formats_should_block_effective(None, None).unwrap());
        assert!(
            !unknown_formats_should_block_effective(None, Some(UnknownFormatPolicy::Ignore))
                .unwrap()
        );
        assert!(unknown_formats_should_block_effective(
            Some(UnknownFormatPolicy::Error),
            Some(UnknownFormatPolicy::Ignore)
        )
        .unwrap());
        assert!(
            unknown_formats_should_block_effective(Some(UnknownFormatPolicy::Ignore), None)
                .is_err()
        );

        let ignore = "[compatibility]\nunknown_formats = \"ignore\""
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(
            unknown_format_policy_value(&ignore).unwrap(),
            Some(UnknownFormatPolicy::Ignore)
        );
        let block = "[compatibility]\nunknown_formats = \"block\""
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(
            unknown_format_policy_value(&block).unwrap(),
            Some(UnknownFormatPolicy::Error)
        );
        let invalid = "[compatibility]\nunknown_formats = \"allow\""
            .parse::<toml::Value>()
            .unwrap();
        assert!(unknown_format_policy_value(&invalid).is_err());
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
unscanned = \"block\""
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
    fn removed_environment_config_has_a_clear_error() {
        let root = temp_test_dir("removed-environment-config");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.toml");
        std::fs::write(&path, "[environment]\nprefix = \"SAFE_\"\n").unwrap();
        let error = reject_removed_environment_config(path).unwrap_err();
        assert!(error.contains("always start with PENTECT_"));
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
    fn project_decode_config_may_only_strengthen_global_coverage() {
        let project = DecodeConfigPartial {
            max_depth: Some(None),
            min_bytes: Some(8),
            max_bytes: Some(None),
            ..DecodeConfigPartial::default()
        };
        let global = DecodeConfigPartial {
            max_depth: Some(Some(9)),
            min_bytes: Some(24),
            max_bytes: Some(Some(2_000_000)),
            ..DecodeConfigPartial::default()
        };
        let merged = merge_decode_config(Profile::Strict, project, global).unwrap();
        assert_eq!(merged.max_depth, None);
        assert_eq!(merged.min_bytes, 8);
        assert_eq!(merged.max_bytes, None);
    }

    #[test]
    fn project_decode_config_cannot_reduce_any_active_coverage_limit() {
        let global = DecodeConfigPartial {
            enabled: Some(true),
            max_depth: Some(Some(10)),
            min_bytes: Some(12),
            max_bytes: Some(Some(1_000_000)),
            max_inflate_bytes: Some(Some(2_000_000)),
            mask_unknown: Some(true),
            unknown_min_bytes: Some(24),
        };
        let weaker = [
            DecodeConfigPartial {
                enabled: Some(false),
                ..DecodeConfigPartial::default()
            },
            DecodeConfigPartial {
                max_depth: Some(Some(9)),
                ..DecodeConfigPartial::default()
            },
            DecodeConfigPartial {
                min_bytes: Some(13),
                ..DecodeConfigPartial::default()
            },
            DecodeConfigPartial {
                max_bytes: Some(Some(999_999)),
                ..DecodeConfigPartial::default()
            },
            DecodeConfigPartial {
                max_inflate_bytes: Some(Some(1_999_999)),
                ..DecodeConfigPartial::default()
            },
            DecodeConfigPartial {
                mask_unknown: Some(false),
                ..DecodeConfigPartial::default()
            },
            DecodeConfigPartial {
                unknown_min_bytes: Some(25),
                ..DecodeConfigPartial::default()
            },
        ];
        for project in weaker {
            assert!(merge_decode_config(Profile::Strict, project, global).is_err());
        }

        let user_disabled = DecodeConfigPartial {
            enabled: Some(false),
            ..global
        };
        assert!(merge_decode_config(
            Profile::Strict,
            DecodeConfigPartial {
                max_depth: Some(Some(1)),
                ..DecodeConfigPartial::default()
            },
            user_disabled,
        )
        .is_ok());
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
            .unwrap()
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
        )
        .unwrap();
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
    fn project_cannot_allow_unscanned_images_unless_user_policy_allows_them() {
        let allow = ImageOcrConfigPartial {
            unscanned_images: Some(UnscannedImagePolicy::Allow),
            ..ImageOcrConfigPartial::default()
        };
        let block = ImageOcrConfigPartial {
            unscanned_images: Some(UnscannedImagePolicy::Block),
            ..ImageOcrConfigPartial::default()
        };
        assert!(merge_image_ocr_config(allow, ImageOcrConfigPartial::default()).is_err());
        assert!(merge_image_ocr_config(allow, block).is_err());
        assert_eq!(
            merge_image_ocr_config(ImageOcrConfigPartial::default(), allow)
                .unwrap()
                .unscanned_images,
            UnscannedImagePolicy::Allow
        );
        assert_eq!(
            merge_image_ocr_config(block, allow)
                .unwrap()
                .unscanned_images,
            UnscannedImagePolicy::Block
        );
    }

    #[test]
    fn project_image_config_cannot_disable_active_user_ocr() {
        let project = ImageOcrConfigPartial {
            mode: Some(ImageOcrMode::Off),
            ..ImageOcrConfigPartial::default()
        };
        let error = merge_image_ocr_config(project, ImageOcrConfigPartial::default()).unwrap_err();
        assert!(error.contains("image.ocr"), "{error}");
    }

    #[test]
    fn project_image_config_cannot_reduce_active_inspection_limits() {
        let cases = [
            (
                ImageOcrConfigPartial {
                    max_pixels: Some(DEFAULT_IMAGE_OCR_MAX_PIXELS - 1),
                    ..ImageOcrConfigPartial::default()
                },
                "image.max_pixels",
            ),
            (
                ImageOcrConfigPartial {
                    max_edge: Some(DEFAULT_IMAGE_OCR_MAX_EDGE - 1),
                    ..ImageOcrConfigPartial::default()
                },
                "image.max_edge",
            ),
            (
                ImageOcrConfigPartial {
                    max_images: Some(DEFAULT_IMAGE_MAX_IMAGES - 1),
                    ..ImageOcrConfigPartial::default()
                },
                "image.max_images",
            ),
            (
                ImageOcrConfigPartial {
                    max_total_bytes: Some(DEFAULT_IMAGE_MAX_TOTAL_BYTES - 1),
                    ..ImageOcrConfigPartial::default()
                },
                "image.max_total_bytes",
            ),
            (
                ImageOcrConfigPartial {
                    max_seconds: Some(DEFAULT_IMAGE_MAX_SECONDS - 1),
                    ..ImageOcrConfigPartial::default()
                },
                "image.max_seconds",
            ),
            (
                ImageOcrConfigPartial {
                    max_image_bytes: Some(DEFAULT_IMAGE_MAX_IMAGE_BYTES - 1),
                    ..ImageOcrConfigPartial::default()
                },
                "image.max_image_bytes",
            ),
            (
                ImageOcrConfigPartial {
                    fetch_seconds: Some(DEFAULT_IMAGE_FETCH_SECONDS - 1),
                    ..ImageOcrConfigPartial::default()
                },
                "image.fetch_seconds",
            ),
        ];

        for (project, field) in cases {
            let error =
                merge_image_ocr_config(project, ImageOcrConfigPartial::default()).unwrap_err();
            assert!(error.contains(field), "{field}: {error}");
        }
    }

    #[test]
    fn project_image_limits_are_unrestricted_when_user_ocr_is_off() {
        let global = ImageOcrConfigPartial {
            mode: Some(ImageOcrMode::Off),
            ..ImageOcrConfigPartial::default()
        };
        let project = ImageOcrConfigPartial {
            mode: Some(ImageOcrMode::On),
            max_pixels: Some(1),
            max_edge: Some(1),
            max_images: Some(1),
            max_total_bytes: Some(1),
            max_seconds: Some(1),
            max_image_bytes: Some(1),
            fetch_seconds: Some(1),
            ..ImageOcrConfigPartial::default()
        };
        assert_eq!(
            merge_image_ocr_config(project, global).unwrap().mode,
            ImageOcrMode::On
        );
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
    fn files_remember_accepts_only_the_canonical_key() {
        let value = "[files]\nremember = false".parse::<toml::Value>().unwrap();
        assert_eq!(files_remember_value(&value).unwrap(), Some(false));

        let value = "[file_pointer_manager]\nsave = true"
            .parse::<toml::Value>()
            .unwrap();
        assert!(files_remember_value(&value).is_err());
    }

    #[test]
    fn activity_share_accepts_only_the_canonical_key() {
        let value = "[activity]\nshare = false".parse::<toml::Value>().unwrap();
        assert_eq!(activity_share_value(&value).unwrap(), Some(false));

        let value = "[activity]\nshare = \"on\"".parse::<toml::Value>().unwrap();
        assert_eq!(activity_share_value(&value).unwrap(), Some(true));

        let value = "[log]\nshare = true".parse::<toml::Value>().unwrap();
        assert!(activity_share_value(&value).is_err());
    }

    #[test]
    fn metrics_enabled_defaults_on_and_accepts_boolean_like_values() {
        let disabled = "[metrics]\nenabled = false".parse::<toml::Value>().unwrap();
        assert_eq!(metrics_enabled_value(&disabled).unwrap(), Some(false));

        let enabled = "[metrics]\nenabled = \"on\""
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(metrics_enabled_value(&enabled).unwrap(), Some(true));

        let invalid = "[metrics]\nenabled = 3".parse::<toml::Value>().unwrap();
        assert!(metrics_enabled_value(&invalid).is_err());
    }

    #[test]
    fn local_privacy_settings_default_on_and_either_scope_can_disable_them() {
        assert!(local_privacy_setting_enabled(None, None));
        assert!(local_privacy_setting_enabled(Some(true), None));
        assert!(local_privacy_setting_enabled(None, Some(true)));
        assert!(local_privacy_setting_enabled(Some(true), Some(true)));
        assert!(!local_privacy_setting_enabled(Some(false), None));
        assert!(!local_privacy_setting_enabled(None, Some(false)));
        assert!(!local_privacy_setting_enabled(Some(false), Some(true)));
        assert!(!local_privacy_setting_enabled(Some(true), Some(false)));
        assert!(!local_privacy_setting_enabled(Some(false), Some(false)));
    }

    #[test]
    fn output_restore_defaults_on_and_either_scope_can_disable_it() {
        let enabled = "[output]\nrestore = true".parse::<toml::Value>().unwrap();
        let disabled = "[output]\nrestore = false".parse::<toml::Value>().unwrap();
        assert_eq!(output_restore_value(&enabled).unwrap(), Some(true));
        assert_eq!(output_restore_value(&disabled).unwrap(), Some(false));
        assert!(output_restore_effective(None, None));
        assert!(output_restore_effective(Some(true), None));
        assert!(output_restore_effective(None, Some(true)));
        assert!(!output_restore_effective(Some(false), Some(true)));
        assert!(!output_restore_effective(None, Some(false)));
        assert!(!output_restore_effective(Some(true), Some(false)));
    }

    #[test]
    fn output_restore_rejects_non_boolean_values() {
        let value = "[output]\nrestore = \"sometimes\""
            .parse::<toml::Value>()
            .unwrap();
        assert!(output_restore_value(&value).is_err());
    }

    #[test]
    fn update_checks_default_on_and_accept_only_booleans() {
        let enabled = "[update]\ncheck = true".parse::<toml::Value>().unwrap();
        let disabled = "[update]\ncheck = false".parse::<toml::Value>().unwrap();
        let invalid = "[update]\ncheck = \"maybe\""
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(update_check_value(&enabled).unwrap(), Some(true));
        assert_eq!(update_check_value(&disabled).unwrap(), Some(false));
        assert!(update_check_value(&invalid).is_err());
    }
}
