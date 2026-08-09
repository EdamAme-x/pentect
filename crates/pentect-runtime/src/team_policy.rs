//! Offline verification and last-known-good caching for signed team policy.

use data_encoding::HEXLOWER;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SCHEMA: &str = "pentect.team-policy.v1";
const DOMAIN: &[u8] = b"pentect:team-policy:v1\0";
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024;
const CACHE_FILE_PREFIX: &str = "team-policy.last-known-good";
const CACHE_DIRECTORY: &str = "team-policy-cache";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedPolicyBundle {
    schema: String,
    issuer: String,
    sequence: u64,
    issued_at: String,
    expires_at: String,
    payload_sha256: String,
    payload: String,
    signature: String,
}

#[derive(Debug)]
struct TeamPolicySettings {
    bundle: PathBuf,
    cache: PathBuf,
    issuer: String,
    trust_root: VerifyingKey,
}

pub(super) fn load(
    project: Option<&toml::Value>,
    user: Option<&toml::Value>,
    user_config_path: &Path,
) -> Result<Option<toml::Value>, String> {
    if project.is_some_and(|value| value.get("team_policy").is_some()) {
        return Err(
            "team_policy may only be configured in the user config at ~/.pentect/config.toml"
                .to_string(),
        );
    }
    let Some(user) = user else {
        return Ok(None);
    };
    let Some(settings) = TeamPolicySettings::parse(user, user_config_path)? else {
        return Ok(None);
    };
    prepare_cache_directory(
        settings
            .cache
            .parent()
            .ok_or_else(|| "team policy cache path has no parent".to_string())?,
    )?;
    let _cache_lock = CacheLock::acquire(&settings.cache)?;
    let cached = read_optional_bundle(&settings.cache)?
        .map(|bundle| verify(bundle, &settings, false))
        .transpose()?;
    #[cfg(test)]
    maybe_delay_after_cache_read();
    let source = match read_optional_bundle(&settings.bundle) {
        Ok(Some(bundle)) => Some(verify(bundle, &settings, true)?),
        Ok(None) => None,
        Err(error) => return Err(error),
    };
    let selected = match (source, cached) {
        (Some(source), Some(cached)) => {
            if source.sequence < cached.sequence {
                return Err("team policy sequence rollback was rejected".to_string());
            }
            if source.sequence == cached.sequence
                && signing_message(&source)? != signing_message(&cached)?
            {
                return Err(
                    "team policy sequence was reused with different metadata or content"
                        .to_string(),
                );
            }
            if source.sequence > cached.sequence {
                write_cache(&settings.cache, &source)?;
            }
            source
        }
        (Some(source), None) => {
            write_cache(&settings.cache, &source)?;
            source
        }
        (None, Some(cached)) => {
            ensure_fresh(&cached)?;
            cached
        }
        (None, None) => {
            return Err(format!(
                "team policy bundle '{}' is unavailable and no cache exists",
                settings.bundle.display()
            ))
        }
    };
    parse_payload(&selected.payload).map(Some)
}

impl TeamPolicySettings {
    fn parse(value: &toml::Value, user_config_path: &Path) -> Result<Option<Self>, String> {
        let Some(raw) = value.get("team_policy") else {
            return Ok(None);
        };
        let table = raw
            .as_table()
            .ok_or_else(|| "team_policy must be a table".to_string())?;
        for key in table.keys() {
            if !matches!(key.as_str(), "bundle" | "issuer" | "public_key") {
                return Err("user config contains an unknown team_policy setting".to_string());
            }
        }
        let bundle = required_string(table, "bundle")?;
        let bundle = PathBuf::from(bundle);
        if !bundle.is_absolute() {
            return Err("team_policy.bundle must be an absolute path".to_string());
        }
        let issuer = normalize_identifier("team_policy.issuer", required_string(table, "issuer")?)?;
        let key_hex = required_string(table, "public_key")?;
        let key_bytes = decode_exact::<32>(key_hex, "team_policy.public_key")?;
        let trust_root = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| "team_policy.public_key is not a valid Ed25519 key".to_string())?;
        let cache_identity = sha256_hex(
            [issuer.as_bytes(), trust_root.as_bytes().as_slice()]
                .concat()
                .as_slice(),
        );
        let cache = user_config_path
            .parent()
            .ok_or_else(|| "user config path has no parent".to_string())?
            .join(CACHE_DIRECTORY)
            .join(format!(
                "{CACHE_FILE_PREFIX}-{}.json",
                &cache_identity[..16]
            ));
        Ok(Some(Self {
            bundle,
            cache,
            issuer,
            trust_root,
        }))
    }
}

fn required_string<'a>(
    table: &'a toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<&'a str, String> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("team_policy.{key} must be a string"))
}

fn read_optional_bundle(path: &Path) -> Result<Option<SignedPolicyBundle>, String> {
    let mut file = match open_bundle(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "could not safely open team policy '{}': {error}",
                path.display()
            ))
        }
    };
    let metadata = file.metadata().map_err(|error| {
        format!(
            "could not inspect team policy '{}': {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(format!("unsafe team policy path '{}'", path.display()));
    }
    if metadata.len() > MAX_BUNDLE_BYTES {
        return Err("team policy bundle is too large".to_string());
    }
    let mut bytes = Vec::with_capacity((metadata.len().min(MAX_BUNDLE_BYTES) as usize) + 1);
    Read::by_ref(&mut file)
        .take(MAX_BUNDLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read team policy '{}': {error}", path.display()))?;
    if bytes.len() as u64 > MAX_BUNDLE_BYTES {
        return Err("team policy bundle is too large".to_string());
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("team policy bundle is invalid JSON: {error}"))
}

fn open_bundle(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn verify(
    bundle: SignedPolicyBundle,
    settings: &TeamPolicySettings,
    require_fresh: bool,
) -> Result<SignedPolicyBundle, String> {
    if bundle.schema != SCHEMA {
        return Err("team policy schema is not supported".to_string());
    }
    let issuer = normalize_identifier("team policy issuer", &bundle.issuer)?;
    if issuer != bundle.issuer {
        return Err("team policy issuer is not canonical".to_string());
    }
    if issuer != settings.issuer {
        return Err("team policy issuer does not match the pinned issuer".to_string());
    }
    if bundle.sequence == 0 {
        return Err("team policy sequence must be positive".to_string());
    }
    let issued_at = parse_timestamp("issued_at", &bundle.issued_at)?;
    let expires_at = parse_timestamp("expires_at", &bundle.expires_at)?;
    if expires_at <= issued_at {
        return Err("team policy expires_at must be after issued_at".to_string());
    }
    if require_fresh {
        ensure_fresh_timestamps(issued_at, expires_at)?;
    }
    let actual_payload_digest = sha256_hex(bundle.payload.as_bytes());
    if !constant_time_eq(
        actual_payload_digest.as_bytes(),
        bundle.payload_sha256.as_bytes(),
    ) {
        return Err("team policy payload digest does not match".to_string());
    }
    let signature_bytes = decode_exact::<64>(&bundle.signature, "team policy signature")?;
    let signature = Signature::from_bytes(&signature_bytes);
    settings
        .trust_root
        .verify_strict(&signing_message(&bundle)?, &signature)
        .map_err(|_| "team policy signature is invalid".to_string())?;
    parse_payload(&bundle.payload)?;
    Ok(bundle)
}

fn ensure_fresh(bundle: &SignedPolicyBundle) -> Result<(), String> {
    ensure_fresh_timestamps(
        parse_timestamp("issued_at", &bundle.issued_at)?,
        parse_timestamp("expires_at", &bundle.expires_at)?,
    )
}

fn ensure_fresh_timestamps(issued_at: i64, expires_at: i64) -> Result<(), String> {
    let now = jiff::Timestamp::now().as_second();
    if issued_at > now + 300 {
        return Err("team policy issued_at is in the future".to_string());
    }
    if expires_at <= now {
        return Err("team policy has expired".to_string());
    }
    Ok(())
}

fn signing_message(bundle: &SignedPolicyBundle) -> Result<Vec<u8>, String> {
    let digest = decode_exact::<32>(&bundle.payload_sha256, "team policy payload_sha256")?;
    let mut output = Vec::with_capacity(256);
    output.extend_from_slice(DOMAIN);
    append(&mut output, bundle.schema.as_bytes());
    append(&mut output, bundle.issuer.as_bytes());
    output.extend_from_slice(&bundle.sequence.to_le_bytes());
    append(&mut output, bundle.issued_at.as_bytes());
    append(&mut output, bundle.expires_at.as_bytes());
    append(&mut output, &digest);
    Ok(output)
}

fn append(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

fn parse_payload(payload: &str) -> Result<toml::Value, String> {
    if payload.len() as u64 > MAX_BUNDLE_BYTES {
        return Err("team policy payload is too large".to_string());
    }
    let value = payload
        .parse::<toml::Value>()
        .map_err(|_| "team policy payload is invalid TOML".to_string())?;
    if !value.is_table() {
        return Err("team policy payload must be a TOML table".to_string());
    }
    if value.get("team_policy").is_some() {
        return Err("team policy payload cannot configure team_policy".to_string());
    }
    let table = value.as_table().expect("checked above");
    for (key, section) in table {
        let allowed: &[&str] = match key.as_str() {
            "handles" => &["scope"],
            "agent" => &["required"],
            "image" => &[
                "ocr",
                "redaction",
                "max_pixels",
                "max_edge",
                "max_images",
                "max_total_bytes",
                "max_seconds",
                "max_image_bytes",
                "fetch_seconds",
                "unscanned",
            ],
            "files" => &["remember"],
            "activity" => &["share"],
            "compatibility" => &["unknown_formats"],
            "decode" => &[
                "enabled",
                "max_depth",
                "min_bytes",
                "max_bytes",
                "max_inflate_bytes",
                "mask_unknown",
                "unknown_min_bytes",
            ],
            _ => {
                return Err("team policy payload contains an unsupported section".to_string());
            }
        };
        let section = section
            .as_table()
            .ok_or_else(|| format!("team policy section '{key}' must be a table"))?;
        for setting in section.keys() {
            if !allowed.contains(&setting.as_str()) {
                return Err("team policy payload contains an unsupported setting".to_string());
            }
        }
    }
    crate::config::validate_team_policy_payload(&value)
        .map_err(|error| format!("team policy payload is invalid: {error}"))?;
    Ok(value)
}

fn parse_timestamp(name: &str, value: &str) -> Result<i64, String> {
    let timestamp = value
        .parse::<jiff::Timestamp>()
        .map_err(|_| format!("team policy {name} is not a valid RFC 3339 timestamp"))?;
    if timestamp.to_string() != value {
        return Err(format!("team policy {name} is not canonical RFC 3339"));
    }
    Ok(timestamp.as_second())
}

fn normalize_identifier(name: &str, value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 200
        || value.chars().any(|character| character.is_control())
    {
        return Err(format!("{name} is invalid"));
    }
    Ok(value.to_string())
}

fn decode_exact<const N: usize>(value: &str, name: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(format!("{name} must be lowercase hexadecimal"));
    }
    let bytes = HEXLOWER
        .decode(value.as_bytes())
        .map_err(|_| format!("{name} must be lowercase hexadecimal"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{name} has the wrong length"))
}

fn sha256_hex(value: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(value))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

struct CacheLock {
    file: File,
}

impl CacheLock {
    fn acquire(cache: &Path) -> Result<Self, String> {
        let path = cache.with_extension("lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options
            .open(&path)
            .map_err(|error| format!("could not open team policy cache lock: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("could not inspect team policy cache lock: {error}"))?;
        if !metadata.is_file() || is_reparse_point(&metadata) {
            return Err("unsafe team policy cache lock path".to_string());
        }
        restrict_file(&path)?;
        lock_file(&file)?;
        Ok(Self { file })
    }
}

impl Drop for CacheLock {
    fn drop(&mut self) {
        unlock_file(&self.file);
    }
}

#[cfg(unix)]
fn lock_file(file: &File) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!("could not lock team policy cache: {error}"));
        }
    }
}

#[cfg(unix)]
fn unlock_file(file: &File) {
    use std::os::fd::AsRawFd;
    let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

#[cfg(windows)]
fn lock_file(file: &File) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK};
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    if unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    } == 0
    {
        Err(format!(
            "could not lock team policy cache: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn unlock_file(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let _ = unsafe { UnlockFileEx(file.as_raw_handle(), 0, u32::MAX, u32::MAX, &mut overlapped) };
}

#[cfg(test)]
fn maybe_delay_after_cache_read() {
    if let Some(path) = std::env::var_os("PENTECT_TEST_POLICY_CACHE_READY") {
        let _ = fs::write(path, b"ready");
    }
    let Some(milliseconds) = std::env::var_os("PENTECT_TEST_POLICY_CACHE_DELAY_MS") else {
        return;
    };
    let Ok(milliseconds) = milliseconds.to_string_lossy().parse::<u64>() else {
        return;
    };
    std::thread::sleep(std::time::Duration::from_millis(milliseconds.min(5_000)));
}

fn prepare_cache_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("unsafe team policy cache directory".to_string());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[allow(unused_mut)]
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            if let Err(error) = builder.create(path) {
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(format!(
                        "could not create team policy cache directory: {error}"
                    ));
                }
            }
            let metadata = fs::symlink_metadata(path).map_err(|error| {
                format!("could not inspect team policy cache directory: {error}")
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("unsafe team policy cache directory".to_string());
            }
        }
        Err(error) => {
            return Err(format!(
                "could not inspect team policy cache directory: {error}"
            ))
        }
    }
    restrict_directory(path)
}

fn write_cache(path: &Path, bundle: &SignedPolicyBundle) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "team policy cache path has no parent".to_string())?;
    prepare_cache_directory(parent)?;
    let bytes = serde_json::to_vec_pretty(bundle)
        .map_err(|error| format!("could not encode team policy cache: {error}"))?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(
        ".team-policy-cache-{}-{nonce}.tmp",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("could not create team policy cache: {error}"))?;
    let result = file
        .write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("could not write team policy cache: {error}"));
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = restrict_file(&temporary) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        let _ = fs::remove_file(&temporary);
        return Err("refusing to replace a symlink team policy cache".to_string());
    }
    if let Err(error) = atomic_replace(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("could not publish team policy cache: {error}"));
    }
    restrict_file(path)
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not restrict team policy cache directory: {error}"))
}

#[cfg(windows)]
fn restrict_directory(path: &Path) -> Result<(), String> {
    restrict_windows_path(path, "directory")
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("could not restrict team policy cache: {error}"))
}

#[cfg(windows)]
fn restrict_file(path: &Path) -> Result<(), String> {
    restrict_windows_path(path, "file")
}

#[cfg(windows)]
fn restrict_windows_path(path: &Path, kind: &str) -> Result<(), String> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
    let mut buffer = [0u16; 32_768];
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err(format!(
            "could not resolve Windows directory for team policy cache {kind} ACL"
        ));
    }
    let system32 =
        PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length as usize])).join("System32");
    let identity = std::process::Command::new(system32.join("whoami.exe"))
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|error| {
            format!("could not resolve account for team policy cache {kind} ACL: {error}")
        })?;
    if !identity.status.success() {
        return Err(format!(
            "could not resolve account for team policy cache {kind} ACL"
        ));
    }
    let identity = String::from_utf8(identity.stdout)
        .map_err(|_| format!("account name for team policy cache {kind} ACL is not UTF-8"))?;
    let status = std::process::Command::new(system32.join("icacls.exe"))
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            &format!("{}:(F)", identity.trim()),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| format!("could not restrict team policy cache {kind} ACL: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("could not restrict team policy cache {kind} ACL"))
    }
}

#[cfg(not(windows))]
fn atomic_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::rename(from, to)?;
    let parent = to.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "team policy cache path has no parent",
        )
    })?;
    File::open(parent)?.sync_all()
}

#[cfg(windows)]
fn atomic_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pentect-team-policy-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn signed(sequence: u64, payload: &str, key: &SigningKey) -> SignedPolicyBundle {
        let mut bundle = SignedPolicyBundle {
            schema: SCHEMA.to_string(),
            issuer: "example-security".to_string(),
            sequence,
            issued_at: "2025-01-01T00:00:00Z".to_string(),
            expires_at: "2999-01-01T00:00:00Z".to_string(),
            payload_sha256: sha256_hex(payload.as_bytes()),
            payload: payload.to_string(),
            signature: String::new(),
        };
        bundle.signature =
            HEXLOWER.encode(&key.sign(&signing_message(&bundle).unwrap()).to_bytes());
        bundle
    }

    fn user_config(bundle: &Path, key: &SigningKey) -> toml::Value {
        format!(
            "[team_policy]\nbundle = {:?}\nissuer = \"example-security\"\npublic_key = \"{}\"\n",
            bundle.to_string_lossy(),
            HEXLOWER.encode(key.verifying_key().as_bytes())
        )
        .parse()
        .unwrap()
    }

    fn cache_path(root: &Path, bundle: &Path, key: &SigningKey) -> PathBuf {
        TeamPolicySettings::parse(&user_config(bundle, key), &root.join("config.toml"))
            .unwrap()
            .unwrap()
            .cache
    }

    #[test]
    fn cache_identity_changes_with_the_pinned_trust_root() {
        let root = root("trust-root-cache");
        let bundle = root.join("bundle.json");
        let first = SigningKey::from_bytes(&[1u8; 32]);
        let second = SigningKey::from_bytes(&[2u8; 32]);
        assert_ne!(
            cache_path(&root, &bundle, &first),
            cache_path(&root, &bundle, &second)
        );
    }

    #[test]
    fn signing_bytes_have_a_stable_canonical_digest() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let bundle = signed(4, "[agent]\nrequired = true\n", &key);
        assert_eq!(
            sha256_hex(&signing_message(&bundle).unwrap()),
            "b6755a5a7dc5a347e6a05014a8d782e6dfcb60387bc071b8adc06ebc9c8de0ec"
        );
    }

    #[test]
    fn verifies_and_caches_signed_policy_without_storing_keys() {
        let root = root("verify");
        fs::create_dir_all(&root).unwrap();
        let bundle_path = root.join("bundle.json");
        let user_path = root.join("config.toml");
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let bundle = signed(4, "[agent]\nrequired = true\n", &key);
        fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
        let value = load(None, Some(&user_config(&bundle_path, &key)), &user_path)
            .unwrap()
            .unwrap();
        assert_eq!(value["agent"]["required"].as_bool(), Some(true));
        let cache = fs::read_to_string(cache_path(&root, &bundle_path, &key)).unwrap();
        assert!(!cache.contains(&HEXLOWER.encode(key.as_bytes())));
        fs::remove_file(&bundle_path).unwrap();
        assert!(
            load(None, Some(&user_config(&bundle_path, &key)), &user_path)
                .unwrap()
                .is_some()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_bad_signature_expiration_and_sequence_rollback() {
        let root = root("reject");
        fs::create_dir_all(&root).unwrap();
        let bundle_path = root.join("bundle.json");
        let user_path = root.join("config.toml");
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let current = signed(5, "[files]\nremember = false\n", &key);
        fs::write(&bundle_path, serde_json::to_vec(&current).unwrap()).unwrap();
        let user = user_config(&bundle_path, &key);
        load(None, Some(&user), &user_path).unwrap();

        let old = signed(4, "[files]\nremember = true\n", &key);
        fs::write(&bundle_path, serde_json::to_vec(&old).unwrap()).unwrap();
        assert!(load(None, Some(&user), &user_path)
            .unwrap_err()
            .contains("rollback"));

        let mut invalid = signed(6, "[files]\nremember = true\n", &key);
        invalid.signature.replace_range(..2, "00");
        fs::write(&bundle_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(load(None, Some(&user), &user_path)
            .unwrap_err()
            .contains("signature"));

        let mut expired = signed(6, "[files]\nremember = true\n", &key);
        expired.expires_at = "2025-01-02T00:00:00Z".to_string();
        expired.signature =
            HEXLOWER.encode(&key.sign(&signing_message(&expired).unwrap()).to_bytes());
        fs::write(&bundle_path, serde_json::to_vec(&expired).unwrap()).unwrap();
        assert!(load(None, Some(&user), &user_path)
            .unwrap_err()
            .contains("expired"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_same_sequence_metadata_changes_and_expired_cache() {
        let root = root("metadata");
        fs::create_dir_all(&root).unwrap();
        let bundle_path = root.join("bundle.json");
        let user_path = root.join("config.toml");
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let current = signed(8, "[agent]\nrequired = true\n", &key);
        fs::write(&bundle_path, serde_json::to_vec(&current).unwrap()).unwrap();
        let user = user_config(&bundle_path, &key);
        load(None, Some(&user), &user_path).unwrap();

        let mut reused = signed(8, "[agent]\nrequired = true\n", &key);
        reused.expires_at = "2998-01-01T00:00:00Z".to_string();
        reused.signature =
            HEXLOWER.encode(&key.sign(&signing_message(&reused).unwrap()).to_bytes());
        fs::write(&bundle_path, serde_json::to_vec(&reused).unwrap()).unwrap();
        assert!(load(None, Some(&user), &user_path)
            .unwrap_err()
            .contains("reused"));

        let mut expired = signed(9, "[agent]\nrequired = true\n", &key);
        expired.expires_at = "2025-01-02T00:00:00Z".to_string();
        expired.signature =
            HEXLOWER.encode(&key.sign(&signing_message(&expired).unwrap()).to_bytes());
        fs::write(
            cache_path(&root, &bundle_path, &key),
            serde_json::to_vec(&expired).unwrap(),
        )
        .unwrap();
        fs::remove_file(&bundle_path).unwrap();
        assert!(load(None, Some(&user), &user_path)
            .unwrap_err()
            .contains("expired"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_unknown_policy_settings_even_when_signed() {
        let root = root("strict");
        fs::create_dir_all(&root).unwrap();
        let bundle_path = root.join("bundle.json");
        let user_path = root.join("config.toml");
        let key = SigningKey::from_bytes(&[13u8; 32]);
        let bundle = signed(1, "[agent]\nrequired = true\nmystery = true\n", &key);
        fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
        assert!(
            load(None, Some(&user_config(&bundle_path, &key)), &user_path)
                .unwrap_err()
                .contains("unsupported")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn invalid_new_policy_does_not_replace_last_known_good() {
        let root = root("semantic-lkg");
        fs::create_dir_all(&root).unwrap();
        let bundle_path = root.join("bundle.json");
        let user_path = root.join("config.toml");
        let key = SigningKey::from_bytes(&[17u8; 32]);
        let user = user_config(&bundle_path, &key);

        let good = signed(3, "[image]\nmax_pixels = 1000\n", &key);
        fs::write(&bundle_path, serde_json::to_vec(&good).unwrap()).unwrap();
        load(None, Some(&user), &user_path).unwrap();

        let invalid = signed(4, "[image]\nmax_pixels = \"many\"\n", &key);
        fs::write(&bundle_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(load(None, Some(&user), &user_path)
            .unwrap_err()
            .contains("image.max_pixels"));

        let cached: SignedPolicyBundle =
            serde_json::from_slice(&fs::read(cache_path(&root, &bundle_path, &key)).unwrap())
                .unwrap();
        assert_eq!(cached.sequence, 3);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_uses_a_dedicated_private_directory() {
        let root = root("cache-directory");
        fs::create_dir_all(&root).unwrap();
        let bundle_path = root.join("bundle.json");
        let key = SigningKey::from_bytes(&[19u8; 32]);
        let cache = cache_path(&root, &bundle_path, &key);
        assert_eq!(
            cache.parent().unwrap().file_name().unwrap(),
            CACHE_DIRECTORY
        );
        prepare_cache_directory(cache.parent().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(cache.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn process_writer_helper() {
        if std::env::var_os("PENTECT_TEST_POLICY_CHILD").is_none() {
            return;
        }
        let root = PathBuf::from(std::env::var_os("PENTECT_TEST_POLICY_ROOT").unwrap());
        let bundle = PathBuf::from(std::env::var_os("PENTECT_TEST_POLICY_BUNDLE").unwrap());
        let key = SigningKey::from_bytes(&[23u8; 32]);
        let result = load(
            None,
            Some(&user_config(&bundle, &key)),
            &root.join("config.toml"),
        );
        if std::env::var_os("PENTECT_TEST_POLICY_EXPECT_ROLLBACK").is_some() {
            assert!(result.unwrap_err().contains("rollback"));
        } else {
            result.unwrap();
        }
    }

    #[test]
    fn concurrent_process_cannot_overwrite_newer_sequence() {
        let root = root("process-lock");
        fs::create_dir_all(&root).unwrap();
        let initial_path = root.join("initial.json");
        let newer_path = root.join("newer.json");
        let older_path = root.join("older.json");
        let ready = root.join("newer-holds-lock");
        let key = SigningKey::from_bytes(&[23u8; 32]);
        fs::write(
            &initial_path,
            serde_json::to_vec(&signed(1, "[agent]\nrequired = true\n", &key)).unwrap(),
        )
        .unwrap();
        fs::write(
            &newer_path,
            serde_json::to_vec(&signed(3, "[agent]\nrequired = true\n", &key)).unwrap(),
        )
        .unwrap();
        fs::write(
            &older_path,
            serde_json::to_vec(&signed(2, "[agent]\nrequired = true\n", &key)).unwrap(),
        )
        .unwrap();
        load(
            None,
            Some(&user_config(&initial_path, &key)),
            &root.join("config.toml"),
        )
        .unwrap();

        let executable = std::env::current_exe().unwrap();
        let child = |bundle: &Path| {
            let mut command = std::process::Command::new(&executable);
            command
                .args([
                    "--exact",
                    "team_policy::tests::process_writer_helper",
                    "--nocapture",
                ])
                .env("PENTECT_TEST_POLICY_CHILD", "1")
                .env("PENTECT_TEST_POLICY_ROOT", &root)
                .env("PENTECT_TEST_POLICY_BUNDLE", bundle);
            command
        };

        let mut newer = child(&newer_path);
        newer
            .env("PENTECT_TEST_POLICY_CACHE_DELAY_MS", "750")
            .env("PENTECT_TEST_POLICY_CACHE_READY", &ready);
        let mut newer = newer.spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            ready.exists(),
            "newer writer did not acquire the cache lock"
        );

        let mut older = child(&older_path);
        older.env("PENTECT_TEST_POLICY_EXPECT_ROLLBACK", "1");
        let older_status = older.status().unwrap();
        let newer_status = newer.wait().unwrap();
        assert!(newer_status.success());
        assert!(older_status.success());

        let cached: SignedPolicyBundle =
            serde_json::from_slice(&fs::read(cache_path(&root, &newer_path, &key)).unwrap())
                .unwrap();
        assert_eq!(cached.sequence, 3);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn bundle_reader_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;
        let root = root("no-follow");
        fs::create_dir_all(&root).unwrap();
        let target = root.join("target.json");
        let link = root.join("bundle.json");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_optional_bundle(&link).is_err());
        let _ = fs::remove_dir_all(root);
    }
}
