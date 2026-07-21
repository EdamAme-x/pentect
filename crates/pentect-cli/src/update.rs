use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RELEASE_API: &str = "https://api.github.com/repos/EdamAme-x/pentect/releases/latest";
const USER_AGENT: &str = "pentect-updater";
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 4 * 1024;

pub(crate) struct DownloadedReleaseAsset {
    pub(crate) version: Version,
    pub(crate) bytes: Vec<u8>,
    pub(crate) sha256: String,
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

#[derive(Clone, Debug, Default)]
struct UpdateOptions {
    check: bool,
    force: bool,
    target: Option<Version>,
}

pub(crate) fn cmd_version() {
    println!("pentect {}", env!("CARGO_PKG_VERSION"));
}

pub(crate) fn cmd_update(args: &[String]) {
    let options = match parse_update_options(args) {
        Ok(options) => options,
        Err(error) => crate::die(error),
    };
    if let Err(error) = update(options) {
        crate::die(error);
    }
}

fn parse_update_options(args: &[String]) -> Result<UpdateOptions, String> {
    let mut options = UpdateOptions::default();
    for arg in &args[2..] {
        match arg.as_str() {
            "--check" => options.check = true,
            "--force" => options.force = true,
            flag if flag.starts_with('-') => return Err(format!("unknown update option: {flag}")),
            value => {
                if options.target.is_some() {
                    return Err("update accepts at most one version".to_string());
                }
                let value = value.strip_prefix('v').unwrap_or(value);
                options.target = Some(
                    Version::parse(value)
                        .map_err(|error| format!("invalid update version '{value}': {error}"))?,
                );
            }
        }
    }
    if options.check && options.force {
        return Err("update accepts either --check or --force".to_string());
    }
    Ok(options)
}

fn update(options: UpdateOptions) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| format!("could not create update client: {e}"))?;
    let release_api = options.target.as_ref().map_or_else(
        || RELEASE_API.to_string(),
        |version| {
            format!("https://api.github.com/repos/EdamAme-x/pentect/releases/tags/v{version}")
        },
    );
    let release: Release = get_response(&client, &release_api, MAX_CHECKSUM_BYTES * 16)?;
    if release.draft || release.prerelease {
        return Err("latest GitHub release is not a stable release".to_string());
    }
    let latest = release_version(&release.tag_name)?;
    if options
        .target
        .as_ref()
        .is_some_and(|target| target != &latest)
    {
        return Err(format!(
            "requested version does not match release tag {}",
            release.tag_name
        ));
    }
    let current = Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|e| format!("invalid installed version: {e}"))?;
    if !options.force && latest == current {
        println!("up to date: {current}");
        return Ok(());
    }
    if options.target.is_none() && !options.force && latest < current {
        println!("installed version {current} is newer than latest release {latest}");
        return Ok(());
    }
    println!("update available: {current} -> {latest}");
    if options.check {
        return Ok(());
    }

    let binary_name = release_asset_name()?;
    let checksum_name = format!("{binary_name}.sha256");
    let binary = find_asset(&release, &binary_name)?;
    let checksum = find_asset(&release, &checksum_name)?;
    if binary.size == 0 || binary.size > MAX_BINARY_BYTES {
        return Err(format!(
            "release binary has invalid size: {} bytes",
            binary.size
        ));
    }
    if checksum.size == 0 || checksum.size > MAX_CHECKSUM_BYTES {
        return Err(format!(
            "release checksum has invalid size: {} bytes",
            checksum.size
        ));
    }
    let expected = download_text(&client, checksum, MAX_CHECKSUM_BYTES)?;
    let expected = parse_sha256(&expected)?;
    let bytes = download_bytes(&client, binary, MAX_BINARY_BYTES)?;
    if bytes.len() as u64 != binary.size {
        return Err(format!(
            "release binary size mismatch: expected {}, received {}",
            binary.size,
            bytes.len()
        ));
    }
    let actual = sha256_hex(&bytes);
    if actual != expected {
        return Err(format!(
            "release checksum mismatch: expected {expected}, received {actual}"
        ));
    }
    install_update(&bytes, &latest, &expected)
}

pub(crate) fn download_latest_release_asset(
    repository: &str,
    asset_name: &str,
) -> Result<DownloadedReleaseAsset, String> {
    validate_repository(repository)?;
    if asset_name.is_empty()
        || asset_name.contains('/')
        || asset_name.contains('\\')
        || asset_name.len() > 200
    {
        return Err(format!("invalid release asset name: {asset_name}"));
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| format!("could not create release client: {e}"))?;
    let api = format!("https://api.github.com/repos/{repository}/releases/latest");
    let release: Release = get_response(&client, &api, MAX_CHECKSUM_BYTES * 16)?;
    if release.draft || release.prerelease {
        return Err("latest GitHub release is not a stable release".to_string());
    }
    let version = release_version(&release.tag_name)?;
    let binary = find_asset(&release, asset_name)?;
    let checksum = find_asset(&release, &format!("{asset_name}.sha256"))?;
    if binary.size == 0 || binary.size > MAX_BINARY_BYTES {
        return Err(format!(
            "release asset has invalid size: {} bytes",
            binary.size
        ));
    }
    let expected = parse_sha256(&download_text(&client, checksum, MAX_CHECKSUM_BYTES)?)?;
    let bytes = download_bytes(&client, binary, MAX_BINARY_BYTES)?;
    if bytes.len() as u64 != binary.size {
        return Err(format!(
            "release asset size mismatch: expected {}, received {}",
            binary.size,
            bytes.len()
        ));
    }
    let actual = sha256_hex(&bytes);
    if actual != expected {
        return Err(format!(
            "release checksum mismatch: expected {expected}, received {actual}"
        ));
    }
    Ok(DownloadedReleaseAsset {
        version,
        bytes,
        sha256: expected,
    })
}

pub(crate) fn validate_repository(repository: &str) -> Result<(), String> {
    let parts = repository.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || part.len() > 100
                || !part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        })
    {
        return Err(format!("invalid GitHub repository: {repository}"));
    }
    Ok(())
}

fn get_response<T: for<'de> Deserialize<'de>>(
    client: &reqwest::blocking::Client,
    url: &str,
    max_bytes: u64,
) -> Result<T, String> {
    let response = client
        .get(url)
        .send()
        .map_err(|e| format!("could not fetch GitHub release: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "could not fetch GitHub release: HTTP {}",
            response.status()
        ));
    }
    if response
        .content_length()
        .is_some_and(|size| size > max_bytes)
    {
        return Err("GitHub release response is too large".to_string());
    }
    let bytes = response
        .bytes()
        .map_err(|e| format!("could not read GitHub release: {e}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err("GitHub release response is too large".to_string());
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid GitHub release response: {e}"))
}

fn release_version(tag: &str) -> Result<Version, String> {
    let raw = tag.strip_prefix('v').unwrap_or(tag);
    Version::parse(raw).map_err(|e| format!("invalid GitHub release tag '{tag}': {e}"))
}

fn release_asset_name() -> Result<String, String> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    match (os, arch) {
        ("windows", "x86_64") => Ok("pentect-windows-x86_64.exe".to_string()),
        ("linux", "x86_64") => Ok("pentect-linux-x86_64".to_string()),
        ("macos", "x86_64") => Ok("pentect-macos-x86_64".to_string()),
        ("macos", "aarch64") => Ok("pentect-macos-aarch64".to_string()),
        _ => Err(format!("updates are not published for {os}/{arch}")),
    }
}

fn find_asset<'a>(release: &'a Release, name: &str) -> Result<&'a ReleaseAsset, String> {
    release
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .ok_or_else(|| format!("GitHub release is missing asset '{name}'"))
}

fn download_text(
    client: &reqwest::blocking::Client,
    asset: &ReleaseAsset,
    max_bytes: u64,
) -> Result<String, String> {
    let bytes = download_bytes(client, asset, max_bytes)?;
    String::from_utf8(bytes).map_err(|e| format!("release checksum is not UTF-8: {e}"))
}

fn download_bytes(
    client: &reqwest::blocking::Client,
    asset: &ReleaseAsset,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    let response = client
        .get(&asset.browser_download_url)
        .send()
        .map_err(|e| format!("could not download '{}': {e}", asset.name))?;
    if !response.status().is_success() {
        return Err(format!(
            "could not download '{}': HTTP {}",
            asset.name,
            response.status()
        ));
    }
    if response
        .content_length()
        .is_some_and(|size| size > max_bytes)
    {
        return Err(format!("release asset '{}' is too large", asset.name));
    }
    let bytes = response
        .bytes()
        .map_err(|e| format!("could not read '{}': {e}", asset.name))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("release asset '{}' is too large", asset.name));
    }
    Ok(bytes.to_vec())
}

fn parse_sha256(value: &str) -> Result<String, String> {
    let hash = value
        .split_whitespace()
        .next()
        .ok_or_else(|| "release checksum is empty".to_string())?
        .to_ascii_lowercase();
    if hash.len() != 64 || !hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("release checksum is not a SHA-256 digest".to_string());
    }
    Ok(hash)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    data_encoding::HEXLOWER.encode(&digest)
}

fn install_update(bytes: &[u8], latest: &Version, expected: &str) -> Result<(), String> {
    let current = std::env::current_exe()
        .map_err(|e| format!("could not locate the installed executable: {e}"))?;
    let parent = current
        .parent()
        .ok_or_else(|| "installed executable has no parent directory".to_string())?;
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let staged = parent.join(format!(
        "pentect.update-{}-{latest}{suffix}",
        std::process::id()
    ));
    std::fs::write(&staged, bytes)
        .map_err(|e| format!("could not stage update '{}': {e}", staged.display()))?;
    if sha256_file(&staged)? != expected {
        let _ = std::fs::remove_file(&staged);
        return Err("staged update checksum mismatch".to_string());
    }
    copy_executable_permissions(&current, &staged)?;
    let backup = backup_path(&current)?;
    std::fs::copy(&current, &backup)
        .map_err(|e| format!("could not back up '{}': {e}", current.display()))?;

    #[cfg(windows)]
    {
        spawn_windows_update_helper(&staged, &current, &backup, expected)?;
        println!("update staged: {latest}");
        println!("the executable will be replaced when this process exits");
        Ok(())
    }
    #[cfg(not(windows))]
    {
        if let Err(error) = std::fs::rename(&current, &backup) {
            let _ = std::fs::remove_file(&staged);
            return Err(format!("could not move current executable: {error}"));
        }
        if let Err(error) = std::fs::rename(&staged, &current) {
            let _ = std::fs::rename(&backup, &current);
            return Err(format!("could not install update: {error}"));
        }
        println!("updated to {latest}");
        Ok(())
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("could not verify '{}': {e}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn backup_path(current: &Path) -> Result<PathBuf, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock error: {e}"))?
        .as_secs();
    let name = current
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "installed executable name is not UTF-8".to_string())?;
    Ok(current.with_file_name(format!("{name}.previous-{timestamp}")))
}

#[cfg(unix)]
fn copy_executable_permissions(current: &Path, staged: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(current)
        .map(|metadata| metadata.permissions().mode())
        .unwrap_or(0o755);
    std::fs::set_permissions(staged, std::fs::Permissions::from_mode(mode | 0o111))
        .map_err(|e| format!("could not mark update executable: {e}"))
}

#[cfg(windows)]
fn copy_executable_permissions(_current: &Path, _staged: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn spawn_windows_update_helper(
    staged: &Path,
    destination: &Path,
    backup: &Path,
    expected: &str,
) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new(staged)
        .arg("__apply-update")
        .arg(std::process::id().to_string())
        .arg(destination)
        .arg(backup)
        .arg(expected)
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not start update helper: {e}"))
}

pub(crate) fn cmd_apply_update(args: &[String]) -> i32 {
    match apply_update(args) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn apply_update(args: &[String]) -> Result<(), String> {
    let [_, command, parent_pid, destination, backup, expected] = args else {
        return Err("invalid update helper arguments".to_string());
    };
    if command != "__apply-update" {
        return Err("invalid update helper command".to_string());
    }
    let _: u32 = parent_pid
        .parse()
        .map_err(|_| "invalid update helper parent".to_string())?;
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    if sha256_file(&source)? != expected.to_ascii_lowercase() {
        return Err("update helper checksum mismatch".to_string());
    }
    let destination = Path::new(destination);
    let backup = Path::new(backup);
    for _ in 0..600 {
        match std::fs::copy(&source, destination) {
            Ok(_) if sha256_file(destination)? == expected.to_ascii_lowercase() => return Ok(()),
            Ok(_) => {
                let _ = std::fs::copy(backup, destination);
                return Err("installed update checksum mismatch".to_string());
            }
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
    Err("timed out waiting to replace the executable".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_update_flags() {
        let args = vec!["pentect".into(), "update".into(), "--check".into()];
        assert!(parse_update_options(&args).unwrap().check);
        let args = vec!["pentect".into(), "update".into(), "v1.2.3".into()];
        assert_eq!(
            parse_update_options(&args).unwrap().target,
            Some(Version::new(1, 2, 3))
        );
        let args = vec![
            "pentect".into(),
            "update".into(),
            "--check".into(),
            "--force".into(),
        ];
        assert!(parse_update_options(&args).is_err());
    }

    #[test]
    fn parses_release_versions_and_checksums() {
        assert_eq!(release_version("v1.2.3").unwrap(), Version::new(1, 2, 3));
        assert!(release_version("latest").is_err());
        let hash = "a".repeat(64);
        assert_eq!(
            parse_sha256(&format!("{hash}  pentect.exe\n")).unwrap(),
            hash
        );
        assert!(parse_sha256("abc").is_err());
    }

    #[test]
    fn selects_a_platform_asset() {
        let name = release_asset_name().unwrap();
        assert!(name.starts_with("pentect-"));
        assert!(!name.ends_with(".zip"));
    }

    #[test]
    fn validates_release_coordinates() {
        assert!(validate_repository("EdamAme-x/pentect").is_ok());
        assert!(validate_repository("owner/repo/extra").is_err());
        assert!(validate_repository("owner/../repo").is_err());
    }
}
