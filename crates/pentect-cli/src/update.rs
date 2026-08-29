use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RELEASE_API: &str = "https://api.github.com/repos/EdamAme-x/pentect/releases/latest";
const USER_AGENT: &str = "pentect-updater";
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 4 * 1024;
const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const UPDATE_CHECK_TIMEOUT: Duration = Duration::from_secs(3);
const UPDATE_CHECK_CACHE: &str = "update-check.json";
const MAX_UPDATE_CACHE_BYTES: u64 = 4 * 1024;

#[derive(Debug, Deserialize)]
struct UpdateCheckRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct UpdateCheckCache {
    checked_at: u64,
    latest: String,
}

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

pub(crate) fn start_update_notification(args: &[String]) {
    if !should_check_on_startup(args) || !pentect_agent::update_check_enabled().unwrap_or(true) {
        return;
    }
    let Ok(cache_path) = update_check_cache_path() else {
        return;
    };
    let now = unix_seconds();
    if let Some(cache) = read_update_check_cache(&cache_path) {
        if now.saturating_sub(cache.checked_at) < UPDATE_CHECK_INTERVAL.as_secs() {
            print_update_notice(&cache.latest);
            return;
        }
    }
    std::thread::spawn(move || {
        if refresh_update_check(&cache_path, now).is_err() {
            pentect_agent::record_diagnostic_activity("update-check", "request-failed");
            pentect_agent::flush_activity_log();
        }
    });
}

fn should_check_on_startup(args: &[String]) -> bool {
    !matches!(
        args.get(1).map(String::as_str),
        None | Some("help" | "--help" | "-h" | "version" | "--version" | "-V" | "update")
            | Some(
                "__apply-update"
                    | "memory-store"
                    | "hook"
                    | "bridge"
                    | "__agent-script"
                    | "__agent-stream"
            )
    )
}

fn refresh_update_check(path: &Path, now: u64) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(UPDATE_CHECK_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .map_err(|error| format!("could not create update-check client: {error}"))?;
    let release: UpdateCheckRelease = get_response(&client, RELEASE_API, MAX_CHECKSUM_BYTES * 4)?;
    if release.draft || release.prerelease {
        return Ok(());
    }
    let latest = release_version(&release.tag_name)?.to_string();
    write_update_check_cache(
        path,
        &UpdateCheckCache {
            checked_at: now,
            latest: latest.clone(),
        },
    )?;
    print_update_notice(&latest);
    Ok(())
}

fn print_update_notice(latest: &str) {
    let Ok(current) = Version::parse(env!("CARGO_PKG_VERSION")) else {
        return;
    };
    let Ok(latest) = Version::parse(latest) else {
        return;
    };
    if latest > current {
        eprintln!("[pentect] update available: {current} -> {latest}; run `pentect update`");
    }
}

fn update_check_cache_path() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = home_dir().map(|home| home.join("Library").join("Application Support"));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".local").join("state")));
    base.map(|base| base.join("pentect").join(UPDATE_CHECK_CACHE))
        .ok_or_else(|| "could not find a local state directory for update checks".to_string())
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}

fn read_update_check_cache(path: &Path) -> Option<UpdateCheckCache> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_UPDATE_CACHE_BYTES {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn write_update_check_cache(path: &Path, cache: &UpdateCheckCache) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "update-check cache path has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("could not create update-check cache directory: {error}"))?;
    let bytes = serde_json::to_vec(cache)
        .map_err(|error| format!("could not encode update-check cache: {error}"))?;
    let temporary = update_cache_staging_path(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("could not create update-check cache: {error}"))?;
    let cleanup = RemoveFileOnDrop(temporary.clone());
    use std::io::Write;
    file.write_all(&bytes)
        .and_then(|_| file.sync_data())
        .map_err(|error| format!("could not write update-check cache: {error}"))?;
    drop(file);
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(&temporary, path)
        .map_err(|error| format!("could not publish update-check cache: {error}"))?;
    drop(cleanup);
    Ok(())
}

fn update_cache_staging_path(path: &Path) -> Result<PathBuf, String> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| format!("OS CSPRNG unavailable for update-check cache: {error}"))?;
    Ok(path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        data_encoding::HEXLOWER.encode(&nonce)
    )))
}

struct RemoveFileOnDrop(PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
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
    let installation = crate::installation::current_installation()?;
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
    let allow_prerelease =
        std::env::var("PENTECT_UPDATE_ALLOW_PRERELEASE").is_ok_and(|value| value == "1");
    if release.draft || (release.prerelease && !allow_prerelease) {
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

    if let Some(installation) = installation
        .as_ref()
        .filter(|value| !value.is_self_managed())
    {
        if installation.manager == "npm" {
            return install_npm_update(&latest);
        }
        return Err(installation.update_message());
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

fn install_npm_update(version: &Version) -> Result<(), String> {
    let installation = crate::installation::npm_installation()?;
    let mut command = npm_update_command(&installation, version);
    let status = command
        .status()
        .map_err(|error| format!("could not start npm update: {error}"))?;
    if !status.success() {
        return Err(format!("npm update failed with {status}"));
    }
    verify_npm_package_version(&installation.package_root, version)?;
    println!("updated: {version}");
    Ok(())
}

fn npm_update_command(
    installation: &crate::installation::NpmInstallation,
    version: &Version,
) -> Command {
    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };
    let package = format!("pentect@{version}");
    let mut command = Command::new(npm);
    command.arg("install");
    match &installation.scope {
        crate::installation::NpmScope::Global => {
            command.arg("--global");
        }
        crate::installation::NpmScope::Local(project) => {
            command.current_dir(project);
        }
    }
    command.arg(&package);
    command
}

fn verify_npm_package_version(package_root: &Path, version: &Version) -> Result<(), String> {
    let metadata = std::fs::read(package_root.join("package.json")).map_err(|error| {
        format!("npm updated Pentect but its package metadata is unreadable: {error}")
    })?;
    let metadata: serde_json::Value = serde_json::from_slice(&metadata).map_err(|error| {
        format!("npm updated Pentect but its package metadata is invalid: {error}")
    })?;
    let installed = metadata.get("version").and_then(serde_json::Value::as_str);
    let expected = version.to_string();
    if installed != Some(expected.as_str()) {
        return Err(format!(
            "npm completed but installed version {} does not match {version}",
            installed.unwrap_or("unknown")
        ));
    }
    Ok(())
}

pub(crate) fn download_latest_release_asset(
    repository: &str,
    asset_name: &str,
    max_asset_bytes: u64,
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
    let api = latest_release_api(repository);
    let release: Release = get_response(&client, &api, MAX_CHECKSUM_BYTES * 16)?;
    if release.draft || release.prerelease {
        return Err("latest GitHub release is not a stable release".to_string());
    }
    let version = release_version(&release.tag_name)?;
    let binary = find_asset(&release, asset_name)?;
    let checksum = find_asset(&release, &format!("{asset_name}.sha256"))?;
    if max_asset_bytes == 0 || max_asset_bytes > MAX_BINARY_BYTES {
        return Err("release asset limit is invalid".to_string());
    }
    if binary.size == 0 || binary.size > max_asset_bytes {
        return Err(format!(
            "release asset has invalid size: {} bytes",
            binary.size
        ));
    }
    let expected = parse_sha256(&download_text(&client, checksum, MAX_CHECKSUM_BYTES)?)?;
    let bytes = download_bytes(&client, binary, max_asset_bytes)?;
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

fn latest_release_api(repository: &str) -> String {
    format!("https://api.github.com/repos/{repository}/releases/latest")
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
    let mut request = client.get(url);
    if let Some(token) = github_token() {
        request = request.bearer_auth(token);
    }
    let response = request
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
    let mut bytes = Vec::new();
    response
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read GitHub release: {e}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err("GitHub release response is too large".to_string());
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid GitHub release response: {e}"))
}

fn github_token() -> Option<String> {
    github_token_from(|name| std::env::var(name).ok())
}

fn github_token_from(mut read: impl FnMut(&str) -> Option<String>) -> Option<String> {
    ["GH_TOKEN", "GITHUB_TOKEN"].into_iter().find_map(|name| {
        read(name).and_then(|value| {
            let value = value.trim();
            (!value.is_empty()).then(|| value.to_string())
        })
    })
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
        ("linux", "aarch64") => Ok("pentect-linux-aarch64".to_string()),
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
    let mut bytes =
        Vec::with_capacity(usize::try_from(asset.size.min(max_bytes)).unwrap_or_default());
    response
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read '{}': {e}", asset.name))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("release asset '{}' is too large", asset.name));
    }
    Ok(bytes)
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
    pentect_agent::sha256_file(path, "release asset")
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
            Ok(_) if sha256_file(destination)? == expected.to_ascii_lowercase() => {
                #[cfg(windows)]
                let _ = spawn_windows_staged_cleanup(&source);
                return Ok(());
            }
            Ok(_) => {
                let _ = std::fs::copy(backup, destination);
                return Err("installed update checksum mismatch".to_string());
            }
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
    Err("timed out waiting to replace the executable".to_string())
}

#[cfg(windows)]
fn spawn_windows_staged_cleanup(staged: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const SCRIPT: &str = r#"param(
    [Parameter(Mandatory=$true)][int]$ParentPid,
    [Parameter(Mandatory=$true)][string]$Target
)
$ErrorActionPreference = 'SilentlyContinue'
for ($attempt = 0; $attempt -lt 600; $attempt++) {
    if (-not (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 100
}
for ($attempt = 0; $attempt -lt 600; $attempt++) {
    Remove-Item -LiteralPath $Target -Force
    if (-not (Test-Path -LiteralPath $Target)) { break }
    Start-Sleep -Milliseconds 100
}
Remove-Item -LiteralPath $PSCommandPath -Force
"#;

    let helper = std::env::temp_dir().join(format!(
        "pentect-update-cleanup-{}-{}.ps1",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    ));
    std::fs::write(&helper, SCRIPT)
        .map_err(|error| format!("could not create update cleanup helper: {error}"))?;
    Command::new(crate::windows_system_executable(
        r"WindowsPowerShell\v1.0\powershell.exe",
    ))
    .args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-File",
    ])
    .arg(&helper)
    .arg("-ParentPid")
    .arg(std::process::id().to_string())
    .arg("-Target")
    .arg(staged)
    .creation_flags(CREATE_NO_WINDOW)
    .spawn()
    .map(|_| ())
    .map_err(|error| format!("could not start update cleanup helper: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installation::{NpmInstallation, NpmScope};

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

    #[test]
    fn plugin_release_assets_use_the_plugin_latest_stable_release() {
        let api = latest_release_api("third-party/example-plugin");
        assert_eq!(
            api,
            "https://api.github.com/repos/third-party/example-plugin/releases/latest"
        );
        assert!(!api.contains(env!("CARGO_PKG_VERSION")));
        assert!(!api.contains("/releases/tags/"));
    }

    #[test]
    fn selects_a_non_empty_github_token_without_exposing_it() {
        let token = github_token_from(|name| match name {
            "GH_TOKEN" => Some("  ".to_string()),
            "GITHUB_TOKEN" => Some(" test-token ".to_string()),
            _ => None,
        });
        assert_eq!(token.as_deref(), Some("test-token"));

        let token = github_token_from(|name| match name {
            "GH_TOKEN" => Some("preferred".to_string()),
            "GITHUB_TOKEN" => Some("fallback".to_string()),
            _ => None,
        });
        assert_eq!(token.as_deref(), Some("preferred"));
    }

    #[test]
    fn builds_global_and_local_npm_updates_without_a_shell() {
        let version = Version::new(1, 2, 3);
        let global = NpmInstallation {
            package_root: PathBuf::from("/npm/pentect"),
            scope: NpmScope::Global,
        };
        let command = npm_update_command(&global, &version);
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["install", "--global", "pentect@1.2.3"]
        );
        assert!(command.get_current_dir().is_none());

        let local = NpmInstallation {
            package_root: PathBuf::from("/project/node_modules/pentect"),
            scope: NpmScope::Local(PathBuf::from("/project")),
        };
        let command = npm_update_command(&local, &version);
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["install", "pentect@1.2.3"]
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/project")));
    }

    #[test]
    fn startup_checks_skip_management_and_internal_commands() {
        assert!(should_check_on_startup(&["pentect".into(), "codex".into()]));
        for command in [
            "help",
            "version",
            "update",
            "memory-store",
            "__apply-update",
        ] {
            assert!(!should_check_on_startup(&[
                "pentect".into(),
                command.into()
            ]));
        }
    }

    #[test]
    fn update_check_cache_is_bounded_and_round_trips() {
        let directory = std::env::temp_dir().join(format!(
            "pentect-update-cache-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join(UPDATE_CHECK_CACHE);
        let stale = path.with_extension(format!("tmp-{}", std::process::id()));
        std::fs::write(&stale, b"stale crashed process").unwrap();
        let cache = UpdateCheckCache {
            checked_at: 123,
            latest: "1.2.3".to_string(),
        };
        write_update_check_cache(&path, &cache).unwrap();
        assert!(
            stale.is_file(),
            "must not delete another process's staging file"
        );
        let random_staging_prefix = path
            .with_extension(format!("tmp-{}-", std::process::id()))
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let random_staging_files = std::fs::read_dir(&directory)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(&random_staging_prefix))
            .collect::<Vec<_>>();
        assert!(random_staging_files.is_empty(), "{random_staging_files:?}");
        let loaded = read_update_check_cache(&path).unwrap();
        assert_eq!(loaded.checked_at, 123);
        assert_eq!(loaded.latest, "1.2.3");

        std::fs::write(&path, vec![b'x'; MAX_UPDATE_CACHE_BYTES as usize + 1]).unwrap();
        assert!(read_update_check_cache(&path).is_none());
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
