//! Launcher for the unmodified Codex desktop application.
//!
//! The app and its bundled Codex process use a loopback-only Responses API
//! gateway. Pentect temporarily overrides the selected provider in the user's
//! Codex configuration, restores the exact original when the App exits, and
//! refuses to launch while another Codex App process is running.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::{fs::OpenOptions, io::Write};

pub(crate) fn cmd_codex_app(args: &[String]) -> i32 {
    match run_codex_app(args) {
        Ok(status) => status.code().unwrap_or(0),
        Err(error) => {
            eprintln!("[pentect] {error}");
            2
        }
    }
}

fn run_codex_app(args: &[String]) -> Result<std::process::ExitStatus, String> {
    let options = CodexAppOptions::parse(args)?;
    let app = options.app.unwrap_or_else(default_codex_app_path);
    if options.check {
        let installed = app.is_file();
        println!("App: {}", app.display());
        println!("Installed: {}", if installed { "yes" } else { "no" });
        println!(
            "Running: {}",
            if codex_app_is_running(&app) {
                "yes"
            } else {
                "no"
            }
        );
        let routing = crate::codex_app_routing(options.upstream)?;
        println!("Provider: {}", routing.provider);
        println!("Protection: OpenAI Responses API (HTTP)");
        if !installed {
            return Err("Codex mode was not found; pass --app PATH".to_string());
        }
        return Ok(success_status());
    }
    if !app.is_file() {
        return Err(format!(
            "Codex App was not found at '{}'; pass --app PATH",
            app.display()
        ));
    }
    if codex_app_is_running(&app) {
        return Err(
            "Codex App is already running; quit it before `pentect codex app` so its bundled Codex process inherits the HTTP gateway"
                .to_string(),
        );
    }

    let routing = crate::codex_app_routing(options.upstream)?;
    let proxy = crate::openai_http_proxy::OpenAiHttpProxyGuard::start(routing.upstream)?;
    let config_lock = CodexConfigLock::acquire()?;
    let config_override = Some(CodexConfigOverride::install(
        &routing.provider,
        proxy.base_url(),
    )?);
    eprintln!("[pentect] Codex App gateway ready at {}", proxy.base_url());
    if config_override.is_some() {
        eprintln!(
            "[pentect] Codex provider '{}' is routed through the gateway for this App session",
            routing.provider
        );
    }
    eprintln!("[pentect] Responses API prompts, files, and completed tool calls are protected");

    let mut command = Command::new(&app);
    command
        .env("OPENAI_BASE_URL", proxy.base_url())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_child_process(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start Codex App: {error}"))?;
    let config_cleanup = Arc::new(Mutex::new(config_override));
    let signal_cleanup = Arc::clone(&config_cleanup);
    let child_id = child.id();
    if let Err(error) = ctrlc::set_handler(move || {
        terminate_child_process(child_id);
        if let Ok(mut cleanup) = signal_cleanup.lock() {
            cleanup.take();
        }
        std::process::exit(130);
    }) {
        terminate_child_process(child_id);
        let _ = child.wait();
        if let Ok(mut cleanup) = config_cleanup.lock() {
            cleanup.take();
        }
        return Err(format!(
            "could not install Codex App config recovery handler: {error}"
        ));
    }
    let status = child
        .wait()
        .map_err(|error| format!("could not wait for Codex App: {error}"))?;
    config_cleanup
        .lock()
        .map_err(|_| "Codex App config recovery lock is unavailable".to_string())?
        .take();
    drop(config_lock);
    drop(proxy);
    Ok(status)
}

#[cfg(windows)]
fn terminate_child_process(pid: u32) {
    let _ = Command::new("taskkill.exe")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(unix)]
fn terminate_child_process(pid: u32) {
    unsafe {
        libc::kill(-(pid as i32), libc::SIGTERM);
    }
}

#[cfg(windows)]
fn configure_child_process(_command: &mut Command) {}

#[cfg(unix)]
fn configure_child_process(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

struct CodexConfigOverride {
    config: PathBuf,
    backup: PathBuf,
    no_original_marker: PathBuf,
}

struct CodexConfigLock {
    path: PathBuf,
}

impl CodexConfigLock {
    fn acquire() -> Result<Self, String> {
        Self::acquire_in(&crate::codex_home_dir()?)
    }

    fn acquire_in(home: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(home)
            .map_err(|error| format!("could not create '{}': {error}", home.display()))?;
        let path = home.join("pentect-codex-app.lock");
        reject_symlink(&path, "Codex App lock")?;
        for attempt in 0..2 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    writeln!(file, "{}", std::process::id()).map_err(|error| {
                        format!("could not initialize '{}': {error}", path.display())
                    })?;
                    file.sync_all().map_err(|error| {
                        format!("could not persist '{}': {error}", path.display())
                    })?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
                    if lock_owner_is_running(&path) {
                        return Err(
                            "another `pentect codex app` session is already active".to_string()
                        );
                    }
                    std::fs::remove_file(&path).map_err(|remove_error| {
                        format!(
                            "could not clear stale Codex App lock '{}': {remove_error}",
                            path.display()
                        )
                    })?;
                }
                Err(error) => {
                    return Err(format!(
                        "could not lock Codex App configuration '{}': {error}",
                        path.display()
                    ));
                }
            }
        }
        Err("could not acquire Codex App configuration lock".to_string())
    }
}

impl Drop for CodexConfigLock {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "[pentect] could not remove Codex App lock '{}': {error}",
                    self.path.display()
                );
            }
        }
    }
}

fn lock_owner_is_running(path: &Path) -> bool {
    let Ok(value) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(pid) = value.trim().parse::<sysinfo::Pid>() else {
        return false;
    };
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).is_some_and(|process| {
        process
            .name()
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with("pentect")
    })
}

impl CodexConfigOverride {
    fn install(provider: &str, gateway: &str) -> Result<Self, String> {
        let home = crate::codex_home_dir()?;
        Self::install_in(&home, provider, gateway)
    }

    fn install_in(home: &Path, provider: &str, gateway: &str) -> Result<Self, String> {
        std::fs::create_dir_all(home)
            .map_err(|error| format!("could not create '{}': {error}", home.display()))?;
        let config = home.join("config.toml");
        let backup = home.join("config.toml.pentect-backup");
        let no_original_marker = home.join("config.toml.pentect-no-original");
        reject_symlink(&config, "Codex config")?;
        reject_symlink(&backup, "Codex recovery backup")?;
        reject_symlink(&no_original_marker, "Codex recovery marker")?;
        if backup.is_file() {
            if config.is_file() {
                std::fs::remove_file(&config).map_err(|error| {
                    format!(
                        "could not recover Codex config '{}': {error}",
                        config.display()
                    )
                })?;
            }
            if no_original_marker.is_file() {
                std::fs::remove_file(&backup).map_err(|error| {
                    format!("could not clear interrupted Codex backup: {error}")
                })?;
                let _ = std::fs::remove_file(&no_original_marker);
            } else {
                std::fs::rename(&backup, &config).map_err(|error| {
                    format!(
                        "could not restore interrupted Codex config override '{}': {error}",
                        backup.display()
                    )
                })?;
            }
            eprintln!("[pentect] restored Codex config left by an interrupted App session");
        }

        let had_original = config.is_file();
        let original = if had_original {
            std::fs::read_to_string(&config)
                .map_err(|error| format!("could not read '{}': {error}", config.display()))?
        } else {
            String::new()
        };
        let mut parsed = if original.trim().is_empty() {
            toml_edit::DocumentMut::new()
        } else {
            original
                .parse::<toml_edit::DocumentMut>()
                .map_err(|error| format!("could not parse '{}': {error}", config.display()))?
        };
        set_provider_gateway(&mut parsed, provider, gateway)?;

        write_new_private_file(&backup, original.as_bytes())
            .map_err(|error| format!("could not back up '{}': {error}", config.display()))?;
        if !had_original {
            write_new_private_file(&no_original_marker, b"")
                .map_err(|error| format!("could not create Codex recovery marker: {error}"))?;
        }
        let temporary = home.join(format!("config.toml.pentect-{}.tmp", std::process::id()));
        reject_symlink(&temporary, "Codex temporary config")?;
        write_new_private_file(&temporary, parsed.to_string().as_bytes())
            .map_err(|error| format!("could not write '{}': {error}", temporary.display()))?;
        if config.is_file() {
            std::fs::remove_file(&config)
                .map_err(|error| format!("could not replace '{}': {error}", config.display()))?;
        }
        if let Err(error) = std::fs::rename(&temporary, &config) {
            if had_original {
                let _ = std::fs::rename(&backup, &config);
            } else {
                let _ = std::fs::remove_file(&backup);
                let _ = std::fs::remove_file(&no_original_marker);
            }
            return Err(format!(
                "could not activate Codex config override '{}': {error}",
                config.display()
            ));
        }
        Ok(Self {
            config,
            backup,
            no_original_marker,
        })
    }

    fn restore(&self) -> Result<(), String> {
        reject_symlink(&self.config, "Codex config")?;
        reject_symlink(&self.backup, "Codex recovery backup")?;
        reject_symlink(&self.no_original_marker, "Codex recovery marker")?;
        if !self.backup.is_file() {
            return Ok(());
        }
        if self.config.is_file() {
            std::fs::remove_file(&self.config).map_err(|error| {
                format!(
                    "could not remove temporary Codex config '{}': {error}",
                    self.config.display()
                )
            })?;
        }
        if self.no_original_marker.is_file() {
            std::fs::remove_file(&self.backup)
                .map_err(|error| format!("could not remove Codex backup: {error}"))?;
            std::fs::remove_file(&self.no_original_marker)
                .map_err(|error| format!("could not remove Codex recovery marker: {error}"))
        } else {
            std::fs::rename(&self.backup, &self.config).map_err(|error| {
                format!(
                    "could not restore Codex config '{}': {error}",
                    self.config.display()
                )
            })
        }
    }
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "{label} '{}' is a symbolic link; Pentect will not replace it",
            path.display()
        )),
        Ok(_) | Err(_) => Ok(()),
    }
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

impl Drop for CodexConfigOverride {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("[pentect] {error}");
        }
    }
}

fn set_provider_gateway(
    config: &mut toml_edit::DocumentMut,
    provider: &str,
    gateway: &str,
) -> Result<(), String> {
    if provider == "openai" {
        config["model_provider"] = toml_edit::value(crate::CODEX_GATEWAY_PROVIDER);
        let providers = config
            .entry("model_providers")
            .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()))
            .as_table_mut()
            .ok_or_else(|| "model_providers is not a TOML table".to_string())?;
        let mut gateway_provider = toml_edit::Table::new();
        gateway_provider.insert("name", toml_edit::value("OpenAI through Pentect"));
        gateway_provider.insert("base_url", toml_edit::value(gateway));
        gateway_provider.insert("wire_api", toml_edit::value("responses"));
        gateway_provider.insert("requires_openai_auth", toml_edit::value(true));
        gateway_provider.insert("supports_websockets", toml_edit::value(false));
        providers.insert(
            crate::CODEX_GATEWAY_PROVIDER,
            toml_edit::Item::Table(gateway_provider),
        );
        return Ok(());
    }
    let providers = config
        .entry("model_providers")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .ok_or_else(|| "model_providers is not a TOML table".to_string())?;
    let provider = providers
        .entry(provider)
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .ok_or_else(|| "selected model provider is not a TOML table".to_string())?;
    provider.insert("base_url", toml_edit::value(gateway));
    provider.insert("supports_websockets", toml_edit::value(false));
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct CodexAppOptions {
    app: Option<PathBuf>,
    upstream: Option<String>,
    check: bool,
}

impl CodexAppOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut app = None;
        let mut upstream = None;
        let mut check = false;
        let mut index = if args.get(1).is_some_and(|arg| arg == "codex")
            && args.get(2).is_some_and(|arg| arg == "app")
        {
            3
        } else {
            2
        };
        while index < args.len() {
            match args[index].as_str() {
                "--app" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--app requires a value".to_string())?;
                    app = Some(PathBuf::from(value));
                    index += 2;
                }
                "--upstream" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--upstream requires a value".to_string())?;
                    upstream = Some(value.clone());
                    index += 2;
                }
                "--check" | "--dry-run" => {
                    check = true;
                    index += 1;
                }
                "--plugins" => {
                    if args
                        .get(index + 1)
                        .is_none_or(|value| value.starts_with("--"))
                    {
                        return Err("--plugins requires a value".to_string());
                    }
                    index += 2;
                }
                value => return Err(format!("unknown codex-app option: {value}")),
            }
        }
        Ok(Self {
            app,
            upstream,
            check,
        })
    }
}

fn default_codex_app_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(path) = find_windows_codex_app() {
            return path;
        }
    }
    #[cfg(target_os = "macos")]
    {
        for candidate in [
            "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
            "/Applications/Codex.app/Contents/MacOS/Codex",
        ] {
            let candidate = PathBuf::from(candidate);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for candidate in [
            "/usr/bin/codex-app",
            "/usr/local/bin/codex-app",
            "/opt/Codex/codex",
        ] {
            let candidate = PathBuf::from(candidate);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from(if cfg!(windows) {
        "Codex.exe"
    } else {
        "codex-app"
    })
}

#[cfg(windows)]
fn find_windows_codex_app() -> Option<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").map(PathBuf::from)?;
    let roots = [
        local_app_data
            .join("Programs")
            .join("OpenAI Codex Standalone"),
        local_app_data.join("Programs").join("OpenAI ChatGPT"),
        local_app_data.join("Programs").join("ChatGPT"),
    ];
    let mut candidates = roots
        .into_iter()
        .filter_map(|root| std::fs::read_dir(root).ok())
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            // Codex.exe is an updater/launcher stub in current standalone
            // builds. ChatGPT.exe is the long-lived Codex browser process
            // whose environment must retain the gateway for the whole app
            // session.
            let executable = ["ChatGPT.exe", "Codex.exe"]
                .into_iter()
                .map(|name| entry.path().join(name))
                .find(|path| path.is_file())?;
            Some((
                version_components(&entry.file_name().to_string_lossy()),
                executable,
            ))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    if let Some((_, executable)) = candidates.pop() {
        return Some(executable);
    }
    find_windows_store_chatgpt()
}

#[cfg(windows)]
fn find_windows_store_chatgpt() -> Option<PathBuf> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const PACKAGES_KEY: &str = r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

    let output = Command::new("reg.exe")
        .args(["query", PACKAGES_KEY])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let keys = String::from_utf8_lossy(&output.stdout);
    let mut candidates = keys
        .lines()
        .map(str::trim)
        .filter(|key| {
            key.rsplit('\\').next().is_some_and(|name| {
                let name = name.to_ascii_lowercase();
                (name.starts_with("chatgpt_") || name.starts_with("openai.chatgpt"))
                    && windows_package_matches_arch(&name)
            })
        })
        .filter_map(|key| {
            let package_name = key.rsplit('\\').next()?.to_string();
            let output = Command::new("reg.exe")
                .args(["query", key, "/v", "PackageRootFolder"])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let root = String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(|line| line.split_once("REG_SZ").map(|(_, value)| value.trim()))?
                .to_string();
            ["ChatGPT.exe", "app\\ChatGPT.exe", "Codex.exe"]
                .into_iter()
                .map(|relative| PathBuf::from(&root).join(relative))
                .find(|path| path.is_file())
                .map(|path| (windows_package_version(&package_name), path))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    candidates.pop().map(|(_, executable)| executable)
}

#[cfg(windows)]
fn windows_package_matches_arch(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if cfg!(target_arch = "aarch64") {
        name.contains("_arm64__")
    } else {
        name.contains("_x64__")
    }
}

#[cfg(windows)]
fn windows_package_version(name: &str) -> Vec<u64> {
    name.split('_')
        .find(|part| {
            part.chars()
                .next()
                .is_some_and(|character| character.is_ascii_digit())
        })
        .unwrap_or_default()
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

#[cfg(windows)]
fn version_components(value: &str) -> Vec<u64> {
    value
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

fn codex_app_is_running(app: &Path) -> bool {
    let expected = app
        .canonicalize()
        .unwrap_or_else(|_| app.to_path_buf())
        .to_string_lossy()
        .to_ascii_lowercase();
    let install_root = app
        .parent()
        .map(|path| {
            path.canonicalize()
                .unwrap_or_else(|_| path.to_path_buf())
                .to_string_lossy()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    system.processes().values().any(|process| {
        process
            .exe()
            .and_then(|path| path.canonicalize().ok())
            .map(|path| path.to_string_lossy().to_ascii_lowercase())
            .is_some_and(|path| {
                path == expected
                    || (!install_root.is_empty()
                        && path.starts_with(&install_root)
                        && matches!(
                            process
                                .name()
                                .to_string_lossy()
                                .to_ascii_lowercase()
                                .as_str(),
                            "codex.exe" | "chatgpt.exe"
                        ))
            })
    })
}

#[cfg(windows)]
fn success_status() -> std::process::ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(0)
}

#[cfg(unix)]
fn success_status() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_launcher_options() {
        let args = vec![
            "pentect".to_string(),
            "codex-app".to_string(),
            "--app".to_string(),
            "Codex.exe".to_string(),
            "--upstream".to_string(),
            "https://example.test/v1".to_string(),
            "--dry-run".to_string(),
        ];
        assert_eq!(
            CodexAppOptions::parse(&args).unwrap(),
            CodexAppOptions {
                app: Some(PathBuf::from("Codex.exe")),
                upstream: Some("https://example.test/v1".to_string()),
                check: true,
            }
        );
    }

    #[test]
    fn parses_nested_codex_app_command() {
        let args = vec![
            "pentect".to_string(),
            "codex".to_string(),
            "app".to_string(),
            "--plugins".to_string(),
            "company-policy".to_string(),
            "--dry-run".to_string(),
        ];
        assert_eq!(
            CodexAppOptions::parse(&args).unwrap(),
            CodexAppOptions {
                app: None,
                upstream: None,
                check: true,
            }
        );
    }

    #[test]
    fn options_reject_missing_plugin_value() {
        let args = vec![
            "pentect".to_string(),
            "codex".to_string(),
            "app".to_string(),
            "--plugins".to_string(),
            "--dry-run".to_string(),
        ];
        assert!(CodexAppOptions::parse(&args).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn version_sort_is_numeric() {
        assert!(version_components("26.10.0") > version_components("26.9.99"));
        assert!(
            windows_package_version("ChatGPT_26.10.0.0_x64__id")
                > windows_package_version("ChatGPT_26.9.99.0_x64__id")
        );
        assert!(windows_package_matches_arch(
            if cfg!(target_arch = "aarch64") {
                "ChatGPT_1.0.0.0_arm64__id"
            } else {
                "ChatGPT_1.0.0.0_x64__id"
            }
        ));
    }

    #[test]
    fn rewrites_only_the_selected_custom_provider() {
        let mut config: toml_edit::DocumentMut = r#"
model_provider = "proxy"

[model_providers.proxy]
base_url = "https://upstream.example/v1"
wire_api = "responses"

[model_providers.other]
base_url = "https://other.example/v1"
"#
        .parse()
        .unwrap();
        set_provider_gateway(&mut config, "proxy", "http://127.0.0.1:47781").unwrap();
        assert_eq!(
            config["model_providers"]["proxy"]["base_url"].as_str(),
            Some("http://127.0.0.1:47781")
        );
        assert_eq!(
            config["model_providers"]["other"]["base_url"].as_str(),
            Some("https://other.example/v1")
        );
        assert_eq!(
            config["model_providers"]["proxy"]["supports_websockets"].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn provider_override_preserves_comments_and_valid_toml() {
        let mut config =
            "# keep this comment\n[model_providers.proxy]\nbase_url = \"https://old.example/v1\"\n"
                .parse::<toml_edit::DocumentMut>()
                .unwrap();
        set_provider_gateway(&mut config, "openai", "http://127.0.0.1:47781").unwrap();
        let encoded = config.to_string();

        assert!(encoded.contains("# keep this comment"), "{encoded}");
        let parsed = encoded.parse::<toml::Value>().unwrap();
        assert_eq!(
            parsed["model_provider"].as_str(),
            Some(crate::CODEX_GATEWAY_PROVIDER)
        );
        assert_eq!(
            parsed["model_providers"][crate::CODEX_GATEWAY_PROVIDER]["base_url"].as_str(),
            Some("http://127.0.0.1:47781")
        );
        assert_eq!(
            parsed["model_providers"][crate::CODEX_GATEWAY_PROVIDER]["supports_websockets"]
                .as_bool(),
            Some(false)
        );
    }

    #[test]
    fn temporary_config_override_restores_the_exact_original() {
        let root = std::env::temp_dir().join(format!(
            "pentect-codex-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let original = "# keep this comment\nopenai_base_url = \"https://example.test/v1\"\n";
        std::fs::write(root.join("config.toml"), original).unwrap();
        {
            let guard =
                CodexConfigOverride::install_in(&root, "openai", "http://127.0.0.1:47781").unwrap();
            let active = std::fs::read_to_string(root.join("config.toml")).unwrap();
            assert!(active.contains("http://127.0.0.1:47781"));
            assert!(root.join("config.toml.pentect-backup").is_file());
            drop(guard);
        }
        assert_eq!(
            std::fs::read_to_string(root.join("config.toml")).unwrap(),
            original
        );
        assert!(!root.join("config.toml.pentect-backup").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_config_override_is_recovered_before_reinstall() {
        let root = std::env::temp_dir().join(format!(
            "pentect-codex-recovery-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let original = "model = \"original\"\n";
        std::fs::write(root.join("config.toml"), "model = \"interrupted\"\n").unwrap();
        std::fs::write(root.join("config.toml.pentect-backup"), original).unwrap();
        let guard =
            CodexConfigOverride::install_in(&root, "openai", "http://127.0.0.1:47781").unwrap();
        drop(guard);
        assert_eq!(
            std::fs::read_to_string(root.join("config.toml")).unwrap(),
            original
        );
        assert!(!root.join("config.toml.pentect-backup").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_override_without_an_original_remains_absent_after_recovery() {
        let root = std::env::temp_dir().join(format!(
            "pentect-codex-no-original-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("config.toml"), "model = \"interrupted\"\n").unwrap();
        std::fs::write(root.join("config.toml.pentect-backup"), b"").unwrap();
        std::fs::write(root.join("config.toml.pentect-no-original"), b"").unwrap();
        let guard =
            CodexConfigOverride::install_in(&root, "openai", "http://127.0.0.1:47781").unwrap();
        drop(guard);
        assert!(!root.join("config.toml").exists());
        assert!(!root.join("config.toml.pentect-backup").exists());
        assert!(!root.join("config.toml.pentect-no-original").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_config_does_not_create_recovery_artifacts() {
        let root = std::env::temp_dir().join(format!(
            "pentect-codex-malformed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let malformed = "[not valid";
        std::fs::write(root.join("config.toml"), malformed).unwrap();
        assert!(
            CodexConfigOverride::install_in(&root, "openai", "http://127.0.0.1:47781").is_err()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("config.toml")).unwrap(),
            malformed
        );
        assert!(!root.join("config.toml.pentect-backup").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn config_symlinks_are_rejected_without_touching_the_target() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "pentect-codex-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("outside.toml");
        std::fs::write(&target, "model = \"untouched\"\n").unwrap();
        symlink(&target, root.join("config.toml")).unwrap();
        assert!(
            CodexConfigOverride::install_in(&root, "openai", "http://127.0.0.1:47781").is_err()
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "model = \"untouched\"\n"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn active_config_and_recovery_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "pentect-codex-permissions-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("config.toml"), "model = \"original\"\n").unwrap();
        let guard =
            CodexConfigOverride::install_in(&root, "openai", "http://127.0.0.1:47781").unwrap();
        for path in [
            root.join("config.toml"),
            root.join("config.toml.pentect-backup"),
        ] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o077,
                0
            );
        }
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn config_lock_rejects_a_second_session_and_clears_on_drop() {
        let home = std::env::temp_dir().join(format!(
            "pentect-codex-app-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = CodexConfigLock::acquire_in(&home).unwrap();
        assert!(CodexConfigLock::acquire_in(&home).is_err());
        drop(first);
        let second = CodexConfigLock::acquire_in(&home).unwrap();
        drop(second);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn config_lock_recovers_a_stale_owner() {
        let home = std::env::temp_dir().join(format!(
            "pentect-codex-app-stale-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("pentect-codex-app.lock"), "4294967295\n").unwrap();
        let lock = CodexConfigLock::acquire_in(&home).unwrap();
        drop(lock);
        std::fs::remove_dir_all(home).unwrap();
    }
}
