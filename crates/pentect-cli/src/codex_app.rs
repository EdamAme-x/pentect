//! Experimental launcher for the unmodified Codex desktop application.
//!
//! The app and its bundled Codex process inherit a loopback-only Responses API
//! gateway through `OPENAI_BASE_URL`. Pentect never changes the user's Codex
//! configuration or kills an existing app process.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

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
    if options.dry_run {
        println!("{}", app.display());
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
    let config_override = routing
        .requires_config_override
        .then(|| CodexConfigOverride::install(&routing.provider, proxy.base_url()))
        .transpose()?;
    eprintln!("[pentect] Codex App gateway ready at {}", proxy.base_url());
    if config_override.is_some() {
        eprintln!(
            "[pentect] Codex provider '{}' is routed through the gateway for this App session",
            routing.provider
        );
    }
    eprintln!("[pentect] Responses API prompts, files, and completed tool calls are protected");

    let mut child = Command::new(&app)
        .env("OPENAI_BASE_URL", proxy.base_url())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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
        let _ = child.kill();
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
        libc::kill(pid as i32, libc::SIGTERM);
    }
}

struct CodexConfigOverride {
    config: PathBuf,
    backup: PathBuf,
    no_original_marker: PathBuf,
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
            toml::Value::Table(toml::map::Map::new())
        } else {
            original
                .parse::<toml::Value>()
                .map_err(|error| format!("could not parse '{}': {error}", config.display()))?
        };
        set_provider_base_url(&mut parsed, provider, gateway)?;

        std::fs::write(&backup, original.as_bytes())
            .map_err(|error| format!("could not back up '{}': {error}", config.display()))?;
        if !had_original {
            std::fs::write(&no_original_marker, b"")
                .map_err(|error| format!("could not create Codex recovery marker: {error}"))?;
        }
        let temporary = home.join(format!("config.toml.pentect-{}.tmp", std::process::id()));
        std::fs::write(&temporary, parsed.to_string())
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

impl Drop for CodexConfigOverride {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("[pentect] {error}");
        }
    }
}

fn set_provider_base_url(
    config: &mut toml::Value,
    provider: &str,
    gateway: &str,
) -> Result<(), String> {
    let root = config
        .as_table_mut()
        .ok_or_else(|| "Codex config root is not a TOML table".to_string())?;
    if provider == "openai" {
        root.insert(
            "openai_base_url".to_string(),
            toml::Value::String(gateway.to_string()),
        );
        return Ok(());
    }
    let providers = root
        .entry("model_providers")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| "model_providers is not a TOML table".to_string())?;
    let provider = providers
        .entry(provider.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| "selected model provider is not a TOML table".to_string())?;
    provider.insert(
        "base_url".to_string(),
        toml::Value::String(gateway.to_string()),
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct CodexAppOptions {
    app: Option<PathBuf>,
    upstream: Option<String>,
    dry_run: bool,
}

impl CodexAppOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut app = None;
        let mut upstream = None;
        let mut dry_run = false;
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
                "--dry-run" => {
                    dry_run = true;
                    index += 1;
                }
                value => return Err(format!("unknown codex-app option: {value}")),
            }
        }
        Ok(Self {
            app,
            upstream,
            dry_run,
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
        return PathBuf::from("/Applications/Codex.app/Contents/MacOS/Codex");
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
    let root = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)?
        .join(Path::new("Programs").join("OpenAI Codex Standalone"));
    let mut candidates = std::fs::read_dir(root)
        .ok()?
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
    candidates.pop().map(|(_, executable)| executable)
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
                dry_run: true,
            }
        );
    }

    #[test]
    fn parses_nested_codex_app_command() {
        let args = vec![
            "pentect".to_string(),
            "codex".to_string(),
            "app".to_string(),
            "--dry-run".to_string(),
        ];
        assert_eq!(
            CodexAppOptions::parse(&args).unwrap(),
            CodexAppOptions {
                app: None,
                upstream: None,
                dry_run: true,
            }
        );
    }

    #[cfg(windows)]
    #[test]
    fn version_sort_is_numeric() {
        assert!(version_components("26.10.0") > version_components("26.9.99"));
    }

    #[test]
    fn rewrites_only_the_selected_custom_provider() {
        let mut config: toml::Value = r#"
model_provider = "proxy"

[model_providers.proxy]
base_url = "https://upstream.example/v1"
wire_api = "responses"

[model_providers.other]
base_url = "https://other.example/v1"
"#
        .parse()
        .unwrap();
        set_provider_base_url(&mut config, "proxy", "http://127.0.0.1:47781").unwrap();
        assert_eq!(
            config["model_providers"]["proxy"]["base_url"].as_str(),
            Some("http://127.0.0.1:47781")
        );
        assert_eq!(
            config["model_providers"]["other"]["base_url"].as_str(),
            Some("https://other.example/v1")
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
}
