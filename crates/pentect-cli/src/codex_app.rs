//! Experimental launcher for the unmodified Codex desktop application.
//!
//! The app and its bundled Codex process inherit a loopback-only Responses API
//! gateway through `OPENAI_BASE_URL`. Pentect never changes the user's Codex
//! configuration or kills an existing app process.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
            "Codex App is already running; quit it before `pentect codex-app` so its bundled Codex process inherits the HTTP gateway"
                .to_string(),
        );
    }

    let upstream = crate::codex_app_upstream(options.upstream)?;
    let proxy = crate::openai_http_proxy::OpenAiHttpProxyGuard::start(upstream)?;
    eprintln!("[pentect] Codex App gateway ready at {}", proxy.base_url());
    eprintln!("[pentect] Responses API prompts and completed tool calls are protected");

    let mut child = Command::new(&app)
        .env("OPENAI_BASE_URL", proxy.base_url())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("could not start Codex App: {error}"))?;
    let status = child
        .wait()
        .map_err(|error| format!("could not wait for Codex App: {error}"))?;
    drop(proxy);
    Ok(status)
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
        let mut index = 2;
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

    #[cfg(windows)]
    #[test]
    fn version_sort_is_numeric() {
        assert!(version_components("26.10.0") > version_components("26.9.99"));
    }
}
