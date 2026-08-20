//! Launcher for the unmodified Codex desktop application.
//!
//! The app and its bundled Codex process use a loopback-only Responses API
//! gateway. The App gets a session-only `CODEX_HOME`; Pentect never changes the
//! user's shared Codex configuration and refuses to launch while another Codex
//! App process is running.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::{fs::OpenOptions, io::Write, thread, time::Duration};

const APP_START_GRACE: Duration = Duration::from_secs(15);
const APP_EXIT_GRACE: Duration = Duration::from_secs(30);
const APP_MONITOR_INTERVAL: Duration = Duration::from_millis(500);
const MAX_LIFECYCLE_LOG_BYTES: u64 = 1024 * 1024;

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
    let recovered_legacy_config = recover_legacy_config()?;
    let app_was_explicit = options.app.is_some();
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
        crate::upstream::header_overrides(&options.upstream_header_env)?;
        println!("Provider: {}", routing.provider);
        println!("Protection: OpenAI Responses API (HTTP)");
        if !installed {
            return Err(codex_app_not_found(&app, app_was_explicit));
        }
        return Ok(success_status());
    }
    if !app.is_file() {
        return Err(codex_app_not_found(&app, app_was_explicit));
    }
    if codex_app_is_running(&app) {
        return Err(
            "Codex App is already running; quit it before `pentect codex app` so its bundled Codex process inherits the HTTP gateway"
                .to_string(),
        );
    }

    let routing = crate::codex_app_routing(options.upstream)?;
    let proxy = crate::openai_http_proxy::OpenAiHttpProxyGuard::start_with_header_env(
        routing.upstream,
        &options.upstream_header_env,
    )?;
    let config_lock = Arc::new(Mutex::new(Some(CodexConfigLock::acquire()?)));
    let session_home = CodexSessionHome::create(&routing.provider, proxy.base_url())?;
    let lifecycle_log = match CodexAppLifecycleLog::open(session_home.source_home()) {
        Ok(log) => Some(log),
        Err(error) => {
            eprintln!("[pentect] warning: Codex App lifecycle log is unavailable: {error}");
            None
        }
    };
    if recovered_legacy_config {
        record_lifecycle(&lifecycle_log, "legacy-config-restored", "completed");
    }
    record_lifecycle(&lifecycle_log, "gateway-started", "loopback");
    eprintln!("[pentect] Codex App gateway ready at {}", proxy.base_url());
    eprintln!(
        "[pentect] Codex provider '{}' is routed through the gateway for this App session",
        routing.provider
    );
    eprintln!("[pentect] Responses API prompts, files, and completed tool calls are protected");

    let mut command = Command::new(&app);
    crate::upstream::hide_header_source_env(&mut command, &options.upstream_header_env);
    command
        .env("CODEX_HOME", session_home.path())
        .env("OPENAI_BASE_URL", proxy.base_url())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if std::env::var_os("CODEX_SQLITE_HOME").is_none() {
        command.env("CODEX_SQLITE_HOME", session_home.source_home());
    }
    configure_child_process(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            record_lifecycle(&lifecycle_log, "launcher-failed", &error.to_string());
            return Err(format!("could not start Codex App: {error}"));
        }
    };
    record_lifecycle(
        &lifecycle_log,
        "launcher-started",
        &format!("pid={}", child.id()),
    );
    let session_cleanup = Arc::new(Mutex::new(Some(session_home)));
    let signal_cleanup = Arc::clone(&session_cleanup);
    let signal_lock = Arc::clone(&config_lock);
    let child_id = child.id();
    let signal_app = app.clone();
    if let Err(error) = ctrlc::set_handler(move || {
        terminate_child_process(child_id);
        terminate_codex_app_processes(&signal_app);
        if let Ok(mut cleanup) = signal_cleanup.lock() {
            cleanup.take();
        }
        if let Ok(mut lock) = signal_lock.lock() {
            lock.take();
        }
        std::process::exit(130);
    }) {
        terminate_child_process(child_id);
        let _ = child.wait();
        if let Ok(mut cleanup) = session_cleanup.lock() {
            cleanup.take();
        }
        if let Ok(mut lock) = config_lock.lock() {
            lock.take();
        }
        return Err(format!(
            "could not install Codex App session cleanup handler: {error}"
        ));
    }
    let status = monitor_codex_app(&mut child, &app, &proxy, &lifecycle_log)?;
    session_cleanup
        .lock()
        .map_err(|_| "Codex App session cleanup lock is unavailable".to_string())?
        .take();
    config_lock
        .lock()
        .map_err(|_| "Codex App session lock is unavailable".to_string())?
        .take();
    drop(proxy);
    record_lifecycle(&lifecycle_log, "session-finished", "app-exited");
    Ok(status)
}

fn monitor_codex_app(
    child: &mut std::process::Child,
    app: &Path,
    proxy: &crate::openai_http_proxy::OpenAiHttpProxyGuard,
    lifecycle_log: &Option<CodexAppLifecycleLog>,
) -> Result<std::process::ExitStatus, String> {
    loop {
        if !proxy.is_running() {
            let reason = proxy
                .failure_reason()
                .unwrap_or_else(|| "gateway thread exited unexpectedly".to_string());
            record_lifecycle(lifecycle_log, "gateway-stopped", &reason);
            terminate_child_process(child.id());
            let _ = child.wait();
            return Err(format!(
                "Codex App gateway stopped: {reason}; inspect the lifecycle entries with `pentect log`"
            ));
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("could not monitor Codex App launcher: {error}"))?
        {
            record_lifecycle(
                lifecycle_log,
                "launcher-exited",
                &format!("status={}", status.code().unwrap_or(-1)),
            );
            if !status.success() {
                return Ok(status);
            }
            return monitor_handed_off_app(app, proxy, lifecycle_log, status);
        }
        thread::sleep(APP_MONITOR_INTERVAL);
    }
}

fn monitor_handed_off_app(
    app: &Path,
    proxy: &crate::openai_http_proxy::OpenAiHttpProxyGuard,
    lifecycle_log: &Option<CodexAppLifecycleLog>,
    launcher_status: std::process::ExitStatus,
) -> Result<std::process::ExitStatus, String> {
    let mut process_probe = CodexAppProcessProbe::new(app);
    let started = std::time::Instant::now();
    let mut observed = false;
    let mut warned_unobservable = false;
    let mut absent_since = None;
    loop {
        ensure_gateway_running(proxy, lifecycle_log)?;
        if process_probe.is_running() {
            if !observed {
                record_lifecycle(lifecycle_log, "app-process-observed", "running");
                observed = true;
            }
            absent_since = None;
        } else if observed {
            let since = absent_since.get_or_insert_with(std::time::Instant::now);
            if since.elapsed() >= APP_EXIT_GRACE {
                record_lifecycle(lifecycle_log, "app-process-exited", "confirmed");
                return Ok(launcher_status);
            }
        } else if started.elapsed() >= APP_START_GRACE && !warned_unobservable {
            // Packaged Windows apps can hide their executable path from normal
            // process enumeration. Never drop the gateway merely because the
            // process cannot be observed: remain in the foreground until Ctrl+C.
            record_lifecycle(lifecycle_log, "app-process-unobservable", "gateway-kept-alive");
            eprintln!(
                "[pentect] Codex App process could not be observed; the gateway will stay active until Ctrl+C"
            );
            warned_unobservable = true;
        }
        thread::sleep(APP_MONITOR_INTERVAL);
    }
}

fn ensure_gateway_running(
    proxy: &crate::openai_http_proxy::OpenAiHttpProxyGuard,
    lifecycle_log: &Option<CodexAppLifecycleLog>,
) -> Result<(), String> {
    if proxy.is_running() {
        return Ok(());
    }
    let reason = proxy
        .failure_reason()
        .unwrap_or_else(|| "gateway thread exited unexpectedly".to_string());
    record_lifecycle(lifecycle_log, "gateway-stopped", &reason);
    Err(format!(
        "Codex App gateway stopped: {reason}; inspect the lifecycle entries with `pentect log`"
    ))
}

struct CodexAppLifecycleLog {
    file: Mutex<std::fs::File>,
}

impl CodexAppLifecycleLog {
    fn open(codex_home: &Path) -> Result<Self, String> {
        let directory = codex_home.join(".pentect").join("logs");
        std::fs::create_dir_all(&directory)
            .map_err(|error| format!("could not create '{}': {error}", directory.display()))?;
        reject_directory_link(&directory, "Codex App log directory")?;
        let path = directory.join("codex-app.log");
        reject_symlink(&path, "Codex App lifecycle log")?;
        if path
            .metadata()
            .is_ok_and(|metadata| metadata.len() > MAX_LIFECYCLE_LOG_BYTES)
        {
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .map_err(|error| format!("could not rotate '{}': {error}", path.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| format!("could not open '{}': {error}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    fn record(&self, event: &str, detail: &str) {
        let detail = detail
            .chars()
            .filter(|character| !matches!(character, '\r' | '\n'))
            .take(512)
            .collect::<String>();
        if let Ok(mut file) = self.file.lock() {
            let entry = serde_json::json!({
                "time": jiff::Timestamp::now().to_string(),
                "action": "lifecycle",
                "surface": "codex-app",
                "event": event,
                "detail": detail,
            });
            let _ = writeln!(file, "{entry}");
            let _ = file.flush();
        }
    }
}

fn record_lifecycle(log: &Option<CodexAppLifecycleLog>, event: &str, detail: &str) {
    if let Some(log) = log {
        log.record(event, detail);
    }
}

fn codex_app_not_found(app: &Path, app_was_explicit: bool) -> String {
    if app_was_explicit {
        format!(
            "Codex App was not found at '{}'; pass an existing executable to --app",
            app.display()
        )
    } else {
        "Codex App was not found automatically; install Codex App or pass its executable with --app PATH"
            .to_string()
    }
}

pub(crate) fn check_mode(args: &[String]) -> Result<bool, String> {
    CodexAppOptions::parse(args).map(|options| options.check)
}

#[cfg(windows)]
fn terminate_child_process(pid: u32) {
    let _ = Command::new(crate::windows_system_executable("taskkill.exe"))
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn terminate_codex_app_processes(app: &Path) {
    for pid in CodexAppProcessProbe::new(app).matching_pids() {
        terminate_process(pid);
    }
}

#[cfg(windows)]
fn terminate_process(pid: u32) {
    let _ = Command::new(crate::windows_system_executable("taskkill.exe"))
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(unix)]
fn terminate_process(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
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

struct CodexSessionHome {
    path: PathBuf,
    source_home: PathBuf,
}

#[derive(Debug)]
struct CodexConfigLock {
    path: PathBuf,
    file: std::fs::File,
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
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|error| {
            format!(
                "could not open Codex App lock '{}': {error}",
                path.display()
            )
        })?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err("another `pentect codex app` session is already active".to_string());
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(format!(
                    "could not lock Codex App session '{}': {error}",
                    path.display()
                ));
            }
        }
        file.set_len(0)
            .and_then(|_| writeln!(file, "{}", std::process::id()))
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("could not initialize '{}': {error}", path.display()))?;
        Ok(Self { path, file })
    }
}

impl Drop for CodexConfigLock {
    fn drop(&mut self) {
        if let Err(error) = self.file.unlock() {
            eprintln!(
                "[pentect] could not release Codex App lock '{}': {error}",
                self.path.display()
            );
        }
    }
}

impl CodexSessionHome {
    fn create(provider: &str, gateway: &str) -> Result<Self, String> {
        Self::create_in(&crate::codex_home_dir()?, provider, gateway)
    }

    fn create_in(source_home: &Path, provider: &str, gateway: &str) -> Result<Self, String> {
        std::fs::create_dir_all(source_home)
            .map_err(|error| format!("could not create '{}': {error}", source_home.display()))?;
        let pentect_state = source_home.join(".pentect");
        reject_directory_link(&pentect_state, "Pentect Codex state directory")?;
        std::fs::create_dir_all(&pentect_state).map_err(|error| {
            format!(
                "could not create Pentect Codex state directory '{}': {error}",
                pentect_state.display()
            )
        })?;
        let sessions = pentect_state.join("codex-app-sessions");
        reject_directory_link(&sessions, "Codex App sessions directory")?;
        std::fs::create_dir_all(&sessions).map_err(|error| {
            format!(
                "could not create Codex App session directory '{}': {error}",
                sessions.display()
            )
        })?;
        cleanup_stale_session_homes(&sessions);
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = sessions.join(format!("{}-{suffix}", std::process::id()));
        std::fs::create_dir(&path).map_err(|error| {
            format!(
                "could not create Codex App session home '{}': {error}",
                path.display()
            )
        })?;
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .map_err(|error| {
                format!(
                    "could not protect Codex App session home '{}': {error}",
                    path.display()
                )
            })?;

        let result = (|| {
            for entry in std::fs::read_dir(source_home).map_err(|error| {
                format!(
                    "could not inspect Codex home '{}': {error}",
                    source_home.display()
                )
            })? {
                let entry = entry
                    .map_err(|error| format!("could not inspect Codex home entry: {error}"))?;
                let name = entry.file_name();
                if session_home_excludes(&name) {
                    continue;
                }
                link_session_entry(&entry.path(), &path.join(&name))?;
            }

            let source_config = source_home.join("config.toml");
            reject_symlink(&source_config, "Codex config")?;
            let original = match std::fs::read_to_string(&source_config) {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(error) => {
                    return Err(format!(
                        "could not read '{}': {error}",
                        source_config.display()
                    ));
                }
            };
            let mut config = if original.trim().is_empty() {
                toml_edit::DocumentMut::new()
            } else {
                original
                    .parse::<toml_edit::DocumentMut>()
                    .map_err(|error| {
                        format!("could not parse '{}': {error}", source_config.display())
                    })?
            };
            set_provider_gateway(&mut config, provider, gateway)?;
            write_new_private_file(&path.join("config.toml"), config.to_string().as_bytes())
                .map_err(|error| format!("could not write Codex App session config: {error}"))?;
            Ok(())
        })();
        if let Err(error) = result {
            cleanup_session_home(&path);
            return Err(error);
        }
        Ok(Self {
            path,
            source_home: source_home.to_path_buf(),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn source_home(&self) -> &Path {
        &self.source_home
    }
}

impl Drop for CodexSessionHome {
    fn drop(&mut self) {
        cleanup_session_home(&self.path);
    }
}

fn session_home_excludes(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy();
    name == ".pentect"
        || name == "config.toml"
        || name == "config.toml.pentect-backup"
        || name == "config.toml.pentect-no-original"
        || name == "pentect-codex-app.lock"
        || (name.starts_with("config.toml.pentect-") && name.ends_with(".tmp"))
}

#[cfg(unix)]
fn link_session_entry(source: &Path, destination: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(source, destination).map_err(|error| {
        format!(
            "could not link Codex state '{}' into the App session: {error}",
            source.display()
        )
    })
}

#[cfg(windows)]
fn link_session_entry(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = std::fs::metadata(source).map_err(|error| {
        format!(
            "could not inspect Codex state '{}': {error}",
            source.display()
        )
    })?;
    if metadata.is_dir() {
        match junction::create(source, destination) {
            Ok(()) => Ok(()),
            Err(junction_error) => {
                // `junction::create` may leave an empty directory behind when
                // the volume does not support junctions.
                let _ = std::fs::remove_dir(destination);
                std::os::windows::fs::symlink_dir(source, destination).map_err(|symlink_error| {
                    format!(
                        "could not link Codex state directory '{}' into the App session: junction failed ({junction_error}); directory symlink failed ({symlink_error})",
                        source.display()
                    )
                })
            }
        }
    } else if metadata.is_file() {
        std::os::windows::fs::symlink_file(source, destination)
            .or_else(|symlink_error| {
                std::fs::hard_link(source, destination).map_err(|hard_link_error| {
                    std::io::Error::new(
                        hard_link_error.kind(),
                        format!(
                            "file symlink failed ({symlink_error}); hard link failed ({hard_link_error})"
                        ),
                    )
                })
            })
            .map_err(|error| {
                format!(
                    "could not link Codex state file '{}' into the App session: {error}",
                    source.display()
                )
            })
    } else {
        Err(format!(
            "Codex state entry '{}' has an unsupported file type",
            source.display()
        ))
    }
}

fn cleanup_stale_session_homes(sessions: &Path) {
    let Ok(entries) = std::fs::read_dir(sessions) else {
        return;
    };
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    for entry in entries.flatten() {
        let Some(pid) = generated_session_pid(&entry.file_name()) else {
            continue;
        };
        if system.process(sysinfo::Pid::from_u32(pid)).is_none() {
            cleanup_session_home(&entry.path());
        }
    }
}

#[cfg(test)]
fn generated_session_name(name: &std::ffi::OsStr) -> bool {
    generated_session_pid(name).is_some()
}

fn generated_session_pid(name: &std::ffi::OsStr) -> Option<u32> {
    let name = name.to_string_lossy();
    let (pid, suffix) = name.split_once('-')?;
    if pid.is_empty()
        || suffix.is_empty()
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || !suffix.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    pid.parse().ok()
}

fn cleanup_session_home(path: &Path) {
    #[cfg(windows)]
    if junction::exists(path).unwrap_or(false) {
        let _ = junction::delete(path);
        let _ = std::fs::remove_dir(path);
        return;
    }
    let Ok(root_metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    if root_metadata.file_type().is_symlink() || root_metadata.is_file() {
        let _ = std::fs::remove_file(path);
        return;
    }
    if !root_metadata.is_dir() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        #[cfg(windows)]
        if junction::exists(&entry_path).unwrap_or(false) {
            let _ = junction::delete(&entry_path);
            let _ = std::fs::remove_dir(&entry_path);
            continue;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&entry_path) else {
            continue;
        };
        if metadata.file_type().is_symlink() || metadata.is_file() {
            if std::fs::remove_file(&entry_path).is_err() {
                // Windows directory symlinks require directory removal.
                let _ = std::fs::remove_dir(&entry_path);
            }
        } else if metadata.is_dir() {
            let _ = std::fs::remove_dir_all(&entry_path);
        }
    }
    let _ = std::fs::remove_dir(path);
}

pub(crate) fn recover_legacy_config() -> Result<bool, String> {
    recover_legacy_config_in(&crate::codex_home_dir()?)
}

fn recover_legacy_config_in(home: &Path) -> Result<bool, String> {
    let config = home.join("config.toml");
    let backup = home.join("config.toml.pentect-backup");
    let no_original_marker = home.join("config.toml.pentect-no-original");
    reject_symlink(&config, "Codex config")?;
    reject_symlink(&backup, "Codex recovery backup")?;
    reject_symlink(&no_original_marker, "Codex recovery marker")?;
    if backup.is_file() {
        if no_original_marker.is_file() {
            if config.is_file() {
                std::fs::remove_file(&config).map_err(|error| {
                    format!(
                        "could not recover Codex config '{}': {error}",
                        config.display()
                    )
                })?;
            }
            std::fs::remove_file(&backup)
                .map_err(|error| format!("could not clear interrupted Codex backup: {error}"))?;
        } else {
            std::fs::rename(&backup, &config).map_err(|error| {
                format!(
                    "could not restore interrupted Codex config '{}': {error}",
                    backup.display()
                )
            })?;
        }
        let _ = std::fs::remove_file(&no_original_marker);
        eprintln!("[pentect] restored Codex config left by an older interrupted App session");
        return Ok(true);
    }
    if !config.is_file() {
        return Ok(false);
    }
    let Ok(original) = std::fs::read_to_string(&config) else {
        return Ok(false);
    };
    let Ok(mut parsed) = original.parse::<toml_edit::DocumentMut>() else {
        return Ok(false);
    };
    if !is_orphaned_legacy_gateway(&parsed) {
        return Ok(false);
    }
    parsed.remove("model_provider");
    if let Some(providers) = parsed
        .get_mut("model_providers")
        .and_then(toml_edit::Item::as_table_mut)
    {
        providers.remove(crate::CODEX_GATEWAY_PROVIDER);
        if providers.is_empty() {
            parsed.remove("model_providers");
        }
    }
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temporary = home.join(format!(
        "config.toml.pentect-recovery-{}-{suffix}.tmp",
        std::process::id()
    ));
    write_new_private_file(&temporary, parsed.to_string().as_bytes())
        .map_err(|error| format!("could not write Codex recovery config: {error}"))?;
    std::fs::rename(&temporary, &config)
        .map_err(|error| format!("could not recover '{}': {error}", config.display()))?;
    eprintln!("[pentect] removed a stale Codex gateway left by an older release");
    Ok(true)
}

fn is_orphaned_legacy_gateway(config: &toml_edit::DocumentMut) -> bool {
    if config
        .get("model_provider")
        .and_then(toml_edit::Item::as_str)
        != Some(crate::CODEX_GATEWAY_PROVIDER)
    {
        return false;
    }
    let Some(provider) = config
        .get("model_providers")
        .and_then(toml_edit::Item::as_table)
        .and_then(|providers| providers.get(crate::CODEX_GATEWAY_PROVIDER))
        .and_then(toml_edit::Item::as_table)
    else {
        return false;
    };
    let base_url = provider
        .get("base_url")
        .and_then(toml_edit::Item::as_str)
        .unwrap_or_default();
    provider.get("name").and_then(toml_edit::Item::as_str) == Some("OpenAI through Pentect")
        && provider.get("wire_api").and_then(toml_edit::Item::as_str) == Some("responses")
        && (base_url.starts_with("http://127.0.0.1:") || base_url.starts_with("http://localhost:"))
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

fn reject_directory_link(path: &Path, label: &str) -> Result<(), String> {
    #[cfg(windows)]
    if junction::exists(path).unwrap_or(false) {
        return Err(format!(
            "{label} '{}' is a junction; Pentect will not use it",
            path.display()
        ));
    }
    reject_symlink(path, label)
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

fn set_provider_gateway(
    config: &mut toml_edit::DocumentMut,
    provider: &str,
    gateway: &str,
) -> Result<(), String> {
    if provider == "openai" {
        // Preserve the built-in provider ID in Codex's thread metadata. The
        // gateway answers WebSocket upgrades with 426 so Codex falls back to
        // the protected HTTP Responses path for this session.
        config["openai_base_url"] = toml_edit::value(gateway);
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
    upstream_header_env: Vec<String>,
    check: bool,
}

impl CodexAppOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut app = None;
        let mut upstream = None;
        let mut upstream_header_env = Vec::new();
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
                "--upstream-header-env" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--upstream-header-env requires a value".to_string())?;
                    upstream_header_env.push(value.clone());
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
            upstream_header_env,
            check,
        })
    }
}

pub(crate) fn default_codex_app_path() -> PathBuf {
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
    find_windows_store_codex_app()
}

#[cfg(windows)]
fn find_windows_store_codex_app() -> Option<PathBuf> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const PACKAGES_KEY: &str = r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

    let reg = crate::windows_system_executable("reg.exe");
    let output = Command::new(&reg)
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
            key.rsplit('\\')
                .next()
                .is_some_and(windows_package_is_codex_app)
        })
        .filter_map(|key| {
            let package_name = key.rsplit('\\').next()?.to_string();
            let output = Command::new(&reg)
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
fn windows_package_is_codex_app(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ["openai.codex_", "openai.chatgpt_", "chatgpt_"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        && windows_package_matches_arch(&name)
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
    CodexAppProcessProbe::new(app).is_running()
}

struct CodexAppProcessProbe {
    expected: String,
    install_root: String,
    system: sysinfo::System,
}

impl CodexAppProcessProbe {
    fn new(app: &Path) -> Self {
        Self {
            expected: app
                .canonicalize()
                .unwrap_or_else(|_| app.to_path_buf())
                .to_string_lossy()
                .to_ascii_lowercase(),
            install_root: app
                .parent()
                .map(|path| {
                    path.canonicalize()
                        .unwrap_or_else(|_| path.to_path_buf())
                        .to_string_lossy()
                        .to_ascii_lowercase()
                })
                .unwrap_or_default(),
            system: sysinfo::System::new(),
        }
    }

    fn is_running(&mut self) -> bool {
        !self.matching_pids().is_empty()
    }

    fn matching_pids(&mut self) -> Vec<u32> {
        self.system
            .refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        self.system
            .processes()
            .iter()
            .filter(|(_, process)| self.matches(process))
            .map(|(pid, _)| pid.as_u32())
            .collect()
    }

    fn matches(&self, process: &sysinfo::Process) -> bool {
        let process_name = process.name().to_string_lossy().to_ascii_lowercase();
        // Windows packaged ChatGPT/Codex processes may not expose their image
        // path to a non-elevated caller. Treat ChatGPT.exe as the App in that
        // case so an already-running process is never mistaken for a protected
        // launch. Do not do this for a bare codex.exe name because that can be
        // the unrelated CLI.
        if cfg!(windows) && process_name == "chatgpt.exe" {
            return true;
        }

        let executable_matches = process
            .exe()
            .map(|path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf()))
            .map(|path| path.to_string_lossy().to_ascii_lowercase())
            .is_some_and(|path| {
                path == self.expected
                    || (!self.install_root.is_empty()
                        && path.starts_with(&self.install_root)
                        && matches!(
                            process_name.as_str(),
                            "codex.exe" | "chatgpt.exe"
                        ))
            });
        if executable_matches {
            return true;
        }

        process.cmd().first().is_some_and(|command| {
            let path = PathBuf::from(command.as_os_str());
            let path = path.canonicalize().unwrap_or(path);
            let path = path.to_string_lossy().to_ascii_lowercase();
            path == self.expected
                || (!self.install_root.is_empty()
                    && path.starts_with(&self.install_root)
                    && matches!(process_name.as_str(), "codex.exe" | "chatgpt.exe"))
        })
    }
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
            "--upstream-header-env".to_string(),
            "x-bf-vk=BIFROST_API_KEY".to_string(),
            "--dry-run".to_string(),
        ];
        assert_eq!(
            CodexAppOptions::parse(&args).unwrap(),
            CodexAppOptions {
                app: Some(PathBuf::from("Codex.exe")),
                upstream: Some("https://example.test/v1".to_string()),
                upstream_header_env: vec!["x-bf-vk=BIFROST_API_KEY".to_string()],
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
                upstream_header_env: Vec::new(),
                check: true,
            }
        );
    }

    #[test]
    fn missing_app_message_distinguishes_auto_detection_from_an_explicit_path() {
        assert_eq!(
            codex_app_not_found(Path::new("Codex.exe"), false),
            "Codex App was not found automatically; install Codex App or pass its executable with --app PATH"
        );
        assert!(codex_app_not_found(Path::new("missing.exe"), true)
            .contains("was not found at 'missing.exe'"));
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

    #[test]
    fn check_mode_does_not_treat_an_option_value_as_a_flag() {
        let args = vec![
            "pentect".to_string(),
            "codex".to_string(),
            "app".to_string(),
            "--app".to_string(),
            "--check".to_string(),
        ];
        assert!(!check_mode(&args).unwrap());
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
    fn lifecycle_log_is_value_free_jsonl() {
        let root = std::env::temp_dir().join(format!(
            "pentect-codex-lifecycle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let log = CodexAppLifecycleLog::open(&root).unwrap();
        log.record("gateway-stopped", "gateway thread exited unexpectedly");
        let payload =
            std::fs::read_to_string(root.join(".pentect").join("logs").join("codex-app.log"))
                .unwrap();
        let value: serde_json::Value = serde_json::from_str(payload.trim()).unwrap();
        assert_eq!(value["action"], "lifecycle");
        assert_eq!(value["surface"], "codex-app");
        assert_eq!(value["event"], "gateway-stopped");
        assert_eq!(value["detail"], "gateway thread exited unexpectedly");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lifecycle_log_is_truncated_before_it_grows_without_bound() {
        let root = std::env::temp_dir().join(format!(
            "pentect-codex-lifecycle-rotation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = root.join(".pentect").join("logs").join("codex-app.log");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![b'x'; MAX_LIFECYCLE_LOG_BYTES as usize + 1]).unwrap();

        let log = CodexAppLifecycleLog::open(&root).unwrap();
        log.record("gateway-started", "loopback");
        let payload = std::fs::read_to_string(&path).unwrap();
        assert_eq!(payload.lines().count(), 1);
        assert!(payload.contains("gateway-started"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn process_probe_observes_the_current_executable() {
        let executable = std::env::current_exe().unwrap();
        assert!(CodexAppProcessProbe::new(&executable).is_running());
    }

    #[cfg(windows)]
    #[test]
    fn recognizes_current_and_legacy_windows_store_packages() {
        let architecture = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x64"
        };
        let other_architecture = if cfg!(target_arch = "aarch64") {
            "x64"
        } else {
            "arm64"
        };

        assert!(windows_package_is_codex_app(&format!(
            "OpenAI.Codex_26.814.5167.0_{architecture}__2p2nqsd0c76g0"
        )));
        assert!(windows_package_is_codex_app(&format!(
            "OpenAI.ChatGPT_1.2026.210.0_{architecture}__2p2nqsd0c76g0"
        )));
        assert!(windows_package_is_codex_app(&format!(
            "ChatGPT_1.2026.210.0_{architecture}__2p2nqsd0c76g0"
        )));
        assert!(!windows_package_is_codex_app(&format!(
            "OpenAI.Codex_26.814.5167.0_{other_architecture}__2p2nqsd0c76g0"
        )));
        assert!(!windows_package_is_codex_app(&format!(
            "OpenAI.CodexHelper_26.814.5167.0_{architecture}__2p2nqsd0c76g0"
        )));
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
            "# keep this comment\nmodel_provider = \"openai\"\n[model_providers.proxy]\nbase_url = \"https://old.example/v1\"\n"
                .parse::<toml_edit::DocumentMut>()
                .unwrap();
        set_provider_gateway(&mut config, "openai", "http://127.0.0.1:47781").unwrap();
        let encoded = config.to_string();

        assert!(encoded.contains("# keep this comment"), "{encoded}");
        let parsed = encoded.parse::<toml::Value>().unwrap();
        assert_eq!(
            parsed["openai_base_url"].as_str(),
            Some("http://127.0.0.1:47781")
        );
        assert_eq!(parsed["model_provider"].as_str(), Some("openai"));
        assert!(parsed["model_providers"]
            .get(crate::CODEX_GATEWAY_PROVIDER)
            .is_none());
    }

    #[test]
    fn stale_cleanup_only_accepts_generated_session_names() {
        assert!(generated_session_name(std::ffi::OsStr::new("123-456")));
        assert!(!generated_session_name(std::ffi::OsStr::new("123")));
        assert!(!generated_session_name(std::ffi::OsStr::new("../outside")));
        assert!(!generated_session_name(std::ffi::OsStr::new("123-current")));
    }

    #[test]
    fn stale_cleanup_keeps_live_sessions_and_removes_dead_ones() {
        let root = test_home("codex-stale-session-cleanup");
        let sessions = root.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let live = sessions.join(format!("{}-1", std::process::id()));
        let stale = sessions.join(format!("{}-2", u32::MAX));
        let unrelated = sessions.join("keep-me");
        std::fs::create_dir(&live).unwrap();
        std::fs::create_dir(&stale).unwrap();
        std::fs::create_dir(&unrelated).unwrap();

        cleanup_stale_session_homes(&sessions);

        assert!(live.exists());
        assert!(!stale.exists());
        assert!(unrelated.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    fn test_home(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "pentect-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn session_home_routes_only_the_app_and_keeps_shared_state_linked() {
        let root = test_home("codex-session-home");
        let original = "# keep this comment\nopenai_base_url = \"https://example.test/v1\"\n";
        std::fs::write(root.join("config.toml"), original).unwrap();
        std::fs::write(root.join("auth.json"), "{\"token\":\"local\"}").unwrap();
        std::fs::create_dir(root.join("sessions")).unwrap();
        std::fs::write(root.join("sessions").join("thread.jsonl"), "thread").unwrap();

        let session =
            CodexSessionHome::create_in(&root, "openai", "http://127.0.0.1:47781").unwrap();
        let session_path = session.path().to_path_buf();
        assert_eq!(
            std::fs::read_to_string(root.join("config.toml")).unwrap(),
            original
        );
        assert!(!root.join("config.toml.pentect-backup").exists());
        let session_config = std::fs::read_to_string(session.path().join("config.toml")).unwrap();
        assert!(session_config.contains("http://127.0.0.1:47781"));
        assert_eq!(
            std::fs::read_to_string(session.path().join("auth.json")).unwrap(),
            "{\"token\":\"local\"}"
        );
        assert_eq!(
            std::fs::read_to_string(session.path().join("sessions").join("thread.jsonl")).unwrap(),
            "thread"
        );
        drop(session);
        assert!(!session_path.exists());
        assert_eq!(
            std::fs::read_to_string(root.join("config.toml")).unwrap(),
            original
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_backup_is_restored_before_a_new_session() {
        let root = test_home("codex-legacy-backup");
        let original = "model = \"original\"\n";
        std::fs::write(root.join("config.toml"), "model = \"interrupted\"\n").unwrap();
        std::fs::write(root.join("config.toml.pentect-backup"), original).unwrap();
        recover_legacy_config_in(&root).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("config.toml")).unwrap(),
            original
        );
        assert!(!root.join("config.toml.pentect-backup").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_override_without_an_original_is_removed() {
        let root = test_home("codex-legacy-no-original");
        std::fs::write(root.join("config.toml"), "model = \"interrupted\"\n").unwrap();
        std::fs::write(root.join("config.toml.pentect-backup"), b"").unwrap();
        std::fs::write(root.join("config.toml.pentect-no-original"), b"").unwrap();
        recover_legacy_config_in(&root).unwrap();
        assert!(!root.join("config.toml").exists());
        assert!(!root.join("config.toml.pentect-backup").exists());
        assert!(!root.join("config.toml.pentect-no-original").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn orphaned_generated_gateway_is_removed_without_touching_other_settings() {
        let root = test_home("codex-orphaned-gateway");
        std::fs::write(
            root.join("config.toml"),
            r#"model = "gpt-5"
model_provider = "pentect-openai-gateway"

[model_providers.pentect-openai-gateway]
name = "OpenAI through Pentect"
base_url = "http://127.0.0.1:40495/v1"
wire_api = "responses"
requires_openai_auth = true
supports_websockets = false

[desktop]
theme = "dark"
"#,
        )
        .unwrap();
        recover_legacy_config_in(&root).unwrap();
        let recovered = std::fs::read_to_string(root.join("config.toml")).unwrap();
        assert!(!recovered.contains("pentect-openai-gateway"));
        assert!(recovered.contains("model = \"gpt-5\""));
        assert!(recovered.contains("theme = \"dark\""));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_config_is_never_replaced() {
        let root = test_home("codex-malformed-config");
        let malformed = "[not valid";
        std::fs::write(root.join("config.toml"), malformed).unwrap();
        assert!(CodexSessionHome::create_in(&root, "openai", "http://127.0.0.1:47781").is_err());
        assert!(!recover_legacy_config_in(&root).unwrap());
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
        assert!(CodexSessionHome::create_in(&root, "openai", "http://127.0.0.1:47781").is_err());
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "model = \"untouched\"\n"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn session_config_is_private() {
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
        let guard = CodexSessionHome::create_in(&root, "openai", "http://127.0.0.1:47781").unwrap();
        assert_eq!(
            std::fs::metadata(guard.path().join("config.toml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn config_lock_rejects_a_second_session_and_releases_on_drop() {
        let home = std::env::temp_dir().join(format!(
            "pentect-codex-app-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = CodexConfigLock::acquire_in(&home).unwrap();
        let error = CodexConfigLock::acquire_in(&home).unwrap_err();
        assert!(error.contains("another `pentect codex app` session is already active"));
        drop(first);
        let second = CodexConfigLock::acquire_in(&home).unwrap();
        drop(second);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn config_lock_ignores_stale_diagnostic_pid() {
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
