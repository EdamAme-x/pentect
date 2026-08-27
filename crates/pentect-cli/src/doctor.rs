use crate::plugins;
use serde_json::json;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

pub(crate) fn cmd_doctor(args: &[String]) {
    let options = match parse_args(args) {
        Ok(value) => value,
        Err(e) => crate::die(e),
    };
    let mut checks = run_checks();
    if options.json {
        println!("{}", checks_json(&checks));
    } else {
        print_checks(&checks);
        if options.fix {
            apply_repairs(&checks, options.yes);
            checks = run_checks();
            println!("\nRechecking...");
            print_checks(&checks);
        }
    }
    if checks.iter().any(|check| check.status == Status::Fail) {
        std::process::exit(1);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DoctorOptions {
    json: bool,
    fix: bool,
    yes: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
    repair: Option<Repair>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Repair {
    AddToPath(PathBuf),
    MigrateConfig {
        path: PathBuf,
    },
    #[cfg(windows)]
    RemoveClaudeDesktopCa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Fail,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }
}

fn parse_args(args: &[String]) -> Result<DoctorOptions, String> {
    let mut options = DoctorOptions::default();
    for arg in &args[2..] {
        match arg.as_str() {
            "--json" => options.json = true,
            "--fix" => options.fix = true,
            "--yes" => options.yes = true,
            flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
            value => return Err(format!("unexpected argument for doctor: {value}")),
        }
    }
    if options.yes && !options.fix {
        return Err("doctor --yes requires --fix".to_string());
    }
    if options.json && options.fix {
        return Err("doctor --json is read-only and cannot be combined with --fix".to_string());
    }
    Ok(options)
}

fn run_checks() -> Vec<Check> {
    let mut checks = vec![check_pentect_binary(), check_path()];
    #[cfg(windows)]
    checks.push(check_claude_desktop_ca());
    checks.extend(check_configs());
    checks.extend([
        check_memory_store(),
        check_config_plugins(),
        check_ocr(),
        check_command("codex"),
        check_command("claude"),
    ]);
    checks
}

#[cfg(windows)]
fn check_claude_desktop_ca() -> Check {
    match crate::claude_app_proxy::windows_ca_cleanup_pending() {
        Ok(false) => Check::ok("claude-app-ca", "no stale temporary certificate"),
        Ok(true) => Check::repairable_warn(
            "claude-app-ca",
            "a previous Claude Desktop session left a temporary certificate",
            Repair::RemoveClaudeDesktopCa,
        ),
        Err(error) => Check::warn("claude-app-ca", error),
    }
}

fn check_pentect_binary() -> Check {
    match std::env::current_exe() {
        Ok(path) if path.is_file() => Check::ok("pentect", compact_path(&path)),
        Ok(path) => Check::fail("pentect", format!("not a file: {}", compact_path(&path))),
        Err(e) => Check::fail("pentect", e.to_string()),
    }
}

fn check_path() -> Check {
    let Ok(executable) = std::env::current_exe() else {
        return Check::warn("path", "could not locate the current executable");
    };
    let Some(directory) = executable.parent() else {
        return Check::warn("path", "the executable has no parent directory");
    };
    if path_contains(directory) {
        return Check::ok("path", "ready");
    }
    #[cfg(not(windows))]
    if std::env::var_os("SHELL")
        .and_then(|path| PathBuf::from(path).file_name().map(|name| name.to_owned()))
        .is_some_and(|name| name == "fish")
    {
        return Check::warn(
            "path",
            format!(
                "{} is not on PATH; run `fish_add_path {}`",
                directory.display(),
                directory.display()
            ),
        );
    }
    Check::repairable_warn(
        "path",
        format!("{} is not on PATH", directory.display()),
        Repair::AddToPath(directory.to_path_buf()),
    )
}

fn path_contains(directory: &Path) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|path| same_path(&path, directory)))
        .unwrap_or(false)
}

fn same_path(left: &Path, right: &Path) -> bool {
    if let (Ok(left), Ok(right)) = (left.canonicalize(), right.canonicalize()) {
        #[cfg(windows)]
        return left
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy());
        #[cfg(not(windows))]
        return left == right;
    }
    #[cfg(windows)]
    return left
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy());
    #[cfg(not(windows))]
    return left == right;
}

fn check_configs() -> Vec<Check> {
    let project = PathBuf::from(".pentect").join("config.toml");
    let global = home_dir().map(|home| home.join(".pentect").join("config.toml"));
    vec![
        check_config("config-project", project),
        global.map_or_else(
            || Check::warn("config-user", "home directory unavailable"),
            |path| check_config("config-user", path),
        ),
    ]
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let variable = "USERPROFILE";
    #[cfg(not(windows))]
    let variable = "HOME";
    std::env::var_os(variable).map(PathBuf::from)
}

fn check_config(name: &'static str, path: PathBuf) -> Check {
    if !path.exists() {
        return Check::ok(name, "defaults");
    }
    let source = match std::fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) => return Check::fail(name, format!("{}: {error}", path.display())),
    };
    match migrate_removed_config_keys(&source) {
        Ok(Some(_)) => Check::repairable_warn(
            name,
            format!("{} uses removed settings", path.display()),
            Repair::MigrateConfig { path },
        ),
        Ok(None) => Check::ok(name, "ready"),
        Err(error) => Check::fail(name, format!("{}: {error}", path.display())),
    }
}

fn migrate_removed_config_keys(source: &str) -> Result<Option<String>, String> {
    if source.trim().is_empty() {
        return Ok(None);
    }
    let mut document = source
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| format!("invalid TOML: {error}"))?;
    let mut changed = false;

    if table_has(&document, "handles", "hash_scope") {
        let scope = table_string(&document, "handles", "hash_scope")
            .ok_or_else(|| "handles.hash_scope must be a string".to_string())?;
        let scope = match scope.as_str() {
            "machine" | "device" => "device",
            "project" => "project",
            "session" => "session",
            _ => return Err("handles.hash_scope cannot be migrated automatically".to_string()),
        };
        let handles = ensure_table(&mut document, "handles")?;
        if !handles.contains_key("scope") {
            handles.insert("scope", toml_edit::value(scope));
        }
        handles.remove("hash_scope");
        changed = true;
    }

    if document.contains_key("require_pentect") {
        let value = document
            .get("require_pentect")
            .and_then(toml_edit::Item::as_bool)
            .ok_or_else(|| "require_pentect must be a boolean".to_string())?;
        let agent = ensure_table(&mut document, "agent")?;
        if !agent.contains_key("required") {
            agent.insert("required", toml_edit::value(value));
        }
        document.remove("require_pentect");
        changed = true;
    }
    if table_has(&document, "agent", "require_pentect") {
        let value = table_bool(&document, "agent", "require_pentect")
            .ok_or_else(|| "agent.require_pentect must be a boolean".to_string())?;
        let agent = ensure_table(&mut document, "agent")?;
        if !agent.contains_key("required") {
            agent.insert("required", toml_edit::value(value));
        }
        agent.remove("require_pentect");
        changed = true;
    }

    if table_has(&document, "image", "unscanned_images") {
        let value = table_string(&document, "image", "unscanned_images")
            .ok_or_else(|| "image.unscanned_images must be a string".to_string())?;
        if !matches!(value.as_str(), "allow" | "block") {
            return Err("image.unscanned_images cannot be migrated automatically".to_string());
        }
        let image = ensure_table(&mut document, "image")?;
        if !image.contains_key("unscanned") {
            image.insert("unscanned", toml_edit::value(value));
        }
        image.remove("unscanned_images");
        changed = true;
    }

    if document.contains_key("file_pointer_manager") {
        let legacy = document["file_pointer_manager"]
            .as_table_like()
            .ok_or_else(|| "file_pointer_manager must be a table".to_string())?;
        if legacy.len() != 1 || !legacy.contains_key("save") {
            return Err("file_pointer_manager cannot be migrated automatically".to_string());
        }
        let value = table_bool(&document, "file_pointer_manager", "save")
            .ok_or_else(|| "file_pointer_manager.save must be a boolean".to_string())?;
        let files = ensure_table(&mut document, "files")?;
        if !files.contains_key("remember") {
            files.insert("remember", toml_edit::value(value));
        }
        document.remove("file_pointer_manager");
        changed = true;
    }
    if document.contains_key("log") {
        let legacy = document["log"]
            .as_table_like()
            .ok_or_else(|| "log must be a table".to_string())?;
        if legacy.len() != 1 || !legacy.contains_key("share") {
            return Err("log cannot be migrated automatically".to_string());
        }
        let value = table_bool(&document, "log", "share")
            .ok_or_else(|| "log.share must be a boolean".to_string())?;
        let activity = ensure_table(&mut document, "activity")?;
        if !activity.contains_key("share") {
            activity.insert("share", toml_edit::value(value));
        }
        document.remove("log");
        changed = true;
    }

    Ok(changed.then(|| document.to_string()))
}

fn table_string(document: &toml_edit::DocumentMut, table: &str, key: &str) -> Option<String> {
    document
        .get(table)?
        .as_table_like()?
        .get(key)?
        .as_str()
        .map(str::to_string)
}

fn table_has(document: &toml_edit::DocumentMut, table: &str, key: &str) -> bool {
    document
        .get(table)
        .and_then(toml_edit::Item::as_table_like)
        .is_some_and(|table| table.contains_key(key))
}

fn table_bool(document: &toml_edit::DocumentMut, table: &str, key: &str) -> Option<bool> {
    document.get(table)?.as_table_like()?.get(key)?.as_bool()
}

fn ensure_table<'a>(
    document: &'a mut toml_edit::DocumentMut,
    name: &str,
) -> Result<&'a mut dyn toml_edit::TableLike, String> {
    if !document.contains_key(name) {
        document[name] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    document[name]
        .as_table_like_mut()
        .ok_or_else(|| format!("{name} config must be a table"))
}

fn check_memory_store() -> Check {
    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => return Check::fail("memory", e.to_string()),
    };
    let mut child = match Command::new(exe)
        .arg("agent")
        .arg("memory-store")
        .arg("--serve")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => return Check::fail("memory", e.to_string()),
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Check::fail("memory", "stdout unavailable");
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = tx.send(result);
    });
    let status = match rx.recv_timeout(Duration::from_secs(3)) {
        Ok(Ok(line)) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&line);
            match parsed {
                Ok(value)
                    if value.get("addr").and_then(|v| v.as_str()).is_some()
                        && value.get("token").and_then(|v| v.as_str()).is_some() =>
                {
                    Check::ok("memory", "ready")
                }
                Ok(_) => Check::fail("memory", "bad startup"),
                Err(_) => Check::fail("memory", "bad startup"),
            }
        }
        Ok(Err(e)) => Check::fail("memory", e.to_string()),
        Err(_) => Check::fail("memory", "timeout"),
    };
    let _ = child.kill();
    let _ = child.wait();
    status
}

fn check_config_plugins() -> Check {
    match plugins::active_from_specs(Vec::new(), true) {
        Ok(_) => Check::ok("plugins", "ready"),
        Err(e) => Check::fail("plugins", e.to_string()),
    }
}

fn check_ocr() -> Check {
    let status = pentect_agent::ocr_status();
    match status {
        "bundled" | "windows" | "macos" => Check::ok("ocr", status),
        "disabled" => Check::warn("ocr", "disabled"),
        "unsupported" => Check::warn("ocr", "unsupported"),
        status => Check::warn("ocr", status),
    }
}

fn check_command(name: &'static str) -> Check {
    match find_command(name) {
        Some(path) => Check::ok(name, compact_path(&path)),
        None => Check::warn(name, "not found"),
    }
}

fn find_command(name: &str) -> Option<PathBuf> {
    let path = Path::new(name);
    if path.is_file() {
        return Some(path.to_path_buf());
    }
    let paths = std::env::var_os("PATH")?;
    let candidates = command_names(name);
    for dir in std::env::split_paths(&paths) {
        for candidate in &candidates {
            let full = dir.join(candidate);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

fn print_checks(checks: &[Check]) {
    for check in checks {
        println!("{}: {} {}", check.name, check.status.as_str(), check.detail);
    }
}

fn apply_repairs(checks: &[Check], assume_yes: bool) {
    let repairs = checks
        .iter()
        .filter_map(|check| check.repair.as_ref().map(|repair| (check.name, repair)))
        .collect::<Vec<_>>();
    if repairs.is_empty() {
        println!("\nNo safe automatic fixes are available.");
        return;
    }
    if !assume_yes && !std::io::stdin().is_terminal() {
        println!("\nInput is not interactive. Rerun with `pentect doctor --fix --yes` to apply safe fixes.");
        return;
    }
    for (name, repair) in repairs {
        let apply = assume_yes || confirm(&format!("I can {}. Fix it?", repair.description()));
        if !apply {
            println!("{name}: skipped");
            continue;
        }
        match repair.apply() {
            Ok(detail) => println!("{name}: fixed {detail}"),
            Err(error) => println!("{name}: fix failed {error}"),
        }
    }
}

fn confirm(prompt: &str) -> bool {
    print!("\n{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .is_ok_and(|_| matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

impl Repair {
    fn description(&self) -> String {
        match self {
            Self::AddToPath(directory) => {
                format!("add '{}' to your user PATH", directory.display())
            }
            Self::MigrateConfig { path } => format!(
                "back up '{}' and migrate its removed setting names",
                path.display()
            ),
            #[cfg(windows)]
            Self::RemoveClaudeDesktopCa => {
                "remove the stale temporary Claude Desktop certificate".to_string()
            }
        }
    }

    fn apply(&self) -> Result<String, String> {
        match self {
            Self::AddToPath(directory) => add_to_user_path(directory),
            Self::MigrateConfig { path } => migrate_config_file(path),
            #[cfg(windows)]
            Self::RemoveClaudeDesktopCa => {
                crate::claude_app_proxy::cleanup_stale_windows_user_ca()?;
                Ok("removed the stale temporary Claude Desktop certificate".to_string())
            }
        }
    }
}

fn migrate_config_file(path: &Path) -> Result<String, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read '{}': {error}", path.display()))?;
    let Some(content) = migrate_removed_config_keys(&source)? else {
        return Ok("(already migrated)".to_string());
    };
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let backup = path.with_extension(format!("toml.pentect-backup-{nonce}"));
    std::fs::copy(path, &backup)
        .map_err(|error| format!("could not back up '{}': {error}", path.display()))?;
    if let Err(error) = std::fs::write(path, &content) {
        let _ = std::fs::copy(&backup, path);
        return Err(format!("could not update '{}': {error}", path.display()));
    }
    Ok(format!("(backup: {})", backup.display()))
}

#[cfg(windows)]
fn add_to_user_path(directory: &Path) -> Result<String, String> {
    const SCRIPT: &str = r#"$ErrorActionPreference='Stop'
$dir=$env:PENTECT_DOCTOR_PATH_DIR
$key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment',$true)
if ($null -eq $key) { throw 'could not open HKCU\Environment' }
try {
  try { $kind=$key.GetValueKind('Path') } catch { $kind=[Microsoft.Win32.RegistryValueKind]::ExpandString }
  $user=$key.GetValue('Path','',[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  $parts=if ($user -is [string[]]) { @($user) } else { @(([string]$user) -split ';' | Where-Object { $_ }) }
if (-not ($parts | Where-Object { $_.TrimEnd('\') -ieq $dir.TrimEnd('\') })) {
    $parts=@($parts)+$dir
    $value=if ($kind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) { [string[]]$parts } else { $parts -join ';' }
    $key.SetValue('Path',$value,$kind)
  }
} finally { $key.Dispose() }"#;
    let output = Command::new(crate::windows_system_executable(
        r"WindowsPowerShell\v1.0\powershell.exe",
    ))
    .args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        SCRIPT,
    ])
    .env("PENTECT_DOCTOR_PATH_DIR", directory)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .output()
    .map_err(|error| format!("could not update the user PATH: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if detail.is_empty() {
            "PowerShell could not update the user PATH".to_string()
        } else {
            format!("PowerShell could not update the user PATH: {detail}")
        });
    }
    update_process_path(directory)?;
    Ok("restart open terminals to inherit the updated PATH".to_string())
}

#[cfg(not(windows))]
fn add_to_user_path(directory: &Path) -> Result<String, String> {
    let home = home_dir().ok_or_else(|| "home directory unavailable".to_string())?;
    let shell = std::env::var_os("SHELL")
        .and_then(|path| PathBuf::from(path).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.to_str().map(str::to_string))
        .unwrap_or_else(|| "sh".to_string());
    if shell == "fish" {
        return Err("fish PATH changes require a manual `fish_add_path`".to_string());
    }
    let profiles = match shell.as_str() {
        "zsh" => vec![home.join(".zprofile"), home.join(".zshrc")],
        "bash" => vec![
            if home.join(".bash_profile").exists() {
                home.join(".bash_profile")
            } else {
                home.join(".profile")
            },
            home.join(".bashrc"),
        ],
        _ => vec![home.join(".profile")],
    };
    let marker = "# Added by `pentect doctor --fix`";
    for profile in &profiles {
        append_path_profile(profile, directory, marker)?;
    }
    update_process_path(directory)?;
    let names = profiles
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Ok(format!(
        "restart login and interactive shells to load {names}"
    ))
}

#[cfg(not(windows))]
fn append_path_profile(profile: &Path, directory: &Path, marker: &str) -> Result<(), String> {
    if std::fs::symlink_metadata(profile).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(format!(
            "refusing to modify symlink '{}'",
            profile.display()
        ));
    }
    let existing = std::fs::read_to_string(profile).unwrap_or_default();
    if existing.contains(marker) {
        return Ok(());
    }
    let line = format!(
        "{marker}\nexport PATH={}:\"$PATH\"\n",
        shell_single_quote(&directory.to_string_lossy())
    );
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(profile)
        .map_err(|error| format!("could not open '{}': {error}", profile.display()))?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(file).map_err(|error| error.to_string())?;
    }
    file.write_all(line.as_bytes())
        .map_err(|error| format!("could not update '{}': {error}", profile.display()))
}

#[cfg(not(windows))]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn update_process_path(directory: &Path) -> Result<(), String> {
    let current = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::iter::once(directory.to_path_buf()).chain(std::env::split_paths(&current));
    let joined = std::env::join_paths(paths).map_err(|error| error.to_string())?;
    std::env::set_var("PATH", joined);
    Ok(())
}

#[cfg(windows)]
fn command_names(name: &str) -> Vec<String> {
    let has_ext = Path::new(name).extension().is_some();
    if has_ext {
        return vec![name.to_string()];
    }
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    pathext
        .split(';')
        .filter(|ext| !ext.is_empty())
        .map(|ext| format!("{name}{ext}"))
        .collect()
}

#[cfg(not(windows))]
fn command_names(name: &str) -> Vec<String> {
    vec![name.to_string()]
}

fn checks_json(checks: &[Check]) -> String {
    json!({
        "checks": checks.iter().map(|check| json!({
            "name": check.name,
            "status": check.status.as_str(),
            "detail": check.detail,
            "fixable": check.repair.is_some(),
        })).collect::<Vec<_>>()
    })
    .to_string()
}

fn compact_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| path.display().to_string())
}

impl Check {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Ok,
            detail: detail.into(),
            repair: None,
        }
    }

    fn warn(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Warn,
            detail: detail.into(),
            repair: None,
        }
    }

    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Fail,
            detail: detail.into(),
            repair: None,
        }
    }

    fn repairable_warn(name: &'static str, detail: impl Into<String>, repair: Repair) -> Self {
        Self {
            name,
            status: Status::Warn,
            detail: detail.into(),
            repair: Some(repair),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_rejects_positionals() {
        let args = vec!["pentect".into(), "doctor".into(), "codex".into()];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn doctor_accepts_json() {
        let args = vec!["pentect".into(), "doctor".into(), "--json".into()];
        assert!(parse_args(&args).unwrap().json);
    }

    #[test]
    fn doctor_fix_flags_are_explicit() {
        let args = vec![
            "pentect".into(),
            "doctor".into(),
            "--fix".into(),
            "--yes".into(),
        ];
        assert_eq!(
            parse_args(&args).unwrap(),
            DoctorOptions {
                fix: true,
                yes: true,
                json: false,
            }
        );
        let invalid = vec![
            "pentect".into(),
            "doctor".into(),
            "--json".into(),
            "--fix".into(),
        ];
        assert!(parse_args(&invalid).is_err());
        let yes_only = vec!["pentect".into(), "doctor".into(), "--yes".into()];
        assert!(parse_args(&yes_only).is_err());
    }

    #[test]
    fn ambiguous_removed_settings_are_reported() {
        assert!(migrate_removed_config_keys("[handles]\nhash_scope = \"team\"\n").is_err());
        assert!(migrate_removed_config_keys("[handles]\nhash_scope = 1\n").is_err());
        assert!(migrate_removed_config_keys("not = = toml").is_err());
    }

    #[test]
    fn inline_removed_config_tables_migrate() {
        let source = concat!(
            "file_pointer_manager = { save = false }\n",
            "log = { share = true }\n",
            "agent = { require_pentect = true }\n",
            "handles = { hash_scope = \"machine\" }\n",
        );
        let migrated = migrate_removed_config_keys(source).unwrap().unwrap();
        assert!(migrated.contains("remember = false"), "{migrated}");
        assert!(migrated.contains("share = true"), "{migrated}");
        assert!(migrated.contains("required = true"), "{migrated}");
        assert!(migrated.contains("scope = \"device\""), "{migrated}");
    }

    #[test]
    fn removed_config_keys_migrate_without_losing_unrelated_settings() {
        let source = r#"# keep this comment
plugins = ["jp-pii"]
require_pentect = true

[handles]
hash_scope = "machine"

[image]
unscanned_images = "block"

[file_pointer_manager]
save = false

[log]
share = true
"#;
        let migrated = migrate_removed_config_keys(source).unwrap().unwrap();
        assert!(migrated.contains("# keep this comment"));
        assert!(migrated.contains("plugins = [\"jp-pii\"]"));
        assert!(migrated.contains("scope = \"device\""));
        assert!(migrated.contains("unscanned = \"block\""));
        assert!(migrated.contains("[agent]"));
        assert!(migrated.contains("required = true"));
        assert!(migrated.contains("[files]"));
        assert!(migrated.contains("remember = false"));
        assert!(migrated.contains("[activity]"));
        assert!(migrated.contains("share = true"));
        for removed in [
            "require_pentect",
            "hash_scope",
            "unscanned_images",
            "file_pointer_manager",
            "[log]",
        ] {
            assert!(!migrated.contains(removed), "{removed}: {migrated}");
        }
        assert!(migrate_removed_config_keys(&migrated).unwrap().is_none());
    }

    #[test]
    fn config_repair_keeps_a_recoverable_backup() {
        let root = std::env::temp_dir().join(format!(
            "pentect-doctor-repair-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.toml");
        let original = "[handles]\nhash_scope = \"machine\"\n";
        std::fs::write(&path, original).unwrap();
        let migrated = migrate_removed_config_keys(original).unwrap().unwrap();
        let detail = migrate_config_file(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), migrated);
        let backup = detail
            .strip_prefix("(backup: ")
            .and_then(|value| value.strip_suffix(')'))
            .map(PathBuf::from)
            .unwrap();
        assert_eq!(std::fs::read_to_string(backup).unwrap(), original);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn doctor_reports_ocr_status() {
        let check = check_ocr();
        assert_eq!(check.name, "ocr");
        match check.detail.as_str() {
            "bundled" | "windows" | "macos" => assert_eq!(check.status, Status::Ok),
            "disabled" | "unsupported" => assert_eq!(check.status, Status::Warn),
            other => panic!("unexpected ocr detail: {other}"),
        }
    }
}
