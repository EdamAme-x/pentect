use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::{Command, Stdio};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Install,
    Remove,
}

pub(crate) fn run_if_requested(tool: &str, args: &[String]) -> Result<Option<()>, String> {
    let Some((action, assume_yes, flag)) = parse_request(tool, args)? else {
        return Ok(None);
    };
    let target = launcher_target(tool)?;
    let verb = match action {
        Action::Install => "install",
        Action::Remove => "remove",
    };
    println!(
        "This will {verb} the Pentect launcher for {tool}.\nLauncher: {}",
        target.display()
    );
    if !assume_yes {
        if !io::stdin().is_terminal() {
            return Err(format!(
                "input is not interactive; rerun `pentect {tool} app {flag} --yes`"
            ));
        }
        print!("\nContinue? [y/N] ");
        io::stdout().flush().map_err(|error| error.to_string())?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(|error| error.to_string())?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("No changes made.");
            return Ok(Some(()));
        }
    }

    let changed = match action {
        Action::Install => install(tool, &target)?,
        Action::Remove => remove(tool, &target)?,
    };
    if changed {
        match action {
            Action::Install => {
                println!("Installed: {}", target.display());
                println!("Pin this launcher if you want quick protected App launches.");
            }
            Action::Remove => println!("Removed: {}", target.display()),
        }
    } else {
        match action {
            Action::Install => println!("The Pentect launcher is already installed."),
            Action::Remove => println!("No Pentect launcher was installed."),
        }
    }
    Ok(Some(()))
}

fn parse_request<'a>(
    tool: &str,
    args: &'a [String],
) -> Result<Option<(Action, bool, &'a str)>, String> {
    let legacy_command = format!("{tool}-app");
    let start = if args.get(1).is_some_and(|arg| arg == tool)
        && args.get(2).is_some_and(|arg| arg == "app")
    {
        3
    } else if args.get(1).is_some_and(|arg| arg == &legacy_command) {
        2
    } else {
        return Ok(None);
    };
    let Some(flag) = args.get(start).map(String::as_str) else {
        return Ok(None);
    };
    let action = match flag {
        "--install-launcher" => Action::Install,
        "--remove-launcher" => Action::Remove,
        _ => return Ok(None),
    };
    let mut assume_yes = false;
    for arg in &args[start + 1..] {
        match arg.as_str() {
            "--yes" if !assume_yes => assume_yes = true,
            _ => return Err(format!("unexpected option for {flag}: {arg}")),
        }
    }

    Ok(Some((action, assume_yes, flag)))
}

#[cfg(any(windows, target_os = "macos"))]
fn display_name(tool: &str) -> &'static str {
    match tool {
        "codex" => "Codex via Pentect",
        "claude" => "Claude via Pentect",
        _ => "AI App via Pentect",
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn app_executable(tool: &str) -> Option<PathBuf> {
    let path = match tool {
        "codex" => crate::codex_app::default_codex_app_path(),
        "claude" => crate::claude_app_proxy::default_claude_app_path(),
        _ => return None,
    };
    path.is_file().then_some(path)
}

#[cfg(windows)]
fn launcher_target(tool: &str) -> Result<PathBuf, String> {
    let app_data = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| "APPDATA is unavailable".to_string())?;
    Ok(app_data
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Pentect")
        .join(format!("{}.lnk", display_name(tool))))
}

#[cfg(target_os = "macos")]
fn launcher_target(tool: &str) -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is unavailable".to_string())?;
    Ok(home
        .join("Applications")
        .join(format!("{}.app", display_name(tool))))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn launcher_target(_tool: &str) -> Result<PathBuf, String> {
    Err("desktop App launchers are currently supported on Windows and macOS".into())
}

fn owner_marker(target: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        target.with_extension("pentect-launcher")
    }
    #[cfg(target_os = "macos")]
    {
        target
            .join("Contents")
            .join("Resources")
            .join("pentect-launcher")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        target.join("pentect-launcher")
    }
}

fn marker_contents(tool: &str) -> String {
    format!("pentect-app-launcher-v1\ntool={tool}\n")
}

fn is_owned(target: &Path, tool: &str) -> bool {
    fs::read_to_string(owner_marker(target)).is_ok_and(|value| value == marker_contents(tool))
}

#[cfg(any(windows, target_os = "macos"))]
fn launcher_executable() -> Result<PathBuf, String> {
    std::env::current_exe()
        .map_err(|error| format!("could not locate the Pentect executable: {error}"))
}

#[cfg(windows)]
fn install(tool: &str, target: &Path) -> Result<bool, String> {
    if target.exists() && !is_owned(target, tool) {
        return Err(format!(
            "refusing to replace launcher not owned by Pentect: '{}'; if this is an interrupted Pentect install, remove that bundle manually and try again",
            target.display()
        ));
    }
    let pentect = launcher_executable()?;
    let powershell = crate::windows_system_executable(r"WindowsPowerShell\v1.0\powershell.exe");
    if !powershell.is_file() {
        return Err(format!(
            "PowerShell was not found at '{}'",
            powershell.display()
        ));
    }
    let parent = target
        .parent()
        .ok_or_else(|| "launcher path has no parent directory".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create '{}': {error}", parent.display()))?;

    let command = format!(
        "& '{}' {tool} app; if ($LASTEXITCODE -ne 0) {{ (New-Object -ComObject WScript.Shell).Popup('Pentect could not start the protected App. Run pentect {tool} app in a terminal for details.',0,'Pentect',16) | Out-Null }}",
        pentect.to_string_lossy().replace('\'', "''")
    );
    let arguments =
        format!("-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -Command \"{command}\"");
    let description = match tool {
        "codex" => "Launch Codex App through Pentect",
        "claude" => "Launch Claude Desktop through Pentect",
        _ => "Launch an AI App through Pentect",
    };
    let icon = app_executable(tool).unwrap_or_else(|| pentect.clone());
    let script = concat!(
        "$w=New-Object -ComObject WScript.Shell;",
        "$s=$w.CreateShortcut($env:PENTECT_LAUNCHER_PATH);",
        "$s.TargetPath=$env:PENTECT_LAUNCHER_TARGET;",
        "$s.Arguments=$env:PENTECT_LAUNCHER_ARGS;",
        "$s.WorkingDirectory=$env:USERPROFILE;",
        "$s.Description=$env:PENTECT_LAUNCHER_DESCRIPTION;",
        "$s.IconLocation=$env:PENTECT_LAUNCHER_ICON;",
        "$s.Save()"
    );
    let status = Command::new(&powershell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .env("PENTECT_LAUNCHER_PATH", target)
        .env("PENTECT_LAUNCHER_TARGET", &powershell)
        .env("PENTECT_LAUNCHER_ARGS", arguments)
        .env("PENTECT_LAUNCHER_DESCRIPTION", description)
        .env("PENTECT_LAUNCHER_ICON", format!("{},0", icon.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("could not create the Windows launcher: {error}"))?;
    if !status.success() || !target.is_file() {
        return Err("Windows did not create the App launcher".into());
    }
    if let Err(error) = fs::write(owner_marker(target), marker_contents(tool)) {
        let _ = fs::remove_file(target);
        return Err(format!("could not record launcher ownership: {error}"));
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
fn install(tool: &str, target: &Path) -> Result<bool, String> {
    if target.exists() && !is_owned(target, tool) {
        return Err(format!(
            "refusing to replace launcher not owned by Pentect: '{}'",
            target.display()
        ));
    }
    let pentect = launcher_executable()?;
    let contents = target.join("Contents");
    let macos = contents.join("MacOS");
    let resources = contents.join("Resources");
    fs::create_dir_all(&macos)
        .and_then(|_| fs::create_dir_all(&resources))
        .map_err(|error| format!("could not create '{}': {error}", target.display()))?;
    let executable = macos.join("launch");
    let quoted = pentect.to_string_lossy().replace('\'', "'\\''");
    fs::write(&executable, format!(
        "#!/bin/sh\n'{quoted}' {tool} app\nstatus=$?\nif [ \"$status\" -ne 0 ]; then\n    osascript -e 'display notification \"Run pentect {tool} app in a terminal for details.\" with title \"Pentect could not start the protected App\"' >/dev/null 2>&1\nfi\nexit \"$status\"\n"
    ))
    .map_err(|error| format!("could not write '{}': {error}", executable.display()))?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("could not make '{}': {error}", executable.display()))?;
    let icon_name = copy_macos_app_icon(tool, &resources)?;
    let icon_entry = icon_name.map_or_else(String::new, |name| {
        format!("<key>CFBundleIconFile</key><string>{name}</string>")
    });
    let bundle_id = format!("dev.pentect.launcher.{tool}");
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>CFBundleExecutable</key><string>launch</string><key>CFBundleIdentifier</key><string>{bundle_id}</string><key>CFBundleName</key><string>{}</string><key>CFBundlePackageType</key><string>APPL</string>{icon_entry}</dict></plist>\n",
        display_name(tool)
    );
    fs::write(contents.join("Info.plist"), plist)
        .and_then(|_| fs::write(owner_marker(target), marker_contents(tool)))
        .map_err(|error| format!("could not finish '{}': {error}", target.display()))?;
    Ok(true)
}

#[cfg(target_os = "macos")]
fn copy_macos_app_icon(tool: &str, resources: &Path) -> Result<Option<String>, String> {
    let Some(executable) = app_executable(tool) else {
        return Ok(None);
    };
    let Some(contents) = executable.parent().and_then(Path::parent) else {
        return Ok(None);
    };
    let source_dir = contents.join("Resources");
    let Ok(entries) = fs::read_dir(source_dir) else {
        return Ok(None);
    };
    let Some(source) = entries.flatten().map(|entry| entry.path()).find(|path| {
        path.extension()
            .is_some_and(|extension| extension == "icns")
    }) else {
        return Ok(None);
    };
    let name = "AppIcon.icns";
    fs::copy(&source, resources.join(name))
        .map_err(|error| format!("could not copy App icon '{}': {error}", source.display()))?;
    Ok(Some(name.to_string()))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn install(_tool: &str, _target: &Path) -> Result<bool, String> {
    Err("desktop App launchers are currently supported on Windows and macOS".into())
}

fn remove(tool: &str, target: &Path) -> Result<bool, String> {
    if !target.exists() {
        #[cfg(windows)]
        {
            let marker = owner_marker(target);
            if fs::read_to_string(&marker).is_ok_and(|value| value == marker_contents(tool)) {
                fs::remove_file(&marker).map_err(|error| {
                    format!(
                        "could not remove stale launcher marker '{}': {error}",
                        marker.display()
                    )
                })?;
                return Ok(true);
            }
        }
        return Ok(false);
    }
    if !is_owned(target, tool) {
        return Err(format!(
            "refusing to remove launcher not owned by Pentect: '{}'; if this is an interrupted Pentect install, remove it manually",
            target.display()
        ));
    }
    #[cfg(windows)]
    {
        fs::remove_file(target)
            .map_err(|error| format!("could not remove '{}': {error}", target.display()))?;
        let marker = owner_marker(target);
        fs::remove_file(&marker)
            .map_err(|error| format!("could not remove '{}': {error}", marker.display()))?;
    }
    #[cfg(target_os = "macos")]
    {
        fs::remove_dir_all(target)
            .map_err(|error| format!("could not remove '{}': {error}", target.display()))?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_nested_and_legacy_routes() {
        let nested = vec![
            "pentect".into(),
            "codex".into(),
            "app".into(),
            "--install-launcher".into(),
        ];
        let legacy = vec![
            "pentect".into(),
            "claude-app".into(),
            "--remove-launcher".into(),
        ];
        assert_eq!(
            parse_request("codex", &nested).unwrap(),
            Some((Action::Install, false, "--install-launcher"))
        );
        assert_eq!(
            parse_request("claude", &legacy).unwrap(),
            Some((Action::Remove, false, "--remove-launcher"))
        );
        assert_eq!(parse_request("codex", &legacy).unwrap(), None);
    }

    #[test]
    fn ownership_marker_is_tool_specific() {
        assert_ne!(marker_contents("codex"), marker_contents("claude"));
        assert!(marker_contents("codex").starts_with("pentect-app-launcher-v1"));
    }

    #[cfg(windows)]
    #[test]
    fn creates_and_removes_a_real_windows_shortcut_in_a_temp_directory() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "pentect-app-launcher-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let target = directory.join("Codex via Pentect.lnk");

        assert!(install("codex", &target).unwrap());
        assert!(target.is_file());
        assert!(is_owned(&target, "codex"));
        assert!(install("claude", &target).is_err());
        assert!(remove("codex", &target).unwrap());
        assert!(!target.exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
