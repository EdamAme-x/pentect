use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Set,
    Unset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShellKind {
    PowerShell,
    Pwsh,
    Bash,
    Zsh,
    Fish,
}

pub(crate) fn run_if_requested(tool: &str, args: &[String]) -> Result<Option<()>, String> {
    let Some(first) = args.first().map(String::as_str) else {
        return Ok(None);
    };
    let action = match first {
        "--set-default" => Action::Set,
        "--unset-default" => Action::Unset,
        _ => return Ok(None),
    };
    if !matches!(tool, "codex" | "claude") {
        return Err(format!("--set-default is not supported for {tool}"));
    }

    let mut assume_yes = false;
    for arg in &args[1..] {
        match arg.as_str() {
            "--yes" if !assume_yes => assume_yes = true,
            _ => return Err(format!("unexpected option for {first}: {arg}")),
        }
    }

    let shell = detect_shell()?;
    let profile = profile_path(shell)?;
    let definition = definition(shell, tool);
    let verb = match action {
        Action::Set => "make",
        Action::Unset => "stop making",
    };
    println!(
        "This will {verb} `{tool}` launch through Pentect by default.\nProfile: {}",
        profile.display()
    );
    if action == Action::Set {
        println!("\n{definition}");
    }

    if !assume_yes {
        if !io::stdin().is_terminal() {
            return Err(format!(
                "input is not interactive; rerun `pentect {tool} {first} --yes`"
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

    match update_profile(&profile, tool, &definition, action)? {
        ProfileUpdate::Changed { backup } => {
            match action {
                Action::Set => println!("`{tool}` now launches through Pentect by default."),
                Action::Unset => {
                    println!("`{tool}` no longer launches through Pentect by default.")
                }
            }
            if let Some(backup) = backup {
                println!("Backup: {}", backup.display());
            }
            println!("Restart the terminal to apply the change.");
        }
        ProfileUpdate::Unchanged => match action {
            Action::Set => println!("`{tool}` already launches through Pentect by default."),
            Action::Unset => println!("No Pentect default was configured for `{tool}`."),
        },
    }
    Ok(Some(()))
}

#[derive(Debug, PartialEq, Eq)]
enum ProfileUpdate {
    Changed { backup: Option<PathBuf> },
    Unchanged,
}

fn update_profile(
    profile: &Path,
    tool: &str,
    definition: &str,
    action: Action,
) -> Result<ProfileUpdate, String> {
    let existing = match fs::read_to_string(profile) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("could not read '{}': {error}", profile.display())),
    };
    let newline = if existing.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let start = format!("# >>> pentect {tool} default >>>");
    let end = format!("# <<< pentect {tool} default <<<");
    let updated = match action {
        Action::Set => install_block(&existing, &start, &end, definition, newline)?,
        Action::Unset => remove_block(&existing, &start, &end)?,
    };
    let Some(updated) = updated else {
        return Ok(ProfileUpdate::Unchanged);
    };

    if fs::symlink_metadata(profile).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(format!(
            "refusing to modify symlink '{}'; add or remove the shown block manually",
            profile.display()
        ));
    }
    if let Some(parent) = profile.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create '{}': {error}", parent.display()))?;
    }

    let backup = if profile.is_file() {
        let backup = backup_path(profile);
        fs::copy(profile, &backup).map_err(|error| {
            format!(
                "could not back up '{}' to '{}': {error}",
                profile.display(),
                backup.display()
            )
        })?;
        Some(backup)
    } else {
        None
    };
    if let Err(error) = write_profile_atomically(profile, updated.as_bytes()) {
        if let Some(backup) = &backup {
            let _ = fs::copy(backup, profile);
        }
        return Err(format!("could not update '{}': {error}", profile.display()));
    }
    Ok(ProfileUpdate::Changed { backup })
}

fn write_profile_atomically(profile: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = profile.parent().unwrap_or_else(|| Path::new("."));
    let name = profile
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("profile");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let staging = parent.join(format!(
        ".{name}.pentect-staging-{}-{nonce}",
        std::process::id()
    ));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)?;
        file.write_all(contents)?;
        file.sync_all()?;
        if let Ok(metadata) = fs::metadata(profile) {
            fs::set_permissions(&staging, metadata.permissions())?;
        }
        atomic_replace(&staging, profile)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staging);
    }
    result
}

#[cfg(not(windows))]
fn atomic_replace(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

#[cfg(windows)]
fn atomic_replace(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    let moved = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn install_block(
    existing: &str,
    start: &str,
    end: &str,
    definition: &str,
    newline: &str,
) -> Result<Option<String>, String> {
    let block = format!("{start}{newline}{definition}{newline}{end}");
    match marker_range(existing, start, end)? {
        Some((from, to)) => {
            if existing[from..to] == block {
                Ok(None)
            } else {
                let mut updated = existing.to_string();
                updated.replace_range(from..to, &block);
                Ok(Some(updated))
            }
        }
        None => {
            let mut updated = existing.to_string();
            if !updated.is_empty() && !updated.ends_with('\n') {
                updated.push_str(newline);
            }
            updated.push_str(&block);
            updated.push_str(newline);
            Ok(Some(updated))
        }
    }
}

fn remove_block(existing: &str, start: &str, end: &str) -> Result<Option<String>, String> {
    let Some((from, mut to)) = marker_range(existing, start, end)? else {
        return Ok(None);
    };
    if existing[to..].starts_with("\r\n") {
        to += 2;
    } else if existing[to..].starts_with('\n') {
        to += 1;
    }
    let mut updated = existing.to_string();
    updated.replace_range(from..to, "");
    Ok(Some(updated))
}

fn marker_range(existing: &str, start: &str, end: &str) -> Result<Option<(usize, usize)>, String> {
    let start_at = existing.find(start);
    let end_at = existing.find(end);
    match (start_at, end_at) {
        (None, None) => Ok(None),
        (Some(start_at), Some(end_at)) if end_at >= start_at => {
            let to = end_at + end.len();
            let inside = &existing[start_at + start.len()..end_at];
            if inside.contains(start)
                || inside.contains(end)
                || existing[to..].contains(start)
                || existing[to..].contains(end)
            {
                return Err(
                    "multiple Pentect default blocks found; edit the profile manually".into(),
                );
            }
            Ok(Some((start_at, to)))
        }
        _ => Err("incomplete Pentect default block found; edit the profile manually".into()),
    }
}

fn backup_path(profile: &Path) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = profile
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("profile");
    profile.with_file_name(format!("{name}.pentect-backup-{nonce}"))
}

fn definition(shell: ShellKind, tool: &str) -> String {
    match shell {
        ShellKind::PowerShell | ShellKind::Pwsh => {
            format!("function global:{tool} {{ & pentect {tool} @args }}")
        }
        ShellKind::Bash | ShellKind::Zsh => {
            format!(r#"{tool}() {{ command pentect {tool} "$@"; }}"#)
        }
        ShellKind::Fish => format!("function {tool}\n    command pentect {tool} $argv\nend"),
    }
}

fn shell_kind_from_name(name: &str) -> Option<ShellKind> {
    let name = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    match name.as_str() {
        "powershell" | "powershell.exe" => Some(ShellKind::PowerShell),
        "pwsh" | "pwsh.exe" => Some(ShellKind::Pwsh),
        "bash" | "bash.exe" => Some(ShellKind::Bash),
        "zsh" | "zsh.exe" => Some(ShellKind::Zsh),
        "fish" | "fish.exe" => Some(ShellKind::Fish),
        _ => None,
    }
}

fn detect_shell() -> Result<ShellKind, String> {
    let ancestry = shell_from_process_ancestry()?;
    let login_shell = std::env::var_os("SHELL").map(|value| value.to_string_lossy().into_owned());
    select_shell(ancestry, login_shell.as_deref())
}

fn select_shell(
    ancestry: Option<ShellKind>,
    login_shell: Option<&str>,
) -> Result<ShellKind, String> {
    if let Some(shell) = ancestry {
        return Ok(shell);
    }
    if let Some(shell) = login_shell.and_then(shell_kind_from_name) {
        return Ok(shell);
    }
    Err("could not detect the shell; use Bash, Zsh, Fish, or PowerShell".into())
}

fn shell_from_process_ancestry() -> Result<Option<ShellKind>, String> {
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut pid = sysinfo::get_current_pid().map_err(|error| error.to_string())?;
    for _ in 0..8 {
        let Some(process) = system.process(pid) else {
            break;
        };
        if let Some(shell) = shell_kind_from_name(&process.name().to_string_lossy()) {
            return Ok(Some(shell));
        }
        let Some(parent) = process.parent() else {
            break;
        };
        pid = parent;
    }
    Ok(None)
}

#[cfg(windows)]
fn profile_path(shell: ShellKind) -> Result<PathBuf, String> {
    if matches!(shell, ShellKind::Bash | ShellKind::Zsh | ShellKind::Fish) {
        return posix_profile_path(shell);
    }
    let executable = powershell_executable(shell)?;
    let output = Command::new(&executable)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [Console]::Write($PROFILE.CurrentUserAllHosts)",
        ])
        .output()
        .map_err(|error| format!("could not query the PowerShell profile: {error}"))?;
    if !output.status.success() {
        return Err("could not query the PowerShell profile".into());
    }
    let path = String::from_utf8(output.stdout)
        .map_err(|_| "PowerShell returned a non-UTF-8 profile path".to_string())?;
    let path = path.trim();
    if path.is_empty() {
        return Err("PowerShell returned an empty profile path".into());
    }
    let path = PathBuf::from(path);
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(format!(
            "{} returned an invalid profile path",
            executable.display()
        ));
    }
    Ok(path)
}

#[cfg(windows)]
fn powershell_executable(shell: ShellKind) -> Result<PathBuf, String> {
    if shell == ShellKind::PowerShell {
        let path = crate::windows_system_executable(r"WindowsPowerShell\v1.0\powershell.exe");
        return path
            .is_file()
            .then_some(path)
            .ok_or_else(|| "Windows PowerShell was not found".to_string());
    }

    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut pid = sysinfo::get_current_pid().map_err(|error| error.to_string())?;
    for _ in 0..8 {
        let Some(process) = system.process(pid) else {
            break;
        };
        if matches!(
            process
                .name()
                .to_string_lossy()
                .to_ascii_lowercase()
                .as_str(),
            "pwsh" | "pwsh.exe"
        ) {
            if let Some(path) = process
                .exe()
                .filter(|path| path.is_absolute() && path.is_file())
            {
                return Ok(path.to_path_buf());
            }
        }
        let Some(parent) = process.parent() else {
            break;
        };
        pid = parent;
    }
    Err("could not locate the PowerShell executable that launched Pentect".to_string())
}

#[cfg(not(windows))]
fn profile_path(shell: ShellKind) -> Result<PathBuf, String> {
    posix_profile_path(shell)
}

fn posix_profile_path(shell: ShellKind) -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is unavailable".to_string())?;
    match shell {
        ShellKind::Bash => Ok(home.join(".bashrc")),
        ShellKind::Zsh => Ok(home.join(".zshrc")),
        ShellKind::Fish => Ok(home.join(".config").join("fish").join("config.fish")),
        ShellKind::PowerShell | ShellKind::Pwsh => {
            Err("PowerShell profiles require Windows".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_windows_and_posix_shell_process_names() {
        assert_eq!(shell_kind_from_name("bash.exe"), Some(ShellKind::Bash));
        assert_eq!(
            shell_kind_from_name(r"C:\Program Files\PowerShell\7\pwsh.exe"),
            Some(ShellKind::Pwsh)
        );
        assert_eq!(shell_kind_from_name("/usr/bin/zsh"), Some(ShellKind::Zsh));
        assert_eq!(shell_kind_from_name("cmd.exe"), None);
    }

    #[test]
    fn current_process_shell_precedes_login_shell_with_a_fallback() {
        assert_eq!(
            select_shell(Some(ShellKind::Bash), Some("/bin/zsh")).unwrap(),
            ShellKind::Bash
        );
        assert_eq!(
            select_shell(None, Some("/bin/fish")).unwrap(),
            ShellKind::Fish
        );
        assert!(select_shell(None, None).is_err());
        assert!(select_shell(None, Some("/bin/unsupported-shell")).is_err());
    }

    #[test]
    fn installs_updates_and_removes_one_owned_block() {
        let start = "# >>> pentect codex default >>>";
        let end = "# <<< pentect codex default <<<";
        let original = "export EDITOR=vim\n";
        let installed = install_block(
            original,
            start,
            end,
            r#"codex() { command pentect codex "$@"; }"#,
            "\n",
        )
        .unwrap()
        .unwrap();
        assert!(installed.starts_with(original));
        assert!(installed.contains("command pentect codex"));
        assert!(install_block(
            &installed,
            start,
            end,
            r#"codex() { command pentect codex "$@"; }"#,
            "\n",
        )
        .unwrap()
        .is_none());
        assert_eq!(
            remove_block(&installed, start, end).unwrap().unwrap(),
            original
        );
    }

    #[test]
    fn preserves_crlf_when_installing() {
        let installed = install_block(
            "# profile\r\n",
            "# >>> pentect claude default >>>",
            "# <<< pentect claude default <<<",
            "function global:claude { & pentect claude @args }",
            "\r\n",
        )
        .unwrap()
        .unwrap();
        assert!(!installed.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn rejects_incomplete_or_duplicate_markers() {
        let start = "# >>> pentect codex default >>>";
        let end = "# <<< pentect codex default <<<";
        assert!(marker_range(start, start, end).is_err());
        assert!(marker_range(&format!("{start}\n{end}\n{start}\n{end}"), start, end).is_err());
    }

    #[test]
    fn updates_a_profile_with_a_backup_and_removes_only_its_block() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "pentect-default-launch-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let profile = directory.join("profile");
        fs::write(&profile, "# user content\n").unwrap();

        let installed = update_profile(
            &profile,
            "codex",
            r#"codex() { command pentect codex "$@"; }"#,
            Action::Set,
        )
        .unwrap();
        let ProfileUpdate::Changed {
            backup: Some(backup),
        } = installed
        else {
            panic!("expected a changed profile with a backup");
        };
        assert_eq!(fs::read_to_string(backup).unwrap(), "# user content\n");
        assert!(fs::read_to_string(&profile)
            .unwrap()
            .contains("command pentect codex"));

        update_profile(&profile, "codex", "unused", Action::Unset).unwrap();
        assert_eq!(fs::read_to_string(&profile).unwrap(), "# user content\n");
        fs::remove_dir_all(directory).unwrap();
    }
}
