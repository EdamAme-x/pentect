use std::path::Path;

pub(crate) fn cmd_uninstall(args: &[String]) {
    if let Err(error) = uninstall(args) {
        crate::die(error);
    }
}

fn uninstall(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err("usage: pentect uninstall".to_string());
    }
    if let Err(error) = crate::codex_app::recover_legacy_config() {
        eprintln!("pentect: warning: could not recover legacy Codex App config: {error}");
    }
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate the installed executable: {error}"))?;
    if let Some(installation) = crate::installation::installation_for_executable(&executable)? {
        if !installation.is_self_managed() {
            return Err(installation.uninstall_message());
        }
    }
    validate_executable_name(&executable)?;
    let install_dir = executable
        .parent()
        .ok_or_else(|| "installed executable has no parent directory".to_string())?;
    let marker = install_dir.join(crate::installation::INSTALL_MARKER);

    #[cfg(windows)]
    {
        spawn_windows_uninstall_helper(&executable, &marker)?;
        println!("pentect: uninstall scheduled");
        println!("pentect: project configuration and plugin data were kept");
    }
    #[cfg(not(windows))]
    {
        remove_update_backups(install_dir, &executable)?;
        std::fs::remove_file(&executable)
            .map_err(|error| format!("could not remove '{}': {error}", executable.display()))?;
        let _ = std::fs::remove_file(&marker);
        remove_empty_install_dir(install_dir);
        println!("pentect: uninstalled {}", executable.display());
        println!("pentect: project configuration and plugin data were kept");
    }
    Ok(())
}

fn validate_executable_name(path: &Path) -> Result<(), String> {
    let name = path.file_name().and_then(|name| name.to_str());
    if matches!(name, Some("pentect" | "pentect.exe")) {
        Ok(())
    } else {
        Err(format!(
            "refusing to uninstall unexpected executable '{}'",
            path.display()
        ))
    }
}

#[cfg(not(windows))]
fn remove_update_backups(install_dir: &Path, executable: &Path) -> Result<(), String> {
    let Some(name) = executable.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    let prefix = format!("{name}.previous-");
    let entries = std::fs::read_dir(install_dir)
        .map_err(|error| format!("could not inspect '{}': {error}", install_dir.display()))?;
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|candidate| candidate.starts_with(&prefix))
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn remove_empty_install_dir(install_dir: &Path) {
    if std::fs::read_dir(install_dir)
        .ok()
        .is_some_and(|mut entries| entries.next().is_none())
    {
        let _ = std::fs::remove_dir(install_dir);
    }
}

#[cfg(windows)]
fn spawn_windows_uninstall_helper(executable: &Path, marker: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const SCRIPT: &str = r#"param(
    [Parameter(Mandatory=$true)][int]$ParentPid,
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$Marker
)
$ErrorActionPreference = 'SilentlyContinue'
for ($attempt = 0; $attempt -lt 3000; $attempt++) {
    if (-not (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 100
}
$installDir = Split-Path -Parent $Target
$updatesQuiesced = $false
for ($attempt = 0; $attempt -lt 3000; $attempt++) {
    $updateRunning = Get-Process -Name 'pentect.update-*' -ErrorAction SilentlyContinue |
        Where-Object {
            try { [string]::Equals((Split-Path -Parent $_.Path), $installDir, [StringComparison]::OrdinalIgnoreCase) }
            catch { $false }
        } |
        Select-Object -First 1
    $stagedUpdates = @(Get-ChildItem -LiteralPath $installDir -Filter 'pentect.update-*.exe' -File)
    if (($null -eq $updateRunning) -and ($stagedUpdates.Count -eq 0)) {
        $updatesQuiesced = $true
        break
    }
    Start-Sleep -Milliseconds 100
}
if (-not $updatesQuiesced) { exit 1 }
$pathAdded = $false
if (Test-Path -LiteralPath $Marker) {
    try { $pathAdded = [bool]((Get-Content -Raw -LiteralPath $Marker | ConvertFrom-Json).path_added) } catch {}
}
for ($attempt = 0; $attempt -lt 600; $attempt++) {
    Remove-Item -LiteralPath $Target -Force
    if (-not (Test-Path -LiteralPath $Target)) {
        # An update helper may have passed its process check but not completed
        # the final copy yet. Require a short quiet period before declaring the
        # target gone so a late replacement is removed as well.
        $remainedAbsent = $true
        for ($quiet = 0; $quiet -lt 20; $quiet++) {
            Start-Sleep -Milliseconds 100
            if (Test-Path -LiteralPath $Target) {
                $remainedAbsent = $false
                break
            }
        }
        if ($remainedAbsent) { break }
    }
    Start-Sleep -Milliseconds 100
}
if (Test-Path -LiteralPath $Target) { exit 1 }
$name = Split-Path -Leaf $Target
Get-ChildItem -LiteralPath $installDir -Filter "$name.previous-*" -File | Remove-Item -Force
Get-ChildItem -LiteralPath $installDir -Filter 'pentect.update-*.exe' -File | Remove-Item -Force
Remove-Item -LiteralPath $Marker -Force
if ($pathAdded) {
    $pathKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    if ($null -ne $pathKey) {
        try {
            try { $pathKind = $pathKey.GetValueKind('Path') } catch { $pathKind = [Microsoft.Win32.RegistryValueKind]::ExpandString }
            $userPath = $pathKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $parts = if ($userPath -is [string[]]) {
                @($userPath | Where-Object { $_ -and $_.TrimEnd('\') -ine $installDir.TrimEnd('\') })
            } else {
                @(([string]$userPath) -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -ine $installDir.TrimEnd('\') })
            }
            $nextPath = if ($pathKind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) { [string[]]$parts } else { $parts -join ';' }
            $pathKey.SetValue('Path', $nextPath, $pathKind)
        } finally {
            $pathKey.Dispose()
        }
    }
}
if ((Test-Path -LiteralPath $installDir) -and -not (Get-ChildItem -LiteralPath $installDir -Force | Select-Object -First 1)) {
    Remove-Item -LiteralPath $installDir -Force
}
Remove-Item -LiteralPath $PSCommandPath -Force
"#;

    let helper = std::env::temp_dir().join(format!(
        "pentect-uninstall-{}-{}.ps1",
        std::process::id(),
        timestamp_suffix()
    ));
    std::fs::write(&helper, SCRIPT)
        .map_err(|error| format!("could not create uninstall helper: {error}"))?;
    Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-File",
        ])
        .arg(&helper)
        .arg("-ParentPid")
        .arg(std::process::id().to_string())
        .arg("-Target")
        .arg(executable)
        .arg("-Marker")
        .arg(marker)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("could not start uninstall helper: {error}"))
}

#[cfg(windows)]
fn timestamp_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_accepts_the_public_command_shape() {
        assert!(uninstall(&["pentect".into()]).is_err());
        assert!(uninstall(&["pentect".into(), "uninstall".into(), "extra".into()]).is_err());
    }

    #[test]
    fn validates_only_pentect_executable_names() {
        assert!(validate_executable_name(Path::new("pentect")).is_ok());
        assert!(validate_executable_name(Path::new("pentect.exe")).is_ok());
        assert!(validate_executable_name(Path::new("other.exe")).is_err());
    }

    #[test]
    fn reads_managed_path_ownership_marker() {
        let marker: serde_json::Value = serde_json::from_str(r#"{"path_added":true}"#).unwrap();
        assert_eq!(marker["path_added"], true);
    }
}
