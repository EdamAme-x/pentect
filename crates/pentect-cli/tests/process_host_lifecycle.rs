use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn one_shot_process_host_is_removed_after_command_exit() {
    run_and_assert_clean(exec_args(), "exec", false);
}

#[test]
fn process_host_is_removed_after_argument_error() {
    run_and_assert_clean(vec!["exec", "--plugins"], "argument-error", false);
}

#[cfg(windows)]
#[test]
fn process_host_initialization_error_is_reported_without_a_panic() {
    let root = test_root("init-error");
    std::fs::create_dir_all(&root).unwrap();
    let blocker = root.join("not-a-directory");
    std::fs::write(&blocker, b"x").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pentect"))
        .args(exec_args())
        .env("LOCALAPPDATA", &blocker)
        .env_remove("PENTECT_PROCESS_HOST_ROOT")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("[pentect]"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    let _ = std::fs::remove_dir_all(root);
}

fn run_and_assert_clean(args: Vec<&'static str>, suffix: &str, stale_store: bool) {
    let root = test_root(suffix);
    std::fs::create_dir_all(&root).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command.args(args);
    command.env("PENTECT_BIN", env!("CARGO_BIN_EXE_pentect"));
    command.env("PENTECT_PROCESS_HOST_ROOT", root.join("untrusted-override"));
    command.env("PENTECT_PLUGIN_CONFIGS", root.join("untrusted-plugin.toml"));
    let process_host_root = configure_runtime_root(&mut command, &root);
    if stale_store {
        command.env("PENTECT_MEMORY_STORE_ADDR", "127.0.0.1:9");
        command.env("PENTECT_MEMORY_STORE_TOKEN", "stale-token");
        command.env("PENTECT_PROCESS_HOST_READ_TOKEN", "stale-read-token");
        command.env("PENTECT_PROCESS_HOST_WRITE_TOKEN", "stale-write-token");
        command.env("PENTECT_AGENT_LAUNCHED", "stale-token");
    } else {
        for name in [
            "PENTECT_MEMORY_STORE_ADDR",
            "PENTECT_MEMORY_STORE_TOKEN",
            "PENTECT_PROCESS_HOST_READ_TOKEN",
            "PENTECT_PROCESS_HOST_WRITE_TOKEN",
            "PENTECT_AGENT_LAUNCHED",
        ] {
            command.env_remove(name);
        }
    }

    let output = command.output().unwrap();
    if suffix != "argument-error" {
        assert!(
            output.status.success(),
            "stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        assert_eq!(output.status.code(), Some(2));
    }
    let runtime = process_host_root.join("runtime");
    assert!(
        !runtime.exists() || std::fs::read_dir(&runtime).unwrap().next().is_none(),
        "process host metadata remained in {}",
        runtime.display()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
fn configure_runtime_root(command: &mut Command, root: &std::path::Path) -> PathBuf {
    command.env("LOCALAPPDATA", root);
    root.join("pentect")
}

#[cfg(target_os = "macos")]
fn configure_runtime_root(command: &mut Command, root: &std::path::Path) -> PathBuf {
    command.env("HOME", root);
    root.join("Library").join("Caches").join("pentect")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn configure_runtime_root(command: &mut Command, root: &std::path::Path) -> PathBuf {
    command.env("XDG_RUNTIME_DIR", root);
    root.join("pentect")
}

#[cfg(windows)]
fn exec_args() -> Vec<&'static str> {
    vec![
        "exec",
        "--",
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Write-Output OK",
    ]
}

#[cfg(not(windows))]
fn exec_args() -> Vec<&'static str> {
    vec!["exec", "--", "sh", "-c", "printf OK"]
}

fn test_root(suffix: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "pentect-process-host-lifecycle-{}-{suffix}-{stamp}",
        std::process::id(),
    ))
}
