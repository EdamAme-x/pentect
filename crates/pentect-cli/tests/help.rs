use std::process::Command;

fn test_home() -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("pentect-cli-help-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn built_in_subcommands_support_both_help_flags() {
    let home = test_home();
    let commands: &[&[&str]] = &[
        &["doctor"],
        &["exec"],
        &["log"],
        &["mask"],
        &["metrics"],
        &["plugins"],
        &["read"],
        &["resolve"],
        &["uninstall"],
        &["update"],
        &["view"],
        &["codex", "app"],
        &["claude", "app"],
    ];
    for command in commands {
        for flag in ["--help", "-h"] {
            let output = Command::new(env!("CARGO_BIN_EXE_pentect"))
                .args(*command)
                .arg(flag)
                .env("PENTECT_HOME", &home)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{command:?} {flag} exited {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("Usage:"),
                "{command:?} {flag} did not print command help"
            );
        }
    }
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn plugin_actions_support_both_help_flags() {
    let home = test_home();
    for action in [
        "add", "config", "dev", "inspect", "list", "new", "publish", "remove", "search", "setup",
        "test", "update",
    ] {
        for flag in ["--help", "-h"] {
            let output = Command::new(env!("CARGO_BIN_EXE_pentect"))
                .args(["plugins", action, flag])
                .env("PENTECT_HOME", &home)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "plugins {action} {flag} exited {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains(&format!("Usage: pentect plugins {action}")),
                "plugins {action} {flag} did not print action help"
            );
        }
    }
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn unknown_command_names_the_invalid_command() {
    let home = test_home();
    let output = Command::new(env!("CARGO_BIN_EXE_pentect"))
        .arg("clade")
        .env("PENTECT_HOME", &home)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("[pentect] unknown command: clade"));
    std::fs::remove_dir_all(home).unwrap();
}
