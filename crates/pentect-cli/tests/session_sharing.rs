#![cfg(unix)]

use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "pentect-session-sharing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("work/.git")).unwrap();
        std::fs::create_dir_all(root.join("work/.pentect")).unwrap();
        std::fs::write(
            root.join("work/.pentect/config.toml"),
            "[update]\ncheck = false\n",
        )
        .unwrap();
        Self(root)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_capture(root: &Path, fixed: bool) -> (Vec<String>, Value) {
    let capture = root.join(if fixed { "fixed" } else { "picker" });
    std::fs::create_dir_all(&capture).unwrap();
    let client = root.join("fake-opencode");
    std::fs::write(
        &client,
        "#!/bin/sh\nprintf '%s\\n' \"$OPENCODE_CONFIG_CONTENT\" > \"$CAPTURE/config\"\nprintf '%s\\n' \"$@\" > \"$CAPTURE/args\"\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&client).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&client, permissions).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command
        .current_dir(root.join("work"))
        .args(["opencode", "--tool"])
        .arg(&client);
    if fixed {
        command.arg("--model=openai/gpt-5");
    }
    let output = command
        .args(["--print-logs", "export", "session-canary", "--no-sanitize"])
        .env("CAPTURE", &capture)
        .env(
            "OPENCODE_CONFIG_CONTENT",
            r#"{"share":"auto","autoshare":true}"#,
        )
        .env_remove("PENTECT_HOME")
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env("LOCALAPPDATA", root.join("local"))
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_STATE_HOME", root.join("state"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");

    let args = std::fs::read_to_string(capture.join("args"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let config = serde_json::from_str(
        std::fs::read_to_string(capture.join("config"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    (args, config)
}

#[test]
fn fixed_and_picker_dispatch_capture_sanitized_export_and_disabled_sharing() {
    let fixture = Fixture::new();
    for fixed in [false, true] {
        let (args, config) = run_capture(&fixture.0, fixed);
        assert_eq!(
            args,
            [
                "--print-logs",
                "export",
                "session-canary",
                "--sanitize=true"
            ]
        );
        assert_eq!(config["share"], "disabled");
        assert_eq!(config["autoshare"], false);
    }
}
