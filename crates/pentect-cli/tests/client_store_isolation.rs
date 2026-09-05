#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const AUTHORITY_ENV: &[&str] = &[
    "PENTECT_MEMORY_STORE_ADDR",
    "PENTECT_MEMORY_STORE_TOKEN",
    "PENTECT_AGENT_LAUNCHED",
    "PENTECT_PROCESS_HOST_ROOT",
    "PENTECT_PROCESS_HOST_READ_TOKEN",
    "PENTECT_PROCESS_HOST_WRITE_TOKEN",
];

#[test]
fn supported_clients_and_their_descendants_do_not_inherit_store_authority() {
    let root = test_root();
    std::fs::create_dir_all(root.join("home/.pentect")).unwrap();
    std::fs::create_dir_all(root.join("project/.git")).unwrap();
    for directory in ["local-app-data", "runtime", "cache", "state"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    std::fs::write(
        root.join("home/.pentect/config.toml"),
        "[update]\ncheck = false\n",
    )
    .unwrap();
    let probe = root.join("client-probe.sh");
    std::fs::write(
        &probe,
        r#"#!/bin/sh
level=${PENTECT_PROBE_DEPTH:-client}
for name in PENTECT_MEMORY_STORE_ADDR PENTECT_MEMORY_STORE_TOKEN PENTECT_AGENT_LAUNCHED PENTECT_PROCESS_HOST_ROOT PENTECT_PROCESS_HOST_READ_TOKEN PENTECT_PROCESS_HOST_WRITE_TOKEN; do
  eval "present=\${$name+set}"
  printf '%s:%s:%s\n' "$level" "$name" "${present:-unset}"
done
printf '%s:PENTECT_UNTRUSTED_CLIENT:%s\n' "$level" "${PENTECT_UNTRUSTED_CLIENT:-unset}"
case "$level" in
  client) PENTECT_PROBE_DEPTH=child /bin/sh "$0" ;;
  child) PENTECT_PROBE_DEPTH=grandchild /bin/sh "$0" ;;
esac
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&probe).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&probe, permissions).unwrap();
    let _cleanup = Cleanup(root.clone());

    for (client, path_flag) in [
        ("codex", "--codex"),
        ("claude", "--claude"),
        ("opencode", "--opencode"),
        ("pi", "--pi"),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
        command
            .args([client, path_flag])
            .arg(&probe)
            .current_dir(root.join("project"))
            .env("HOME", root.join("home"))
            .env("USERPROFILE", root.join("home"))
            .env("LOCALAPPDATA", root.join("local-app-data"))
            .env("XDG_RUNTIME_DIR", root.join("runtime"))
            .env("XDG_CACHE_HOME", root.join("cache"))
            .env("XDG_STATE_HOME", root.join("state"))
            .env("OPENAI_BASE_URL", "http://127.0.0.1:9/v1")
            .env("ANTHROPIC_BASE_URL", "http://127.0.0.1:9")
            .env("PENTECT_DISABLE_UPDATE_CHECK", "1")
            .stdin(Stdio::null());
        for name in AUTHORITY_ENV {
            command.env(name, "hostile-inherited-value");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{client}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        for level in ["client", "child", "grandchild"] {
            for name in AUTHORITY_ENV {
                assert!(
                    stdout.contains(&format!("{level}:{name}:unset")),
                    "{client} {level} inherited {name}: {stdout}"
                );
            }
            assert!(
                stdout.contains(&format!("{level}:PENTECT_UNTRUSTED_CLIENT:1")),
                "{client} {level} lost client marker: {stdout}"
            );
        }
    }
}

#[test]
fn nested_helpers_fail_before_running_or_starting_a_store() {
    let root = test_root();
    std::fs::create_dir_all(root.join("home/.pentect")).unwrap();
    std::fs::create_dir_all(root.join("project/.git")).unwrap();
    for directory in ["local-app-data", "runtime", "cache", "state"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    std::fs::write(
        root.join("home/.pentect/config.toml"),
        "[update]\ncheck = false\n",
    )
    .unwrap();
    let _cleanup = Cleanup(root.clone());
    let marker = root.join("must-not-run");

    let output = Command::new(env!("CARGO_BIN_EXE_pentect"))
        .args(["exec", "--", "/usr/bin/touch"])
        .arg(&marker)
        .current_dir(root.join("project"))
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env("LOCALAPPDATA", root.join("local-app-data"))
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("PENTECT_UNTRUSTED_CLIENT", "1")
        .env("PENTECT_DISABLE_UPDATE_CHECK", "1")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(!marker.exists());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("unavailable inside a Pentect-launched client"));
    assert!(stderr.contains("normal shell, file, or MCP tools"));
}

fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "pentect-client-store-isolation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
