#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const AUTHORITY_ENV: &[&str] = &[
    "PENTECT_MEMORY_STORE_ADDR",
    "PENTECT_MEMORY_STORE_TOKEN",
    "PENTECT_AGENT_LAUNCHED",
    "PENTECT_PROCESS_HOST_ROOT",
    "PENTECT_PROCESS_HOST_READ_TOKEN",
    "PENTECT_PROCESS_HOST_WRITE_TOKEN",
];

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "pentect-claude-boundary-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn wait_bounded(mut child: Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().unwrap(),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "protected Claude boundary fixture timed out: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("could not wait for protected Claude fixture: {error}");
            }
        }
    }
}

fn generated_root(home: &Path, runtime: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Caches/pentect/private/claude-settings-v1")
    } else {
        runtime.join("pentect/private/claude-settings-v1")
    }
}

#[test]
fn actual_noninteractive_claude_keeps_guardian_authority_out_of_client() {
    let root = test_root();
    let _cleanup = Cleanup(root.clone());
    let home = root.join("home");
    let project = root.join("project");
    let runtime = root.join("runtime");
    let temporary = root.join("tmp");
    for directory in [&home, &project, &runtime, &temporary] {
        std::fs::create_dir_all(directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::create_dir(project.join(".git")).unwrap();
    let config = home.join(".config/pentect");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("config.toml"), "[update]\ncheck = false\n").unwrap();

    let input_settings = root.join("caller-settings.json");
    let input_bytes = br#"{"env":{"PENTECT_BOUNDARY_SENTINEL":"synthetic-only"}}"#;
    std::fs::write(&input_settings, input_bytes).unwrap();
    let report = root.join("client-report.json");
    let fd_control = root.join("fd-control");
    std::fs::write(&fd_control, b"descriptor-enumeration-control").unwrap();
    let probe = root.join("claude-probe.py");
    std::fs::write(
        &probe,
        r#"#!/usr/bin/env python3
import json
import os
import stat
import sys

settings = None
for index, argument in enumerate(sys.argv[1:]):
    if argument == "--settings" and index + 2 <= len(sys.argv[1:]):
        settings = sys.argv[index + 2]
    elif argument.startswith("--settings="):
        settings = argument.split("=", 1)[1]

fd_root = "/proc/self/fd" if os.path.isdir("/proc/self/fd") else "/dev/fd"
positive = open(os.environ["FD_CONTROL"], "rb")
owner = os.stat(os.path.join(os.path.dirname(settings), "owner.lock"))
descriptors = []
for name in os.listdir(fd_root):
    if not name.isdigit() or int(name) < 3:
        continue
    try:
        info = os.fstat(int(name))
    except OSError:
        continue
    descriptors.append({
        "fd": int(name),
        "socket": stat.S_ISSOCK(info.st_mode),
        "owner_lock": (info.st_dev, info.st_ino) == (owner.st_dev, owner.st_ino),
    })

authority = {}
for name in (
    "PENTECT_MEMORY_STORE_ADDR",
    "PENTECT_MEMORY_STORE_TOKEN",
    "PENTECT_AGENT_LAUNCHED",
    "PENTECT_PROCESS_HOST_ROOT",
    "PENTECT_PROCESS_HOST_READ_TOKEN",
    "PENTECT_PROCESS_HOST_WRITE_TOKEN",
):
    authority[name] = name in os.environ

payload = {
    "settings": settings,
    "settings_exists": bool(settings and os.path.isfile(settings)),
    "descriptors": descriptors,
    "positive_fd": positive.fileno(),
    "authority": authority,
    "untrusted": os.environ.get("PENTECT_UNTRUSTED_CLIENT"),
}
temporary = os.environ["REPORT"] + ".tmp"
with open(temporary, "x", encoding="utf-8") as output:
    json.dump(payload, output, separators=(",", ":"))
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, os.environ["REPORT"])
raise SystemExit(37)
"#,
    )
    .unwrap();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o700)).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command
        .args(["claude", "--claude"])
        .arg(&probe)
        .args(["--upstream", "http://127.0.0.1:9", "--", "--settings"])
        .arg(&input_settings)
        .current_dir(&project)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_STATE_HOME", home.join(".local/state"))
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("TMP", &temporary)
        .env("TEMP", &temporary)
        .env("TMPDIR", &temporary)
        .env("REPORT", &report)
        .env("FD_CONTROL", &fd_control)
        .env("PENTECT_DISABLE_UPDATE_CHECK", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in AUTHORITY_ENV {
        command.env(name, "hostile-inherited-value");
    }

    let output = wait_bounded(command.spawn().unwrap(), Duration::from_secs(20));
    assert_eq!(
        output.status.code(),
        Some(37),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(value["settings_exists"], true);
    let generated = PathBuf::from(value["settings"].as_str().unwrap());
    let expected_root = std::fs::canonicalize(generated_root(&home, &runtime))
        .expect("generated Claude settings root was not created");
    assert!(
        generated.starts_with(&expected_root),
        "generated settings path {} is outside expected root {}",
        generated.display(),
        expected_root.display()
    );
    assert!(!generated.exists());
    assert_eq!(std::fs::read(&input_settings).unwrap(), input_bytes);
    assert_eq!(value["untrusted"], "1");
    assert!(value["descriptors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|descriptor| {
            descriptor["fd"] == value["positive_fd"]
                && descriptor["socket"] == false
                && descriptor["owner_lock"] == false
        }));
    for name in AUTHORITY_ENV {
        assert_eq!(value["authority"][name], false, "client inherited {name}");
    }
    for descriptor in value["descriptors"].as_array().unwrap() {
        assert_eq!(
            descriptor["socket"], false,
            "client inherited a control socket"
        );
        assert_eq!(
            descriptor["owner_lock"], false,
            "client inherited the settings owner lease"
        );
    }
}
