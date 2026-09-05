#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn root() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pentect-claude-guardian-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

#[test]
fn noninteractive_guardian_preserves_status_and_cleans_after_wrapper_sigkill() {
    let root = root();
    let runtime = root.join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let ready = root.join("ready");
    let script = root.join("client.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nif [ \"$1\" = exit37 ]; then exit 37; fi\nlast=\nfor arg in \"$@\"; do last=$arg; done\nprintf '%s\\n%s\\n' \"$$\" \"$last\" > \"$READY\"\nwhile :; do sleep 1; done\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pentect = env!("CARGO_BIN_EXE_pentect");

    let status = Command::new(pentect)
        .args([
            "__test-claude-unix-wrapper",
            script.to_str().unwrap(),
            "exit37",
        ])
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("READY", &ready)
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(37));

    let mut wrapper = Command::new(pentect)
        .args([
            "__test-claude-unix-wrapper",
            script.to_str().unwrap(),
            "block",
        ])
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("READY", &ready)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let lines = std::fs::read_to_string(&ready).unwrap();
    let mut lines = lines.lines();
    let client: i32 = lines.next().unwrap().parse().unwrap();
    let settings = std::path::PathBuf::from(lines.next().unwrap());
    assert!(settings.is_file());
    unsafe {
        libc::kill(wrapper.id() as i32, libc::SIGKILL);
    }
    wrapper.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while unsafe { libc::kill(client, 0) } == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_ne!(unsafe { libc::kill(client, 0) }, 0);
    assert!(!settings.exists());

    std::fs::remove_file(ready).unwrap();
    std::fs::remove_file(script).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
