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
    let home = root.join("home");
    let cache = root.join("cache");
    let state = root.join("state");
    let config = root.join("config");
    for directory in [&runtime, &home, &cache, &state, &config] {
        std::fs::create_dir(directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let ready = root.join("ready");
    let script = root.join("client.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nsettings=\nnext=0\nfor arg in \"$@\"; do [ \"$arg\" = slow37 ] && { sleep 6; exit 37; }; if [ \"$next\" = 1 ]; then settings=$arg; next=0; elif [ \"$arg\" = --settings ]; then next=1; fi; done\nprintf '%s\\n%s\\n' \"$$\" \"$settings\" > \"$READY\"\nwhile :; do sleep 1; done\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pentect = env!("CARGO_BIN_EXE_pentect");

    let status = Command::new(pentect)
        .args([
            "__test-claude-unix-wrapper",
            script.to_str().unwrap(),
            "slow37",
        ])
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_CONFIG_HOME", &config)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
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
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_CONFIG_HOME", &config)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
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
