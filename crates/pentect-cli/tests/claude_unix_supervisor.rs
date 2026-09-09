#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

struct FixtureRoot(std::path::PathBuf);

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn id(&self) -> u32 {
        self.0.as_ref().expect("child already reaped").id()
    }

    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.0.take().expect("child already reaped").wait()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn root() -> FixtureRoot {
    let path = std::env::temp_dir().join(format!(
        "pentect-claude-guardian-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&path).unwrap();
    FixtureRoot(path)
}

fn wait_for_ready(path: &std::path::Path) -> Result<(i32, std::path::PathBuf), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let mut lines = contents.lines();
                let client = lines
                    .next()
                    .ok_or_else(|| "READY is missing the client PID".to_string())?
                    .parse::<i32>()
                    .map_err(|error| format!("invalid client PID in READY: {error}"))?;
                let settings = lines
                    .next()
                    .filter(|line| !line.is_empty())
                    .ok_or_else(|| "READY is missing the settings path".to_string())?;
                return Ok((client, settings.into()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("failed to read READY: {error}")),
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for READY".to_string());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn noninteractive_guardian_preserves_status_and_cleans_after_wrapper_sigkill() {
    let root = root();
    let runtime = root.0.join("runtime");
    let home = root.0.join("home");
    let cache = root.0.join("cache");
    let state = root.0.join("state");
    let config = root.0.join("config");
    for directory in [&runtime, &home, &cache, &state, &config] {
        std::fs::create_dir(directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let ready = root.0.join("ready");
    let script = root.0.join("client.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nsettings=\nnext=0\nfor arg in \"$@\"; do [ \"$arg\" = slow37 ] && { sleep 6; exit 37; }; [ \"$arg\" = catchint ] && trap '' INT; if [ \"$next\" = 1 ]; then settings=$arg; next=0; elif [ \"$arg\" = --settings ]; then next=1; fi; done\ntemporary=$READY.tmp.$$\nprintf '%s\\n%s\\n' \"$$\" \"$settings\" > \"$temporary\"\nmv \"$temporary\" \"$READY\"\nwhile :; do sleep 1; done\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pentect = env!("CARGO_BIN_EXE_pentect");

    let mut normal = ChildGuard::new(
        Command::new(pentect)
            .args(["claude", "--claude", script.to_str().unwrap(), "slow37"])
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("XDG_CACHE_HOME", &cache)
            .env("XDG_STATE_HOME", &state)
            .env("XDG_CONFIG_HOME", &config)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("READY", &ready)
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let status = normal.wait().unwrap();
    assert_eq!(status.code(), Some(37));

    let mut wrapper = ChildGuard::new(
        Command::new(pentect)
            .args(["claude", "--claude", script.to_str().unwrap(), "block"])
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("XDG_CACHE_HOME", &cache)
            .env("XDG_STATE_HOME", &state)
            .env("XDG_CONFIG_HOME", &config)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("READY", &ready)
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let (client, settings) = wait_for_ready(&ready).unwrap();
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
    let deadline = Instant::now() + Duration::from_secs(10);
    while settings.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!settings.exists());

    std::fs::remove_file(&ready).unwrap();
    let mut interrupted = ChildGuard::new(
        Command::new(pentect)
            .args(["claude", "--claude", script.to_str().unwrap(), "catchint"])
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("XDG_CACHE_HOME", &cache)
            .env("XDG_STATE_HOME", &state)
            .env("XDG_CONFIG_HOME", &config)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("READY", &ready)
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let (_, interrupted_settings) = wait_for_ready(&ready).unwrap();
    unsafe {
        libc::kill(interrupted.id() as i32, libc::SIGINT);
    }
    let status = interrupted.wait().unwrap();
    assert_eq!(status.code(), Some(137));
    assert!(!interrupted_settings.exists());
}
