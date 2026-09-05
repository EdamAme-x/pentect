#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    root: std::path::PathBuf,
    wrapper: Option<Child>,
    group: Option<i32>,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "pentect-native-supervisor-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        Self {
            root,
            wrapper: None,
            group: None,
        }
    }

    fn stop_wrapper(&mut self) {
        if let Some(mut wrapper) = self.wrapper.take() {
            unsafe {
                libc::kill(wrapper.id() as i32, libc::SIGKILL);
            }
            let _ = wrapper.wait();
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop_wrapper();
        if let Some(group) = self.group {
            // The managed client is the group leader. Only clean this exact
            // fixture group while that leader identity still exists.
            if unsafe { libc::getpgid(group) } == group {
                unsafe {
                    libc::kill(-group, libc::SIGKILL);
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn wait_ready(path: &std::path::Path) -> (i32, i32, String) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let mut lines = contents.lines();
                return (
                    lines.next().unwrap().parse().unwrap(),
                    lines.next().unwrap().parse().unwrap(),
                    lines.next().unwrap_or_default().to_string(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("could not read readiness marker: {error}"),
        }
        assert!(Instant::now() < deadline, "client did not become ready");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_dead(pid: i32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while unsafe { libc::kill(pid, 0) } == 0 {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

#[test]
fn typed_native_clients_terminate_their_ordinary_process_groups() {
    for (client, flag, tail) in [
        ("codex", "--codex", Vec::<&str>::new()),
        ("opencode", "--opencode", vec!["auth"]),
        ("pi", "--pi", vec!["-p", "offline"]),
    ] {
        let mut fixture = Fixture::new(client);
        let home = fixture.root.join("home");
        let project = fixture.root.join("project");
        let runtime = fixture.root.join("runtime");
        let cache = fixture.root.join("cache");
        let state = fixture.root.join("state");
        let config = fixture.root.join("config");
        for directory in [&home, &project, &runtime, &cache, &state, &config] {
            std::fs::create_dir(directory).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::create_dir(home.join(".pentect")).unwrap();
        std::fs::create_dir(project.join(".git")).unwrap();
        std::fs::write(
            home.join(".pentect/config.toml"),
            "[update]\ncheck = false\n",
        )
        .unwrap();
        let ready = fixture.root.join("ready");
        let script = fixture.root.join("client.sh");
        std::fs::write(
            &script,
            r##"#!/bin/sh
(while :; do sleep 1; done) &
child=$!
settings=no
for arg in "$@"; do case "$arg" in --settings|--settings=*) settings=yes;; esac; done
temporary="$READY.tmp.$$"
printf '%s\n%s\n%s:%s:%s' "$$" "$child" "$PWD" "${PENTECT_MEMORY_STORE_TOKEN-unset}" "$settings" > "$temporary"
mv "$temporary" "$READY"
wait "$child"
"##,
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
        command
            .arg(client)
            .arg(flag)
            .arg(&script)
            .args(tail)
            .current_dir(&project)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("XDG_CACHE_HOME", cache)
            .env("XDG_STATE_HOME", state)
            .env("XDG_CONFIG_HOME", config)
            .env("PENTECT_LOG_DIR", fixture.root.join("log"))
            .env("PENTECT_MEMORY_STORE_TOKEN", "hostile-parent-token")
            .env("READY", &ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        fixture.wrapper = Some(command.spawn().unwrap());
        let (client_pid, child_pid, state) = wait_ready(&ready);
        fixture.group = Some(client_pid);
        assert_eq!(state, format!("{}:unset:no", project.display()));

        fixture.stop_wrapper();
        assert!(
            wait_dead(client_pid),
            "{client} client survived wrapper kill"
        );
        assert!(
            wait_dead(child_pid),
            "{client} descendant survived wrapper kill"
        );
        fixture.group = None;
    }
}
