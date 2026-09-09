#![cfg(target_os = "linux")]

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Root(PathBuf);

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct ProcessGuard {
    fd: OwnedFd,
}

impl ProcessGuard {
    fn open(pid: i32) -> Self {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        assert!(
            fd >= 0,
            "pidfd_open({pid}) failed: {}",
            std::io::Error::last_os_error()
        );
        Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        }
    }

    fn alive(&self) -> bool {
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        match unsafe { libc::poll(&mut poll, 1, 0) } {
            0 => true,
            1 => false,
            result => panic!(
                "pidfd poll returned {result}: {}",
                std::io::Error::last_os_error()
            ),
        }
    }

    fn kill(&self) {
        if self.alive() {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            assert_eq!(
                result,
                0,
                "pidfd_send_signal failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    fn kill_best_effort(&self) {
        if self.alive() {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
    }

    fn wait_dead(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while self.alive() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        !self.alive()
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        self.kill_best_effort();
        let _ = self.wait_dead(Duration::from_secs(5));
    }
}

fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "pentect-claude-guardian-loss-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn process_parent(pid: i32) -> Option<i32> {
    let value = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, suffix) = value.rsplit_once(") ")?;
    suffix.split_whitespace().nth(1)?.parse().ok()
}

fn process_children(parent: i32) -> Vec<i32> {
    let mut children = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        if process_parent(pid) == Some(parent) {
            children.push(pid);
        }
    }
    children
}

fn wait_report(path: &Path, wrapper: &mut Child, timeout: Duration) -> (i32, PathBuf) {
    let deadline = Instant::now() + timeout;
    while !path.is_file() && Instant::now() < deadline {
        assert!(
            wrapper.try_wait().unwrap().is_none(),
            "wrapper exited before client readiness"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let value = std::fs::read_to_string(path).expect("client did not publish readiness");
    let mut lines = value.lines();
    (
        lines.next().unwrap().parse().unwrap(),
        PathBuf::from(lines.next().unwrap()),
    )
}

fn wait_child(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let status = child.wait().unwrap();
            panic!("wrapper timed out with {status}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn protected_command(root: &Path, script: &Path, report: &Path, mode: &str) -> Command {
    let home = root.join("home");
    let runtime = root.join("runtime");
    let temporary = root.join("tmp");
    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command
        .args(["claude", "--claude"])
        .arg(script)
        .args(["--upstream", "http://127.0.0.1:9", "--", "--settings"])
        .arg(root.join("caller-settings.json"))
        .arg(mode)
        .current_dir(root.join("project"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_STATE_HOME", home.join(".local/state"))
        .env("XDG_RUNTIME_DIR", runtime)
        .env("TMP", &temporary)
        .env("TEMP", &temporary)
        .env("TMPDIR", temporary)
        .env("REPORT", report)
        .env("PENTECT_DISABLE_UPDATE_CHECK", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[test]
fn guardian_loss_preserves_live_client_settings_as_unreleased() {
    let root = test_root();
    let _root = Root(root.clone());
    for directory in [
        root.join("home/.config/pentect"),
        root.join("project/.git"),
        root.join("runtime"),
        root.join("tmp"),
    ] {
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(
        root.join("home/.config/pentect/config.toml"),
        "[update]\ncheck = false\n",
    )
    .unwrap();
    let input = br#"{"env":{"PENTECT_GUARDIAN_LOSS_SENTINEL":"synthetic-only"}}"#;
    std::fs::write(root.join("caller-settings.json"), input).unwrap();
    let script = root.join("claude-fixture.py");
    std::fs::write(
        &script,
        r#"#!/usr/bin/env python3
import os
import signal
import sys

settings = None
mode = None
arguments = sys.argv[1:]
for index, argument in enumerate(arguments):
    if argument == "--settings":
        settings = arguments[index + 1]
    elif argument in ("block", "once"):
        mode = argument
temporary = os.environ["REPORT"] + ".tmp"
with open(temporary, "x", encoding="utf-8") as output:
    output.write(f"{os.getpid()}\n{settings}\n")
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, os.environ["REPORT"])
if mode == "once":
    raise SystemExit(37)
while True:
    signal.pause()
"#,
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();

    let first_report = root.join("first-report");
    let mut wrapper = ChildGuard(
        protected_command(&root, &script, &first_report, "block")
            .spawn()
            .unwrap(),
    );
    let (client_pid, settings) =
        wait_report(&first_report, &mut wrapper.0, Duration::from_secs(10));
    let client = ProcessGuard::open(client_pid);
    let guardian_pid = process_parent(client_pid).expect("client has no guardian parent");
    assert_eq!(process_parent(guardian_pid), Some(wrapper.0.id() as i32));
    let guardian = ProcessGuard::open(guardian_pid);
    let guardian_children = process_children(guardian_pid);
    assert_eq!(
        guardian_children.len(),
        2,
        "unexpected guardian process tree"
    );
    assert!(guardian_children.contains(&client_pid));
    let relay_pid = *guardian_children
        .iter()
        .find(|&&pid| pid != client_pid)
        .unwrap();
    let relay = ProcessGuard::open(relay_pid);
    assert!(settings.is_file());

    guardian.kill();
    assert!(guardian.wait_dead(Duration::from_secs(5)));
    let wrapper_status = wait_child(&mut wrapper.0, Duration::from_secs(10));
    assert!(!wrapper_status.success());
    assert!(client.alive(), "guardian loss terminated the actual client");
    assert!(
        settings.is_file(),
        "guardian loss deleted unreleased settings"
    );

    let second_report = root.join("second-report");
    let mut next = ChildGuard(
        protected_command(&root, &script, &second_report, "once")
            .spawn()
            .unwrap(),
    );
    let next_status = wait_child(&mut next.0, Duration::from_secs(10));
    assert_eq!(next_status.code(), Some(37));
    assert!(
        settings.is_file(),
        "next launch deleted a live unreleased session"
    );
    assert!(client.alive());
    assert_eq!(
        std::fs::read(root.join("caller-settings.json")).unwrap(),
        input
    );

    relay.kill();
    assert!(relay.wait_dead(Duration::from_secs(5)));
    client.kill();
    assert!(client.wait_dead(Duration::from_secs(5)));
}
