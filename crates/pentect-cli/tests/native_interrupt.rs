#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PROBE: &str = r##"
import os
import pty
import select
import signal
import stat
import sys
import tempfile
import time

with tempfile.TemporaryDirectory(prefix="pentect-interrupt-") as root:
    home = os.path.join(root, "home")
    project = os.path.join(root, "project")
    os.makedirs(os.path.join(home, ".pentect"))
    os.makedirs(os.path.join(project, ".git"))
    with open(os.path.join(home, ".pentect", "config.toml"), "w") as config:
        config.write("[update]\ncheck = false\n")
    client = os.path.join(root, "client.py")
    with open(client, "w") as script:
        script.write("#!/usr/bin/env python3\nimport signal,time\nsignal.signal(signal.SIGINT, lambda *_: print('CANCELLED', flush=True))\nprint('READY', flush=True)\nwhile True: time.sleep(1)\n")
    os.chmod(client, os.stat(client).st_mode | stat.S_IXUSR)
    env = os.environ.copy()
    env["HOME"] = home
    env.pop("USERPROFILE", None)
    env["PENTECT_LOG_DIR"] = os.path.join(root, "log")
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(project)
        os.execve(sys.argv[1], [sys.argv[1], "codex", "--codex", client], env)

    output = b""
    reaped = False
    def read_until_count(needle, count, timeout):
        global output
        deadline = time.monotonic() + timeout
        while output.count(needle) < count and time.monotonic() < deadline:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    output += os.read(fd, 4096)
                except OSError:
                    break
        return output.count(needle) >= count

    def assert_alive_for(seconds, label):
        global output
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if os.waitpid(pid, os.WNOHANG)[0] != 0:
                raise RuntimeError("Pentect exited after " + label + ": " + repr(output))
            if select.select([fd], [], [], 0.05)[0]:
                try:
                    output += os.read(fd, 4096)
                except OSError:
                    pass

    try:
        if not read_until_count(b"READY", 1, 10):
            raise RuntimeError("client did not become ready: " + repr(output))
        os.write(fd, b"\x03")
        if not read_until_count(b"CANCELLED", 1, 3):
            raise RuntimeError("client did not receive first Ctrl-C: " + repr(output))
        assert_alive_for(2.5, "the first cancellation")

        os.write(fd, b"\x03")
        if not read_until_count(b"CANCELLED", 2, 3):
            raise RuntimeError("client did not receive separated Ctrl-C: " + repr(output))
        assert_alive_for(2.5, "the separated cancellation")

        os.write(fd, b"\x03")
        if not read_until_count(b"CANCELLED", 3, 3):
            raise RuntimeError("client did not receive shutdown Ctrl-C: " + repr(output))
        time.sleep(0.25)
        os.write(fd, b"\x03")
        deadline = time.monotonic() + 5
        observed = 0
        while observed == 0 and time.monotonic() < deadline:
            observed, _ = os.waitpid(pid, os.WNOHANG)
            time.sleep(0.05)
        if observed == 0:
            raise RuntimeError("Pentect did not stop after repeated Ctrl-C")
        reaped = True
    finally:
        if not reaped:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        os.close(fd)
"##;

#[test]
fn terminal_first_ctrl_c_belongs_to_client_and_repeat_stops_wrapper() {
    let output = Command::new("python3")
        .args(["-c", PROBE, env!("CARGO_BIN_EXE_pentect")])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "pentect-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_native_client(root: &Path, body: &str) -> Output {
    let home = root.join("home");
    let project = root.join("project");
    std::fs::create_dir_all(home.join(".pentect")).unwrap();
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::write(
        home.join(".pentect/config.toml"),
        "[update]\ncheck = false\n",
    )
    .unwrap();
    let client = root.join("client.sh");
    std::fs::write(&client, format!("#!/bin/sh\n{body}\n")).unwrap();
    let mut permissions = std::fs::metadata(&client).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&client, permissions).unwrap();

    Command::new(env!("CARGO_BIN_EXE_pentect"))
        .args(["codex", "--codex"])
        .arg(client)
        .current_dir(project)
        .env("HOME", home)
        .env_remove("USERPROFILE")
        .env("PENTECT_LOG_DIR", root.join("log"))
        .output()
        .unwrap()
}

#[test]
fn native_client_exit_codes_preserve_normal_and_signal_status() {
    for (body, expected) in [
        ("exit 37", 37),
        ("kill -INT $$", 130),
        ("kill -TERM $$", 143),
    ] {
        let fixture = TestDirectory::new("native-exit-status");
        let output = run_native_client(&fixture.0, body);
        assert_eq!(
            output.status.code(),
            Some(expected),
            "body={body:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
