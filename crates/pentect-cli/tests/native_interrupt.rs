#![cfg(unix)]

use std::process::Command;

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
