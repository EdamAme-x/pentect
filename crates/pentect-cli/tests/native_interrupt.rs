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
    env["USERPROFILE"] = home
    for name in ["runtime", "cache", "state", "config"]: os.makedirs(os.path.join(root, name))
    env["XDG_RUNTIME_DIR"] = os.path.join(root, "runtime")
    env["XDG_CACHE_HOME"] = os.path.join(root, "cache")
    env["XDG_STATE_HOME"] = os.path.join(root, "state")
    env["XDG_CONFIG_HOME"] = os.path.join(root, "config")
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

const CLAUDE_JOB_PROBE: &str = r##"
import os,pty,select,signal,stat,sys,tempfile,time,shlex,re
with tempfile.TemporaryDirectory(prefix="pentect-claude-job-") as root:
 home=os.path.join(root,"home"); project=os.path.join(root,"project")
 os.makedirs(os.path.join(home,".pentect")); os.makedirs(os.path.join(project,".git"))
 open(os.path.join(home,".pentect","config.toml"),"w").write("[update]\ncheck = false\n")
 client=os.path.join(root,"client.py")
 open(client,"w").write("#!/usr/bin/env python3\nimport os\nprint('READY',flush=True)\nwhile os.tcgetpgrp(0)!=os.getpgrp(): pass\nprint('FOREGROUND',flush=True)\nprint('GOT='+input(),flush=True)\n")
 os.chmod(client,os.stat(client).st_mode|stat.S_IXUSR)
 env=os.environ.copy(); env["HOME"]=home; env["USERPROFILE"]=home; env["PS1"]="PENTECT-PROMPT> "; env["PENTECT_LOG_DIR"]=os.path.join(root,"log")
 for name in ["runtime","cache","state","config"]: os.makedirs(os.path.join(root,name))
 env["XDG_RUNTIME_DIR"]=os.path.join(root,"runtime"); env["XDG_CACHE_HOME"]=os.path.join(root,"cache"); env["XDG_STATE_HOME"]=os.path.join(root,"state"); env["XDG_CONFIG_HOME"]=os.path.join(root,"config")
 pid,fd=pty.fork()
 if pid==0: os.chdir(project); os.execve("/bin/sh",["sh","-i"],env)
 output=b""; reaped=False; wrapper=None
 def until(needle,count,timeout):
  global output
  end=time.monotonic()+timeout
  while output.count(needle)<count and time.monotonic()<end:
   if select.select([fd],[],[],.1)[0]:
    try: output+=os.read(fd,4096)
    except OSError: break
  return output.count(needle)>=count
 def wait_reaped(timeout):
  global output
  end=time.monotonic()+timeout
  while time.monotonic()<end:
   if select.select([fd],[],[],.05)[0]:
    try: output+=os.read(fd,4096)
    except OSError: pass
   try: observed,status=os.waitpid(pid,os.WNOHANG)
   except ChildProcessError: return 0
   if observed!=0: return status
  return None
 try:
  if not until(b"PENTECT-PROMPT> ",1,5): raise RuntimeError(repr(output))
  shell_group=os.tcgetpgrp(fd)
  cmd=shlex.quote(sys.argv[1])+" claude --claude "+shlex.quote(client)+" & echo WRAPPER=$!\n"
  os.write(fd,cmd.encode())
  if not until(b"PENTECT-PROMPT> ",2,10): raise RuntimeError("no background prompt "+repr(output))
  match=re.search(rb"WRAPPER=(\d+)",output)
  if not match: raise RuntimeError("wrapper pid missing "+repr(output))
  wrapper=int(match.group(1))
  if os.tcgetpgrp(fd)!=shell_group: raise RuntimeError("background stole tty")
  os.write(fd,b"fg\n")
  if not until(b"FOREGROUND",1,5): raise RuntimeError("fg failed "+repr(output))
  os.write(fd,b"\x1a")
  if not until(b"PENTECT-PROMPT> ",3,5): raise RuntimeError("Ctrl-Z failed "+repr(output))
  if os.tcgetpgrp(fd)!=shell_group: raise RuntimeError("shell did not regain tty")
  os.write(fd,b"fg\n")
  time.sleep(.2); os.write(fd,b"hello\n")
  if not until(b"GOT=hello",1,5): raise RuntimeError("resume/read failed "+repr(output))
  if not until(b"PENTECT-PROMPT> ",4,5): raise RuntimeError("final prompt missing "+repr(output))
  wrapper=None
  os.write(fd,b"exit\n")
  status=wait_reaped(5)
  if status is None: raise RuntimeError("shell did not exit "+repr(output))
  if os.waitstatus_to_exitcode(status)!=0: raise RuntimeError("shell exit status "+str(status)+" "+repr(output))
  reaped=True
 finally:
  if not reaped:
   if wrapper:
    try: os.kill(wrapper,signal.SIGKILL)
    except OSError: pass
   try: os.killpg(pid,signal.SIGKILL)
   except OSError: pass
   wait_reaped(5)
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

#[test]
fn claude_terminal_first_ctrl_c_belongs_to_client_and_repeat_stops_wrapper() {
    let probe = PROBE.replace(
        r#"[sys.argv[1], "codex", "--codex", client]"#,
        r#"[sys.argv[1], "claude", "--claude", client]"#,
    );
    let output = Command::new("python3")
        .args(["-c", &probe, env!("CARGO_BIN_EXE_pentect")])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn claude_background_fg_and_ctrl_z_restore_terminal() {
    let output = Command::new("python3")
        .args(["-c", CLAUDE_JOB_PROBE, env!("CARGO_BIN_EXE_pentect")])
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

fn run_claude_client(root: &Path, body: &str) -> Output {
    let home = root.join("home");
    let project = root.join("project");
    let runtime = root.join("runtime");
    let cache = root.join("cache");
    let state = root.join("state");
    let config = root.join("config");
    std::fs::create_dir_all(home.join(".pentect")).unwrap();
    std::fs::create_dir_all(project.join(".git")).unwrap();
    for directory in [&runtime, &cache, &state, &config] {
        std::fs::create_dir_all(directory).unwrap();
    }
    std::fs::write(
        home.join(".pentect/config.toml"),
        "[update]\ncheck = false\n",
    )
    .unwrap();
    let client = root.join("client.sh");
    std::fs::write(&client, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o700)).unwrap();
    Command::new(env!("CARGO_BIN_EXE_pentect"))
        .args(["claude", "--claude"])
        .arg(client)
        .current_dir(project)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_CACHE_HOME", cache)
        .env("XDG_STATE_HOME", state)
        .env("XDG_CONFIG_HOME", config)
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

#[test]
fn claude_guardian_preserves_normal_and_signal_status() {
    for (body, expected) in [
        ("exit 37", 37),
        ("kill -INT $$", 130),
        ("kill -TERM $$", 143),
    ] {
        let fixture = TestDirectory::new("claude-exit-status");
        let output = run_claude_client(&fixture.0, body);
        assert_eq!(
            output.status.code(),
            Some(expected),
            "body={body:?}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
