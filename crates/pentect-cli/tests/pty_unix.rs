#![cfg(unix)]

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const INITIAL_SIZE: (u16, u16) = (177, 43);
const RESIZED_SIZE: (u16, u16) = (101, 31);
static PTY_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn agent_pty_inherits_and_tracks_parent_dimensions() {
    let _serial = PTY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();

    let pty = native_pty_system();
    let pair = pty.openpty(pty_size(INITIAL_SIZE)).unwrap();
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_pentect"));
    command.args([
        "opencode",
        "--tool",
        "/bin/sh",
        "--",
        "-c",
        size_probe_script(),
    ]);
    command.cwd(&root);
    command.env("PENTECT_BIN", env!("CARGO_BIN_EXE_pentect"));
    command.env("PENTECT_PROCESS_HOST_ROOT", root.join("untrusted-override"));
    command.env("XDG_RUNTIME_DIR", root.join("runtime-base"));
    for name in [
        "PENTECT_MEMORY_STORE_ADDR",
        "PENTECT_MEMORY_STORE_TOKEN",
        "PENTECT_PROCESS_HOST_READ_TOKEN",
        "PENTECT_PROCESS_HOST_WRITE_TOKEN",
        "PENTECT_AGENT_LAUNCHED",
    ] {
        command.env_remove(name);
    }

    let mut child = pair.slave.spawn_command(command).unwrap();
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx
                        .send(String::from_utf8_lossy(&buf[..n]).into_owned())
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    let mut output = String::new();
    wait_for_text(&rx, &mut output, "SIZE:177x43");
    pair.master.resize(pty_size(RESIZED_SIZE)).unwrap();
    wait_for_text(&rx, &mut output, "SIZE:101x31");

    let status = wait_for_child(child.as_mut());
    assert_eq!(status.exit_code(), 0, "{output:?}");
    drop(pair.master);
    join_reader(reader_thread);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn agent_pty_releases_a_standalone_escape_key() {
    let _serial = PTY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();

    let pty = native_pty_system();
    let pair = pty.openpty(pty_size(INITIAL_SIZE)).unwrap();
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_pentect"));
    command.args([
        "opencode",
        "--tool",
        "/bin/sh",
        "--",
        "-c",
        "stty raw -echo; printf 'READY\\n'; value=$(od -An -tu1 -N1 | tr -d ' '); printf 'KEY:%s\\n' \"$value\"",
    ]);
    command.cwd(&root);
    command.env("PENTECT_BIN", env!("CARGO_BIN_EXE_pentect"));
    command.env("PENTECT_PROCESS_HOST_ROOT", root.join("untrusted-override"));
    command.env("XDG_RUNTIME_DIR", root.join("runtime-base"));
    for name in [
        "PENTECT_MEMORY_STORE_ADDR",
        "PENTECT_MEMORY_STORE_TOKEN",
        "PENTECT_PROCESS_HOST_READ_TOKEN",
        "PENTECT_PROCESS_HOST_WRITE_TOKEN",
        "PENTECT_AGENT_LAUNCHED",
    ] {
        command.env_remove(name);
    }

    let mut child = pair.slave.spawn_command(command).unwrap();
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().unwrap();
    let mut writer = pair.master.take_writer().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx
                        .send(String::from_utf8_lossy(&buf[..n]).into_owned())
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    let mut output = String::new();
    wait_for_text(&rx, &mut output, "READY");
    writer.write_all(b"\x1b").unwrap();
    writer.flush().unwrap();
    wait_for_text(&rx, &mut output, "KEY:27");

    let status = wait_for_child(child.as_mut());
    assert_eq!(status.exit_code(), 0, "{output:?}");
    drop(writer);
    drop(pair.master);
    join_reader(reader_thread);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn agent_pty_stops_background_process_groups_on_exit() {
    let _serial = PTY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();

    let pty = native_pty_system();
    let pair = pty.openpty(pty_size(INITIAL_SIZE)).unwrap();
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_pentect"));
    command.args([
        "opencode",
        "--tool",
        "/bin/sh",
        "--",
        "-c",
        "python3 -c 'import os,time; os.setpgid(0,0); time.sleep(30)' & printf 'READY\\n'",
    ]);
    command.cwd(&root);
    command.env("PENTECT_BIN", env!("CARGO_BIN_EXE_pentect"));
    command.env("PENTECT_PROCESS_HOST_ROOT", root.join("untrusted-override"));
    command.env("XDG_RUNTIME_DIR", root.join("runtime-base"));
    for name in [
        "PENTECT_MEMORY_STORE_ADDR",
        "PENTECT_MEMORY_STORE_TOKEN",
        "PENTECT_PROCESS_HOST_READ_TOKEN",
        "PENTECT_PROCESS_HOST_WRITE_TOKEN",
        "PENTECT_AGENT_LAUNCHED",
    ] {
        command.env_remove(name);
    }

    let mut child = pair.slave.spawn_command(command).unwrap();
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx
                        .send(String::from_utf8_lossy(&buf[..n]).into_owned())
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    let mut output = String::new();
    wait_for_text(&rx, &mut output, "READY");
    let status = wait_for_child(child.as_mut());
    assert_eq!(status.exit_code(), 0, "{output:?}");
    drop(pair.master);
    join_reader(reader_thread);
    let _ = std::fs::remove_dir_all(root);
}

fn size_probe_script() -> &'static str {
    concat!(
        "set -- $(stty size); ",
        "printf 'SIZE:%sx%s\\n' \"$2\" \"$1\"; ",
        "old=\"$*\"; i=0; ",
        "while [ \"$i\" -lt 200 ]; do ",
        "sleep 0.05; set -- $(stty size); next=\"$*\"; ",
        "if [ \"$next\" != \"$old\" ]; then ",
        "printf 'SIZE:%sx%s\\n' \"$2\" \"$1\"; exit 0; fi; ",
        "i=$((i + 1)); done; exit 2"
    )
}

fn pty_size((cols, rows): (u16, u16)) -> PtySize {
    PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn wait_for_text(rx: &mpsc::Receiver<String>, output: &mut String, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !output.contains(expected) {
        let timeout = deadline.saturating_duration_since(Instant::now());
        assert!(!timeout.is_zero(), "missing {expected:?} in {output:?}");
        match rx.recv_timeout(timeout) {
            Ok(chunk) => output.push_str(&chunk),
            Err(error) => panic!("missing {expected:?}: {error}; output={output:?}"),
        }
    }
}

fn wait_for_child(child: &mut dyn portable_pty::Child) -> portable_pty::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let stop_deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < stop_deadline {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("PTY child did not exit within 15 seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn join_reader(thread: std::thread::JoinHandle<()>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !thread.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(thread.is_finished(), "PTY reader did not reach EOF");
    thread.join().unwrap();
}

fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "pentect-pty-unix-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
