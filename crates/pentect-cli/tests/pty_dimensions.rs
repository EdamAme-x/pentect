#![cfg(windows)]

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const INITIAL_SIZE: (u16, u16) = (177, 43);
const RESIZED_SIZE: (u16, u16) = (101, 31);

#[test]
fn shell_pty_inherits_and_tracks_parent_dimensions() {
    assert_pty_dimensions(&[
        "shell",
        "--",
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
    ]);
}

#[test]
fn agent_pty_inherits_and_tracks_parent_dimensions() {
    assert_pty_dimensions(&[
        "opencode",
        "--tool",
        "powershell.exe",
        "--",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
    ]);
}

#[test]
fn agent_pty_preserves_backspace_as_one_key_event() {
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();

    let pty = native_pty_system();
    let pair = pty.openpty(pty_size(INITIAL_SIZE)).unwrap();
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_pentect"));
    command.args([
        "opencode",
        "--tool",
        "powershell.exe",
        "--",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
    ]);
    command.arg(concat!(
        "Write-Output 'READY';",
        "$key=[Console]::ReadKey($true);",
        "Write-Output ('KEY:{0}:{1}' -f $key.Key,[int]$key.KeyChar)"
    ));
    command.cwd(&root);
    command.env("PENTECT_BIN", env!("CARGO_BIN_EXE_pentect"));
    command.env("PENTECT_PROCESS_HOST_ROOT", root.join("host"));
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
    let reader = pair.master.try_clone_reader().unwrap();
    let writer = Arc::new(Mutex::new(pair.master.take_writer().unwrap()));
    let terminal_size = Arc::new(AtomicU32::new(pack_size(INITIAL_SIZE)));
    let (tx, rx) = mpsc::channel();
    let reader_thread = {
        let writer = writer.clone();
        std::thread::spawn(move || forward_output(reader, writer, terminal_size, tx))
    };

    let mut output = String::new();
    wait_for_text(&rx, &mut output, "READY");
    {
        let mut input = writer.lock().unwrap();
        input
            .write_all(b"\x1b[8;14;8;1;0;1_\x1b[8;14;8;0;0;1_")
            .unwrap();
        input.flush().unwrap();
    }
    wait_for_text(&rx, &mut output, "KEY:Backspace:8");

    let status = child.wait().unwrap();
    assert_eq!(status.exit_code(), 0, "{output:?}");
    drop(pair.master);
    reader_thread.join().unwrap();
    let _ = std::fs::remove_dir_all(root);
}

fn assert_pty_dimensions(command_prefix: &[&str]) {
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();

    let pty = native_pty_system();
    let pair = pty.openpty(pty_size(INITIAL_SIZE)).unwrap();
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_pentect"));
    command.args(command_prefix);
    command.arg(size_probe_script());
    command.cwd(&root);
    command.env("PENTECT_BIN", env!("CARGO_BIN_EXE_pentect"));
    command.env("PENTECT_PROCESS_HOST_ROOT", root.join("host"));
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
    let reader = pair.master.try_clone_reader().unwrap();
    let writer = Arc::new(Mutex::new(pair.master.take_writer().unwrap()));
    let terminal_size = Arc::new(AtomicU32::new(pack_size(INITIAL_SIZE)));
    let (tx, rx) = mpsc::channel();
    let reader_thread = {
        let writer = writer.clone();
        let terminal_size = terminal_size.clone();
        std::thread::spawn(move || forward_output(reader, writer, terminal_size, tx))
    };

    let mut output = String::new();
    wait_for_text(&rx, &mut output, "SIZE:177x43");
    terminal_size.store(pack_size(RESIZED_SIZE), Ordering::Relaxed);
    pair.master.resize(pty_size(RESIZED_SIZE)).unwrap();
    wait_for_text(&rx, &mut output, "SIZE:101x31");

    let status = child.wait().unwrap();
    assert_eq!(status.exit_code(), 0, "{output:?}");
    drop(pair.master);
    reader_thread.join().unwrap();
    let _ = std::fs::remove_dir_all(root);
}

fn size_probe_script() -> String {
    concat!(
        "$size=$Host.UI.RawUI.WindowSize;",
        "Write-Output ('SIZE:{0}x{1}' -f $size.Width,$size.Height);",
        "for($i=0;$i -lt 100;$i++){",
        "Start-Sleep -Milliseconds 50;",
        "$next=$Host.UI.RawUI.WindowSize;",
        "if($next.Width -ne $size.Width -or $next.Height -ne $size.Height){",
        "Write-Output ('SIZE:{0}x{1}' -f $next.Width,$next.Height);exit 0",
        "}};exit 2"
    )
    .to_string()
}

fn pty_size((cols, rows): (u16, u16)) -> PtySize {
    PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn forward_output(
    mut reader: Box<dyn Read + Send>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    terminal_size: Arc<AtomicU32>,
    tx: mpsc::Sender<String>,
) {
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buf[..n].windows(4).any(|bytes| bytes == b"\x1b[6n") {
                    let (cols, rows) = unpack_size(terminal_size.load(Ordering::Relaxed));
                    let response = format!("\x1b[{rows};{cols}R");
                    if let Ok(mut writer) = writer.lock() {
                        let _ = writer.write_all(response.as_bytes());
                        let _ = writer.flush();
                    }
                }
                if tx
                    .send(String::from_utf8_lossy(&buf[..n]).into_owned())
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

fn pack_size((cols, rows): (u16, u16)) -> u32 {
    u32::from(cols) << 16 | u32::from(rows)
}

fn unpack_size(size: u32) -> (u16, u16) {
    ((size >> 16) as u16, size as u16)
}

fn wait_for_text(rx: &mpsc::Receiver<String>, output: &mut String, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !output.contains(expected) {
        let timeout = deadline.saturating_duration_since(Instant::now());
        assert!(!timeout.is_zero(), "missing {expected:?} in {output:?}");
        match rx.recv_timeout(timeout) {
            Ok(chunk) => output.push_str(&chunk),
            Err(error) => panic!("missing {expected:?}: {error}; output={output:?}"),
        }
    }
}

fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "pentect-pty-size-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
