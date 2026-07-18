#![cfg(windows)]

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const INITIAL_SIZE: (u16, u16) = (177, 43);
const RESIZED_SIZE: (u16, u16) = (101, 31);
static PTY_TEST_LOCK: Mutex<()> = Mutex::new(());

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

    let status = wait_for_child(child.as_mut());
    assert_eq!(status.exit_code(), 0, "{output:?}");
    drop(pair.master);
    join_reader(reader_thread);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn agent_pty_does_not_forward_nested_win32_input_mode() {
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
        "powershell.exe",
        "--",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$esc=[char]27;Write-Output 'BEFORE';[Console]::Out.Write($esc+'[?9001h');Write-Output 'READY';[Console]::Out.Write($esc+'[?9001l');Write-Output 'AFTER'",
    ]);
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

    let status = wait_for_child(child.as_mut());
    assert_eq!(status.exit_code(), 0);
    drop(pair.master);
    join_reader(reader_thread);
    let output = rx.try_iter().collect::<String>().into_bytes();
    let start = find_bytes(&output, b"BEFORE").expect("child output was not forwarded");
    let end = find_bytes(&output[start..], b"AFTER")
        .map(|offset| start + offset + b"AFTER".len())
        .expect("child output was truncated");
    assert!(!output[start..end]
        .windows(b"\x1b[?9001h".len())
        .any(|window| window == b"\x1b[?9001h"));
    assert!(!output[start..end]
        .windows(b"\x1b[?9001l".len())
        .any(|window| window == b"\x1b[?9001l"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn agent_pty_does_not_leak_mouse_reports_to_parent_shell() {
    let _serial = PTY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();
    let parent_script = root.join("parent.ps1");
    let release_file = root.join("release-child");
    std::fs::write(
        &parent_script,
        concat!(
            "$child = '$esc=[char]27;[Console]::Out.Write($esc+''[?1003h''+$esc+''[?1006h''+$esc+''[?1016h'');",
            "Write-Output ''READY'';while(-not (Test-Path -LiteralPath $env:PENTECT_TEST_RELEASE)){Start-Sleep -Milliseconds 5}'\n",
            "& $env:PENTECT_BIN opencode --tool powershell.exe -- -NoLogo -NoProfile -NonInteractive -Command $child\n",
            "Write-Output 'PARENT_READY'\n",
            "$line = [Console]::ReadLine()\n",
            "Write-Output ('PARENT_INPUT:' + $line + ':END')\n",
        ),
    )
    .unwrap();

    let pty = native_pty_system();
    let pair = pty.openpty(pty_size(INITIAL_SIZE)).unwrap();
    let mut command = CommandBuilder::new("powershell.exe");
    command.args(["-NoLogo", "-NoProfile", "-File"]);
    command.arg(&parent_script);
    command.cwd(&root);
    command.env("PENTECT_BIN", env!("CARGO_BIN_EXE_pentect"));
    command.env("PENTECT_PROCESS_HOST_ROOT", root.join("host"));
    command.env("PENTECT_TEST_RELEASE", &release_file);
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
    let enabled = output
        .find("\x1b[?1016h")
        .expect("pixel mouse mode was not enabled");
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let injected = Arc::new(AtomicU32::new(0));
    let input_thread = {
        let writer = writer.clone();
        let stop = stop.clone();
        let injected = injected.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                if let Ok(mut input) = writer.lock() {
                    if input
                        .write_all(b"\x1b[<35;48;15M")
                        .and_then(|_| input.flush())
                        .is_ok()
                    {
                        injected.fetch_add(1, Ordering::Release);
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    };
    let injection_deadline = Instant::now() + Duration::from_secs(2);
    while injected.load(Ordering::Acquire) < 10 && Instant::now() < injection_deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(injected.load(Ordering::Acquire) >= 10);
    std::fs::write(&release_file, b"ready").unwrap();
    wait_for_text(&rx, &mut output, "\x1b[?1016l");
    let disabled = output[enabled + "\x1b[?1016h".len()..]
        .find("\x1b[?1016l")
        .map(|offset| enabled + "\x1b[?1016h".len() + offset)
        .expect("pixel mouse mode was not disabled");
    assert!(disabled > enabled);
    stop.store(true, Ordering::Release);
    input_thread.join().unwrap();
    wait_for_text(&rx, &mut output, "PARENT_READY");
    {
        let mut input = writer.lock().unwrap();
        input.write_all(b"SAFE\r").unwrap();
        input.flush().unwrap();
    }
    wait_for_text(&rx, &mut output, ":END");

    let status = wait_for_child(child.as_mut());
    assert_eq!(status.exit_code(), 0, "{output:?}");
    let start = output
        .rfind("PARENT_INPUT:")
        .map(|offset| offset + "PARENT_INPUT:".len())
        .expect("parent input marker was not written");
    let end = output[start..]
        .find(":END")
        .map(|offset| start + offset)
        .expect("parent input marker was incomplete");
    assert_eq!(&output[start..end], "SAFE", "{output:?}");
    drop(pair.master);
    join_reader(reader_thread);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn agent_pty_stops_background_processes_on_exit() {
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
        "powershell.exe",
        "--",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Start-Process ping.exe -ArgumentList '-t','127.0.0.1' -NoNewWindow | Out-Null; Write-Output 'READY'",
    ]);
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
    let status = wait_for_child(child.as_mut());
    assert_eq!(status.exit_code(), 0, "{output:?}");
    drop(pair.master);
    join_reader(reader_thread);
    let _ = std::fs::remove_dir_all(root);
}

fn assert_pty_dimensions(command_prefix: &[&str]) {
    let _serial = PTY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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

    let status = wait_for_child(child.as_mut());
    assert_eq!(status.exit_code(), 0, "{output:?}");
    drop(pair.master);
    join_reader(reader_thread);
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
    let mut dsr_state = 0usize;
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let query_count = buf[..n]
                    .iter()
                    .filter(|byte| observe_dsr(&mut dsr_state, **byte))
                    .count();
                if query_count > 0 {
                    let (cols, rows) = unpack_size(terminal_size.load(Ordering::Relaxed));
                    let response = format!("\x1b[{rows};{cols}R");
                    if let Ok(mut writer) = writer.lock() {
                        for _ in 0..query_count {
                            let _ = writer.write_all(response.as_bytes());
                        }
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

fn observe_dsr(state: &mut usize, byte: u8) -> bool {
    const DSR: &[u8] = b"\x1b[6n";
    if byte == DSR[*state] {
        *state += 1;
        if *state == DSR.len() {
            *state = 0;
            return true;
        }
    } else {
        *state = usize::from(byte == DSR[0]);
    }
    false
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

#[test]
fn dsr_detection_survives_read_boundaries() {
    let mut state = 0usize;
    assert_eq!(
        b"prefix\x1b["
            .iter()
            .filter(|byte| observe_dsr(&mut state, **byte))
            .count(),
        0
    );
    assert_eq!(
        b"6n\x1b[6n\x1b[6n"
            .iter()
            .filter(|byte| observe_dsr(&mut state, **byte))
            .count(),
        3
    );
}

fn pack_size((cols, rows): (u16, u16)) -> u32 {
    u32::from(cols) << 16 | u32::from(rows)
}

fn unpack_size(size: u32) -> (u16, u16) {
    ((size >> 16) as u16, size as u16)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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
