use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[test]
fn scan_shows_progress_in_a_terminal() {
    let root = std::env::temp_dir().join(format!(
        "pentect-scan-progress-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("clean.txt"), "ordinary text\n").unwrap();

    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize {
            rows: 24,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_pentect"));
    command.args(["scan", "--no-fail"]);
    command.arg(&root);
    let mut child = pair.slave.spawn_command(command).unwrap();
    drop(pair.slave);

    let output = Arc::new(Mutex::new(String::new()));
    let reader = pair.master.try_clone_reader().unwrap();
    let writer = Arc::new(Mutex::new(pair.master.take_writer().unwrap()));
    let reader_output = output.clone();
    let reader_writer = writer.clone();
    let reader_thread = std::thread::spawn(move || {
        let mut reader = reader;
        let mut buffer = [0u8; 4096];
        let mut dsr_state = 0usize;
        while let Ok(read) = reader.read(&mut buffer) {
            if read == 0 {
                break;
            }
            reader_output
                .lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&buffer[..read]));
            for byte in &buffer[..read] {
                if observe_dsr(&mut dsr_state, *byte) {
                    let mut writer = reader_writer.lock().unwrap();
                    writer.write_all(b"\x1b[1;1R").unwrap();
                    writer.flush().unwrap();
                }
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("scan did not exit: {:?}", output.lock().unwrap());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(pair.master);
    let reader_deadline = Instant::now() + Duration::from_secs(5);
    while !reader_thread.is_finished() && Instant::now() < reader_deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(reader_thread.is_finished(), "PTY reader did not reach EOF");
    reader_thread.join().unwrap();
    let output = output.lock().unwrap().clone();

    assert_eq!(status.exit_code(), 0, "{output:?}");
    assert!(output.contains("[pentect] walk"), "{output:?}");
    assert!(output.contains("[pentect] scan 0/1"), "{output:?}");
    assert!(output.contains("[pentect] scan 1/1"), "{output:?}");
    assert!(output.contains("pentect scan engine=pentect"), "{output:?}");

    let _ = std::fs::remove_dir_all(root);
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
