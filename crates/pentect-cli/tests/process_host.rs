use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PRIVATE_ENV: &[&str] = &[
    "PENTECT_MEMORY_STORE_ADDR",
    "PENTECT_MEMORY_STORE_TOKEN",
    "PENTECT_PROCESS_HOST_ROOT",
    "PENTECT_PROCESS_HOST_READ_TOKEN",
    "PENTECT_PROCESS_HOST_WRITE_TOKEN",
    "PENTECT_AGENT_LAUNCHED",
];

#[test]
fn codex_dry_run_routes_through_the_http_gateway() {
    let root = test_root();
    let config_dir = root.join(".pentect");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        "[handles]\nscope = \"device\"\n",
    )
    .unwrap();
    let _cleanup = Cleanup {
        root: root.clone(),
        host_pid: None,
        command_pids: Vec::new(),
    };

    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command
        .args(["codex", "--dry-run"])
        .current_dir(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in PRIVATE_ENV {
        command.env_remove(name);
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{:?}", output.status);
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(rendered.contains("openai_base_url"), "{rendered}");
    assert!(!rendered.contains("pentect-openai-gateway"), "{rendered}");
    assert!(rendered.contains("<pentect-gateway>"), "{rendered}");
    assert!(!rendered.contains("PENTECT_KEY_hash"), "{rendered}");
}

#[test]
fn claude_dry_run_shows_the_generated_gateway_settings() {
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();
    let _cleanup = Cleanup {
        root: root.clone(),
        host_pid: None,
        command_pids: Vec::new(),
    };

    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command
        .args(["claude", "--dry-run"])
        .current_dir(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", &root)
        .env("USERPROFILE", &root)
        .env("APPDATA", &root)
        .env("PROGRAMDATA", &root)
        .env("CLAUDE_CONFIG_DIR", root.join("claude"));
    for name in PRIVATE_ENV.iter().chain(
        [
            "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_USE_VERTEX",
            "CLAUDE_CODE_USE_FOUNDRY",
            "CLAUDE_CODE_USE_MANTLE",
        ]
        .iter(),
    ) {
        command.env_remove(name);
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{:?}", output.status);
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(rendered.contains("--settings"), "{rendered}");
    assert!(rendered.contains("<pentect-settings>"), "{rendered}");
    assert!(!rendered.contains("pentect-claude-settings-"), "{rendered}");
}

#[test]
fn log_hosts_while_running_but_help_does_not() {
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();
    let mut cleanup = Cleanup {
        root: root.clone(),
        host_pid: None,
        command_pids: Vec::new(),
    };

    let mut log = spawn_command(&root, &["log", "--json"]);
    cleanup.command_pids.push(log.id());
    let host_file = host_root(&root)
        .join("runtime")
        .join("delegated-process-host.json");
    wait_until(Duration::from_secs(10), || host_file.is_file());
    let host = read_json(&host_file);
    cleanup.host_pid = host["pid"].as_u64().map(|pid| pid as u32);
    assert_host_alive(&host);

    log.kill().unwrap();
    log.wait().unwrap();
    cleanup.command_pids.clear();

    let help_root = root.join("help-only");
    std::fs::create_dir_all(&help_root).unwrap();
    let mut help = spawn_command(&help_root, &["help"]);
    let status = help.wait().unwrap();
    assert!(status.success(), "pentect help failed: {status}");
    assert!(!host_root(&help_root).join("runtime").exists());
}

#[test]
fn human_log_marks_when_it_starts_following_live_events() {
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();
    let mut cleanup = Cleanup {
        root: root.clone(),
        host_pid: None,
        command_pids: Vec::new(),
    };
    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command
        .arg("log")
        .current_dir(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    for name in PRIVATE_ENV {
        command.env_remove(name);
    }
    configure_runtime_root(&mut command, &root);
    let mut log = command.spawn().unwrap();
    cleanup.command_pids.push(log.id());
    let stdout = log.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("following live events") {
                let _ = sender.send(line);
                return;
            }
        }
    });

    let indicator = receiver.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(indicator.contains("Ctrl-C"), "{indicator}");
    log.kill().unwrap();
    log.wait().unwrap();
    cleanup.command_pids.clear();
    reader.join().unwrap();
}

fn spawn_command(root: &Path, args: &[&str]) -> std::process::Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for name in PRIVATE_ENV {
        command.env_remove(name);
    }
    command.env("PENTECT_PROCESS_HOST_ROOT", root.join("untrusted-override"));
    configure_runtime_root(&mut command, root);
    command.spawn().unwrap()
}

fn assert_host_alive(host: &Value) {
    let addr = host["addr"].as_str().unwrap();
    let token = host["read_token"].as_str().unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();
    writeln!(stream, "{token}\tLOGS\t0").unwrap();
    stream.flush().unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    assert!(response.starts_with("OK\t"), "{response}");
}

#[cfg(windows)]
fn configure_runtime_root(command: &mut Command, root: &Path) {
    command.env("LOCALAPPDATA", root);
}

#[cfg(windows)]
fn host_root(root: &Path) -> PathBuf {
    root.join("pentect")
}

#[cfg(target_os = "macos")]
fn configure_runtime_root(command: &mut Command, root: &Path) {
    command.env("HOME", root);
}

#[cfg(target_os = "macos")]
fn host_root(root: &Path) -> PathBuf {
    root.join("Library").join("Caches").join("pentect")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn configure_runtime_root(command: &mut Command, root: &Path) {
    command.env("XDG_RUNTIME_DIR", root);
}

#[cfg(all(unix, not(target_os = "macos")))]
fn host_root(root: &Path) -> PathBuf {
    root.join("pentect")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(Instant::now() < deadline, "condition timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "pentect-up-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

struct Cleanup {
    root: PathBuf,
    host_pid: Option<u32>,
    command_pids: Vec<u32>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let runtime = host_root(&self.root).join("runtime");
        let mut pids = self.command_pids.drain(..).collect::<Vec<_>>();
        if let Some(pid) = self.host_pid {
            pids.push(pid);
        }
        for name in ["delegated-process-host.json"] {
            if let Some(endpoint) = std::fs::read(runtime.join(name))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            {
                if let Some(pid) = endpoint["pid"].as_u64() {
                    pids.push(pid as u32);
                }
            }
        }
        pids.sort_unstable();
        pids.dedup();
        for pid in pids {
            stop_process(pid);
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[cfg(windows)]
fn stop_process(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(unix)]
fn stop_process(pid: u32) {
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
