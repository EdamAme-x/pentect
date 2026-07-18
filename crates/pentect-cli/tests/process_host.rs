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
fn up_returns_keeps_one_host_and_is_idempotent() {
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();
    let mut cleanup = Cleanup {
        root: root.clone(),
        host_pid: None,
        command_pids: Vec::new(),
    };

    run_up(&root);
    let host_file = host_root(&root)
        .join("runtime")
        .join("delegated-process-host.json");
    wait_until(Duration::from_secs(10), || host_file.is_file());
    let host = read_json(&host_file);
    let host_pid = host["pid"].as_u64().unwrap() as u32;
    cleanup.host_pid = Some(host_pid);
    assert_host_alive(&host);
    assert_eq!(candidate_count(&root), 1);

    run_up(&root);
    assert_eq!(candidate_count(&root), 1);
    let second = read_json(&host_file);
    assert_eq!(second["pid"].as_u64(), Some(host_pid as u64));
    assert_host_alive(&second);
}

#[test]
fn concurrent_up_keeps_one_persistent_host() {
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();
    let mut cleanup = Cleanup {
        root: root.clone(),
        host_pid: None,
        command_pids: Vec::new(),
    };

    let first = spawn_up(&root);
    let second = spawn_up(&root);
    wait_for_up(first);
    wait_for_up(second);

    let host_file = host_root(&root)
        .join("runtime")
        .join("delegated-process-host.json");
    wait_until(Duration::from_secs(10), || host_file.is_file());
    let host = read_json(&host_file);
    cleanup.host_pid = host["pid"].as_u64().map(|pid| pid as u32);
    wait_until(Duration::from_secs(10), || candidate_count(&root) == 1);
    assert_host_alive(&host);
}

#[test]
fn codex_dry_run_uses_project_environment_prefix() {
    let root = test_root();
    let config_dir = root.join(".pentect");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        "[environment]\nprefix = \"SAFE_\"\n",
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
    assert!(rendered.contains("SAFE_<LABEL>_<HASH>"), "{rendered}");
    assert!(rendered.contains("$env:SAFE_NAME_hash"), "{rendered}");
    assert!(!rendered.contains("PENTECT_NAME_hash"), "{rendered}");
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
    assert_eq!(host["persistent"].as_bool(), Some(false));
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

fn run_up(root: &Path) {
    wait_for_up(spawn_up(root));
}

fn spawn_up(root: &Path) -> std::process::Child {
    spawn_command(root, &["up"])
}

fn spawn_command(root: &Path, args: &[&str]) -> std::process::Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for name in PRIVATE_ENV {
        command.env_remove(name);
    }
    command.env("PENTECT_PROCESS_HOST_ROOT", root.join("untrusted-override"));
    configure_runtime_root(&mut command, root);
    command.spawn().unwrap()
}

fn wait_for_up(mut child: std::process::Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "pentect up failed: {status}");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("pentect up did not return");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
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

fn candidate_count(root: &Path) -> usize {
    std::fs::read_dir(host_root(root).join("runtime"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                name.starts_with("process-host-candidate-")
                    || name == "process-host-persistent.json"
            })
        })
        .count()
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
        for pid in self.command_pids.drain(..) {
            stop_process(pid);
        }
        if let Some(pid) = self.host_pid {
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
