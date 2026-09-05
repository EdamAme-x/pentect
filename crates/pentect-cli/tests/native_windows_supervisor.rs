#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "pentect-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
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

struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct ProcessHandle(HANDLE);

impl ProcessHandle {
    fn open(pid: u32) -> Self {
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        assert!(!handle.is_null(), "could not retain fixture process {pid}");
        Self(handle)
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn isolated_command(root: &Path, client: &Path) -> Command {
    let home = root.join("home");
    let project = root.join("project");
    for directory in [&home, &project, &root.join("logs")] {
        std::fs::create_dir_all(directory).unwrap();
    }
    std::fs::create_dir_all(home.join(".pentect")).unwrap();
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::write(
        home.join(".pentect/config.toml"),
        "[update]\ncheck = false\n",
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command
        .current_dir(project)
        .args(["opencode", "--opencode"])
        .arg(client)
        .arg("auth")
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("PENTECT_LOG_DIR", root.join("logs"))
        .env_remove("PENTECT_HOME");
    command
}

fn write_cmd(path: &Path, body: &str) {
    std::fs::write(path, format!("@echo off\r\n{body}\r\n")).unwrap();
}

fn wait_for_pid(marker: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(value) = std::fs::read_to_string(marker) {
            if let Ok(pid) = value.trim().parse() {
                return pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "native fixture did not become ready"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn wrapper_hard_kill_terminates_the_exact_native_client_descendant() {
    let fixture = TestDirectory::new("native-windows-parent-kill");
    let marker = fixture.0.join("client.pid");
    let client = fixture.0.join("opencode.cmd");
    write_cmd(
        &client,
        r#"powershell.exe -NoLogo -NoProfile -NonInteractive -Command "[IO.File]::WriteAllText($env:PENTECT_NATIVE_MARKER, [string]$PID); Start-Sleep -Seconds 30""#,
    );
    let mut wrapper = isolated_command(&fixture.0, &client);
    wrapper
        .env("PENTECT_NATIVE_MARKER", &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut wrapper = ChildGuard(Some(wrapper.spawn().unwrap()));
    let client_pid = wait_for_pid(&marker);
    let client = ProcessHandle::open(client_pid);

    // Child::kill targets only the retained wrapper process handle. Closing
    // its sole job handle must terminate the separately retained client.
    wrapper.0.as_mut().unwrap().kill().unwrap();
    wrapper.0.as_mut().unwrap().wait().unwrap();
    wrapper.0.take();
    assert_eq!(
        unsafe { WaitForSingleObject(client.0, 5_000) },
        WAIT_OBJECT_0
    );
}

#[test]
fn native_supervisor_preserves_normal_nonzero_and_still_active_exit_codes() {
    for expected in [0_u32, 37, 259] {
        let fixture = TestDirectory::new("native-windows-exit");
        let client = fixture.0.join("opencode.cmd");
        write_cmd(&client, &format!("exit /b {expected}"));
        let status = isolated_command(&fixture.0, &client).status().unwrap();
        assert_eq!(status.code().map(|code| code as u32), Some(expected));
    }
}

#[test]
fn bad_native_executable_fails_without_waiting_for_startup_timeout() {
    let fixture = TestDirectory::new("native-windows-bad-executable");
    let client = fixture.0.join("invalid.exe");
    std::fs::write(&client, b"not a Windows executable").unwrap();
    let started = Instant::now();
    let status = isolated_command(&fixture.0, &client).status().unwrap();
    assert!(!status.success());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "bad executable waited for the supervisor startup deadline"
    );
}
