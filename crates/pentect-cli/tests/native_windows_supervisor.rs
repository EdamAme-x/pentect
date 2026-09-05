#![cfg(windows)]

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
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
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, 0, pid) };
        assert!(!handle.is_null(), "could not retain fixture process {pid}");
        Self(handle)
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if unsafe { WaitForSingleObject(self.0, 0) } == windows_sys::Win32::Foundation::WAIT_TIMEOUT
        {
            unsafe { TerminateProcess(self.0, 1) };
            let _ = unsafe { WaitForSingleObject(self.0, 5_000) };
        }
        unsafe { CloseHandle(self.0) };
    }
}

fn output_bounded(mut command: Command, root: &Path, timeout: Duration) -> Output {
    let stdout_path = root.join("wrapper.stdout");
    let stderr_path = root.join("wrapper.stderr");
    command
        .stdout(Stdio::from(std::fs::File::create(&stdout_path).unwrap()))
        .stderr(Stdio::from(std::fs::File::create(&stderr_path).unwrap()));
    let spawned = command.spawn().unwrap();
    // Do not retain the parent's copies of the fixture output handles.
    drop(command);
    let mut child = ChildGuard(Some(spawned));
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
            drop(child.0.take());
            return Output {
                status,
                stdout: std::fs::read(&stdout_path).unwrap(),
                stderr: std::fs::read(&stderr_path).unwrap(),
            };
        }
        assert!(Instant::now() < deadline, "supervised command did not exit");
        std::thread::sleep(Duration::from_millis(20));
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

fn diagnostic_tail(path: &Path) -> String {
    const LIMIT: u64 = 4 * 1024;
    let Ok(mut file) = std::fs::File::open(path) else {
        return String::new();
    };
    let length = file.metadata().map(|value| value.len()).unwrap_or(0);
    let _ = file.seek(SeekFrom::Start(length.saturating_sub(LIMIT)));
    let mut bytes = Vec::with_capacity(LIMIT as usize);
    let _ = file.take(LIMIT).read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

fn wrapper_diagnostics(stdout: &Path, stderr: &Path) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        diagnostic_tail(stdout),
        diagnostic_tail(stderr)
    )
}

fn wait_for_pid(marker: &Path, wrapper: &mut ChildGuard, stdout: &Path, stderr: &Path) -> u32 {
    // This fixture deadline includes the synthetic PowerShell startup after
    // cmd.exe launches; it is separate from each supervisor protocol stage.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(value) = std::fs::read_to_string(marker) {
            if let Ok(pid) = value.trim().parse() {
                return pid;
            }
        }
        if let Some(status) = wrapper.0.as_mut().unwrap().try_wait().unwrap() {
            drop(wrapper.0.take());
            panic!(
                "native fixture exited before readiness with {status}: {}",
                wrapper_diagnostics(stdout, stderr)
            );
        }
        assert!(
            Instant::now() < deadline,
            "native fixture did not become ready: {}",
            wrapper_diagnostics(stdout, stderr)
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
    let stdout = fixture.0.join("parent-kill.stdout");
    let stderr = fixture.0.join("parent-kill.stderr");
    wrapper
        .env("PENTECT_NATIVE_MARKER", &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::fs::File::create(&stdout).unwrap()))
        .stderr(Stdio::from(std::fs::File::create(&stderr).unwrap()));
    let spawned = wrapper.spawn().unwrap();
    // Do not retain parent copies of output handles while observing readiness.
    drop(wrapper);
    let mut wrapper = ChildGuard(Some(spawned));
    let client_pid = wait_for_pid(&marker, &mut wrapper, &stdout, &stderr);
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
        let output = output_bounded(
            isolated_command(&fixture.0, &client),
            &fixture.0,
            Duration::from_secs(20),
        );
        assert_eq!(
            output.status.code().map(|code| code as u32),
            Some(expected),
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn bad_native_executable_fails_without_waiting_for_startup_timeout() {
    let fixture = TestDirectory::new("native-windows-bad-executable");
    let client = fixture.0.join("invalid.exe");
    std::fs::write(&client, b"not a Windows executable").unwrap();
    let output = output_bounded(
        isolated_command(&fixture.0, &client),
        &fixture.0,
        Duration::from_secs(20),
    );
    assert!(!output.status.success());
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !diagnostic.contains("startup timed out") && !diagnostic.contains("payload timed out"),
        "bad executable reached a supervisor timeout instead of failing startup: {diagnostic}"
    );
}
