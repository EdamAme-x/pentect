//! Windows primitives for the Claude settings supervisor.
//!
//! Nothing confidential may be created or sent until the blocked helper has
//! been authenticated and assigned to `ClaudeJob`.

use std::ffi::c_void;
use std::io::IsTerminal as _;
use std::io::Write as _;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
use windows_sys::Win32::Foundation::{LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::JobObjects::IsProcessInJob;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, WaitForSingleObject,
};

const PROTOCOL_VERSION: u8 = 1;
const MAX_FRAME: usize = 4 * 1024 * 1024;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

fn current_user_sid() -> Result<String, String> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err("could not identify Claude supervisor owner".to_string());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
    let mut needed = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err("could not identify Claude supervisor owner".to_string());
    }
    let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err("could not identify Claude supervisor owner".to_string());
    }
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err("could not identify Claude supervisor owner".to_string());
    }
    let length = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| "could not identify Claude supervisor owner".to_string());
    unsafe { LocalFree(text.cast()) };
    sid
}

pub(crate) struct OwnerOnlySecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

impl OwnerOnlySecurity {
    pub(crate) fn new() -> Result<Self, String> {
        use std::os::windows::ffi::OsStrExt;
        let sddl = format!("D:P(A;;GA;;;{})", current_user_sid()?);
        let wide: Vec<u16> = std::ffi::OsStr::new(&sddl)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err("could not prepare private Claude supervisor security".to_string());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.cast(),
            bInheritHandle: 0,
        };
        Ok(Self {
            descriptor,
            attributes,
        })
    }

    pub(crate) fn attributes(&mut self) -> *mut c_void {
        std::ptr::addr_of_mut!(self.attributes).cast()
    }
}

impl Drop for OwnerOnlySecurity {
    fn drop(&mut self) {
        unsafe { LocalFree(self.descriptor.cast()) };
    }
}

pub(crate) fn create_private_pipe(
) -> Result<(String, tokio::net::windows::named_pipe::NamedPipeServer), String> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| "could not name Claude supervisor pipe".to_string())?;
    let name = format!(
        r"\\.\pipe\pentect-claude-{}-{}",
        std::process::id(),
        data_encoding::HEXLOWER.encode(&nonce)
    );
    let mut security = OwnerOnlySecurity::new()?;
    let server = unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(&name, security.attributes())
    }
    .map_err(|_| "could not create private Claude supervisor pipe".to_string())?;
    Ok((name, server))
}

pub(crate) struct ClaudeJob(OwnedHandle);

impl ClaudeJob {
    pub(crate) fn new() -> Result<Self, String> {
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err("could not create Claude supervisor job".to_string());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                handle.as_raw_handle().cast(),
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(info).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        } == 0
        {
            return Err("could not configure Claude supervisor job".to_string());
        }
        Ok(Self(handle))
    }

    pub(crate) fn assign_live(&self, child: &Child) -> Result<(), String> {
        let process = child.as_raw_handle().cast();
        if unsafe { AssignProcessToJobObject(self.0.as_raw_handle().cast(), process) } == 0 {
            return Err("could not contain Claude supervisor process".to_string());
        }
        if unsafe { WaitForSingleObject(process, 0) } != WAIT_TIMEOUT {
            return Err("Claude supervisor exited before secure startup".to_string());
        }
        Ok(())
    }
}

struct PrivateSettings {
    directory: PathBuf,
    path: PathBuf,
    file: Option<std::fs::File>,
}

impl PrivateSettings {
    fn create(contents: &[u8]) -> Result<Self, String> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateDirectoryW, CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL,
            FILE_FLAG_DELETE_ON_CLOSE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| "could not name protected Claude settings".to_string())?;
        let directory = std::env::temp_dir().join(format!(
            "pentect-claude-settings-{}-{}",
            std::process::id(),
            data_encoding::HEXLOWER.encode(&nonce)
        ));
        let mut security = OwnerOnlySecurity::new()?;
        let dir_wide: Vec<u16> = directory.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe { CreateDirectoryW(dir_wide.as_ptr(), security.attributes().cast()) } == 0 {
            return Err("could not create private Claude settings directory".to_string());
        }
        let path = directory.join("settings.json");
        let file_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let raw = unsafe {
            CreateFileW(
                file_wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                security.attributes().cast(),
                windows_sys::Win32::Storage::FileSystem::CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
                std::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            let _ = std::fs::remove_dir(&directory);
            return Err("could not create private Claude settings".to_string());
        }
        let mut file = unsafe { std::fs::File::from_raw_handle(raw.cast()) };
        if file
            .write_all(contents)
            .and_then(|_| file.sync_all())
            .is_err()
        {
            drop(file);
            let _ = std::fs::remove_dir(&directory);
            return Err("could not write private Claude settings".to_string());
        }
        Ok(Self {
            directory,
            path,
            file: Some(file),
        })
    }
}

impl Drop for PrivateSettings {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn payload_args(payload: &LaunchPayload, path: &Path) -> Result<Vec<String>, String> {
    let path = path.to_string_lossy();
    let mut args = payload.args.clone();
    match payload.location {
        SettingsLocation::Inline(index)
            if args
                .get(index)
                .is_some_and(|v| v.starts_with("--settings=")) =>
        {
            args[index] = format!("--settings={path}");
        }
        SettingsLocation::Separate(index)
            if index > 0
                && args.get(index - 1).map(String::as_str) == Some("--settings")
                && args.get(index).is_some() =>
        {
            args[index] = path.into_owned();
        }
        SettingsLocation::InsertFront => {
            args.insert(0, path.into_owned());
            args.insert(0, "--settings".to_string());
        }
        _ => return Err("Claude supervisor settings argument is invalid".to_string()),
    }
    Ok(args)
}

pub(crate) fn run_helper(argv: &[String]) -> i32 {
    let Some(pipe_name) = argv.get(2).filter(|_| argv.len() == 3) else {
        return 2;
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return 2,
    };
    runtime.block_on(async {
        let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
        let mut pipe = loop {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(pipe_name) {
                Ok(pipe) => break pipe,
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(_) => return 2,
            }
        };
        let frame = match tokio::time::timeout(STARTUP_TIMEOUT, read_frame(&mut pipe)).await {
            Ok(Ok(frame)) => frame,
            _ => return 2,
        };
        let payload: LaunchPayload = match serde_json::from_slice(&frame) {
            Ok(payload) if payload.version == PROTOCOL_VERSION => payload,
            _ => return 2,
        };
        if payload.program.is_empty() || payload.settings.len() > MAX_FRAME {
            return 2;
        }
        let mut contained = 0;
        let mut server_pid = 0;
        if unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut contained) } == 0
            || contained == 0
            || unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &mut server_pid) }
                == 0
            || server_pid != payload.wrapper_pid
            || payload_args(&payload, Path::new(r"C:\pentect-settings-probe")).is_err()
        {
            return 2;
        }
        let settings = match PrivateSettings::create(&payload.settings) {
            Ok(value) => value,
            Err(_) => return 2,
        };
        let args = match payload_args(&payload, &settings.path) {
            Ok(value) => value,
            Err(_) => return 2,
        };
        let mut command = Command::new(from_wide(&payload.program));
        if let Some(cwd) = payload.cwd.as_deref() {
            command.current_dir(from_wide(cwd));
        }
        command
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => return 2,
        };
        if pipe.write_u8(1).await.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return 2;
        }
        if crate::install_native_interrupt_handler().is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return 2;
        }
        crate::NATIVE_COMMAND_INTERRUPTS.store(0, std::sync::atomic::Ordering::SeqCst);
        match crate::wait_for_native_child(
            &mut child,
            &crate::NATIVE_COMMAND_INTERRUPTS,
            std::io::stdin().is_terminal(),
            crate::NATIVE_REPEAT_INTERRUPT_WINDOW,
            crate::NATIVE_INTERRUPT_GRACE,
        ) {
            Ok(status) => status.code().unwrap_or(1),
            Err(_) => 2,
        }
    })
}

pub(crate) fn verify_pipe_client(pipe: HANDLE, child: &Child) -> Result<(), String> {
    let mut pid = 0;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 || pid != child.id() {
        return Err("Claude supervisor pipe identity mismatch".to_string());
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
enum SettingsLocation {
    Inline(usize),
    Separate(usize),
    InsertFront,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LaunchPayload {
    version: u8,
    wrapper_pid: u32,
    program: Vec<u16>,
    cwd: Option<Vec<u16>>,
    args: Vec<String>,
    settings: Vec<u8>,
    location: SettingsLocation,
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().collect()
}

fn from_wide(value: &[u16]) -> std::ffi::OsString {
    use std::os::windows::ffi::OsStringExt;
    std::ffi::OsString::from_wide(value)
}

async fn write_frame(
    pipe: &mut (impl AsyncWriteExt + Unpin),
    payload: &[u8],
) -> Result<(), String> {
    if payload.len() > MAX_FRAME {
        return Err("Claude supervisor payload is too large".to_string());
    }
    pipe.write_u32_le(payload.len() as u32)
        .await
        .map_err(|_| "could not send Claude supervisor payload".to_string())?;
    pipe.write_all(payload)
        .await
        .map_err(|_| "could not send Claude supervisor payload".to_string())
}

async fn read_frame(pipe: &mut (impl AsyncReadExt + Unpin)) -> Result<Vec<u8>, String> {
    let length = pipe
        .read_u32_le()
        .await
        .map_err(|_| "could not receive Claude supervisor payload".to_string())?
        as usize;
    if length == 0 || length > MAX_FRAME {
        return Err("Claude supervisor payload length is invalid".to_string());
    }
    let mut payload = vec![0; length];
    pipe.read_exact(&mut payload)
        .await
        .map_err(|_| "could not receive Claude supervisor payload".to_string())?;
    Ok(payload)
}

pub(crate) fn launch(
    client: &Command,
    prepared: crate::PreparedClaudeGateway,
    display: &Path,
) -> Result<ExitStatus, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| "could not initialize Claude supervisor".to_string())?;
    let (pipe_name, mut pipe) = runtime.block_on(async { create_private_pipe() })?;
    let job = ClaudeJob::new()?;
    let mut helper = Command::new(
        std::env::current_exe().map_err(|_| "could not locate Claude supervisor".to_string())?,
    );
    helper.arg("__claude-windows-supervisor").arg(&pipe_name);
    if let Some(cwd) = client.get_current_dir() {
        helper.current_dir(cwd);
    }
    for (name, value) in client.get_envs() {
        match value {
            Some(value) => helper.env(name, value),
            None => helper.env_remove(name),
        };
    }
    helper
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let child = helper
        .spawn()
        .map_err(|_| "could not start Claude supervisor".to_string())?;
    let mut guard = StartupGuard {
        child: Some(child),
        job: Some(job),
    };
    let child = guard.child.as_mut().expect("helper retained");
    guard
        .job
        .as_ref()
        .expect("job retained")
        .assign_live(child)?;
    runtime
        .block_on(async { tokio::time::timeout(STARTUP_TIMEOUT, pipe.connect()).await })
        .map_err(|_| "Claude supervisor startup timed out".to_string())?
        .map_err(|_| "could not connect Claude supervisor".to_string())?;
    verify_pipe_client(pipe.as_raw_handle().cast(), &child)?;
    guard
        .job
        .as_ref()
        .expect("job retained")
        .assign_live_check(child)?;
    let location = match prepared.settings_arg {
        crate::ClaudeSettingsArg::Inline { index } => SettingsLocation::Inline(index),
        crate::ClaudeSettingsArg::Separate { value_index } => {
            SettingsLocation::Separate(value_index)
        }
        crate::ClaudeSettingsArg::InsertFront => SettingsLocation::InsertFront,
    };
    let payload = LaunchPayload {
        version: PROTOCOL_VERSION,
        wrapper_pid: std::process::id(),
        program: wide(client.get_program()),
        cwd: client.get_current_dir().map(wide),
        args: prepared.args,
        settings: prepared.encoded,
        location,
    };
    let encoded = serde_json::to_vec(&payload)
        .map_err(|_| "could not encode Claude supervisor payload".to_string())?;
    runtime
        .block_on(async {
            tokio::time::timeout(STARTUP_TIMEOUT, write_frame(&mut pipe, &encoded)).await
        })
        .map_err(|_| "Claude supervisor payload timed out".to_string())??;
    let acknowledged =
        runtime.block_on(async { tokio::time::timeout(STARTUP_TIMEOUT, pipe.read_u8()).await });
    if !matches!(acknowledged, Ok(Ok(1))) {
        return Err("Claude supervisor did not confirm client startup".to_string());
    }
    drop(pipe);
    let mut child = guard.child.take().expect("helper retained");
    let job = guard.job.take().expect("job retained");
    let status = crate::wait_for_native_child(
        &mut child,
        &crate::NATIVE_COMMAND_INTERRUPTS,
        std::io::stdin().is_terminal(),
        crate::NATIVE_REPEAT_INTERRUPT_WINDOW,
        crate::NATIVE_INTERRUPT_GRACE,
    )
    .map_err(|error| format!("could not wait for '{}': {error}", display.display()))?;
    drop(job);
    Ok(status)
}

struct StartupGuard {
    child: Option<Child>,
    job: Option<ClaudeJob>,
}

impl Drop for StartupGuard {
    fn drop(&mut self) {
        // Close the sole job handle first so the blocked helper is terminated,
        // then reap its retained process handle.
        drop(self.job.take());
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl ClaudeJob {
    fn assign_live_check(&self, child: &Child) -> Result<(), String> {
        if unsafe { WaitForSingleObject(child.as_raw_handle().cast(), 0) } != WAIT_TIMEOUT {
            return Err("Claude supervisor exited before secure startup".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_security_is_non_inheritable() {
        let security = OwnerOnlySecurity::new().unwrap();
        assert_eq!(security.attributes.bInheritHandle, 0);
        assert!(!security.descriptor.is_null());
    }

    #[test]
    fn job_handle_is_valid_and_non_inherited_by_construction() {
        let job = ClaudeJob::new().unwrap();
        assert!(!job.0.as_raw_handle().is_null());
    }
}
