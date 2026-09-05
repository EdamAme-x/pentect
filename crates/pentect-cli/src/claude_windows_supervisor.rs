//! Windows primitives for the Claude settings supervisor.
//!
//! Nothing confidential may be created or sent until the blocked helper has
//! been authenticated and assigned to `ClaudeJob`.

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::Child;
use windows_sys::Win32::Foundation::{LocalFree, HANDLE, STILL_ACTIVE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
};

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
    let mut buffer = vec![0_u8; needed as usize];
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
        let mut code = 0;
        if unsafe { GetExitCodeProcess(process, &mut code) } == 0 || code != STILL_ACTIVE as u32 {
            return Err("Claude supervisor exited before secure startup".to_string());
        }
        Ok(())
    }
}

pub(crate) fn verify_pipe_client(pipe: HANDLE, child: &Child) -> Result<(), String> {
    let mut pid = 0;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 || pid != child.id() {
        return Err("Claude supervisor pipe identity mismatch".to_string());
    }
    Ok(())
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
