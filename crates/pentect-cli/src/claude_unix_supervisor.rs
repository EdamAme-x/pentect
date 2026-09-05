use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;

const MAX_PAYLOAD: usize = 1024 * 1024;
const HELLO: u8 = 1;
const READY: u8 = 2;
const ACK: u8 = 3;
const STATUS: u8 = 4;
const GO: u8 = 5;

pub(crate) fn hidden_main(args: &[String]) -> Option<i32> {
    match args.get(1).map(String::as_str) {
        Some("__claude-unix-guardian") => Some(guardian_main(args)),
        Some("__claude-unix-bootstrap") => Some(bootstrap_main(args)),
        #[cfg(debug_assertions)]
        Some("__test-claude-unix-wrapper") => Some(test_wrapper(args)),
        _ => None,
    }
}

#[cfg(debug_assertions)]
fn test_wrapper(args: &[String]) -> i32 {
    let Some(program) = args.get(2) else { return 2 };
    let command = Command::new(program);
    let prepared = crate::PreparedClaudeGateway {
        encoded: br#"{"synthetic":"guardian-test"}"#.to_vec(),
        args: args[3..].to_vec(),
        settings_arg: crate::ClaudeSettingsArg::InsertFront,
    };
    match spawn_claude(&command, &prepared).and_then(|(child, owner)| wait(child, owner)) {
        Ok(status) => {
            use std::os::unix::process::ExitStatusExt as _;
            status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
        }
        Err(error) => {
            eprintln!("[pentect] {error}");
            1
        }
    }
}

pub(crate) fn spawn_claude(
    command: &Command,
    prepared: &crate::PreparedClaudeGateway,
) -> Result<(Child, UnixStream), String> {
    let payload = encode_payload(command, prepared)?;
    let (mut owner, inherited) = UnixStream::pair()
        .map_err(|error| format!("could not create Claude guardian socket: {error}"))?;
    let timeout = Some(std::time::Duration::from_secs(5));
    owner.set_read_timeout(timeout).map_err(|e| e.to_string())?;
    owner
        .set_write_timeout(timeout)
        .map_err(|e| e.to_string())?;
    let fd = inherited.as_raw_fd();
    let mut guardian = Command::new(
        std::env::current_exe().map_err(|error| format!("could not locate Pentect: {error}"))?,
    );
    guardian
        .arg("__claude-unix-guardian")
        .arg(fd.to_string())
        .process_group(0)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(cwd) = command.get_current_dir() {
        guardian.current_dir(cwd);
    }
    for (name, value) in command.get_envs() {
        match value {
            Some(value) => guardian.env(name, value),
            None => guardian.env_remove(name),
        };
    }
    unsafe {
        guardian.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = guardian
        .spawn()
        .map_err(|error| format!("could not start Claude guardian: {error}"))?;
    drop(inherited);
    let mut hello = [0];
    if let Err(error) = owner.read_exact(&mut hello) {
        cleanup_startup_guardian(&mut child, owner);
        return Err(format!("Claude guardian did not start: {error}"));
    }
    if hello[0] != HELLO {
        cleanup_startup_guardian(&mut child, owner);
        return Err("Claude guardian returned an invalid hello".to_string());
    }
    if let Err(error) = owner
        .write_all(&(payload.len() as u32).to_ne_bytes())
        .and_then(|_| owner.write_all(&payload))
    {
        cleanup_startup_guardian(&mut child, owner);
        return Err(format!("could not configure Claude guardian: {error}"));
    }
    let mut ready = [0];
    if let Err(error) = owner.read_exact(&mut ready) {
        cleanup_startup_guardian(&mut child, owner);
        return Err(format!("Claude guardian startup failed: {error}"));
    }
    if ready[0] != READY {
        cleanup_startup_guardian(&mut child, owner);
        return Err("Claude guardian returned invalid readiness".to_string());
    }
    if let Err(error) = owner.write_all(&[ACK]) {
        cleanup_startup_guardian(&mut child, owner);
        return Err(format!("could not release Claude bootstrap: {error}"));
    }
    owner
        .set_read_timeout(None)
        .map_err(|error| error.to_string())?;
    owner
        .set_write_timeout(None)
        .map_err(|error| error.to_string())?;
    Ok((child, owner))
}

fn cleanup_startup_guardian(child: &mut Child, owner: UnixStream) {
    drop(owner);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            _ if std::time::Instant::now() >= deadline => break,
            _ => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn wait(mut guardian: Child, mut owner: UnixStream) -> Result<ExitStatus, String> {
    let mut message = [0_u8; 5];
    if let Err(error) = owner.read_exact(&mut message) {
        cleanup_startup_guardian(&mut guardian, owner);
        return Err(format!("Claude guardian exited without status: {error}"));
    }
    let _ = guardian.wait();
    if message[0] != STATUS {
        return Err("Claude guardian returned invalid status".to_string());
    }
    use std::os::unix::process::ExitStatusExt as _;
    Ok(ExitStatus::from_raw(i32::from_ne_bytes(
        message[1..].try_into().unwrap(),
    )))
}

fn encode_payload(
    command: &Command,
    prepared: &crate::PreparedClaudeGateway,
) -> Result<Vec<u8>, String> {
    if command.get_program().to_str().is_none()
        || command
            .get_args()
            .any(|argument| argument.to_str().is_none())
    {
        return Err("Claude program and arguments must be valid UTF-8 on Unix".to_string());
    }
    let mut out = Vec::new();
    put(&mut out, &prepared.encoded)?;
    let (kind, index) = match prepared.settings_arg {
        crate::ClaudeSettingsArg::Inline { index } => (1_u8, index),
        crate::ClaudeSettingsArg::Separate { value_index } => (2, value_index),
        crate::ClaudeSettingsArg::InsertFront => (3, 0),
    };
    out.push(kind);
    out.extend_from_slice(
        &u32::try_from(index)
            .map_err(|_| "Claude settings index is too large")?
            .to_ne_bytes(),
    );
    put(&mut out, command.get_program().as_bytes())?;
    let args = &prepared.args;
    out.extend_from_slice(&(args.len() as u32).to_ne_bytes());
    for arg in args {
        put(&mut out, arg.as_bytes())?;
    }
    if out.len() > MAX_PAYLOAD {
        return Err("Claude guardian payload is too large".to_string());
    }
    Ok(out)
}

fn put(out: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "Claude guardian value is too large")?;
    out.extend_from_slice(&length.to_ne_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn guardian_main(args: &[String]) -> i32 {
    guardian_run(args).unwrap_or_else(|error| {
        eprintln!("[pentect] {error}");
        1
    })
}

fn guardian_run(args: &[String]) -> Result<i32, String> {
    let fd = parse_socket(args)?;
    let mut owner = unsafe { UnixStream::from_raw_fd(fd) };
    owner
        .write_all(&[HELLO])
        .map_err(|error| error.to_string())?;
    let payload = read_payload(&mut owner)?;
    owner
        .set_read_timeout(None)
        .map_err(|error| error.to_string())?;
    let (tx, rx) = mpsc::channel();
    let mut watcher = owner.try_clone().map_err(|error| error.to_string())?;
    std::thread::spawn(move || {
        let mut byte = [0];
        loop {
            match watcher.read(&mut byte) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(1) => {
                    if tx.send(Some(byte[0])).is_err() {
                        break;
                    }
                }
                _ => {
                    let _ = tx.send(None);
                    break;
                }
            }
        }
    });
    let session = crate::claude_settings_session::Session::create(&payload.settings)?;
    let path = session.settings_path();
    let client_args = match payload.args_with_settings_path(&path) {
        Ok(args) => args,
        Err(error) => {
            session.abort();
            return Err(error);
        }
    };
    let (barrier_reader, barrier_writer) = match UnixStream::pair() {
        Ok(pair) => pair,
        Err(error) => {
            session.abort();
            return Err(error.to_string());
        }
    };
    let barrier_fd = barrier_reader.as_raw_fd();
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            session.abort();
            return Err(error.to_string());
        }
    };
    let mut client = Command::new(executable);
    client
        .arg("__claude-unix-bootstrap")
        .arg(barrier_fd.to_string())
        .arg(&payload.program)
        .arg("--")
        .args(&client_args)
        .process_group(0)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    unsafe {
        client.pre_exec(move || {
            if libc::fcntl(barrier_fd, libc::F_SETFD, 0) == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut client = match client.spawn() {
        Ok(client) => client,
        Err(error) => {
            session.abort();
            return Err(format!("could not start Claude bootstrap: {error}"));
        }
    };
    drop(barrier_reader);
    if let Err(error) = owner.write_all(&[READY]) {
        terminate_anchored(&mut client)?;
        session.abort();
        return Err(error.to_string());
    }
    match rx.recv().unwrap_or(None) {
        Some(ACK) => {
            if let Err(error) = (&barrier_writer).write_all(&[GO]) {
                terminate_anchored(&mut client)?;
                session.abort();
                return Err(error.to_string());
            }
        }
        _ => {
            terminate_anchored(&mut client)?;
            session.abort();
            return Err("Claude owner exited during startup".to_string());
        }
    }
    loop {
        if matches!(
            rx.try_recv(),
            Ok(None) | Err(mpsc::TryRecvError::Disconnected)
        ) {
            terminate_anchored(&mut client)?;
            session.release();
            return Ok(1);
        }
        let exited = match exited_without_reaping(client.id()) {
            Ok(exited) => exited,
            Err(error) => {
                terminate_anchored(&mut client)?;
                session.release();
                return Err(error);
            }
        };
        if exited {
            let status = terminate_anchored(&mut client)?;
            let raw = raw_status(status);
            let mut message = [STATUS, 0, 0, 0, 0];
            message[1..].copy_from_slice(&raw.to_ne_bytes());
            let _ = owner.write_all(&message);
            session.release();
            return Ok(0);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

struct Payload {
    settings: Vec<u8>,
    settings_kind: u8,
    settings_index: usize,
    program: OsString,
    args: Vec<OsString>,
}

fn read_payload(owner: &mut UnixStream) -> Result<Payload, String> {
    let mut length = [0; 4];
    owner.read_exact(&mut length).map_err(|e| e.to_string())?;
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_PAYLOAD {
        return Err("Claude guardian payload is too large".to_string());
    }
    let mut bytes = vec![0; length];
    owner.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    let mut at = 0;
    let settings = take(&bytes, &mut at)?;
    let settings_kind = *bytes
        .get(at)
        .ok_or("Claude guardian payload is truncated")?;
    at += 1;
    let settings_index = take_u32(&bytes, &mut at)? as usize;
    let program = OsString::from_vec(take(&bytes, &mut at)?);
    let count = take_u32(&bytes, &mut at)? as usize;
    if count > 4096 {
        return Err("Claude guardian has too many arguments".to_string());
    }
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        args.push(OsString::from_vec(take(&bytes, &mut at)?));
    }
    if at != bytes.len() || program.is_empty() {
        return Err("Claude guardian payload is invalid".to_string());
    }
    Ok(Payload {
        settings,
        settings_kind,
        settings_index,
        program,
        args,
    })
}

impl Payload {
    fn args_with_settings_path(&self, path: &std::path::Path) -> Result<Vec<OsString>, String> {
        let path = path.as_os_str().to_owned();
        let mut args = self.args.clone();
        match self.settings_kind {
            1 if args
                .get(self.settings_index)
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("--settings=")) =>
            {
                let mut value = OsString::from("--settings=");
                value.push(path);
                args[self.settings_index] = value;
            }
            2 if self.settings_index > 0
                && args.get(self.settings_index - 1).and_then(|v| v.to_str())
                    == Some("--settings")
                && args.get(self.settings_index).is_some() =>
            {
                args[self.settings_index] = path
            }
            3 => {
                args.insert(0, path);
                args.insert(0, OsString::from("--settings"));
            }
            _ => return Err("Claude guardian settings location is invalid".to_string()),
        }
        Ok(args)
    }
}

fn take(bytes: &[u8], at: &mut usize) -> Result<Vec<u8>, String> {
    let length = take_u32(bytes, at)? as usize;
    let end = at
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or("Claude guardian payload is truncated")?;
    let value = bytes[*at..end].to_vec();
    *at = end;
    Ok(value)
}
fn take_u32(bytes: &[u8], at: &mut usize) -> Result<u32, String> {
    let end = at
        .checked_add(4)
        .filter(|end| *end <= bytes.len())
        .ok_or("Claude guardian payload is truncated")?;
    let value = u32::from_ne_bytes(bytes[*at..end].try_into().unwrap());
    *at = end;
    Ok(value)
}

fn parse_socket(args: &[String]) -> Result<i32, String> {
    let fd = args
        .get(2)
        .ok_or("missing Claude guardian socket")?
        .parse::<i32>()
        .map_err(|_| "invalid Claude guardian socket")?;
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if fd < 3
        || unsafe { libc::getpid() == libc::getpgrp() } == false
        || unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
    {
        return Err("invalid Claude guardian boundary".to_string());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(fd)
}

fn bootstrap_main(args: &[String]) -> i32 {
    let result = (|| -> Result<(), String> {
        let fd = args
            .get(2)
            .ok_or("missing bootstrap barrier")?
            .parse::<i32>()
            .map_err(|_| "invalid bootstrap barrier")?;
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if fd < 3
            || unsafe { libc::fstat(fd, &mut stat) } != 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
            || unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1
        {
            return Err("invalid Claude bootstrap barrier".to_string());
        }
        let program = args.get(3).ok_or("missing Claude program")?;
        if args.get(4).map(String::as_str) != Some("--") {
            return Err("invalid bootstrap arguments".to_string());
        }
        let mut barrier = unsafe { UnixStream::from_raw_fd(fd) };
        let mut byte = [0];
        barrier.read_exact(&mut byte).map_err(|e| e.to_string())?;
        if byte[0] != GO {
            return Err("Claude bootstrap was not released".to_string());
        }
        drop(barrier);
        let error = Command::new(program).args(&args[5..]).exec();
        Err(format!("could not exec Claude: {error}"))
    })();
    result.map(|_| 0).unwrap_or_else(|error| {
        eprintln!("[pentect] {error}");
        1
    })
}

fn exited_without_reaping(pid: u32) -> Result<bool, String> {
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == -1 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(unsafe { info.si_pid() } == pid as i32)
    }
}

fn terminate_anchored(child: &mut Child) -> Result<ExitStatus, String> {
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    child
        .wait()
        .map_err(|error| format!("could not reap Claude: {error}"))
}

fn raw_status(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt as _;
    status.into_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_location_is_replaced_exactly() {
        let path = std::path::Path::new("/private/generated.json");
        for (kind, index, args, expected) in [
            (
                1,
                1,
                vec!["x", "--settings=old"],
                vec!["x", "--settings=/private/generated.json"],
            ),
            (
                2,
                2,
                vec!["x", "--settings", "old"],
                vec!["x", "--settings", "/private/generated.json"],
            ),
            (
                3,
                0,
                vec!["x"],
                vec!["--settings", "/private/generated.json", "x"],
            ),
        ] {
            let payload = Payload {
                settings: vec![],
                settings_kind: kind,
                settings_index: index,
                program: OsString::from("client"),
                args: args.into_iter().map(OsString::from).collect(),
            };
            assert_eq!(
                payload.args_with_settings_path(path).unwrap(),
                expected.into_iter().map(OsString::from).collect::<Vec<_>>()
            );
        }
    }
}
