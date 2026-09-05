use std::ffi::OsString;
use std::io::IsTerminal as _;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;

const MAX_PAYLOAD: usize = 1024 * 1024;
const STARTUP_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(target_os = "linux")]
const DESCENDANT_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
// Startup can spend one bounded interval writing the bootstrap frame and a
// second draining descendants after EOF. Leave scheduling slack for both.
const GUARDIAN_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);
const HELLO: u8 = 1;
const READY: u8 = 2;
const ACK: u8 = 3;
const STATUS: u8 = 4;
const GO: u8 = 5;
const RELAY_READY: u8 = 6;
const INTERRUPT: u8 = 7;
const STOPPED: u8 = 8;
const CONTINUE: u8 = 9;
const CANCEL: u8 = 10;
const STATUS_ACK: u8 = 11;
static RELAY_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
#[cfg(target_os = "linux")]
static LINUX_TREE_DRAIN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn hidden_main(args: &[String]) -> Option<i32> {
    match args.get(1).map(String::as_str) {
        Some("__claude-unix-guardian") => Some(guardian_main(args)),
        Some("__claude-unix-bootstrap") => Some(bootstrap_main(args)),
        Some("__claude-unix-relay") => Some(relay_main(args)),
        _ => None,
    }
}

pub(crate) enum NativeSetup<'a> {
    None,
    Claude(&'a crate::PreparedClaudeGateway),
}

pub(crate) fn spawn_native(
    command: &Command,
    setup: NativeSetup<'_>,
) -> Result<Supervised, String> {
    let payload = encode_payload(command, setup)?;
    let (mut owner, inherited) = UnixStream::pair()
        .map_err(|error| format!("could not create Claude guardian socket: {error}"))?;
    let timeout = Some(STARTUP_IO_TIMEOUT);
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
        cleanup_startup_guardian(&mut child, &owner);
        return Err(format!("Claude guardian did not start: {error}"));
    }
    if hello[0] != HELLO {
        cleanup_startup_guardian(&mut child, &owner);
        return Err("Claude guardian returned an invalid hello".to_string());
    }
    if let Err(error) = owner
        .write_all(&(payload.len() as u32).to_ne_bytes())
        .and_then(|_| owner.write_all(&payload))
    {
        cleanup_startup_guardian(&mut child, &owner);
        return Err(format!("could not configure Claude guardian: {error}"));
    }
    let mut ready = [0; 5];
    if let Err(error) = owner.read_exact(&mut ready) {
        cleanup_startup_guardian(&mut child, &owner);
        return Err(format!("Claude guardian startup failed: {error}"));
    }
    if ready[0] != READY {
        cleanup_startup_guardian(&mut child, &owner);
        return Err("Claude guardian returned invalid readiness".to_string());
    }
    let pgid = i32::from_ne_bytes(ready[1..].try_into().unwrap());
    if pgid <= 0 {
        cleanup_startup_guardian(&mut child, &owner);
        return Err("Claude guardian returned invalid process group".to_string());
    }
    let foreground = match Foreground::give_to(pgid) {
        Ok(value) => value,
        Err(error) => {
            cleanup_startup_guardian(&mut child, &owner);
            return Err(error);
        }
    };
    if let Err(error) = owner.write_all(&[ACK]) {
        cleanup_startup_guardian(&mut child, &owner);
        return Err(format!("could not release Claude bootstrap: {error}"));
    }
    if let Err(error) = owner
        .set_read_timeout(None)
        .and_then(|_| owner.set_write_timeout(None))
    {
        cleanup_startup_guardian(&mut child, &owner);
        return Err(error.to_string());
    }
    Ok(Supervised {
        guardian: child,
        owner,
        pgid,
        foreground,
    })
}

pub(crate) struct Supervised {
    guardian: Child,
    owner: UnixStream,
    pgid: i32,
    foreground: Option<Foreground>,
}

impl Drop for Supervised {
    fn drop(&mut self) {
        drop(self.foreground.take());
        let _ = self.owner.shutdown(std::net::Shutdown::Both);
        let deadline = std::time::Instant::now() + GUARDIAN_CLEANUP_TIMEOUT;
        loop {
            match self.guardian.try_wait() {
                Ok(Some(_)) => break,
                _ if std::time::Instant::now() >= deadline => {
                    let _ = self.guardian.kill();
                    let _ = self.guardian.wait();
                    break;
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
    }
}

fn cleanup_startup_guardian(child: &mut Child, owner: &UnixStream) {
    let _ = owner.shutdown(std::net::Shutdown::Both);
    let deadline = std::time::Instant::now() + GUARDIAN_CLEANUP_TIMEOUT;
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

pub(crate) fn wait(mut managed: Supervised) -> Result<ExitStatus, String> {
    managed
        .owner
        .set_nonblocking(true)
        .map_err(|e| e.to_string())?;
    let mut message = [0_u8; 5];
    let mut received = 0;
    let mut interrupts = 0;
    loop {
        if managed.foreground.is_none()
            && std::io::stdin().is_terminal()
            && unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) == libc::getpgrp() }
        {
            managed.foreground = Foreground::give_to(managed.pgid)?;
            managed
                .owner
                .write_all(&[CONTINUE])
                .map_err(|e| e.to_string())?;
        }
        let count = crate::NATIVE_COMMAND_INTERRUPTS.load(std::sync::atomic::Ordering::SeqCst);
        if count != interrupts {
            interrupts = count;
            managed
                .owner
                .write_all(&[CANCEL])
                .map_err(|e| e.to_string())?;
        }
        match managed.owner.read(&mut message[received..]) {
            Ok(0) => {
                drop(managed.foreground.take());
                cleanup_startup_guardian(&mut managed.guardian, &managed.owner);
                return Err("Claude guardian exited without status".to_string());
            }
            Ok(n) => {
                received += n;
                if received == 5 {
                    match message[0] {
                        STATUS => {
                            restore_foreground(&mut managed.foreground)?;
                            managed
                                .owner
                                .write_all(&[STATUS_ACK])
                                .map_err(|e| e.to_string())?;
                            let guardian_status = managed.guardian.wait().map_err(|error| {
                                format!("could not reap Claude guardian: {error}")
                            })?;
                            validate_guardian_status(guardian_status)?;
                            use std::os::unix::process::ExitStatusExt as _;
                            return Ok(ExitStatus::from_raw(i32::from_ne_bytes(
                                message[1..].try_into().unwrap(),
                            )));
                        }
                        STOPPED => {
                            restore_foreground(&mut managed.foreground)?;
                            unsafe {
                                libc::kill(libc::getpid(), libc::SIGSTOP);
                            }
                            managed.foreground = Foreground::give_to(managed.pgid)?;
                            managed
                                .owner
                                .write_all(&[CONTINUE])
                                .map_err(|e| e.to_string())?;
                        }
                        _ => return Err("Claude guardian returned invalid event".to_string()),
                    }
                    received = 0;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn validate_guardian_status(status: ExitStatus) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("Claude guardian exited with status {status}"))
    }
}

fn encode_payload(command: &Command, setup: NativeSetup<'_>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let args: Vec<OsString> = match setup {
        NativeSetup::None => {
            out.push(0);
            command.get_args().map(OsString::from).collect()
        }
        NativeSetup::Claude(prepared) => {
            out.push(1);
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
            prepared.args.iter().map(OsString::from).collect()
        }
    };
    put(&mut out, command.get_program().as_bytes())?;
    out.extend_from_slice(&(args.len() as u32).to_ne_bytes());
    for arg in &args {
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

fn encode_exec_payload(program: &std::ffi::OsStr, args: &[OsString]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    put(&mut out, program.as_bytes())?;
    out.extend_from_slice(
        &u32::try_from(args.len())
            .map_err(|_| "native client has too many arguments")?
            .to_ne_bytes(),
    );
    for arg in args {
        put(&mut out, arg.as_bytes())?;
    }
    if out.len() > MAX_PAYLOAD {
        Err("native client exec payload is too large".to_string())
    } else {
        Ok(out)
    }
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
    #[cfg(target_os = "linux")]
    if let Err(error) = enable_linux_tree_drain() {
        eprintln!(
            "[pentect] warning: descendant cleanup is limited to the managed process group: {error}"
        );
    }
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
    let session = ManagedSession::create(payload.setup.as_ref())?;
    let settings_path = session.settings_path();
    let client_args = match payload.args_with_settings_path(settings_path.as_deref()) {
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
    let mut client = Command::new(&executable);
    client
        .arg("__claude-unix-bootstrap")
        .arg(barrier_fd.to_string())
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
    let (mut relay_events, relay_inherited) = match UnixStream::pair() {
        Ok(pair) => pair,
        Err(error) => {
            terminate_anchored(&mut client)?;
            session.abort();
            return Err(error.to_string());
        }
    };
    let relay_fd = relay_inherited.as_raw_fd();
    let group = client.id() as i32;
    let mut relay_command = Command::new(&executable);
    relay_command
        .arg("__claude-unix-relay")
        .arg(relay_fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    unsafe {
        relay_command.pre_exec(move || {
            if libc::setpgid(0, group) == -1 || libc::fcntl(relay_fd, libc::F_SETFD, 0) == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut relay = match relay_command.spawn() {
        Ok(child) => child,
        Err(error) => {
            terminate_anchored(&mut client)?;
            session.abort();
            return Err(error.to_string());
        }
    };
    drop(relay_inherited);
    if let Err(error) = relay_events.set_read_timeout(Some(std::time::Duration::from_secs(5))) {
        terminate_managed(&mut client, &mut relay)?;
        session.abort();
        return Err(error.to_string());
    }
    let mut relay_ready = [0];
    if relay_events.read_exact(&mut relay_ready).is_err() || relay_ready[0] != RELAY_READY {
        terminate_managed(&mut client, &mut relay)?;
        session.abort();
        return Err("Claude signal relay did not start".to_string());
    }
    if let Err(error) = relay_events.set_nonblocking(true) {
        terminate_managed(&mut client, &mut relay)?;
        session.abort();
        return Err(error.to_string());
    }
    let mut ready = [READY, 0, 0, 0, 0];
    ready[1..].copy_from_slice(&(client.id() as i32).to_ne_bytes());
    if let Err(error) = owner.write_all(&ready) {
        terminate_managed(&mut client, &mut relay)?;
        session.abort();
        return Err(error.to_string());
    }
    match rx.recv_timeout(STARTUP_IO_TIMEOUT).unwrap_or(None) {
        Some(ACK) => {
            if let Err(error) = barrier_writer.set_write_timeout(Some(STARTUP_IO_TIMEOUT)) {
                terminate_managed(&mut client, &mut relay)?;
                session.abort();
                return Err(error.to_string());
            }
            let exec_payload = match encode_exec_payload(&payload.program, &client_args) {
                Ok(payload) => payload,
                Err(error) => {
                    terminate_managed(&mut client, &mut relay)?;
                    session.abort();
                    return Err(error);
                }
            };
            if let Err(error) = (&barrier_writer)
                .write_all(&(exec_payload.len() as u32).to_ne_bytes())
                .and_then(|_| (&barrier_writer).write_all(&exec_payload))
                .and_then(|_| (&barrier_writer).write_all(&[GO]))
            {
                terminate_managed(&mut client, &mut relay)?;
                session.abort();
                return Err(error.to_string());
            }
        }
        _ => {
            terminate_managed(&mut client, &mut relay)?;
            session.abort();
            return Err("Claude owner exited during startup".to_string());
        }
    }
    let mut first_interrupt = None;
    let mut shutdown = None;
    let mut forced = false;
    #[cfg(target_os = "linux")]
    let mut last_orphan_reap = std::time::Instant::now();
    #[cfg(target_os = "linux")]
    let mut orphan_reap_cursor = 0;
    loop {
        match rx.try_recv() {
            Ok(None) | Err(mpsc::TryRecvError::Disconnected) => {
                terminate_managed(&mut client, &mut relay)?;
                session.release();
                return Ok(1);
            }
            Ok(Some(CANCEL)) => {
                if shutdown.is_none() {
                    unsafe {
                        libc::kill(-(client.id() as i32), libc::SIGINT);
                    }
                    shutdown = Some(std::time::Instant::now());
                }
            }
            Ok(Some(CONTINUE)) => unsafe {
                libc::kill(-(client.id() as i32), libc::SIGCONT);
            },
            _ => {}
        }
        let mut signal = [0];
        match relay_events.read(&mut signal) {
            Ok(1) if signal[0] == INTERRUPT => {
                let now = std::time::Instant::now();
                if first_interrupt.is_some_and(|at: std::time::Instant| {
                    now.duration_since(at) <= std::time::Duration::from_secs(2)
                }) {
                    shutdown.get_or_insert(now);
                } else {
                    first_interrupt = Some(now);
                }
            }
            Ok(0) => {
                unsafe {
                    libc::kill(-(client.id() as i32), libc::SIGKILL);
                }
                forced = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) | Ok(_) => {
                unsafe {
                    libc::kill(-(client.id() as i32), libc::SIGKILL);
                }
                forced = true;
            }
        }
        if first_interrupt.is_some_and(|at| at.elapsed() > std::time::Duration::from_secs(2)) {
            first_interrupt = None;
        }
        if !forced && shutdown.is_some_and(|at| at.elapsed() >= std::time::Duration::from_secs(2)) {
            unsafe {
                libc::kill(-(client.id() as i32), libc::SIGKILL);
            }
            forced = true;
        }
        #[cfg(target_os = "linux")]
        if LINUX_TREE_DRAIN.load(std::sync::atomic::Ordering::Acquire)
            && last_orphan_reap.elapsed() >= std::time::Duration::from_millis(500)
        {
            if let Err(error) = reap_linux_adopted_zombies(
                client.id() as i32,
                relay.id() as i32,
                &mut orphan_reap_cursor,
            ) {
                terminate_managed(&mut client, &mut relay)?;
                session.release();
                return Err(error);
            }
            last_orphan_reap = std::time::Instant::now();
        }
        let stopped = match stopped_without_reaping(client.id()) {
            Ok(stopped) => stopped,
            Err(error) => {
                terminate_managed(&mut client, &mut relay)?;
                session.release();
                return Err(error);
            }
        };
        if stopped {
            let event = [STOPPED, 0, 0, 0, 0];
            if let Err(error) = owner.write_all(&event) {
                terminate_managed(&mut client, &mut relay)?;
                session.release();
                return Err(error.to_string());
            }
        }
        let exited = match raw_status_without_reaping(client.id()) {
            Ok(status) => status,
            Err(error) => {
                terminate_managed(&mut client, &mut relay)?;
                session.release();
                return Err(error);
            }
        };
        if let Some(raw) = exited {
            unsafe {
                libc::kill(-(client.id() as i32), libc::SIGKILL);
            }
            let mut message = [STATUS, 0, 0, 0, 0];
            message[1..].copy_from_slice(&raw.to_ne_bytes());
            if let Err(error) = owner.write_all(&message) {
                terminate_managed(&mut client, &mut relay)?;
                session.release();
                return Err(error.to_string());
            }
            // Keep the direct Claude child unreaped as the PGID anchor until
            // the live wrapper confirms it restored terminal ownership. Owner
            // EOF remains the fail-safe when the wrapper dies while paused.
            if !await_status_ack(&rx) {
                terminate_managed(&mut client, &mut relay)?;
                session.release();
                return Ok(1);
            }
            terminate_managed(&mut client, &mut relay)?;
            session.release();
            return Ok(0);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn await_status_ack(rx: &mpsc::Receiver<Option<u8>>) -> bool {
    loop {
        match rx.recv().unwrap_or(None) {
            Some(STATUS_ACK) => return true,
            Some(_) => continue,
            None => return false,
        }
    }
}

struct ClaudeSetup {
    settings: Vec<u8>,
    settings_kind: u8,
    settings_index: usize,
}

struct Payload {
    setup: Option<ClaudeSetup>,
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
    let setup = match bytes.get(at).copied() {
        Some(0) => {
            at += 1;
            None
        }
        Some(1) => {
            at += 1;
            let settings = take(&bytes, &mut at)?;
            let settings_kind = *bytes
                .get(at)
                .ok_or("Claude guardian payload is truncated")?;
            at += 1;
            let settings_index = take_u32(&bytes, &mut at)? as usize;
            Some(ClaudeSetup {
                settings,
                settings_kind,
                settings_index,
            })
        }
        _ => return Err("native guardian setup is invalid".to_string()),
    };
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
        setup,
        program,
        args,
    })
}

impl Payload {
    fn args_with_settings_path(
        &self,
        path: Option<&std::path::Path>,
    ) -> Result<Vec<OsString>, String> {
        let Some(setup) = &self.setup else {
            return Ok(self.args.clone());
        };
        let path = path.ok_or("Claude guardian settings session is missing")?;
        let path = path.as_os_str().to_owned();
        let mut args = self.args.clone();
        match setup.settings_kind {
            1 if args
                .get(setup.settings_index)
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("--settings=")) =>
            {
                let mut value = OsString::from("--settings=");
                value.push(path);
                args[setup.settings_index] = value;
            }
            2 if setup.settings_index > 0
                && args.get(setup.settings_index - 1).and_then(|v| v.to_str())
                    == Some("--settings")
                && args.get(setup.settings_index).is_some() =>
            {
                args[setup.settings_index] = path
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

struct ManagedSession(Option<crate::claude_settings_session::Session>);

impl ManagedSession {
    fn create(setup: Option<&ClaudeSetup>) -> Result<Self, String> {
        setup
            .map(|setup| crate::claude_settings_session::Session::create(&setup.settings))
            .transpose()
            .map(Self)
    }

    fn settings_path(&self) -> Option<std::path::PathBuf> {
        self.0.as_ref().map(|session| session.settings_path())
    }

    fn abort(self) {
        if let Some(session) = self.0 {
            session.abort();
        }
    }

    fn release(self) {
        if let Some(session) = self.0 {
            session.release();
        }
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
        || unsafe { libc::getpid() != libc::getpgrp() }
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
        if args.len() != 3 {
            return Err("invalid bootstrap arguments".to_string());
        }
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
        let mut barrier = unsafe { UnixStream::from_raw_fd(fd) };
        let mut length = [0; 4];
        barrier.read_exact(&mut length).map_err(|e| e.to_string())?;
        let length = u32::from_ne_bytes(length) as usize;
        if length > MAX_PAYLOAD {
            return Err("native client exec payload is too large".to_string());
        }
        let mut encoded = vec![0; length];
        barrier
            .read_exact(&mut encoded)
            .map_err(|e| e.to_string())?;
        let mut at = 0;
        let program = OsString::from_vec(take(&encoded, &mut at)?);
        let count = take_u32(&encoded, &mut at)? as usize;
        if count > 4096 {
            return Err("native client has too many arguments".to_string());
        }
        let mut client_args = Vec::with_capacity(count);
        for _ in 0..count {
            client_args.push(OsString::from_vec(take(&encoded, &mut at)?));
        }
        if at != encoded.len() || program.is_empty() {
            return Err("native client exec payload is invalid".to_string());
        }
        let mut byte = [0];
        barrier.read_exact(&mut byte).map_err(|e| e.to_string())?;
        if byte[0] != GO {
            return Err("Claude bootstrap was not released".to_string());
        }
        drop(barrier);
        let error = Command::new(program).args(client_args).exec();
        Err(format!("could not exec native client: {error}"))
    })();
    result.map(|_| 0).unwrap_or_else(|error| {
        eprintln!("[pentect] {error}");
        1
    })
}

extern "C" fn relay_interrupt(_: i32) {
    let fd = RELAY_FD.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        let byte = INTERRUPT;
        unsafe {
            libc::write(fd, &byte as *const u8 as *const libc::c_void, 1);
        }
    }
}

fn relay_main(args: &[String]) -> i32 {
    let result = (|| -> Result<(), String> {
        let fd = args
            .get(2)
            .ok_or("missing relay socket")?
            .parse::<i32>()
            .map_err(|_| "invalid relay socket")?;
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if fd < 3
            || unsafe { libc::fstat(fd, &mut stat) } != 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
            || unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1
        {
            return Err("invalid relay socket".to_string());
        }
        RELAY_FD.store(fd, std::sync::atomic::Ordering::Relaxed);
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = relay_interrupt as *const () as usize;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
        }
        if unsafe { libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) } == -1 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let ready = RELAY_READY;
        if unsafe { libc::write(fd, &ready as *const u8 as *const libc::c_void, 1) } != 1 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        loop {
            unsafe {
                libc::pause();
            }
        }
    })();
    result.map(|_| 0).unwrap_or_else(|error| {
        eprintln!("[pentect] {error}");
        1
    })
}

fn raw_status_without_reaping(pid: u32) -> Result<Option<i32>, String> {
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
        if unsafe { info.si_pid() } != pid as i32 {
            return Ok(None);
        }
        let code = info.si_code;
        let status = unsafe { info.si_status() };
        Ok(Some(match code {
            libc::CLD_EXITED => status << 8,
            libc::CLD_DUMPED => status | 0x80,
            _ => status,
        }))
    }
}

fn stopped_without_reaping(pid: u32) -> Result<bool, String> {
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    let result =
        unsafe { libc::waitid(libc::P_PID, pid, &mut info, libc::WSTOPPED | libc::WNOHANG) };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD) {
            Ok(false)
        } else {
            Err(error.to_string())
        }
    } else {
        Ok(unsafe { info.si_pid() } == pid as i32)
    }
}

fn terminate_anchored(child: &mut Child) -> Result<ExitStatus, String> {
    #[cfg(target_os = "linux")]
    if LINUX_TREE_DRAIN.load(std::sync::atomic::Ordering::Acquire) {
        return terminate_linux_descendants(child.id() as i32);
    }
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    child
        .wait()
        .map_err(|error| format!("could not reap Claude: {error}"))
}

fn terminate_managed(client: &mut Child, relay: &mut Child) -> Result<ExitStatus, String> {
    #[cfg(target_os = "linux")]
    if LINUX_TREE_DRAIN.load(std::sync::atomic::Ordering::Acquire) {
        return terminate_linux_descendants(client.id() as i32);
    }
    unsafe {
        libc::kill(-(client.id() as i32), libc::SIGKILL);
    }
    let client_result = client
        .wait()
        .map_err(|error| format!("could not reap Claude: {error}"));
    let relay_result = relay
        .wait()
        .map_err(|error| format!("could not reap Claude signal relay: {error}"));
    match (client_result, relay_result) {
        (Ok(status), Ok(_)) => Ok(status),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn enable_linux_tree_drain() -> Result<(), String> {
    use std::os::fd::FromRawFd as _;

    std::fs::read_to_string("/proc/thread-self/children")
        .map_err(|error| format!("procfs child discovery unavailable: {error}"))?;
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 };
    if raw == -1 {
        return Err(format!(
            "pidfd unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } == -1
    {
        return Err(format!(
            "pidfd signaling unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    if unsafe {
        libc::waitid(
            libc::P_PIDFD,
            pidfd.as_raw_fd() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } != -1
        || std::io::Error::last_os_error().raw_os_error() != Some(libc::ECHILD)
    {
        return Err("pidfd child verification unavailable".to_string());
    }
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    action.sa_sigaction = libc::SIG_DFL;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
    }
    if unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) } == -1 {
        return Err(format!(
            "could not reset child status handling: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == -1 {
        return Err(format!(
            "subreaper unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    LINUX_TREE_DRAIN.store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}

#[cfg(target_os = "linux")]
fn reap_linux_adopted_zombies(client: i32, relay: i32, cursor: &mut usize) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
    let children = match linux_direct_children(deadline) {
        Ok(children) => children,
        Err(error) if error.starts_with("timed out discovering") => return Ok(()),
        Err(error) => return Err(error),
    };
    if children.is_empty() {
        *cursor = 0;
        return Ok(());
    }
    let start = *cursor % children.len();
    let count = children.len().min(256);
    let mut visited = 0;
    for offset in 0..count {
        if std::time::Instant::now() >= deadline {
            break;
        }
        visited += 1;
        let pid = children[(start + offset) % children.len()];
        if pid == client || pid == relay {
            continue;
        }
        let Some(pidfd) = open_verified_child_pidfd(pid)? else {
            continue;
        };
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pidfd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == -1 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                continue;
            }
            return Err(std::io::Error::last_os_error().to_string());
        }
        if unsafe { info.si_pid() } != 0 {
            let result = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    pidfd.as_raw_fd() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG,
                )
            };
            if result == -1 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ECHILD)
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
    }
    *cursor = advance_reap_cursor(start, visited, children.len());
    Ok(())
}

#[cfg(target_os = "linux")]
fn advance_reap_cursor(start: usize, visited: usize, length: usize) -> usize {
    (start + visited) % length
}

#[cfg(target_os = "linux")]
fn terminate_linux_descendants(leader: i32) -> Result<ExitStatus, String> {
    use std::os::unix::process::ExitStatusExt as _;

    unsafe {
        libc::kill(-leader, libc::SIGKILL);
    }
    let deadline = std::time::Instant::now() + DESCENDANT_DRAIN_TIMEOUT;
    let mut leader_status = None;
    loop {
        for pid in linux_direct_children(deadline)? {
            if std::time::Instant::now() >= deadline {
                return Err("timed out terminating native client descendants".to_string());
            }
            let Some(pidfd) = open_verified_child_pidfd(pid)? else {
                continue;
            };
            let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    pidfd.as_raw_fd() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == -1 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                    continue;
                }
                return Err(std::io::Error::last_os_error().to_string());
            }
            if unsafe { info.si_pid() } == 0
                && unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                } == -1
            {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error.to_string());
                }
            }
        }

        loop {
            if std::time::Instant::now() >= deadline {
                return Err("timed out terminating native client descendants".to_string());
            }
            let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            let result =
                unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOHANG) };
            if result == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    return leader_status
                        .map(ExitStatus::from_raw)
                        .ok_or_else(|| "native client status was not observed".to_string());
                }
                return Err(error.to_string());
            }
            let pid = unsafe { info.si_pid() };
            if pid == 0 {
                break;
            }
            if pid == leader {
                leader_status = Some(raw_status_from_siginfo(&info));
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err("timed out terminating native client descendants".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn linux_direct_children(deadline: std::time::Instant) -> Result<Vec<i32>, String> {
    let mut children = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir("/proc/self/task").map_err(|error| error.to_string())? {
        if std::time::Instant::now() >= deadline {
            return Err("timed out discovering native client descendants".to_string());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path().join("children");
        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.to_string()),
        };
        for value in contents.split_whitespace() {
            if std::time::Instant::now() >= deadline {
                return Err("timed out discovering native client descendants".to_string());
            }
            let pid = value
                .parse::<i32>()
                .map_err(|_| "procfs returned an invalid child PID".to_string())?;
            children.insert(pid);
        }
    }
    Ok(children.into_iter().collect())
}

#[cfg(target_os = "linux")]
fn open_verified_child_pidfd(pid: i32) -> Result<Option<std::os::fd::OwnedFd>, String> {
    use std::os::fd::FromRawFd as _;

    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
    if raw == -1 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(None)
        } else {
            Err(error.to_string())
        };
    }
    let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    let result = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            pidfd.as_raw_fd() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
        Ok(None)
    } else if result == -1 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(Some(pidfd))
    }
}

#[cfg(target_os = "linux")]
fn raw_status_from_siginfo(info: &libc::siginfo_t) -> i32 {
    let status = unsafe { info.si_status() };
    match info.si_code {
        libc::CLD_EXITED => status << 8,
        libc::CLD_DUMPED => status | 0x80,
        _ => status,
    }
}

struct Foreground {
    terminal: i32,
    original: i32,
}

impl Foreground {
    fn give_to(group: i32) -> Result<Option<Self>, String> {
        if !std::io::stdin().is_terminal() {
            return Ok(None);
        }
        let terminal = libc::STDIN_FILENO;
        let original = unsafe { libc::tcgetpgrp(terminal) };
        if original == -1 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if original != unsafe { libc::getpgrp() } {
            return Ok(None);
        }
        set_foreground(terminal, group)?;
        Ok(Some(Self { terminal, original }))
    }

    fn restore(self) -> Result<(), String> {
        set_foreground(self.terminal, self.original)?;
        std::mem::forget(self);
        Ok(())
    }
}

fn restore_foreground(foreground: &mut Option<Foreground>) -> Result<(), String> {
    if let Some(foreground) = foreground.take() {
        foreground.restore()?;
    }
    Ok(())
}

impl Drop for Foreground {
    fn drop(&mut self) {
        let _ = set_foreground(self.terminal, self.original);
    }
}

fn set_foreground(terminal: i32, group: i32) -> Result<(), String> {
    let mut block = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut old = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut block);
        libc::sigaddset(&mut block, libc::SIGTTOU);
    }
    let blocked = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &block, &mut old) };
    if blocked != 0 {
        return Err(std::io::Error::from_raw_os_error(blocked).to_string());
    }
    let result = unsafe { libc::tcsetpgrp(terminal, group) };
    let terminal_error = (result == -1).then(std::io::Error::last_os_error);
    let restored = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
    if result == -1 {
        Err(terminal_error.unwrap().to_string())
    } else if restored != 0 {
        Err(std::io::Error::from_raw_os_error(restored).to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_payload_preserves_raw_program_and_arguments() {
        let program = OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', 0xff]);
        let argument = OsString::from_vec(vec![b'a', 0xfe, b'b']);
        let mut command = Command::new(&program);
        command.arg(&argument);
        let encoded = encode_payload(&command, NativeSetup::None).unwrap();
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer
            .write_all(&(encoded.len() as u32).to_ne_bytes())
            .unwrap();
        writer.write_all(&encoded).unwrap();
        let payload = read_payload(&mut reader).unwrap();
        assert!(payload.setup.is_none());
        assert_eq!(payload.program, program);
        assert_eq!(payload.args, [argument]);
        assert_eq!(payload.args_with_settings_path(None).unwrap(), payload.args);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_verification_accepts_only_owned_live_children() {
        assert!(open_verified_child_pidfd(std::process::id() as i32)
            .unwrap()
            .is_none());
        assert!(open_verified_child_pidfd(i32::MAX).unwrap().is_none());

        let mut child = Command::new("sh").args(["-c", "sleep 15"]).spawn().unwrap();
        let pid = child.id() as i32;
        assert!(open_verified_child_pidfd(pid).unwrap().is_some());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(open_verified_child_pidfd(pid).unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn adopted_zombie_cursor_advances_only_past_visited_children() {
        assert_eq!(advance_reap_cursor(0, 3, 10), 3);
        assert_eq!(advance_reap_cursor(8, 3, 10), 1);
        assert_eq!(advance_reap_cursor(4, 0, 10), 4);
    }

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
                setup: Some(ClaudeSetup {
                    settings: vec![],
                    settings_kind: kind,
                    settings_index: index,
                }),
                program: OsString::from("client"),
                args: args.into_iter().map(OsString::from).collect(),
            };
            assert_eq!(
                payload.args_with_settings_path(Some(path)).unwrap(),
                expected.into_iter().map(OsString::from).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn status_ack_ignores_stale_controls_but_not_owner_eof() {
        let (tx, rx) = mpsc::channel();
        tx.send(Some(CONTINUE)).unwrap();
        tx.send(Some(CANCEL)).unwrap();
        tx.send(Some(STATUS_ACK)).unwrap();
        assert!(await_status_ack(&rx));

        let (tx, rx) = mpsc::channel();
        tx.send(Some(CONTINUE)).unwrap();
        drop(tx);
        assert!(!await_status_ack(&rx));
    }

    #[test]
    fn guardian_failure_is_not_reported_as_client_success() {
        let status = Command::new("sh").args(["-c", "exit 1"]).status().unwrap();
        assert!(validate_guardian_status(status).is_err());
    }
}
