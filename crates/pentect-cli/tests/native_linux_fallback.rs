#![cfg(target_os = "linux")]

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 2;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

struct Fixture {
    root: std::path::PathBuf,
    wrapper: Option<Child>,
    tracked: Vec<OwnedFd>,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "pentect-native-linux-fallback-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        Self {
            root,
            wrapper: None,
            tracked: Vec::new(),
        }
    }

    fn track(&mut self, pid: i32) {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        assert_ne!(raw, -1, "could not capture fixture process identity");
        self.tracked.push(unsafe { OwnedFd::from_raw_fd(raw) });
    }

    fn stop_wrapper(&mut self) {
        if let Some(mut wrapper) = self.wrapper.take() {
            unsafe {
                libc::kill(wrapper.id() as i32, libc::SIGKILL);
            }
            let _ = wrapper.wait();
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop_wrapper();
        for pidfd in &self.tracked {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn deny_pidfd_open() -> std::io::Result<()> {
    let mut filter = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_pidfd_open as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1
        || unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                SECCOMP_SET_MODE_FILTER,
                &program as *const libc::sock_fprog,
            )
        } == -1
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wait_ready(path: &std::path::Path) -> (i32, i32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let mut lines = contents.lines();
                return (
                    lines.next().unwrap().parse().unwrap(),
                    lines.next().unwrap().parse().unwrap(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("could not read fixture readiness: {error}"),
        }
        assert!(Instant::now() < deadline, "fixture client did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_pidfd_dead(pidfd: &OwnedFd) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pollfd, 1, 0) } == 1 && pollfd.revents & libc::POLLIN != 0 {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn unavailable_pidfd_keeps_group_lifecycle_compatible() {
    let mut fixture = Fixture::new();
    let home = fixture.root.join("home");
    let project = fixture.root.join("project");
    let runtime = fixture.root.join("runtime");
    for directory in [&home, &project, &runtime] {
        std::fs::create_dir(directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::create_dir(home.join(".pentect")).unwrap();
    std::fs::create_dir(project.join(".git")).unwrap();
    std::fs::write(
        home.join(".pentect/config.toml"),
        "[update]\ncheck = false\n",
    )
    .unwrap();
    let ready = fixture.root.join("ready");
    let stderr = fixture.root.join("stderr");
    let script = fixture.root.join("client.sh");
    std::fs::write(
        &script,
        r##"#!/bin/sh
sleep 30 &
child=$!
temporary="$READY.tmp.$$"
printf '%s\n%s\n' "$$" "$child" > "$temporary"
mv "$temporary" "$READY"
wait "$child"
"##,
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();

    let stderr_file = std::fs::File::create(&stderr).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command
        .arg("opencode")
        .arg("--opencode")
        .arg(&script)
        .arg("auth")
        .current_dir(&project)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("XDG_CACHE_HOME", fixture.root.join("cache"))
        .env("XDG_STATE_HOME", fixture.root.join("state"))
        .env("XDG_CONFIG_HOME", fixture.root.join("config"))
        .env("PENTECT_LOG_DIR", fixture.root.join("log"))
        .env("READY", &ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr_file);
    unsafe {
        command.pre_exec(deny_pidfd_open);
    }
    fixture.wrapper = Some(command.spawn().unwrap());
    let (client, child) = wait_ready(&ready);
    fixture.track(client);
    fixture.track(child);

    fixture.stop_wrapper();
    assert!(
        wait_pidfd_dead(&fixture.tracked[0]),
        "client survived wrapper kill"
    );
    assert!(
        wait_pidfd_dead(&fixture.tracked[1]),
        "same-group child survived wrapper kill"
    );
    let diagnostics = std::fs::read_to_string(&stderr).unwrap();
    assert!(diagnostics.contains(
        "warning: descendant cleanup is limited to the managed process group: pidfd unavailable"
    ));
}
