use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const SECRET: &str = "sk-proj-pentect-synthetic-exec-restoration-1234567890";

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    handle: String,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "pentect-exec-restoration-metrics-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(home.join(".pentect")).unwrap();
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::write(
            home.join(".pentect/config.toml"),
            "[activity]\nshare = false\n[update]\ncheck = false\n",
        )
        .unwrap();

        let source = project.join("source.env");
        std::fs::write(&source, format!("OPENAI_API_KEY={SECRET}\n")).unwrap();
        let mut fixture = Self {
            root,
            home,
            project,
            handle: String::new(),
        };
        let output = fixture.run("seed", ["read".into(), source.into_os_string()]);
        assert_success(&output, "seed handle");
        let masked = String::from_utf8(output.stdout).unwrap();
        fixture.handle = first_handle(&masked);
        assert!(!fixture.handle.contains(SECRET));
        fixture
    }

    fn run<I>(&self, label: &str, args: I) -> Output
    where
        I: IntoIterator<Item = std::ffi::OsString>,
    {
        let log_dir = self.root.join("logs").join(label);
        let runtime = self.root.join("runtime");
        let cache = self.root.join("cache");
        let state = self.root.join("state");
        let temp = self.root.join("tmp");
        for path in [&log_dir, &runtime, &cache, &state, &temp] {
            std::fs::create_dir_all(path).unwrap();
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
        command
            .args(args)
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("XDG_CACHE_HOME", &cache)
            .env("XDG_STATE_HOME", &state)
            .env("TMPDIR", &temp)
            .env("TMP", &temp)
            .env("TEMP", &temp)
            .env("PENTECT_LOG_DIR", &log_dir)
            .env("PENTECT_BIN", env!("CARGO_BIN_EXE_pentect"));
        for name in [
            "PENTECT_MEMORY_STORE_ADDR",
            "PENTECT_MEMORY_STORE_TOKEN",
            "PENTECT_PROCESS_HOST_READ_TOKEN",
            "PENTECT_PROCESS_HOST_WRITE_TOKEN",
            "PENTECT_AGENT_LAUNCHED",
        ] {
            command.env_remove(name);
        }
        command.output().unwrap()
    }

    fn resolve_events(&self, label: &str) -> Vec<Value> {
        let path = self.root.join("logs").join(label).join("pentect.log");
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            !raw.contains(SECRET),
            "activity log contained fixture value"
        );
        raw.lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|event| event["action"] == "resolve" && event["surface"] == "exec")
            .collect()
    }

    fn assert_resolve_count(&self, label: &str, expected: usize) {
        let events = self.resolve_events(label);
        assert_eq!(events.len(), expected, "{label}: {events:?}");
        assert!(events.iter().all(|event| event["count"] == 1));
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn actual_exec_records_completed_input_restoration_once() {
    let fixture = Fixture::new();

    for (label, live) in [("shell-buffered", false), ("shell-live", true)] {
        let output = fixture.run(label, shell_args(&fixture.handle, live));
        assert_success(&output, label);
        fixture.assert_resolve_count(label, 1);
    }

    for (label, live) in [("stdin-buffered", false), ("stdin-live", true)] {
        let output = fixture.run(label, secret_stdin_args(&fixture.handle, live));
        assert_success(&output, label);
        fixture.assert_resolve_count(label, 1);
    }

    let output = fixture.run("referenced-env", referenced_env_args(&fixture.handle));
    assert_success(&output, "referenced-env");
    fixture.assert_resolve_count("referenced-env", 1);

    let output = fixture.run("argv-nonzero", argv_args(&fixture.handle, 37));
    assert_eq!(output.status.code(), Some(37), "{output:?}");
    fixture.assert_resolve_count("argv-nonzero", 1);

    let missing = fixture.root.join("program-that-does-not-exist");
    let output = fixture.run(
        "spawn-failure",
        [
            "exec".into(),
            "--allow-secret-argv".into(),
            "--".into(),
            missing.into_os_string(),
            fixture.handle.clone().into(),
        ],
    );
    assert!(!output.status.success(), "{output:?}");
    fixture.assert_resolve_count("spawn-failure", 1);
}

#[test]
fn actual_exec_does_not_count_noop_or_failed_input_preparation() {
    let fixture = Fixture::new();

    let output = fixture.run("noop", noop_args());
    assert_success(&output, "noop");
    fixture.assert_resolve_count("noop", 0);

    let output = fixture.run("argv-denied", argv_args_without_opt_in(&fixture.handle));
    assert!(!output.status.success(), "{output:?}");
    fixture.assert_resolve_count("argv-denied", 0);

    let unknown = unknown_handle(&fixture.handle);
    let output = fixture.run("unknown", secret_stdin_args(&unknown, false));
    assert!(!output.status.success(), "{output:?}");
    fixture.assert_resolve_count("unknown", 0);
}

fn first_handle(masked: &str) -> String {
    let start = masked
        .find("<<")
        .unwrap_or_else(|| panic!("missing handle"));
    let end = masked[start..]
        .find(">>")
        .map(|offset| start + offset + 2)
        .unwrap_or_else(|| panic!("unterminated handle"));
    masked[start..end].to_string()
}

fn unknown_handle(handle: &str) -> String {
    let mut unknown = handle.as_bytes().to_vec();
    let prefix = b"OPENAI_API_KEY_";
    let hash_start = unknown
        .windows(prefix.len())
        .position(|window| window == prefix)
        .map(|index| index + prefix.len())
        .unwrap();
    let index = unknown[hash_start..]
        .iter()
        .position(|byte| byte.is_ascii_hexdigit() && byte.is_ascii_lowercase())
        .map(|index| hash_start + index)
        .unwrap();
    unknown[index] = if unknown[index] == b'a' { b'b' } else { b'a' };
    String::from_utf8(unknown).unwrap()
}

fn env_name_for_handle(handle: &str) -> String {
    let inner = handle
        .strip_prefix("<<")
        .and_then(|value| value.strip_suffix(">>"))
        .unwrap();
    let core = inner
        .rsplit_once("_length_at_least_")
        .or_else(|| inner.rsplit_once("_length_"))
        .or_else(|| inner.rsplit_once("_len"))
        .map_or(inner, |(core, _)| core);
    format!("PENTECT_{core}")
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context}: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn shell_args(handle: &str, live: bool) -> Vec<std::ffi::OsString> {
    let mut args = vec!["exec".into()];
    if live {
        args.push("--live".into());
    }
    args.push(format!(": '{handle}'").into());
    args
}

#[cfg(unix)]
fn referenced_env_args(handle: &str) -> Vec<std::ffi::OsString> {
    let name = env_name_for_handle(handle);
    vec![
        "exec".into(),
        format!(": '{handle}'; test -n \"${name}\"").into(),
    ]
}

#[cfg(windows)]
fn shell_args(handle: &str, live: bool) -> Vec<std::ffi::OsString> {
    let mut args = vec!["exec".into()];
    if live {
        args.push("--live".into());
    }
    args.push(format!("'{handle}' | Out-Null").into());
    args
}

#[cfg(windows)]
fn referenced_env_args(handle: &str) -> Vec<std::ffi::OsString> {
    let name = env_name_for_handle(handle);
    vec![
        "exec".into(),
        format!("'{handle}' | Out-Null; if (-not $env:{name}) {{ exit 1 }}").into(),
    ]
}

#[cfg(unix)]
fn secret_stdin_args(handle: &str, live: bool) -> Vec<std::ffi::OsString> {
    let mut args = vec!["exec".into()];
    if live {
        args.push("--live".into());
    }
    args.extend([
        "--secret-stdin".into(),
        handle.into(),
        "--".into(),
        "sh".into(),
        "-c".into(),
        "IFS= read -r value; test -n \"$value\"".into(),
    ]);
    args
}

#[cfg(windows)]
fn secret_stdin_args(handle: &str, live: bool) -> Vec<std::ffi::OsString> {
    let mut args = vec!["exec".into()];
    if live {
        args.push("--live".into());
    }
    args.extend([
        "--secret-stdin".into(),
        handle.into(),
        "--".into(),
        "powershell.exe".into(),
        "-NoLogo".into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-Command".into(),
        "$value=[Console]::In.ReadToEnd(); if ($value.Length -eq 0) { exit 1 }".into(),
    ]);
    args
}

#[cfg(unix)]
fn argv_args(handle: &str, exit: i32) -> Vec<std::ffi::OsString> {
    vec![
        "exec".into(),
        "--allow-secret-argv".into(),
        "--".into(),
        "sh".into(),
        "-c".into(),
        format!("exit {exit}").into(),
        "pentect-test".into(),
        handle.into(),
    ]
}

#[cfg(windows)]
fn argv_args(handle: &str, exit: i32) -> Vec<std::ffi::OsString> {
    vec![
        "exec".into(),
        "--allow-secret-argv".into(),
        "--".into(),
        "powershell.exe".into(),
        "-NoLogo".into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-Command".into(),
        format!("exit {exit}").into(),
        handle.into(),
    ]
}

fn argv_args_without_opt_in(handle: &str) -> Vec<std::ffi::OsString> {
    let mut args = argv_args(handle, 0);
    args.remove(1);
    args
}

#[cfg(unix)]
fn noop_args() -> Vec<std::ffi::OsString> {
    vec![
        "exec".into(),
        "--".into(),
        "sh".into(),
        "-c".into(),
        "exit 0".into(),
    ]
}

#[cfg(windows)]
fn noop_args() -> Vec<std::ffi::OsString> {
    vec![
        "exec".into(),
        "--".into(),
        "powershell.exe".into(),
        "-NoLogo".into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-Command".into(),
        "exit 0".into(),
    ]
}
