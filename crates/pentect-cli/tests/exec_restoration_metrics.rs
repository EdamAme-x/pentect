use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SECRET: &str = "sk-proj-pentect-synthetic-exec-restoration-1234567890";

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    source: PathBuf,
    verifier: PathBuf,
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
        let verifier = project.join("verify.ps1");
        std::fs::write(
            &verifier,
            concat!(
                "param([string]$Mode,[string]$ExpectedPath,[string]$Value,[int]$ExitCode=0)\n",
                "$expected=(Get-Content -Raw -LiteralPath $ExpectedPath).TrimEnd(\"`r\",\"`n\") -replace '^OPENAI_API_KEY=', ''\n",
                "if ($Mode -eq 'stdin') { $Value=[Console]::In.ReadToEnd() }\n",
                "if ($Value -cne $expected) { exit 1 }\n",
                "exit $ExitCode\n",
            ),
        )
        .unwrap();
        let mut fixture = Self {
            root,
            home,
            project,
            source,
            verifier,
            handle: String::new(),
        };
        let output = fixture.run(
            "seed",
            ["read".into(), fixture.source.clone().into_os_string()],
        );
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
            .env_clear()
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
        for name in ["PATH", "SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        bounded_output(command, label)
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
            .filter(|event| event["action"] == "resolve")
            .collect()
    }

    fn assert_resolve_count(&self, label: &str, expected: usize) {
        let events = self.resolve_events(label);
        assert_eq!(events.len(), expected, "{label}: {events:?}");
        let env_name = env_name_for_handle(&self.handle);
        for event in events {
            assert_eq!(event["surface"], "exec", "{label}: {event:?}");
            assert_eq!(event["count"], 1, "{label}: {event:?}");
            assert!(
                event
                    .get("labels")
                    .is_none_or(|labels| labels == &Value::Array(Vec::new())),
                "{label}: {event:?}"
            );
            assert!(event.get("target").is_none(), "{label}: {event:?}");
            let encoded = serde_json::to_string(&event).unwrap();
            for private in [
                SECRET,
                self.handle.as_str(),
                self.source.to_str().unwrap(),
                env_name.as_str(),
            ] {
                assert!(!encoded.contains(private), "{label}: {event:?}");
            }
        }
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
        let output = fixture.run(label, shell_args(&fixture.handle, &fixture.source, live));
        assert_success(&output, label);
        fixture.assert_resolve_count(label, 1);
    }

    for (label, live) in [("stdin-buffered", false), ("stdin-live", true)] {
        let output = fixture.run(
            label,
            secret_stdin_args(&fixture.handle, &fixture.source, &fixture.verifier, live),
        );
        assert_success(&output, label);
        fixture.assert_resolve_count(label, 1);
    }

    let output = fixture.run(
        "referenced-env",
        referenced_env_args(&fixture.handle, &fixture.source),
    );
    assert_success(&output, "referenced-env");
    fixture.assert_resolve_count("referenced-env", 1);

    for (label, live) in [("argv-nonzero", false), ("argv-nonzero-live", true)] {
        let output = fixture.run(
            label,
            argv_args(
                &fixture.handle,
                &fixture.source,
                &fixture.verifier,
                37,
                live,
            ),
        );
        assert_eq!(output.status.code(), Some(37), "{output:?}");
        fixture.assert_resolve_count(label, 1);
    }

    for (label, live) in [("spawn-failure", false), ("spawn-failure-live", true)] {
        let missing = fixture.root.join("program-that-does-not-exist");
        let mut args = vec!["exec".into()];
        if live {
            args.push("--live".into());
        }
        args.extend([
            "--allow-secret-argv".into(),
            "--".into(),
            missing.into_os_string(),
            fixture.handle.clone().into(),
        ]);
        let output = fixture.run(label, args);
        assert!(!output.status.success(), "{output:?}");
        fixture.assert_resolve_count(label, 1);
    }
}

#[test]
fn actual_exec_does_not_count_noop_or_failed_input_preparation() {
    let fixture = Fixture::new();

    let output = fixture.run("noop", noop_args());
    assert_success(&output, "noop");
    fixture.assert_resolve_count("noop", 0);

    let output = fixture.run(
        "argv-denied",
        argv_args_without_opt_in(&fixture.handle, &fixture.source, &fixture.verifier),
    );
    assert!(!output.status.success(), "{output:?}");
    fixture.assert_resolve_count("argv-denied", 0);

    let unknown = unknown_handle(&fixture.handle);
    for (label, live) in [("late-unknown", false), ("late-unknown-live", true)] {
        let output = fixture.run(
            label,
            argv_with_late_unknown(&fixture.handle, &unknown, live),
        );
        assert!(!output.status.success(), "{output:?}");
        fixture.assert_resolve_count(label, 0);
    }
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
    let index = hash_start;
    assert!(unknown[index].is_ascii_hexdigit());
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

fn bounded_output(mut command: Command, context: &str) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{context}: pentect command did not exit within 15 seconds");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn shell_args(handle: &str, source: &Path, live: bool) -> Vec<std::ffi::OsString> {
    let mut args = vec!["exec".into()];
    if live {
        args.push("--live".into());
    }
    args.push(
        format!(
            "expected=$(cut -d= -f2- '{}'); test '{handle}' = \"$expected\"; test '{handle}' = \"$expected\"",
            source.display()
        )
        .into(),
    );
    args
}

#[cfg(unix)]
fn referenced_env_args(handle: &str, source: &Path) -> Vec<std::ffi::OsString> {
    let name = env_name_for_handle(handle);
    vec![
        "exec".into(),
        format!(
            "expected=$(cut -d= -f2- '{}'); : '{handle}'; test \"${name}\" = \"$expected\"",
            source.display()
        )
        .into(),
    ]
}

#[cfg(windows)]
fn shell_args(handle: &str, source: &Path, live: bool) -> Vec<std::ffi::OsString> {
    let mut args = vec!["exec".into()];
    if live {
        args.push("--live".into());
    }
    args.push(
        format!(
            "$expected=(Get-Content -LiteralPath '{}') -replace '^OPENAI_API_KEY=', ''; if ('{handle}' -ne $expected -or '{handle}' -ne $expected) {{ exit 1 }}",
            source.display()
        )
        .into(),
    );
    args
}

#[cfg(windows)]
fn referenced_env_args(handle: &str, source: &Path) -> Vec<std::ffi::OsString> {
    let name = env_name_for_handle(handle);
    vec![
        "exec".into(),
        format!(
            "$expected=(Get-Content -LiteralPath '{}') -replace '^OPENAI_API_KEY=', ''; '{handle}' | Out-Null; if ($env:{name} -ne $expected) {{ exit 1 }}",
            source.display()
        )
        .into(),
    ]
}

#[cfg(unix)]
fn secret_stdin_args(
    handle: &str,
    source: &Path,
    _verifier: &Path,
    live: bool,
) -> Vec<std::ffi::OsString> {
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
        format!(
            "IFS= read -r value; expected=$(cut -d= -f2- '{}'); test \"$value\" = \"$expected\"",
            source.display()
        )
        .into(),
    ]);
    args
}

#[cfg(windows)]
fn secret_stdin_args(
    handle: &str,
    source: &Path,
    verifier: &Path,
    live: bool,
) -> Vec<std::ffi::OsString> {
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
        "-File".into(),
        verifier.to_path_buf().into_os_string(),
        "stdin".into(),
        source.to_path_buf().into_os_string(),
    ]);
    args
}

#[cfg(unix)]
fn argv_args(
    handle: &str,
    source: &Path,
    _verifier: &Path,
    exit: i32,
    live: bool,
) -> Vec<std::ffi::OsString> {
    let mut args = vec!["exec".into()];
    if live {
        args.push("--live".into());
    }
    args.extend([
        "--allow-secret-argv".into(),
        "--".into(),
        "sh".into(),
        "-c".into(),
        format!(
            "expected=$(cut -d= -f2- \"$2\"); test \"$1\" = \"$expected\" || exit 1; exit {exit}"
        )
        .into(),
        "pentect-test".into(),
        handle.into(),
        source.to_path_buf().into_os_string(),
    ]);
    args
}

#[cfg(windows)]
fn argv_args(
    handle: &str,
    source: &Path,
    verifier: &Path,
    exit: i32,
    live: bool,
) -> Vec<std::ffi::OsString> {
    let mut args = vec!["exec".into()];
    if live {
        args.push("--live".into());
    }
    args.extend([
        "--allow-secret-argv".into(),
        "--".into(),
        "powershell.exe".into(),
        "-NoLogo".into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-File".into(),
        verifier.to_path_buf().into_os_string(),
        "argv".into(),
        source.to_path_buf().into_os_string(),
        handle.into(),
        exit.to_string().into(),
    ]);
    args
}

fn argv_args_without_opt_in(
    handle: &str,
    source: &Path,
    verifier: &Path,
) -> Vec<std::ffi::OsString> {
    let mut args = argv_args(handle, source, verifier, 0, false);
    args.remove(1);
    args
}

fn argv_with_late_unknown(known: &str, unknown: &str, live: bool) -> Vec<std::ffi::OsString> {
    let mut args = vec!["exec".into()];
    if live {
        args.push("--live".into());
    }
    args.extend([
        "--allow-secret-argv".into(),
        "--".into(),
        "program-is-never-spawned".into(),
        known.into(),
        unknown.into(),
    ]);
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
