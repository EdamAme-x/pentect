use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "pentect-log-once-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let work = root.join("work");
        std::fs::create_dir_all(work.join(".git")).unwrap();
        std::fs::create_dir_all(work.join(".pentect")).unwrap();
        std::fs::write(
            work.join(".pentect/config.toml"),
            "[update]\ncheck = false\n",
        )
        .unwrap();
        Self { root }
    }
}

impl std::ops::Deref for Fixture {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.root
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn event(index: usize) -> String {
    json!({
        "time": format!("2026-01-01T00:00:{index:02}Z"),
        "action": "diagnostic",
        "surface": "test",
        "count": index
    })
    .to_string()
}

fn run(root: &Path, args: &[&str]) -> std::process::Output {
    configured_command(root)
        .arg("log")
        .args(args)
        .output()
        .unwrap()
}

fn run_agent_alias(root: &Path, args: &[&str]) -> std::process::Output {
    configured_command(root)
        .args(["agent", "log"])
        .args(args)
        .output()
        .unwrap()
}

fn configured_command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command
        .current_dir(root.join("work"))
        .env("PENTECT_LOG_DIR", root.join("logs"))
        .env_remove("PENTECT_HOME")
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env("LOCALAPPDATA", root.join("local"))
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_STATE_HOME", root.join("state"));
    command
}

fn json_lines(output: &[u8]) -> Vec<Value> {
    String::from_utf8(output.to_vec())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn once_is_empty_and_does_not_start_a_process_host() {
    for (label, command) in [
        ("direct", run as fn(&Path, &[&str]) -> std::process::Output),
        ("agent", run_agent_alias),
    ] {
        let root = Fixture::new(label);
        let output = command(&root, &["--once", "--json"]);
        assert!(output.status.success(), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(!root.join("runtime/pentect").exists());
        assert!(!root.join("local/pentect").exists());
        assert!(!root.join("logs").exists());
    }
}

#[test]
fn once_tails_large_and_rotated_logs_in_chronological_order() {
    let root = Fixture::new("rotated");
    let logs = root.join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    let rotated = (0..50_000).map(event).collect::<Vec<_>>().join("\n") + "\n";
    let current = (50_000..50_005).map(event).collect::<Vec<_>>().join("\n") + "\n";
    std::fs::write(logs.join("pentect.log.1"), rotated).unwrap();
    std::fs::write(logs.join("pentect.log"), current).unwrap();

    let output = run(&root, &["--json", "--once", "--tail", "7"]);
    assert!(output.status.success(), "{output:?}");
    let events = json_lines(&output.stdout);
    assert_eq!(events.len(), 7);
    assert_eq!(events[0]["count"], 49_998);
    assert_eq!(events[6]["count"], 50_004);
}

#[test]
fn once_ignores_an_incomplete_concurrent_append() {
    let root = Fixture::new("partial");
    let logs = root.join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(
        logs.join("pentect.log"),
        format!("{}\n{}", event(1), r#"{"time":"incomplete""#),
    )
    .unwrap();

    let output = run(&root, &["--once", "--json"]);
    assert!(output.status.success(), "{output:?}");
    let events = json_lines(&output.stdout);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["count"], 1);
}

#[test]
fn log_rejects_invalid_limits_and_path_combinations() {
    let root = Fixture::new("invalid");
    for args in [
        &["--once", "--tail", "0"][..],
        &["--once", "--tail", "10001"][..],
        &["--once", "--tail", "nope"][..],
        &["--tail", "1"][..],
        &["--path", "--once"][..],
        &["--once", "--follow"][..],
    ] {
        let output = run(&root, args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
    }
    let path = run(&root, &["--path"]);
    assert!(path.status.success(), "{path:?}");
    assert_eq!(
        String::from_utf8(path.stdout).unwrap().trim(),
        root.join("logs/pentect.log").display().to_string()
    );
}

#[test]
fn once_rejects_an_unbounded_unterminated_record() {
    let root = Fixture::new("unterminated");
    let logs = root.join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(logs.join("pentect.log"), vec![b'x'; 1024 * 1024 + 1]).unwrap();

    let output = run(&root, &["--once", "--json", "--tail", "1"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("line limit"));
}
