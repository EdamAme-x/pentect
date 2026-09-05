use serde_json::json;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Fixture(std::path::PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn event(action: &str, surface: &str, count: u64) -> serde_json::Value {
    json!({
        "time": "2026-01-01T00:00:00Z",
        "action": action,
        "surface": surface,
        "count": count
    })
}

fn run_metrics(mut command: Command) -> Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("pentect metrics did not exit within five seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn metrics_human_describes_stable_codes_without_echoing_untrusted_values() {
    let root = std::env::temp_dir().join(format!(
        "pentect-metrics-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let fixture = Fixture(root);
    let home = fixture.0.join("home");
    let logs = fixture.0.join("logs");
    std::fs::create_dir_all(home.join(".pentect")).unwrap();
    std::fs::create_dir(&logs).unwrap();
    std::fs::create_dir(fixture.0.join(".git")).unwrap();
    std::fs::write(
        home.join(".pentect/config.toml"),
        "[metrics]\nenabled = true\n",
    )
    .unwrap();

    let sentinel = "SECRET_PATH_\u{1b}[31m_/private/account";
    let mut records = Vec::new();
    let mut masked = event("mask", "prompt", 2);
    masked["labels"] = json!([
        {"name": "API_KEY", "count": 2},
        {"name": sentinel, "count": 3}
    ]);
    masked["target"] = json!(sentinel);
    records.push(masked);
    let mut unknown_surface = event("mask", sentinel, 4);
    unknown_surface["labels"] = json!([{"name": sentinel, "count": 4}]);
    records.push(unknown_surface);
    for (reason, count) in [
        ("upstream-response", 4),
        ("scan-unavailable-allowed", 3),
        ("scan-unavailable-blocked", 1),
        ("request-rejected", 2),
        ("no-protected-connection", 2),
        ("response-restore-skipped", 1),
        (sentinel, 5),
    ] {
        let mut warning = event("warning", "openai", count);
        warning["event"] = json!(reason);
        records.push(warning);
    }
    let payload = records
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(logs.join("pentect.log"), payload).unwrap();

    let run = |json: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
        command
            .arg("metrics")
            .current_dir(&fixture.0)
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", fixture.0.join("config"))
            .env("XDG_CACHE_HOME", fixture.0.join("cache"))
            .env("XDG_STATE_HOME", fixture.0.join("state"))
            .env("XDG_RUNTIME_DIR", fixture.0.join("runtime"))
            .env("PENTECT_LOG_DIR", &logs)
            .env("TMPDIR", fixture.0.join("tmp"));
        if json {
            command.arg("--json");
        }
        run_metrics(command)
    };

    let human = run(false);
    assert!(
        human.status.success(),
        "{}",
        String::from_utf8_lossy(&human.stderr)
    );
    let human = String::from_utf8(human.stdout).unwrap();
    for expected in [
        "prompt (Text sent to a model): 2",
        "OTHER (Other protected surface): 4",
        "API_KEY (Api Key): 2",
        "OTHER (Other): 7",
        "unknown (Unknown or unclassified warning): 5",
        "upstream-response (A provider response status was observed): 4",
        "scan-unavailable-allowed (Policy allowed image content without OCR inspection): 3",
        "scan-unavailable-blocked (Affected image content was blocked because OCR inspection was unavailable): 1",
        "request-rejected (A request was rejected to preserve protection): 2",
        "no-protected-connection (No protected client connection was observed): 2",
        "response-restore-skipped (Local response-handle restoration was skipped): 1",
    ] {
        assert!(human.contains(expected), "missing {expected:?}:\n{human}");
    }
    assert!(!human.contains(sentinel));
    let ordered = [
        "unknown (",
        "upstream-response (",
        "scan-unavailable-allowed (",
    ];
    assert!(ordered
        .windows(2)
        .all(|pair| human.find(pair[0]) < human.find(pair[1])));

    let encoded = run(true);
    assert!(
        encoded.status.success(),
        "{}",
        String::from_utf8_lossy(&encoded.stderr)
    );
    let metrics: serde_json::Value = serde_json::from_slice(&encoded.stdout).unwrap();
    assert_eq!(metrics["masked_text_occurrences"], 6);
    assert_eq!(metrics["warning_occurrences"], 18);
    assert_eq!(metrics["blocked_occurrences"], 3);
    assert_eq!(metrics["by_secret_type"], json!({"API_KEY": 2, "OTHER": 7}));
    assert_eq!(metrics["by_surface"], json!({"OTHER": 4, "prompt": 2}));
    assert_eq!(metrics["by_warning_reason"]["unknown"], 5);
    assert_eq!(metrics["by_warning_reason"]["scan-unavailable-allowed"], 3);
    assert_eq!(metrics["by_warning_reason"]["scan-unavailable-blocked"], 1);
    assert!(!String::from_utf8(encoded.stdout)
        .unwrap()
        .contains(sentinel));
}
