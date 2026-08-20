use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn temp_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "pentect-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn events(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn process_lifecycle_is_persisted_without_arguments_or_environment() {
    let root = temp_root("persistent-log");
    let secret = "sk-pentect-persistent-log-secret";
    let output = Command::new(env!("CARGO_BIN_EXE_pentect"))
        .arg("version")
        .arg(secret)
        .env("PENTECT_LOG_DIR", &root)
        .env("PENTECT_TEST_SECRET", secret)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");

    let path = root.join("pentect.log");
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(!raw.contains(secret));
    let events = events(&path);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event"], "started");
    assert_eq!(events[1]["event"], "finished");
    assert_eq!(events[1]["exit_code"], 0);
    assert_eq!(events[1]["version"], env!("CARGO_PKG_VERSION"));
    assert!(events.iter().all(|event| event["surface"] == "version"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn panic_is_flushed_with_location_and_backtrace_but_not_payload() {
    let root = temp_root("panic-log");
    let output = Command::new(env!("CARGO_BIN_EXE_pentect"))
        .arg("__test-panic")
        .env("PENTECT_LOG_DIR", &root)
        .env("PENTECT_INTERNAL_TEST_PANIC", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());

    let path = root.join("pentect.log");
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(!raw.contains("payload that must not be persisted"));
    let events = events(&path);
    let panic = events
        .iter()
        .find(|event| event["event"] == "panic")
        .expect("missing panic event");
    assert_eq!(panic["surface"], "test-panic");
    assert!(panic["panic_location"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert!(panic["backtrace"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    let _ = std::fs::remove_dir_all(root);
}
