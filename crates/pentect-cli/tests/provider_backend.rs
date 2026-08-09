use std::io::{BufRead, Read};
use std::process::{Command, Stdio};

#[test]
fn vscode_provider_reports_one_authenticated_loopback_route_and_stops_on_eof() {
    let binary = env!("CARGO_BIN_EXE_pentect");
    let synthetic_key = "sk-test-provider-backend-never-valid-123456789";
    let mut child = Command::new(binary)
        .args([
            "provider",
            "vscode",
            "--upstream",
            "http://127.0.0.1:9",
            "--model",
            "synthetic-model",
        ])
        .env_remove("PENTECT_AGENT_LAUNCHED")
        .env_remove("PENTECT_MEMORY_STORE_ADDR")
        .env_remove("PENTECT_MEMORY_STORE_TOKEN")
        .env("OPENAI_API_KEY", synthetic_key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("provider backend starts");
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut errors = child.stderr.take().unwrap();
    let mut ready = String::new();
    output.read_line(&mut ready).expect("read readiness line");
    let ready: serde_json::Value = serde_json::from_str(&ready).expect("readiness is JSON");
    assert!(!ready.to_string().contains(synthetic_key));
    assert_eq!(ready["protocol"], 1);
    assert_eq!(ready["model"], "synthetic-model");
    let base = ready["baseUrl"].as_str().expect("base URL is text");
    let route = base
        .strip_prefix("http://127.0.0.1:")
        .expect("provider binds only to IPv4 loopback");
    let (_, token) = route.split_once('/').expect("route includes auth token");
    assert_eq!(token.len(), 64);
    assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));

    drop(child.stdin.take());
    let status = child.wait().expect("provider exits after stdin EOF");
    assert!(status.success());
    let mut extra = String::new();
    output.read_line(&mut extra).expect("read remaining stdout");
    assert!(extra.is_empty(), "readiness must be the only stdout record");
    let mut stderr = String::new();
    errors.read_to_string(&mut stderr).unwrap();
    assert!(!stderr.contains(synthetic_key));
}
