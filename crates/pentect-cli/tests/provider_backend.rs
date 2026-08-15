use std::io::BufRead;
use std::process::{Command, Stdio};

#[test]
fn pi_provider_reports_the_selected_api_without_exposing_credentials() {
    let binary = env!("CARGO_BIN_EXE_pentect");
    let synthetic_key = "sk-test-pi-extension-never-valid-123456789";
    let mut child = Command::new(binary)
        .args([
            "provider",
            "pi",
            "--upstream",
            "http://127.0.0.1:9",
            "--model",
            "synthetic-model",
            "--api",
            "responses",
        ])
        .env_remove("PENTECT_AGENT_LAUNCHED")
        .env_remove("PENTECT_MEMORY_STORE_ADDR")
        .env_remove("PENTECT_MEMORY_STORE_TOKEN")
        .env("OPENAI_API_KEY", synthetic_key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Pi provider backend starts");
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut ready = String::new();
    output.read_line(&mut ready).expect("read readiness line");
    let ready: serde_json::Value = serde_json::from_str(&ready).expect("readiness is JSON");
    assert!(!ready.to_string().contains(synthetic_key));
    assert_eq!(ready["protocol"], 1);
    assert_eq!(ready["integration"], "pi");
    assert_eq!(ready["model"], "synthetic-model");
    assert_eq!(ready["api"], "openai-responses");

    drop(child.stdin.take());
    assert!(child
        .wait()
        .expect("provider exits after stdin EOF")
        .success());
}
