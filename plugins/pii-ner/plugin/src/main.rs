mod model;

use serde::Deserialize;
use serde_json::json;
use std::io::{self, BufRead, Write};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginRequest {
    schema: String,
    id: u64,
    #[serde(rename = "type")]
    kind: String,
    stage: Option<String>,
    payload: Option<serde_json::Value>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| format!("read request: {e}"))?;
        let request: PluginRequest =
            serde_json::from_str(&line).map_err(|e| format!("parse request: {e}"))?;
        if request.schema != "pentect.plugin.v1" {
            return Err("unsupported schema".to_string());
        }
        let response = match request.kind.as_str() {
            "initialize" => json!({
                "schema": "pentect.plugin.v1",
                "id": request.id,
                "type": "initialized",
            }),
            "event" if request.stage.as_deref() == Some("detect") => {
                let text = request
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.get("text"))
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "detect event requires payload.text".to_string())?;
                let spans = model::detect_pii(text)?;
                json!({
                    "schema": "pentect.plugin.v1",
                    "id": request.id,
                    "type": "result",
                    "action": "next",
                    "spans": spans.into_iter().map(|span| json!({
                        "start": span.start,
                        "end": span.end,
                        "label": span.label,
                        "category": "pii",
                        "confidence": span.confidence,
                    })).collect::<Vec<_>>()
                })
            }
            "event" => json!({
                "schema": "pentect.plugin.v1",
                "id": request.id,
                "type": "result",
                "action": "next",
            }),
            _ => return Err("unsupported request type".to_string()),
        };
        serde_json::to_writer(&mut stdout, &response)
            .map_err(|e| format!("write response: {e}"))?;
        stdout
            .write_all(b"\n")
            .and_then(|()| stdout.flush())
            .map_err(|e| format!("flush response: {e}"))?;
    }
    Ok(())
}
