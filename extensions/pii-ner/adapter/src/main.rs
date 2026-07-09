mod model;

use serde::Deserialize;
use serde_json::json;
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterRequest {
    schema: String,
    kind: String,
    text: String,
    context: Option<serde_json::Value>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("read request: {e}"))?;
    let request: AdapterRequest =
        serde_json::from_str(&input).map_err(|e| format!("parse request: {e}"))?;
    if request.schema != "pentect.model_adapter.v1" {
        return Err("unsupported schema".to_string());
    }
    let _ = (&request.kind, &request.context);
    let spans = model::detect_pii(&request.text)?;
    let response = json!({
        "spans": spans.into_iter().map(|span| json!({
            "start": span.start,
            "end": span.end,
            "label": span.label,
            "category": "pii",
            "confidence": span.confidence,
        })).collect::<Vec<_>>()
    });
    println!("{response}");
    Ok(())
}
