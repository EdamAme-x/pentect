//! Small, synchronous helpers for persistent Pentect stdio plugins.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, BufRead, Write};

pub const SCHEMA: &str = "pentect.plugin.v1";

pub fn config_path() -> Option<std::path::PathBuf> {
    std::env::var_os("PENTECT_PLUGIN_CONFIG").map(Into::into)
}

pub fn cache_path() -> Option<std::path::PathBuf> {
    std::env::var_os("PENTECT_PLUGIN_CACHE_DIR").map(Into::into)
}

#[derive(Debug, Deserialize)]
pub struct Request {
    pub schema: String,
    pub id: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub stage: Option<String>,
    pub payload: Option<Value>,
    pub context: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub schema: &'static str,
    pub id: u64,
    #[serde(rename = "type")]
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spans: Option<Value>,
}

impl Response {
    pub fn next(id: u64) -> Self {
        Self {
            schema: SCHEMA,
            id,
            kind: "result",
            action: Some("next"),
            outcome: None,
            payload: None,
            message: None,
            spans: None,
        }
    }

    pub fn block(id: u64, message: impl Into<String>) -> Self {
        Self {
            outcome: Some("block"),
            message: Some(message.into()),
            action: Some("stop"),
            ..Self::next(id)
        }
    }
}

pub fn serve(
    mut handler: impl FnMut(Request) -> Result<Response, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let request: Request = serde_json::from_str(&line?)?;
        if request.schema != SCHEMA {
            return Err("unsupported Pentect plugin schema".into());
        }
        let response = if request.kind == "initialize" {
            Response {
                schema: SCHEMA,
                id: request.id,
                kind: "initialized",
                action: None,
                outcome: None,
                payload: None,
                message: None,
                spans: None,
            }
        } else {
            handler(request)?
        };
        serde_json::to_writer(&mut stdout, &response)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}
