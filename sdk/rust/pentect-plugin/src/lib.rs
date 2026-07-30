//! Small, synchronous helpers for persistent Pentect stdio plugins.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, BufRead, Write};

pub const SCHEMA: &str = "pentect.plugin.v1";
#[doc(hidden)]
pub use serde_json as __serde_json;

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

/// Export Pentect's capability-sandboxed WebAssembly ABI for a typed handler.
///
/// The resulting module imports nothing from the host. Build the plugin as a
/// `cdylib` for `wasm32-unknown-unknown` and use `execution.runtime = "wasm"`.
#[macro_export]
macro_rules! export_wasm_plugin {
    ($handler:path) => {
        #[no_mangle]
        pub extern "C" fn pentect_alloc(len: i32) -> i32 {
            let len = usize::try_from(len).expect("negative Pentect input length");
            let mut input = Vec::<u8>::with_capacity(len);
            let pointer = input.as_mut_ptr();
            std::mem::forget(input);
            pointer as i32
        }

        #[no_mangle]
        pub unsafe extern "C" fn pentect_handle(pointer: i32, len: i32) -> i64 {
            let pointer = usize::try_from(pointer).expect("negative Pentect input pointer");
            let len = usize::try_from(len).expect("negative Pentect input length");
            let input = unsafe { Vec::from_raw_parts(pointer as *mut u8, len, len) };
            let request: $crate::Request = $crate::__serde_json::from_slice(&input)
                .expect("invalid Pentect request");
            let response = $handler(request).expect("Pentect plugin handler failed");
            let mut output =
                $crate::__serde_json::to_vec(&response).expect("Pentect response failed");
            let output_pointer = output.as_mut_ptr() as u32;
            let output_len = u32::try_from(output.len()).expect("Pentect response too large");
            std::mem::forget(output);
            (((output_pointer as u64) << 32) | output_len as u64) as i64
        }
    };
}
