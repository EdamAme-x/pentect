//! Small helpers for sandboxed Pentect WebAssembly plugins.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const SCHEMA: &str = "pentect.plugin.v1";
#[doc(hidden)]
pub use serde_json as __serde_json;

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

#[derive(Debug, Serialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body: String,
}

impl HttpRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: "GET".to_string(),
            url: url.into(),
            headers: BTreeMap::new(),
            body: String::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HttpResponse {
    pub status: Option<u16>,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub error: Option<String>,
}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "pentect:http")]
extern "C" {
    #[link_name = "request"]
    fn pentect_http_request(
        request_ptr: i32,
        request_len: i32,
        response_ptr: i32,
        response_capacity: i32,
    ) -> i32;
}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "pentect:config")]
extern "C" {
    #[link_name = "read"]
    fn pentect_config_read(
        key_ptr: i32,
        key_len: i32,
        response_ptr: i32,
        response_capacity: i32,
    ) -> i32;
}

/// Read one approved plugin configuration key.
///
/// The plugin must declare `config:read` in `[middleware].permissions`.
#[cfg(target_arch = "wasm32")]
pub fn config(key: &str) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    const RESPONSE_CAPACITY: usize = 1024 * 1024;
    let key_len = i32::try_from(key.len())?;
    let mut output = vec![0_u8; RESPONSE_CAPACITY];
    let output_len = unsafe {
        pentect_config_read(
            key.as_ptr() as i32,
            key_len,
            output.as_mut_ptr() as i32,
            RESPONSE_CAPACITY as i32,
        )
    };
    if output_len < 0 {
        return Err(format!("Pentect config read failed with code {output_len}").into());
    }
    output.truncate(usize::try_from(output_len)?);
    let value: Value = serde_json::from_slice(&output)?;
    Ok((value != Value::Null).then_some(value))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn config(_key: &str) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    Err("Pentect config access is only available inside WebAssembly plugins".into())
}

/// Perform an outbound request through Pentect's approved network access.
///
/// The origin and method must be declared in `[network]`. Pentect
/// performs the request without granting the module ambient socket access.
#[cfg(target_arch = "wasm32")]
pub fn http_request(
    request: &HttpRequest,
    response_capacity: usize,
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    const MAX_RESPONSE_CAPACITY: usize = 4 * 1024 * 1024;
    if response_capacity == 0 || response_capacity > MAX_RESPONSE_CAPACITY {
        return Err("invalid Pentect HTTP response capacity".into());
    }
    let encoded = serde_json::to_vec(request)?;
    let request_len = i32::try_from(encoded.len())?;
    let response_capacity_i32 = i32::try_from(response_capacity)?;
    let mut output = vec![0_u8; response_capacity];
    let output_len = unsafe {
        pentect_http_request(
            encoded.as_ptr() as i32,
            request_len,
            output.as_mut_ptr() as i32,
            response_capacity_i32,
        )
    };
    if output_len < 0 {
        return Err(format!("Pentect network request failed with code {output_len}").into());
    }
    let output_len = usize::try_from(output_len)?;
    output.truncate(output_len);
    Ok(serde_json::from_slice(&output)?)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn http_request(
    _request: &HttpRequest,
    _response_capacity: usize,
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    Err("Pentect network access is only available inside WebAssembly plugins".into())
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

/// Export Pentect's sandboxed WebAssembly ABI for a typed handler.
///
/// The resulting module imports nothing from the host. Build the plugin as a
/// `cdylib` for `wasm32-unknown-unknown` and use `execution.runtime = "wasm"`.
#[macro_export]
macro_rules! export_wasm_plugin {
    ($handler:path) => {
        #[no_mangle]
        pub extern "C" fn pentect_alloc(len: i32) -> i32 {
            let len = usize::try_from(len).expect("negative Pentect input length");
            let input = vec![0_u8; len].into_boxed_slice();
            std::boxed::Box::into_raw(input) as *mut u8 as i32
        }

        #[no_mangle]
        pub unsafe extern "C" fn pentect_handle(pointer: i32, len: i32) -> i64 {
            let pointer = usize::try_from(pointer).expect("negative Pentect input pointer");
            let len = usize::try_from(len).expect("negative Pentect input length");
            let input = unsafe {
                std::boxed::Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                    pointer as *mut u8,
                    len,
                ))
            };
            let request: $crate::Request = $crate::__serde_json::from_slice(&input)
                .expect("invalid Pentect request");
            let response = $handler(request).expect("Pentect plugin handler failed");
            let output = $crate::__serde_json::to_vec(&response)
                .expect("Pentect response failed")
                .into_boxed_slice();
            let output_len = u32::try_from(output.len()).expect("Pentect response too large");
            let output_pointer = std::boxed::Box::into_raw(output) as *mut u8 as u32;
            (((output_pointer as u64) << 32) | output_len as u64) as i64
        }
    };
}
