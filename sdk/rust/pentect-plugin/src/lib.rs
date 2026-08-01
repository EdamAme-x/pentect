//! Small, typed helpers for sandboxed Pentect WebAssembly plugins.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const SCHEMA: &str = "pentect.plugin.v1";
pub type PluginResult = Result<(), Box<dyn std::error::Error>>;

#[doc(hidden)]
pub use serde_json as __serde_json;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Text {
    pub kind: String,
    pub text: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub start: usize,
    pub end: usize,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
}

impl Finding {
    pub fn new(start: usize, end: usize, label: impl Into<String>) -> Self {
        Self {
            start,
            end,
            label: label.into(),
            category: None,
            confidence: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct Base {
    schema: String,
    id: u64,
    #[serde(default)]
    metadata: Option<Value>,
    #[serde(skip)]
    output: Output,
}

impl Base {
    fn block(&mut self, message: String) {
        self.output.action = Action::Stop;
        self.output.outcome = Some(Outcome::Block);
        self.output.message = Some(message);
    }
}

macro_rules! context {
    ($name:ident, $payload:ty) => {
        #[derive(Debug, Deserialize)]
        pub struct $name {
            #[serde(flatten)]
            base: Base,
            #[serde(rename = "payload")]
            pub input: $payload,
        }

        impl $name {
            pub fn metadata(&self) -> Option<&Value> {
                self.base.metadata.as_ref()
            }

            pub fn block(&mut self, message: impl Into<String>) {
                self.base.block(message.into());
            }

            pub fn config(&self, key: &str) -> Result<Option<Value>, Box<dyn std::error::Error>> {
                config(key)
            }

            pub fn fetch(
                &self,
                request: &HttpRequest,
                response_capacity: usize,
            ) -> Result<HttpResponse, Box<dyn std::error::Error>> {
                http_request(request, response_capacity)
            }
        }

        impl __private::HookContext for $name {
            fn id(&self) -> u64 {
                self.base.id
            }

            fn schema(&self) -> &str {
                &self.base.schema
            }

            fn finish(self) -> WireResponse {
                WireResponse::from_parts(self.base, self.input)
            }
        }
    };
}

context!(Prepare, Text);
context!(Inspect, Text);
context!(Finalize, Text);
context!(Request, Value);
context!(Response, Value);
context!(ToolCall, Value);
context!(File, FileInfo);

impl Prepare {
    pub fn replace(&mut self, text: impl Into<String>) {
        self.input.text = text.into();
        self.base.output.payload = serde_json::to_value(&self.input).ok();
    }
}

impl Inspect {
    pub fn add_finding(&mut self, finding: Finding) {
        self.base.output.findings.push(finding);
    }
}

impl Finalize {
    pub fn replace(&mut self, text: impl Into<String>) {
        self.input.text = text.into();
        self.base.output.payload = serde_json::to_value(&self.input).ok();
    }
}

macro_rules! replace_body {
    ($name:ident) => {
        impl $name {
            pub fn replace(&mut self, body: Value) {
                self.input = body.clone();
                self.base.output.payload = Some(body);
            }
        }
    };
}

replace_body!(Request);
replace_body!(Response);
replace_body!(ToolCall);

impl Request {
    pub fn respond(&mut self, body: Value) {
        self.input = body.clone();
        self.base.output.payload = Some(body);
        self.base.output.action = Action::Stop;
        self.base.output.outcome = Some(Outcome::Respond);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileInfo {
    pub filename: String,
    pub media_type: Option<String>,
    pub size: usize,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    #[default]
    Next,
    Stop,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Block,
    Respond,
}

#[derive(Debug, Default)]
struct Output {
    action: Action,
    outcome: Option<Outcome>,
    payload: Option<Value>,
    message: Option<String>,
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
#[doc(hidden)]
pub struct WireResponse {
    schema: &'static str,
    id: u64,
    #[serde(rename = "type")]
    kind: &'static str,
    action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    spans: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<PluginError>,
}

impl WireResponse {
    fn from_parts<T>(base: Base, _input: T) -> Self {
        Self {
            schema: SCHEMA,
            id: base.id,
            kind: "result",
            action: base.output.action,
            outcome: base.output.outcome,
            payload: base.output.payload,
            message: base.output.message,
            spans: base.output.findings,
            error: None,
        }
    }

    fn failure(id: u64) -> Self {
        Self {
            schema: SCHEMA,
            id,
            kind: "result",
            action: Action::Next,
            outcome: None,
            payload: None,
            message: None,
            spans: Vec::new(),
            error: Some(PluginError {
                code: "handler_error",
            }),
        }
    }
}

#[derive(Debug, Serialize)]
struct PluginError {
    code: &'static str,
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

#[cfg(target_arch = "wasm32")]
fn config(key: &str) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    const CAPACITY: usize = 1024 * 1024;
    let mut output = vec![0_u8; CAPACITY];
    let len = unsafe {
        pentect_config_read(
            key.as_ptr() as i32,
            i32::try_from(key.len())?,
            output.as_mut_ptr() as i32,
            CAPACITY as i32,
        )
    };
    if len < 0 {
        return Err(format!("Pentect config read failed with code {len}").into());
    }
    output.truncate(usize::try_from(len)?);
    let value: Value = serde_json::from_slice(&output)?;
    Ok((value != Value::Null).then_some(value))
}

#[cfg(not(target_arch = "wasm32"))]
fn config(_key: &str) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    Err("Pentect config is only available inside WebAssembly plugins".into())
}

#[cfg(target_arch = "wasm32")]
fn http_request(
    request: &HttpRequest,
    response_capacity: usize,
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    const MAX_CAPACITY: usize = 4 * 1024 * 1024;
    if response_capacity == 0 || response_capacity > MAX_CAPACITY {
        return Err("invalid Pentect HTTP response capacity".into());
    }
    let encoded = serde_json::to_vec(request)?;
    let mut output = vec![0_u8; response_capacity];
    let len = unsafe {
        pentect_http_request(
            encoded.as_ptr() as i32,
            i32::try_from(encoded.len())?,
            output.as_mut_ptr() as i32,
            i32::try_from(response_capacity)?,
        )
    };
    if len < 0 {
        return Err(format!("Pentect network request failed with code {len}").into());
    }
    output.truncate(usize::try_from(len)?);
    Ok(serde_json::from_slice(&output)?)
}

#[cfg(not(target_arch = "wasm32"))]
fn http_request(
    _request: &HttpRequest,
    _response_capacity: usize,
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    Err("Pentect network access is only available inside WebAssembly plugins".into())
}

#[doc(hidden)]
pub mod __private {
    use super::*;

    pub trait HookContext: DeserializeOwned {
        fn id(&self) -> u64;
        fn schema(&self) -> &str;
        fn finish(self) -> WireResponse;
    }

    pub unsafe fn dispatch<C: HookContext>(
        pointer: i32,
        len: i32,
        handler: fn(&mut C) -> PluginResult,
    ) -> i64 {
        let pointer = usize::try_from(pointer).expect("negative Pentect input pointer");
        let len = usize::try_from(len).expect("negative Pentect input length");
        let input =
            unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer as *mut u8, len)) };
        let mut context: C = serde_json::from_slice(&input).expect("invalid Pentect hook input");
        assert_eq!(context.schema(), SCHEMA, "unsupported Pentect hook schema");
        let id = context.id();
        let response = match handler(&mut context) {
            Ok(()) => context.finish(),
            Err(_) => WireResponse::failure(id),
        };
        let output = serde_json::to_vec(&response)
            .expect("Pentect response failed")
            .into_boxed_slice();
        let output_len = u32::try_from(output.len()).expect("Pentect response too large");
        let output_pointer = Box::into_raw(output) as *mut u8 as u32;
        (((output_pointer as u64) << 32) | output_len as u64) as i64
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __export_hook {
    (prepare) => {
        #[no_mangle]
        pub unsafe extern "C" fn pentect_prepare(pointer: i32, len: i32) -> i64 {
            unsafe { $crate::__private::dispatch::<$crate::Prepare>(pointer, len, prepare) }
        }
    };
    (inspect) => {
        #[no_mangle]
        pub unsafe extern "C" fn pentect_inspect(pointer: i32, len: i32) -> i64 {
            unsafe { $crate::__private::dispatch::<$crate::Inspect>(pointer, len, inspect) }
        }
    };
    (finalize) => {
        #[no_mangle]
        pub unsafe extern "C" fn pentect_finalize(pointer: i32, len: i32) -> i64 {
            unsafe { $crate::__private::dispatch::<$crate::Finalize>(pointer, len, finalize) }
        }
    };
    (request) => {
        #[no_mangle]
        pub unsafe extern "C" fn pentect_request(pointer: i32, len: i32) -> i64 {
            unsafe { $crate::__private::dispatch::<$crate::Request>(pointer, len, request) }
        }
    };
    (response) => {
        #[no_mangle]
        pub unsafe extern "C" fn pentect_response(pointer: i32, len: i32) -> i64 {
            unsafe { $crate::__private::dispatch::<$crate::Response>(pointer, len, response) }
        }
    };
    (tool_call) => {
        #[no_mangle]
        pub unsafe extern "C" fn pentect_tool_call(pointer: i32, len: i32) -> i64 {
            unsafe { $crate::__private::dispatch::<$crate::ToolCall>(pointer, len, tool_call) }
        }
    };
    (file) => {
        #[no_mangle]
        pub unsafe extern "C" fn pentect_file(pointer: i32, len: i32) -> i64 {
            unsafe { $crate::__private::dispatch::<$crate::File>(pointer, len, file) }
        }
    };
}

/// Export only the hooks this plugin implements.
#[macro_export]
macro_rules! export {
    ($($hook:ident),+ $(,)?) => {
        #[no_mangle]
        pub extern "C" fn pentect_alloc(len: i32) -> i32 {
            let len = usize::try_from(len).expect("negative Pentect input length");
            let input = vec![0_u8; len].into_boxed_slice();
            Box::into_raw(input) as *mut u8 as i32
        }

        $($crate::__export_hook!($hook);)+
    };
}
