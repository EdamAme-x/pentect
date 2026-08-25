//! Google Cloud Code Assist gateway used by the official Antigravity CLI.
//!
//! `agy` supports a process-local `CLOUD_CODE_URL` override. Requests remain
//! authenticated by the official client; Pentect only protects model-visible
//! content and restores handles in completed function-call arguments.

use futures_util::{stream, Stream, StreamExt};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::convert::Infallible;
use std::error::Error;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Semaphore};
use zeroize::Zeroize;

use crate::handle_contract::HANDLE_CONTRACT;

const MAX_HTTP_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_PENDING_SSE_BYTES: usize = 8 * 1024 * 1024;
static WARNED_UNKNOWN_ENDPOINT: AtomicBool = AtomicBool::new(false);

type ProxyBodyError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, ProxyBodyError>;
type UpstreamByteStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static>>;

fn proxy_diagnostic(reason: &str) {
    let (kind, retryable) = match reason {
        "gateway-stopped" => ("runtime", false),
        "connection-failed" => ("client-connection", true),
        "request-invalid-json" | "unknown-endpoint" => ("protocol", false),
        "request-protection-skipped"
        | "response-protection-skipped"
        | "stream-event-protection-skipped" => ("protection", false),
        _ => ("unclassified", false),
    };
    pentect_agent::record_http_diagnostic_activity(
        "cloud-code",
        reason,
        kind,
        "gateway",
        "HTTP",
        None,
        retryable,
        env!("CARGO_PKG_VERSION"),
    );
}

pub(crate) struct CloudCodeHttpProxyGuard {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl CloudCodeHttpProxyGuard {
    #[cfg(test)]
    pub(crate) fn start(upstream: String) -> Result<Self, String> {
        Self::start_with_header_env(upstream, &[])
    }

    pub(crate) fn start_with_header_env(
        upstream: String,
        header_env: &[String],
    ) -> Result<Self, String> {
        let upstream = crate::upstream::parse_base(&upstream, "Google Cloud Code")?;
        let headers = crate::upstream::header_overrides(header_env)?;
        let auth = random_auth_token()?;
        let (ready_tx, ready_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let thread_auth = auth.clone();
        let thread = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!(
                        "could not start Google Cloud Code gateway runtime: {error}"
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                if run_proxy(upstream, headers, thread_auth, ready_tx, shutdown_rx)
                    .await
                    .is_err()
                {
                    proxy_diagnostic("gateway-stopped");
                }
            });
        });
        let base_url = ready_rx
            .recv_timeout(crate::GATEWAY_STARTUP_TIMEOUT)
            .map_err(|_| {
                "Google Cloud Code gateway did not start within 30 seconds".to_string()
            })??;
        Ok(Self {
            base_url,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Drop for CloudCodeHttpProxyGuard {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.base_url.zeroize();
    }
}

struct ProxyState {
    upstream: reqwest::Url,
    auth: String,
    client: reqwest::Client,
    masker: Mutex<pentect_agent::ActiveToolOutputMasker>,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
    requests: Arc<Semaphore>,
    block_unknown_formats: bool,
    headers: crate::upstream::HeaderOverrides,
}

impl Drop for ProxyState {
    fn drop(&mut self) {
        self.auth.zeroize();
    }
}

async fn run_proxy(
    upstream: reqwest::Url,
    headers: crate::upstream::HeaderOverrides,
    auth: String,
    ready_tx: mpsc::Sender<Result<String, String>>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|error| format!("could not bind Google Cloud Code gateway: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("could not read Google Cloud Code gateway address: {error}"))?;
    let local_base_url = format!("http://{address}/{auth}");
    let plugins = pentect_agent::PluginMiddleware::from_env()?;
    let state = Arc::new(ProxyState {
        upstream,
        auth,
        client: crate::upstream::client("Google Cloud Code")?,
        masker: Mutex::new(pentect_agent::ActiveToolOutputMasker::new_with_plugins(
            plugins.clone(),
        )?),
        plugins: Arc::new(Mutex::new(plugins)),
        requests: Arc::new(Semaphore::new(32)),
        block_unknown_formats: pentect_agent::unknown_formats_should_block()?,
        headers,
    });
    let _ = ready_tx.send(Ok(local_base_url));

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            accepted = listener.accept() => {
                let (socket, _) = accepted
                    .map_err(|error| format!("Google Cloud Code gateway accept failed: {error}"))?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(socket);
                    let service = service_fn(move |request| proxy_request(request, Arc::clone(&state)));
                    if let Err(error) = http1::Builder::new()
                        .max_buf_size(64 * 1024)
                        .max_headers(128)
                        .serve_connection(io, service)
                        .await
                    {
                        if !error.is_incomplete_message() {
                            proxy_diagnostic("connection-failed");
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

async fn proxy_request(
    request: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<ProxyBody>, Infallible> {
    let request_path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let context = crate::gateway_diagnostics::RequestContext {
        endpoint: diagnostic_endpoint_name(request_path, &state.auth),
        method: crate::gateway_diagnostics::method_name(request.method()),
    };
    let Ok(_permit) = Arc::clone(&state.requests).try_acquire_owned() else {
        crate::gateway_diagnostics::record(
            "cloud-code",
            "gateway-busy",
            "capacity",
            context,
            Some(StatusCode::SERVICE_UNAVAILABLE.as_u16()),
            true,
        );
        return Ok(text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Pentect gateway is busy",
        ));
    };
    match proxy_request_inner(request, &state).await {
        Ok(response) => Ok(response),
        Err(error) => {
            let local = crate::gateway_diagnostics::is_local_rejection(&error);
            let response_status = if local {
                StatusCode::UNPROCESSABLE_ENTITY
            } else {
                StatusCode::BAD_GATEWAY
            };
            crate::gateway_diagnostics::record_request_failure(
                "cloud-code",
                context,
                &error,
                response_status.as_u16(),
            );
            Ok(if local {
                owned_text_response(StatusCode::UNPROCESSABLE_ENTITY, &error)
            } else {
                text_response(StatusCode::BAD_GATEWAY, "Pentect gateway request failed")
            })
        }
    }
}

async fn proxy_request_inner(
    request: Request<Incoming>,
    state: &ProxyState,
) -> Result<Response<ProxyBody>, String> {
    let request_path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let Some(path_and_query) = authenticated_request_path(request_path, &state.auth) else {
        return Ok(text_response(StatusCode::FORBIDDEN, "Forbidden"));
    };
    let endpoint = classify_endpoint(path_and_query);
    enforce_known_endpoint(endpoint, state.block_unknown_formats)?;
    let method = request.method().clone();
    let protected = endpoint.is_protected() && method == hyper::Method::POST;
    if endpoint.is_protected() && method != hyper::Method::POST {
        return Err(
            "unknown format blocked: Google Cloud Code model endpoints must use POST".to_string(),
        );
    }
    let is_stream = endpoint == CloudCodeEndpoint::StreamGenerateContent;
    let upstream_url =
        crate::upstream::join_url(&state.upstream, path_and_query, "Google Cloud Code")?;
    let request_headers = request.headers().clone();
    let body = if protected {
        let body = match Limited::new(request.into_body(), MAX_HTTP_BODY_BYTES)
            .collect()
            .await
        {
            Ok(body) => body.to_bytes(),
            Err(error) if error.is::<http_body_util::LengthLimitError>() => {
                return Ok(text_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request body too large",
                ));
            }
            Err(error) => return Err(format!("could not read Google Cloud Code request: {error}")),
        };
        let mut remote_budget = crate::remote_content::RemoteRequestBudget::default();
        let body = resolve_cloud_code_remote_files(body, &mut remote_budget).await?;
        let protected = protect_request_body(
            &body,
            endpoint,
            &state.masker,
            &state.plugins,
            state.block_unknown_formats,
        )?;
        if let Some(response) = protected.local_response {
            return Ok(json_response(StatusCode::OK, response));
        }
        reqwest::Body::from(protected.body)
    } else {
        let stream = request.into_body().into_data_stream().map(|chunk| {
            chunk.map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, error))
        });
        reqwest::Body::wrap_stream(stream)
    };

    let mut upstream_request = state.client.request(method.clone(), upstream_url);
    let connection_headers = connection_named_headers(&request_headers);
    for (name, value) in &request_headers {
        if state.headers.forward_incoming_header(name.as_str())
            && should_forward_request_header(name.as_str())
            && !connection_headers.contains(&name.as_str().to_ascii_lowercase())
        {
            upstream_request = upstream_request.header(name, value);
        }
    }
    let upstream = state
        .headers
        .apply(upstream_request)
        .body(body)
        .send()
        .await
        .map_err(|error| reqwest_error_message("could not reach Google Cloud Code", &error))?;
    let status = upstream.status();
    crate::gateway_diagnostics::record_upstream_status(
        "cloud-code",
        crate::gateway_diagnostics::RequestContext {
            endpoint: endpoint.diagnostic_name(),
            method: crate::gateway_diagnostics::method_name(&method),
        },
        status,
    );
    let response_headers = upstream.headers().clone();
    if response_headers
        .get(hyper::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err("Google Cloud Code returned an unsupported content encoding".to_string());
    }
    let media_type = response_headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    let event_stream = media_type
        .is_some_and(|value| value.eq_ignore_ascii_case("text/event-stream"))
        || (is_stream && media_type.is_none());
    let mut builder = Response::builder().status(status);
    let connection_headers = connection_named_headers(&response_headers);
    for (name, value) in &response_headers {
        if should_forward_response_header(name.as_str())
            && !connection_headers.contains(&name.as_str().to_ascii_lowercase())
        {
            builder = builder.header(name, value);
        }
    }
    builder = builder.header(
        "x-pentect-coverage",
        if protected { "full" } else { "none" },
    );
    if event_stream && endpoint == CloudCodeEndpoint::StreamGenerateContent && status.is_success() {
        return builder
            .body(streaming_response_body(
                upstream,
                Arc::clone(&state.plugins),
                state.block_unknown_formats,
            ))
            .map_err(|error| format!("could not build Google Cloud Code stream: {error}"));
    }
    if !endpoint.is_model_response() || !status.is_success() {
        return builder
            .body(passthrough_response_body(upstream))
            .map_err(|error| format!("could not build Google Cloud Code response: {error}"));
    }
    let Some(body) = read_response_capped(upstream).await? else {
        return Ok(text_response(
            StatusCode::BAD_GATEWAY,
            "Upstream response body too large",
        ));
    };
    let rewritten = match rewrite_response_body(&body, &state.plugins, state.block_unknown_formats)
    {
        Ok(rewritten) => rewritten,
        Err(error)
            if !state.block_unknown_formats && error.starts_with("unknown format blocked:") =>
        {
            proxy_diagnostic("response-protection-skipped");
            body.to_vec()
        }
        Err(error) => return Err(error),
    };
    builder
        .body(full_body(Bytes::from(rewritten)))
        .map_err(|error| format!("could not build Google Cloud Code response: {error}"))
}

async fn resolve_cloud_code_remote_files(
    body: Bytes,
    budget: &mut crate::remote_content::RemoteRequestBudget,
) -> Result<Bytes, String> {
    let mut value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return Ok(body),
    };
    resolve_cloud_code_remote_values(&mut value, budget).await?;
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|_| "could not encode resolved Google Cloud Code attachment".to_string())
}

fn resolve_cloud_code_remote_values<'a>(
    value: &'a mut Value,
    budget: &'a mut crate::remote_content::RemoteRequestBudget,
) -> Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        match value {
            Value::Array(values) => {
                for value in values {
                    resolve_cloud_code_remote_values(value, budget).await?;
                }
            }
            Value::Object(object) => {
                if let Some(file_data) = object.get("fileData").and_then(Value::as_object) {
                    let uri = file_data
                        .get("fileUri")
                        .or_else(|| file_data.get("file_uri"))
                        .and_then(Value::as_str)
                        .filter(|uri| uri.starts_with("https://"))
                        .map(str::to_string);
                    if let Some(uri) = uri {
                        let mut remote =
                            crate::remote_content::fetch_with_budget(&uri, budget).await?;
                        let encoded = data_encoding::BASE64.encode(&remote.bytes);
                        remote.bytes.zeroize();
                        object.remove("fileData");
                        object.insert(
                            "inlineData".to_string(),
                            serde_json::json!({
                                "mimeType": remote.media_type,
                                "data": encoded,
                            }),
                        );
                        return Ok(());
                    }
                }
                for value in object.values_mut() {
                    resolve_cloud_code_remote_values(value, budget).await?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloudCodeEndpoint {
    GenerateContent,
    StreamGenerateContent,
    CountTokens,
    Telemetry,
    Control,
    Unknown,
}

impl CloudCodeEndpoint {
    fn diagnostic_name(self) -> &'static str {
        match self {
            Self::GenerateContent => "generate-content",
            Self::StreamGenerateContent => "stream-generate-content",
            Self::CountTokens => "count-tokens",
            Self::Telemetry => "telemetry",
            Self::Control => "control",
            Self::Unknown => "unknown",
        }
    }

    fn is_protected(self) -> bool {
        matches!(
            self,
            Self::GenerateContent
                | Self::StreamGenerateContent
                | Self::CountTokens
                | Self::Telemetry
        )
    }

    fn is_model_response(self) -> bool {
        matches!(self, Self::GenerateContent | Self::StreamGenerateContent)
    }
}

fn classify_endpoint(path_and_query: &str) -> CloudCodeEndpoint {
    let path = path_and_query.split('?').next().unwrap_or(path_and_query);
    match path {
        "/v1internal:generateContent" => CloudCodeEndpoint::GenerateContent,
        "/v1internal:streamGenerateContent" => CloudCodeEndpoint::StreamGenerateContent,
        "/v1internal:countTokens" => CloudCodeEndpoint::CountTokens,
        "/v1internal:fetchAvailableModels"
        | "/v1internal:fetchAdminControls"
        | "/v1internal:getCodeAssistGlobalUserSetting"
        | "/v1internal:setCodeAssistGlobalUserSetting"
        | "/v1internal:listExperiments"
        | "/v1internal:retrieveUserQuota"
        | "/v1internal:retrieveUserQuotaSummary"
        | "/v1internal:loadCodeAssist"
        | "/v1internal:onboardUser"
        | "/v1internal:listCloudAICompanionProjects"
        | "/v1internal:fetchUserInfo"
        | "/v1internal:setUserSettings"
        | "/v1internal:fetchCodeCustomizationState"
        | "/v1internal:listModelConfigs"
        | "/v1internal:listAgents"
        | "/v1internal:listRemoteRepositories" => CloudCodeEndpoint::Control,
        "/v1internal:recordCodeAssistMetrics"
        | "/v1internal:recordClientEvent"
        | "/v1internal:recordTrajectoryAnalytics"
        | "/v1internal:recordSmartchoicesFeedback" => CloudCodeEndpoint::Telemetry,
        _ => CloudCodeEndpoint::Unknown,
    }
}

fn diagnostic_endpoint_name(request_path: &str, auth: &str) -> &'static str {
    authenticated_request_path(request_path, auth)
        .map(classify_endpoint)
        .unwrap_or(CloudCodeEndpoint::Unknown)
        .diagnostic_name()
}

fn enforce_known_endpoint(
    endpoint: CloudCodeEndpoint,
    block_unknown_formats: bool,
) -> Result<(), String> {
    if endpoint != CloudCodeEndpoint::Unknown {
        return Ok(());
    }
    if block_unknown_formats {
        return Err("unknown format blocked: Google Cloud Code endpoint is not supported; set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through".to_string());
    }
    if !WARNED_UNKNOWN_ENDPOINT.swap(true, Ordering::Relaxed) {
        proxy_diagnostic("unknown-endpoint");
    }
    Ok(())
}

#[derive(Debug)]
struct ProtectedRequest {
    body: Bytes,
    local_response: Option<Bytes>,
}

fn protect_request_body(
    body: &Bytes,
    endpoint: CloudCodeEndpoint,
    masker: &Mutex<pentect_agent::ActiveToolOutputMasker>,
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    block_unknown_formats: bool,
) -> Result<ProtectedRequest, String> {
    let mut value: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) if block_unknown_formats => {
            return Err(format!(
                "unknown format blocked: Google Cloud Code request is not valid JSON ({error})"
            ));
        }
        Err(_) => {
            proxy_diagnostic("request-invalid-json");
            return Ok(ProtectedRequest {
                body: body.clone(),
                local_response: None,
            });
        }
    };
    let run = plugins
        .lock()
        .map_err(|_| "Google Cloud Code plugin lock was poisoned".to_string())?
        .run(
            pentect_agent::MiddlewareStage::Request,
            value,
            Some(serde_json::json!({"provider": "google-cloud-code", "transport": "http"})),
        )?;
    if run.stopped == Some(pentect_agent::StopOutcome::Block) {
        return Err(format!(
            "plugin blocked: {}",
            run.message.unwrap_or_else(|| "request blocked".to_string())
        ));
    }
    value = run.payload;
    if run.stopped.is_some() {
        let body = serde_json::to_vec(&value)
            .map(Bytes::from)
            .map_err(|error| format!("could not encode plugin response: {error}"))?;
        return Ok(ProtectedRequest {
            body: Bytes::new(),
            local_response: Some(body),
        });
    }
    if block_unknown_formats && run.coverage == pentect_agent::MiddlewareCoverage::Partial {
        return Err(
            "unknown format blocked: a plugin reported partial Google Cloud Code request coverage"
                .to_string(),
        );
    }
    let mut masker = masker
        .lock()
        .map_err(|_| "Google Cloud Code request masker lock was poisoned".to_string())?;
    let mask_result = if endpoint == CloudCodeEndpoint::Telemetry {
        mask_value_strings(&mut value, false, &mut masker)
    } else {
        mask_cloud_code_request(&mut value, &mut masker, block_unknown_formats)
    };
    if let Err(error) = mask_result {
        if !block_unknown_formats && error.starts_with("unknown format blocked:") {
            proxy_diagnostic("request-protection-skipped");
            return Ok(ProtectedRequest {
                body: body.clone(),
                local_response: None,
            });
        }
        return Err(error);
    }
    if matches!(
        endpoint,
        CloudCodeEndpoint::GenerateContent | CloudCodeEndpoint::StreamGenerateContent
    ) {
        inject_handle_contract(&mut value)?;
    }
    let body = serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|error| {
            format!("could not encode protected Google Cloud Code request: {error}")
        })?;
    Ok(ProtectedRequest {
        body,
        local_response: None,
    })
}

fn mask_cloud_code_request(
    value: &mut Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    block_unknown_formats: bool,
) -> Result<(), String> {
    let request = value
        .get_mut("request")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            "unknown format blocked: Google Cloud Code request.request must be an object"
                .to_string()
        })?;
    for (key, value) in request.iter_mut() {
        if !matches!(key.as_str(), "contents" | "systemInstruction") {
            mask_value_strings(value, false, masker)?;
        }
    }
    let contents = request
        .get_mut("contents")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            "unknown format blocked: Google Cloud Code request.contents must be an array"
                .to_string()
        })?;
    for content in contents {
        mask_content(content, false, masker, block_unknown_formats)?;
    }
    if let Some(system) = request.get_mut("systemInstruction") {
        mask_content(system, false, masker, block_unknown_formats)?;
    }
    Ok(())
}

pub(crate) fn mask_content(
    content: &mut Value,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    block_unknown_formats: bool,
) -> Result<(), String> {
    let object = content.as_object_mut().ok_or_else(|| {
        "unknown format blocked: Google Cloud Code content must be an object".to_string()
    })?;
    let parts = object
        .get_mut("parts")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            "unknown format blocked: Google Cloud Code content.parts must be an array".to_string()
        })?;
    let original = std::mem::take(parts);
    for mut part in original {
        let note = mask_part(&mut part, tool_result, masker, block_unknown_formats)?;
        parts.push(part);
        if let Some(text) = note {
            parts.push(serde_json::json!({"text": text}));
        }
    }
    Ok(())
}

fn mask_part(
    part: &mut Value,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    block_unknown_formats: bool,
) -> Result<Option<String>, String> {
    let object = part.as_object_mut().ok_or_else(|| {
        "unknown format blocked: Google Cloud Code part must be an object".to_string()
    })?;
    const DATA_FIELDS: &[&str] = &[
        "text",
        "functionCall",
        "functionResponse",
        "inlineData",
        "fileData",
        "executableCode",
        "codeExecutionResult",
    ];
    const METADATA_FIELDS: &[&str] = &[
        "thought",
        "thoughtSignature",
        "videoMetadata",
        "partMetadata",
        "mediaResolution",
    ];
    let recognized = DATA_FIELDS.iter().any(|key| object.contains_key(*key));
    if !recognized && block_unknown_formats {
        return Err(
            "unknown format blocked: Google Cloud Code content part is unsupported".to_string(),
        );
    }
    if block_unknown_formats {
        if let Some(key) = object.keys().find(|key| {
            !DATA_FIELDS.contains(&key.as_str()) && !METADATA_FIELDS.contains(&key.as_str())
        }) {
            return Err(format!(
                "unknown format blocked: Google Cloud Code content part field '{key}' is unsupported"
            ));
        }
    }
    if let Some(Value::String(text)) = object.get_mut("text") {
        crate::claude_http_proxy::mask_string(text, tool_result, masker)?;
    }
    if let Some(call) = object.get_mut("functionCall") {
        mask_value_strings(call, true, masker)?;
    }
    if let Some(response) = object.get_mut("functionResponse") {
        mask_value_strings(response, true, masker)?;
    }
    let note = object
        .get_mut("inlineData")
        .map(|inline| inspect_inline_data(inline, tool_result, masker))
        .transpose()?
        .flatten();
    if object.contains_key("fileData") && pentect_agent::unscanned_images_should_block()? {
        return Err(
            "document blocked: Google Cloud Code fileData could not be scanned".to_string(),
        );
    }
    if let Some(code) = object.get_mut("executableCode") {
        mask_value_strings(code, false, masker)?;
    }
    if let Some(result) = object.get_mut("codeExecutionResult") {
        mask_value_strings(result, true, masker)?;
    }
    Ok(note)
}

fn mask_value_strings(
    value: &mut Value,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    match value {
        Value::String(text) => crate::claude_http_proxy::mask_string(text, tool_result, masker),
        Value::Array(values) => {
            for value in values {
                mask_value_strings(value, tool_result, masker)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for value in object.values_mut() {
                mask_value_strings(value, tool_result, masker)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn inspect_inline_data(
    value: &mut Value,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<Option<String>, String> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| "unknown format blocked: inlineData must be an object".to_string())?;
    let media_type = object
        .get("mimeType")
        .or_else(|| object.get("mime_type"))
        .and_then(Value::as_str)
        .unwrap_or("application/octet-stream")
        .to_string();
    let Some(data) = object
        .get("data")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return Err("unknown format blocked: inlineData.data must be base64 text".to_string());
    };
    if media_type.starts_with("image/") {
        if let Some(protected) = crate::claude_http_proxy::redact_inline_image_data(&data)? {
            object.insert("data".to_string(), Value::String(protected.data));
            object.insert(
                "mimeType".to_string(),
                Value::String("image/png".to_string()),
            );
            object.remove("mime_type");
            return Ok(Some(protected.note));
        }
        return Ok(None);
    }
    if media_type.starts_with("text/") || media_type == "application/json" {
        let mut decoded = data_encoding::BASE64
            .decode(data.as_bytes())
            .map_err(|_| "document blocked: invalid base64 inline text".to_string())?;
        let text = std::str::from_utf8(&decoded)
            .map_err(|_| "document blocked: inline text is not UTF-8".to_string())?;
        let mut protected = text.to_string();
        crate::claude_http_proxy::mask_string(&mut protected, tool_result, masker)?;
        decoded.zeroize();
        object.insert(
            "data".to_string(),
            Value::String(data_encoding::BASE64.encode(protected.as_bytes())),
        );
        protected.zeroize();
        return Ok(None);
    }
    crate::claude_http_proxy::enforce_unscanned_document_policy().map(|_| None)
}

fn inject_handle_contract(value: &mut Value) -> Result<(), String> {
    let request = value
        .get_mut("request")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "Google Cloud Code request.request must be an object".to_string())?;
    let system = request
        .entry("systemInstruction")
        .or_insert_with(|| serde_json::json!({"role": "system", "parts": []}));
    let object = system
        .as_object_mut()
        .ok_or_else(|| "Google Cloud Code systemInstruction must be an object".to_string())?;
    let parts = object
        .entry("parts")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| "Google Cloud Code systemInstruction.parts must be an array".to_string())?;
    if !parts
        .iter()
        .any(|part| part.get("text").and_then(Value::as_str) == Some(HANDLE_CONTRACT))
    {
        parts.push(serde_json::json!({"text": HANDLE_CONTRACT}));
    }
    Ok(())
}

fn rewrite_response_body(
    body: &[u8],
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    block_unknown_formats: bool,
) -> Result<Vec<u8>, String> {
    let mut value: Value = serde_json::from_slice(body).map_err(|error| {
        format!("unknown format blocked: Google Cloud Code response is not valid JSON ({error})")
    })?;
    rewrite_response_value(&mut value, plugins, block_unknown_formats)?;
    serde_json::to_vec(&value)
        .map_err(|error| format!("could not encode restored Google Cloud Code response: {error}"))
}

fn rewrite_response_value(
    value: &mut Value,
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    block_unknown_formats: bool,
) -> Result<(), String> {
    validate_response_value(value, block_unknown_formats)?;
    let mut run = plugins
        .lock()
        .map_err(|_| "Google Cloud Code plugin lock was poisoned".to_string())?
        .run(
            pentect_agent::MiddlewareStage::Response,
            value.clone(),
            Some(serde_json::json!({"provider": "google-cloud-code", "transport": "http"})),
        )?;
    if block_unknown_formats && run.coverage == pentect_agent::MiddlewareCoverage::Partial {
        return Err(
            "unknown format blocked: a plugin reported partial Google Cloud Code response coverage"
                .to_string(),
        );
    }
    if run.stopped == Some(pentect_agent::StopOutcome::Block) {
        return Err(format!(
            "plugin blocked: {}",
            run.message
                .unwrap_or_else(|| "response blocked".to_string())
        ));
    }
    let mut payload = std::mem::take(&mut run.payload);
    validate_response_value(&payload, block_unknown_formats)?;
    let plugins = plugins
        .lock()
        .map_err(|_| "Google Cloud Code plugin lock was poisoned".to_string())?;
    run_tool_plugins(&mut payload, &plugins)?;
    drop(plugins);
    let mut resolve = crate::claude_http_proxy::request_scoped_resolver();
    resolve_function_calls(&mut payload, &mut resolve)?;
    *value = payload;
    Ok(())
}

fn validate_response_value(value: &Value, block_unknown_formats: bool) -> Result<(), String> {
    if !block_unknown_formats {
        return Ok(());
    }
    let response = value
        .get("response")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            "unknown format blocked: Google Cloud Code response.response must be an object"
                .to_string()
        })?;
    let Some(candidates) = response.get("candidates") else {
        return Ok(());
    };
    let candidates = candidates.as_array().ok_or_else(|| {
        "unknown format blocked: Google Cloud Code response candidates must be an array".to_string()
    })?;
    for candidate in candidates {
        let candidate = candidate.as_object().ok_or_else(|| {
            "unknown format blocked: Google Cloud Code candidate must be an object".to_string()
        })?;
        let Some(content) = candidate.get("content") else {
            continue;
        };
        validate_response_content(content)?;
    }
    Ok(())
}

fn validate_response_content(content: &Value) -> Result<(), String> {
    let content = content.as_object().ok_or_else(|| {
        "unknown format blocked: Google Cloud Code response content must be an object".to_string()
    })?;
    let parts = content
        .get("parts")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "unknown format blocked: Google Cloud Code response content.parts must be an array"
                .to_string()
        })?;
    for part in parts {
        let part = part.as_object().ok_or_else(|| {
            "unknown format blocked: Google Cloud Code response part must be an object".to_string()
        })?;
        const DATA_FIELDS: &[&str] = &[
            "text",
            "functionCall",
            "functionResponse",
            "inlineData",
            "fileData",
            "executableCode",
            "codeExecutionResult",
        ];
        const METADATA_FIELDS: &[&str] = &[
            "thought",
            "thoughtSignature",
            "videoMetadata",
            "partMetadata",
            "mediaResolution",
        ];
        if !DATA_FIELDS.iter().any(|key| part.contains_key(*key)) {
            return Err(
                "unknown format blocked: Google Cloud Code response part is unsupported"
                    .to_string(),
            );
        }
        if let Some(key) = part.keys().find(|key| {
            !DATA_FIELDS.contains(&key.as_str()) && !METADATA_FIELDS.contains(&key.as_str())
        }) {
            return Err(format!(
                "unknown format blocked: Google Cloud Code response part field '{key}' is unsupported"
            ));
        }
    }
    Ok(())
}

fn run_tool_plugins(
    value: &mut Value,
    plugins: &pentect_agent::PluginMiddleware,
) -> Result<(), String> {
    match value {
        Value::Array(values) => {
            for value in values {
                run_tool_plugins(value, plugins)?;
            }
        }
        Value::Object(object) => {
            if let Some(call) = object.get_mut("functionCall") {
                let run = plugins.run(
                    pentect_agent::MiddlewareStage::ToolCall,
                    call.clone(),
                    Some(serde_json::json!({"provider": "google-cloud-code", "transport": "http"})),
                )?;
                if run.stopped == Some(pentect_agent::StopOutcome::Block) {
                    return Err(format!(
                        "plugin blocked: {}",
                        run.message
                            .unwrap_or_else(|| "tool call blocked".to_string())
                    ));
                }
                *call = run.payload;
            }
            for child in object.values_mut() {
                run_tool_plugins(child, plugins)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn resolve_function_calls<R>(value: &mut Value, resolve: &mut R) -> Result<(), String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    match value {
        Value::Array(values) => {
            for value in values {
                resolve_function_calls(value, resolve)?;
            }
        }
        Value::Object(object) => {
            if let Some(call) = object.get_mut("functionCall") {
                let name = call.get("name").and_then(Value::as_str).map(str::to_string);
                if let Some(args) = call.get_mut("args") {
                    let encoded = serde_json::to_string(args).map_err(|error| {
                        format!("could not encode Google tool arguments: {error}")
                    })?;
                    let restored = crate::claude_http_proxy::resolve_tool_input_json(
                        &encoded,
                        name.as_deref(),
                        resolve,
                    )?;
                    *args = serde_json::from_str(&restored).map_err(|error| {
                        format!("restored Google tool arguments are invalid: {error}")
                    })?;
                }
            }
            for child in object.values_mut() {
                resolve_function_calls(child, resolve)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct StreamState {
    upstream: UpstreamByteStream,
    pending: Vec<u8>,
    ready: VecDeque<Result<Frame<Bytes>, ProxyBodyError>>,
    finished: bool,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
    block_unknown_formats: bool,
}

fn streaming_response_body(
    response: reqwest::Response,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
    block_unknown_formats: bool,
) -> ProxyBody {
    let state = StreamState {
        upstream: Box::pin(response.bytes_stream()),
        pending: Vec::new(),
        ready: VecDeque::new(),
        finished: false,
        plugins,
        block_unknown_formats,
    };
    let stream = stream::unfold(state, |mut state| async move {
        loop {
            if let Some(item) = state.ready.pop_front() {
                return Some((item, state));
            }
            if state.finished {
                return None;
            }
            match state.upstream.next().await {
                Some(Ok(chunk)) => {
                    if state.pending.len().saturating_add(chunk.len()) > MAX_PENDING_SSE_BYTES {
                        state.finished = true;
                        state.ready.push_back(Err(Box::new(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Google Cloud Code SSE event exceeded limit",
                        ))));
                        continue;
                    }
                    state.pending.extend_from_slice(&chunk);
                    while let Some(end) = first_sse_block_end(&state.pending) {
                        let block = state.pending.drain(..end).collect::<Vec<_>>();
                        match rewrite_sse_block(&block, &state.plugins, state.block_unknown_formats)
                        {
                            Ok(block) => state.ready.push_back(Ok(Frame::data(block))),
                            Err(error) => {
                                state.finished = true;
                                state.ready.push_back(Err(Box::new(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    error,
                                ))));
                                break;
                            }
                        }
                    }
                }
                Some(Err(error)) => {
                    state.finished = true;
                    state.ready.push_back(Err(Box::new(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        reqwest_error_message("Google Cloud Code stream failed", &error),
                    ))));
                }
                None => {
                    state.finished = true;
                    if !state.pending.is_empty() {
                        let pending = std::mem::take(&mut state.pending);
                        match rewrite_sse_block(
                            &pending,
                            &state.plugins,
                            state.block_unknown_formats,
                        ) {
                            Ok(block) => state.ready.push_back(Ok(Frame::data(block))),
                            Err(error) => state.ready.push_back(Err(Box::new(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                error,
                            )))),
                        }
                    }
                }
            }
        }
    });
    StreamBody::new(stream).boxed_unsync()
}

fn rewrite_sse_block(
    block: &[u8],
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    block_unknown_formats: bool,
) -> Result<Bytes, String> {
    let text = match std::str::from_utf8(block) {
        Ok(text) => text,
        Err(error) if block_unknown_formats => {
            return Err(format!(
                "unknown format blocked: Google Cloud Code stream event is not UTF-8 ({error})"
            ));
        }
        Err(_) => {
            proxy_diagnostic("stream-event-protection-skipped");
            return Ok(Bytes::copy_from_slice(block));
        }
    };
    let data = text
        .lines()
        .filter_map(|line| line.strip_prefix("data:").map(str::trim_start))
        .collect::<Vec<_>>();
    if data.is_empty() || data == ["[DONE]"] {
        return Ok(Bytes::copy_from_slice(block));
    }
    let mut value: Value = match serde_json::from_str(&data.join("\n")) {
        Ok(value) => value,
        Err(error) if block_unknown_formats => {
            return Err(format!(
                "unknown format blocked: Google Cloud Code stream event is not valid JSON ({error})"
            ));
        }
        Err(_) => {
            proxy_diagnostic("stream-event-protection-skipped");
            return Ok(Bytes::copy_from_slice(block));
        }
    };
    rewrite_response_value(&mut value, plugins, block_unknown_formats)?;
    let encoded = serde_json::to_string(&value)
        .map_err(|error| format!("could not encode Google Cloud Code SSE event: {error}"))?;
    let ending = if text.ends_with("\r\n\r\n") {
        "\r\n\r\n"
    } else {
        "\n\n"
    };
    let metadata = text
        .lines()
        .filter(|line| !line.starts_with("data:"))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let mut output = String::new();
    for line in metadata {
        output.push_str(line);
        output.push('\n');
    }
    output.push_str("data: ");
    output.push_str(&encoded);
    output.push_str(ending);
    Ok(Bytes::from(output))
}

fn passthrough_response_body(response: reqwest::Response) -> ProxyBody {
    let stream = response.bytes_stream().map(|chunk| {
        chunk
            .map(Frame::data)
            .map_err(|error| -> ProxyBodyError { Box::new(error) })
    });
    StreamBody::new(stream).boxed_unsync()
}

async fn read_response_capped(response: reqwest::Response) -> Result<Option<Bytes>, String> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            reqwest_error_message("could not read Google Cloud Code response", &error)
        })?;
        if body.len().saturating_add(chunk.len()) > MAX_HTTP_BODY_BYTES {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(Bytes::from(body)))
}

fn first_sse_block_end(bytes: &[u8]) -> Option<usize> {
    let lf = bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|at| at + 2);
    let crlf = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4);
    match (lf, crlf) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(end), None) | (None, Some(end)) => Some(end),
        (None, None) => None,
    }
}

fn authenticated_request_path<'a>(path_and_query: &'a str, token: &str) -> Option<&'a str> {
    let prefix_len = token.len().checked_add(1)?;
    let prefix = path_and_query.get(..prefix_len)?;
    if !prefix.starts_with('/') || prefix.get(1..)? != token {
        return None;
    }
    let rest = path_and_query.get(prefix_len..)?;
    if rest.is_empty() {
        Some("/")
    } else if rest.starts_with('/') || rest.starts_with('?') {
        Some(rest)
    } else {
        None
    }
}

fn should_forward_request_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade"
            | "accept-encoding"
    )
}

fn should_forward_response_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "content-length"
            | "transfer-encoding"
            | "connection"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade"
            | "content-encoding"
    )
}

fn connection_named_headers(headers: &hyper::HeaderMap) -> HashSet<String> {
    headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn reqwest_error_message(context: &str, error: &reqwest::Error) -> String {
    if error.is_timeout() {
        format!("{context}: timed out")
    } else if error.is_connect() {
        format!("{context}: connection failed")
    } else if error.is_body() || error.is_decode() {
        format!("{context}: invalid response body")
    } else {
        format!("{context}: request failed")
    }
}

fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn text_response(status: StatusCode, text: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::from_static(text.as_bytes())))
        .expect("static response is valid")
}

fn owned_text_response(status: StatusCode, text: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::copy_from_slice(text.as_bytes())))
        .expect("text response is valid")
}

fn json_response(status: StatusCode, body: Bytes) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(full_body(body))
        .expect("JSON response is valid")
}

fn random_auth_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| format!("could not create Google Cloud Code gateway token: {error}"))?;
    let token = data_encoding::HEXLOWER.encode(&bytes);
    bytes.zeroize();
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestEnv {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
        home: std::path::PathBuf,
        process_host_candidate: Option<std::path::PathBuf>,
    }

    impl TestEnv {
        fn install(store: &pentect_agent::InProcessMemoryStore) -> Self {
            let names = [
                "PENTECT_MEMORY_STORE_ADDR",
                "PENTECT_MEMORY_STORE_TOKEN",
                "PENTECT_AGENT_LAUNCHED",
                "PENTECT_HOME",
                "LOCALAPPDATA",
            ];
            let saved = names
                .into_iter()
                .map(|name| (name, std::env::var_os(name)))
                .collect();
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let home = std::env::temp_dir().join(format!(
                "pentect-cloud-code-e2e-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir_all(&home).unwrap();
            std::env::set_var("PENTECT_MEMORY_STORE_ADDR", store.addr());
            std::env::set_var("PENTECT_MEMORY_STORE_TOKEN", store.token());
            std::env::set_var("PENTECT_AGENT_LAUNCHED", store.token());
            std::env::set_var("PENTECT_HOME", &home);
            std::env::set_var("LOCALAPPDATA", &home);
            let process_host_candidate = Some(
                pentect_agent::register_process_host_candidate(
                    &pentect_agent::process_host_root().unwrap(),
                    store.addr(),
                    store.token(),
                    store.process_host_read_token(),
                    store.process_host_write_token(),
                    std::process::id(),
                )
                .unwrap(),
            );
            Self {
                saved,
                home,
                process_host_candidate,
            }
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            if let Some(path) = self.process_host_candidate.take() {
                pentect_agent::unregister_process_host_candidate(&path);
            }
            for (name, value) in self.saved.drain(..) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }

    fn first_handle(text: &str) -> Option<String> {
        let start = text.find("<<")?;
        let end = start + text[start..].find(">>")? + 2;
        Some(text[start..end].to_string())
    }

    fn mock_cloud_code_upstream() -> (
        String,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (body_tx, body_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let header_end;
            loop {
                let read = socket.read(&mut buffer).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
                if let Some(at) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    header_end = at + 4;
                    break;
                }
            }
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let read = socket.read(&mut buffer).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
            }
            let body = String::from_utf8(request[header_end..header_end + content_length].to_vec())
                .unwrap();
            let handle = first_handle(&body).expect("masked request contains a handle");
            body_tx.send(body).unwrap();
            let response = serde_json::json!({
                "response": {"candidates": [{"content": {"role": "model", "parts": [
                    {"text": handle},
                    {"functionCall": {"name": "custom_tool", "args": {"token": handle}}}
                ]}}]}
            })
            .to_string();
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
            socket.flush().unwrap();
        });
        (format!("http://{address}"), body_rx, thread)
    }

    fn mock_streaming_cloud_code_upstream() -> (
        String,
        std::sync::mpsc::Receiver<(String, String)>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let header_end;
            loop {
                let read = socket.read(&mut buffer).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
                if let Some(at) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    header_end = at + 4;
                    break;
                }
            }
            let headers = std::str::from_utf8(&request[..header_end])
                .unwrap()
                .to_string();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let read = socket.read(&mut buffer).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
            }
            let body = String::from_utf8(request[header_end..header_end + content_length].to_vec())
                .unwrap();
            let handle = first_handle(&body).expect("masked stream request contains a handle");
            request_tx.send((headers, body)).unwrap();
            let event = format!(
                "data: {}\n\n",
                serde_json::json!({
                    "response": {"candidates": [{"content": {"parts": [
                        {"text": handle},
                        {"functionCall": {"name": "custom_tool", "args": {"token": handle}}}
                    ]}}]}
                })
            );
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            for chunk in event.as_bytes().chunks(7) {
                write!(socket, "{:X}\r\n", chunk.len()).unwrap();
                socket.write_all(chunk).unwrap();
                socket.write_all(b"\r\n").unwrap();
                socket.flush().unwrap();
            }
            socket.write_all(b"0\r\n\r\n").unwrap();
            socket.flush().unwrap();
        });
        (format!("http://{address}"), request_rx, thread)
    }

    #[test]
    fn classifies_model_and_control_endpoints() {
        assert_eq!(
            classify_endpoint("/v1internal:streamGenerateContent?alt=sse"),
            CloudCodeEndpoint::StreamGenerateContent
        );
        assert_eq!(
            classify_endpoint("/v1internal:countTokens"),
            CloudCodeEndpoint::CountTokens
        );
        assert_eq!(
            classify_endpoint("/v1internal:fetchAvailableModels"),
            CloudCodeEndpoint::Control
        );
        assert_eq!(
            classify_endpoint("/v1internal:futureModelEndpoint"),
            CloudCodeEndpoint::Unknown
        );
        assert!(enforce_known_endpoint(CloudCodeEndpoint::Unknown, true).is_err());
        assert!(enforce_known_endpoint(CloudCodeEndpoint::Unknown, false).is_ok());
    }

    #[test]
    fn custom_cloud_code_base_path_and_query_are_preserved() {
        let upstream = crate::upstream::parse_base(
            "http://127.0.0.1:8080/team/cloud-code?tenant=demo",
            "Google Cloud Code",
        )
        .unwrap();
        let joined = crate::upstream::join_url(
            &upstream,
            "/v1internal:streamGenerateContent?alt=sse",
            "Google Cloud Code",
        )
        .unwrap();
        assert_eq!(
            joined.as_str(),
            "http://127.0.0.1:8080/team/cloud-code/v1internal:streamGenerateContent?tenant=demo&alt=sse"
        );
    }

    #[test]
    fn auth_path_cannot_be_confused_by_a_prefix() {
        assert_eq!(
            authenticated_request_path("/token/v1internal:countTokens", "token"),
            Some("/v1internal:countTokens")
        );
        assert_eq!(
            authenticated_request_path("/tokenx/v1internal:countTokens", "token"),
            None
        );
        assert_eq!(
            diagnostic_endpoint_name("/token/v1internal:countTokens", "token"),
            "count-tokens"
        );
        assert_eq!(
            diagnostic_endpoint_name("/tokenx/v1internal:countTokens", "token"),
            "unknown"
        );
    }

    #[test]
    fn response_rewriter_only_resolves_function_call_arguments() {
        let handle = "<<SECRET_0123456789abcdef>>";
        let mut value = serde_json::json!({
            "response": {"candidates": [{"content": {"parts": [
                {"text": handle},
                {"functionCall": {"name": "read_file", "args": {"path": handle}}}
            ]}}]}
        });
        let mut resolve = |text: &str| Ok(text.replace(handle, "C:/private.txt"));
        resolve_function_calls(&mut value, &mut resolve).unwrap();
        assert_eq!(
            value["response"]["candidates"][0]["content"]["parts"][0]["text"],
            handle
        );
        assert_eq!(
            value["response"]["candidates"][0]["content"]["parts"][1]["functionCall"]["args"]
                ["path"],
            "C:/private.txt"
        );
    }

    #[test]
    fn provider_boundary_masks_requests_and_restores_only_function_calls() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let secret = [
            "rpa_",
            "ZYXWVUTS",
            "RQPONMLK",
            "JIHGFEDC",
            "BA098765",
            "4321fedcba",
        ]
        .concat();
        let (upstream, captured, thread) = mock_cloud_code_upstream();
        let proxy = CloudCodeHttpProxyGuard::start(upstream).unwrap();
        let request_body = serde_json::to_vec(&serde_json::json!({
            "model": "test",
            "request": {"contents": [{"role": "user", "parts": [{
                "text": format!("Use RUNPOD_API_KEY={secret}")
            }]}]}
        }))
        .unwrap();
        let response = reqwest::blocking::Client::new()
            .post(format!("{}/v1internal:generateContent", proxy.base_url()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request_body)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .unwrap();
        let response: Value = serde_json::from_str(&response).unwrap();
        let request = captured
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        thread.join().unwrap();
        assert!(!request.contains(&secret));
        let handle = first_handle(&request).unwrap();
        let protected_request: Value = serde_json::from_str(&request).unwrap();
        assert_eq!(
            protected_request["request"]["systemInstruction"]["parts"][0]["text"],
            HANDLE_CONTRACT
        );
        assert_eq!(
            response["response"]["candidates"][0]["content"]["parts"][0]["text"],
            handle
        );
        assert_eq!(
            response["response"]["candidates"][0]["content"]["parts"][1]["functionCall"]["args"]
                ["token"],
            secret
        );
    }

    #[test]
    fn fragmented_http_sse_restores_only_function_calls_and_forwards_auth() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let secret = [
            "rpa_",
            "ZYXWVUTS",
            "RQPONMLK",
            "JIHGFEDC",
            "BA098765",
            "4321fedcba",
        ]
        .concat();
        let (upstream, captured, thread) = mock_streaming_cloud_code_upstream();
        let proxy = CloudCodeHttpProxyGuard::start(upstream).unwrap();
        let response = reqwest::blocking::Client::new()
            .post(format!(
                "{}/v1internal:streamGenerateContent?alt=sse",
                proxy.base_url()
            ))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .bearer_auth("official-client-token")
            .body(
                serde_json::to_vec(&serde_json::json!({
                    "request": {"contents": [{"role": "user", "parts": [{
                        "text": format!("Use RUNPOD_API_KEY={secret}")
                    }]}]}
                }))
                .unwrap(),
            )
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .unwrap();
        let (headers, request) = captured
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        thread.join().unwrap();
        assert!(headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("authorization: Bearer official-client-token")));
        assert!(!request.contains(&secret));
        let handle = first_handle(&request).unwrap();
        assert!(response.contains(&handle));
        assert!(response.contains(&secret));
        let data = response
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap();
        let response: Value = serde_json::from_str(data).unwrap();
        assert_eq!(
            response["response"]["candidates"][0]["content"]["parts"][0]["text"],
            handle
        );
        assert_eq!(
            response["response"]["candidates"][0]["content"]["parts"][1]["functionCall"]["args"]
                ["token"],
            secret
        );
    }

    #[test]
    fn unknown_routes_and_wrong_model_methods_are_blocked_before_upstream() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let proxy = CloudCodeHttpProxyGuard::start("http://127.0.0.1:9".to_string()).unwrap();
        let client = reqwest::blocking::Client::new();
        let unknown = client
            .post(format!("{}/v1internal:futureEndpoint", proxy.base_url()))
            .body("{}")
            .send()
            .unwrap();
        assert_eq!(unknown.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
        assert!(unknown.text().unwrap().contains("unknown format blocked:"));
        let wrong_method = client
            .get(format!("{}/v1internal:generateContent", proxy.base_url()))
            .send()
            .unwrap();
        assert_eq!(
            wrong_method.status(),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY
        );
        assert!(wrong_method
            .text()
            .unwrap()
            .contains("model endpoints must use POST"));
    }

    #[test]
    fn inline_text_is_masked_and_unscanned_file_data_is_blocked() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let secret = ["rpa_", "ABCDEFGHIJKLMNOP", "QRSTUVWXYZ012345", "6789abcdef"].concat();
        let plugins = pentect_agent::PluginMiddleware::from_env().unwrap();
        let masker = Mutex::new(
            pentect_agent::ActiveToolOutputMasker::new_with_plugins(plugins.clone()).unwrap(),
        );
        let plugins = Mutex::new(plugins);
        let encoded = data_encoding::BASE64.encode(format!("RUNPOD_API_KEY={secret}").as_bytes());
        let request = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "request": {"contents": [{"role": "user", "parts": [{
                    "inlineData": {"mimeType": "text/plain", "data": encoded}
                }]}]}
            }))
            .unwrap(),
        );
        let protected = protect_request_body(
            &request,
            CloudCodeEndpoint::GenerateContent,
            &masker,
            &plugins,
            true,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&protected.body).unwrap();
        let encoded = value["request"]["contents"][0]["parts"][0]["inlineData"]["data"]
            .as_str()
            .unwrap();
        let decoded = data_encoding::BASE64.decode(encoded.as_bytes()).unwrap();
        let decoded = std::str::from_utf8(&decoded).unwrap();
        assert!(!decoded.contains(&secret));
        assert!(first_handle(decoded).is_some());

        let file_request = Bytes::from_static(
            br#"{"request":{"contents":[{"role":"user","parts":[{"fileData":{"mimeType":"application/pdf","fileUri":"gs://example/private.pdf"}}]}]}}"#,
        );
        let error = protect_request_body(
            &file_request,
            CloudCodeEndpoint::GenerateContent,
            &masker,
            &plugins,
            true,
        )
        .unwrap_err();
        assert!(error.starts_with("document blocked:"));
    }

    #[test]
    fn count_tokens_and_telemetry_are_masked_without_contract_injection() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let secret = ["rpa_", "ABCDEFGHIJKLMNOP", "QRSTUVWXYZ012345", "6789abcdef"].concat();
        let plugins = pentect_agent::PluginMiddleware::from_env().unwrap();
        let masker = Mutex::new(
            pentect_agent::ActiveToolOutputMasker::new_with_plugins(plugins.clone()).unwrap(),
        );
        let plugins = Mutex::new(plugins);

        let count = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "request": {"contents": [{"role": "user", "parts": [{
                    "text": format!("Count RUNPOD_API_KEY={secret}")
                }]}]}
            }))
            .unwrap(),
        );
        let count = protect_request_body(
            &count,
            CloudCodeEndpoint::CountTokens,
            &masker,
            &plugins,
            true,
        )
        .unwrap();
        let count = String::from_utf8(count.body.to_vec()).unwrap();
        assert!(!count.contains(&secret));
        assert!(first_handle(&count).is_some());
        assert!(!count.contains(HANDLE_CONTRACT));

        let telemetry = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "project": "safe-project",
                "event": {"prompt": format!("Accidental RUNPOD_API_KEY={secret}")}
            }))
            .unwrap(),
        );
        let telemetry = protect_request_body(
            &telemetry,
            CloudCodeEndpoint::Telemetry,
            &masker,
            &plugins,
            true,
        )
        .unwrap();
        let telemetry = String::from_utf8(telemetry.body.to_vec()).unwrap();
        assert!(!telemetry.contains(&secret));
        assert!(first_handle(&telemetry).is_some());
        assert!(!telemetry.contains(HANDLE_CONTRACT));
    }

    #[test]
    fn sse_restores_handles_only_inside_function_calls() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let secret = ["rpa_", "ABCDEFGHIJKLMNOP", "QRSTUVWXYZ012345", "6789abcdef"].concat();
        let plugins = pentect_agent::PluginMiddleware::from_env().unwrap();
        let masker = Mutex::new(
            pentect_agent::ActiveToolOutputMasker::new_with_plugins(plugins.clone()).unwrap(),
        );
        let plugins = Mutex::new(plugins);
        let request = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "request": {"contents": [{"role": "user", "parts": [{
                    "text": format!("Use RUNPOD_API_KEY={secret}")
                }]}]}
            }))
            .unwrap(),
        );
        let protected = protect_request_body(
            &request,
            CloudCodeEndpoint::StreamGenerateContent,
            &masker,
            &plugins,
            true,
        )
        .unwrap();
        let handle = first_handle(std::str::from_utf8(&protected.body).unwrap()).unwrap();
        let event = serde_json::json!({
            "response": {"candidates": [{"content": {"parts": [
                {"text": handle},
                {"functionCall": {"name": "custom_tool", "args": {"token": handle}}}
            ]}}]}
        });
        let block = format!("event: message\ndata: {event}\n\n");
        let rewritten = rewrite_sse_block(block.as_bytes(), &plugins, true).unwrap();
        let rewritten = std::str::from_utf8(&rewritten).unwrap();
        assert!(rewritten.contains(&handle));
        assert!(rewritten.contains(&secret));
        assert!(rewritten.starts_with("event: message\n"));
    }

    #[test]
    fn sse_blocks_are_found_across_line_endings() {
        assert_eq!(first_sse_block_end(b"data: {}\n\nnext"), Some(10));
        assert_eq!(first_sse_block_end(b"data: {}\r\n\r\nnext"), Some(12));
        assert_eq!(first_sse_block_end(b"data: {}"), None);
    }

    #[test]
    fn malformed_stream_events_follow_unknown_format_policy() {
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::from_env().unwrap());
        let block = b"data: {broken\n\n";
        assert!(rewrite_sse_block(block, &plugins, true)
            .unwrap_err()
            .starts_with("unknown format blocked:"));
        assert_eq!(
            rewrite_sse_block(block, &plugins, false).unwrap(),
            block.as_slice()
        );
        assert!(rewrite_response_body(b"{broken", &plugins, true)
            .unwrap_err()
            .starts_with("unknown format blocked:"));
        assert!(rewrite_sse_block(&[0xff], &plugins, true)
            .unwrap_err()
            .starts_with("unknown format blocked:"));
    }

    #[test]
    fn unterminated_sse_event_is_still_inspected() {
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::from_env().unwrap());
        let block = br#"data: {"response":{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}}"#;
        let rewritten = rewrite_sse_block(block, &plugins, true).unwrap();
        assert!(rewritten.ends_with(b"\n\n"));
    }

    #[test]
    fn unknown_part_fields_are_blocked_on_both_boundaries() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let plugins = pentect_agent::PluginMiddleware::from_env().unwrap();
        let masker = Mutex::new(
            pentect_agent::ActiveToolOutputMasker::new_with_plugins(plugins.clone()).unwrap(),
        );
        let plugins = Mutex::new(plugins);
        let request = Bytes::from_static(
            br#"{"request":{"contents":[{"role":"user","parts":[{"text":"ok","futureContent":"secret"}]}]}}"#,
        );
        assert!(protect_request_body(
            &request,
            CloudCodeEndpoint::GenerateContent,
            &masker,
            &plugins,
            true,
        )
        .unwrap_err()
        .starts_with("unknown format blocked:"));

        let response = serde_json::json!({
            "response": {"candidates": [{"content": {"parts": [{
                "text": "ok",
                "futureToolCall": {"name": "run", "args": {}}
            }]}}]}
        });
        assert!(validate_response_value(&response, true)
            .unwrap_err()
            .starts_with("unknown format blocked:"));
        assert!(validate_response_value(&response, false).is_ok());
    }

    #[test]
    fn request_metadata_and_executable_code_are_masked() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let secret = ["rpa_", "ABCDEFGHIJKLMNOP", "QRSTUVWXYZ012345", "6789abcdef"].concat();
        let plugins = pentect_agent::PluginMiddleware::from_env().unwrap();
        let masker = Mutex::new(
            pentect_agent::ActiveToolOutputMasker::new_with_plugins(plugins.clone()).unwrap(),
        );
        let plugins = Mutex::new(plugins);
        let request = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "request": {
                    "contents": [{"role": "user", "parts": [{
                        "executableCode": {
                            "language": "shell",
                            "code": format!("RUNPOD_API_KEY={secret} command")
                        }
                    }]}],
                    "tools": [{"functionDeclarations": [{
                        "name": "lookup",
                        "description": format!("Use RUNPOD_API_KEY={secret}")
                    }]}]
                }
            }))
            .unwrap(),
        );
        let protected = protect_request_body(
            &request,
            CloudCodeEndpoint::GenerateContent,
            &masker,
            &plugins,
            true,
        )
        .unwrap();
        let protected = std::str::from_utf8(&protected.body).unwrap();
        assert!(!protected.contains(&secret));
        assert!(protected.matches("<<").count() >= 2);
    }
}
