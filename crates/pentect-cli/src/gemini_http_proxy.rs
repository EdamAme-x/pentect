//! Native Gemini API gateway used by Gemini CLI.
//!
//! This is deliberately separate from Google Cloud Code Assist: the clients
//! use related content objects but different endpoints, envelopes, and auth.

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
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Semaphore};
use zeroize::Zeroize;

use crate::handle_contract::HANDLE_CONTRACT;

const MAX_HTTP_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_PENDING_SSE_BYTES: usize = 8 * 1024 * 1024;
type ProxyBodyError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, ProxyBodyError>;
type UpstreamByteStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static>>;

fn diagnostic(reason: &str) {
    let (kind, retryable) = match reason {
        "gateway-stopped" => ("runtime", false),
        "connection-failed" => ("client-connection", true),
        "request-invalid-json" => ("protocol", false),
        "request-protection-skipped" | "response-protection-skipped" => ("protection", false),
        _ => ("unclassified", false),
    };
    pentect_agent::record_http_diagnostic_activity(
        "gemini",
        reason,
        kind,
        "gateway",
        "HTTP",
        None,
        retryable,
        env!("CARGO_PKG_VERSION"),
    );
}

pub(crate) struct GeminiHttpProxyGuard {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl GeminiHttpProxyGuard {
    pub(crate) fn start_with_header_env(
        upstream: String,
        header_env: &[String],
    ) -> Result<Self, String> {
        Self::start_with_header_env_and_api_key(upstream, header_env, None)
    }

    pub(crate) fn start_with_header_env_and_api_key(
        upstream: String,
        header_env: &[String],
        api_key: Option<String>,
    ) -> Result<Self, String> {
        let upstream = crate::upstream::parse_base(&upstream, "Gemini")?;
        let headers = crate::upstream::header_overrides_with_google_api_key(header_env, api_key)?;
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
                        "could not start Gemini gateway runtime: {error}"
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                if run_proxy(upstream, headers, thread_auth, ready_tx, shutdown_rx)
                    .await
                    .is_err()
                {
                    diagnostic("gateway-stopped");
                }
            });
        });
        let base_url = ready_rx
            .recv_timeout(crate::GATEWAY_STARTUP_TIMEOUT)
            .map_err(|_| "Gemini gateway initialization timed out".to_string())??;
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

impl Drop for GeminiHttpProxyGuard {
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
        .map_err(|error| format!("could not bind Gemini gateway: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("could not read Gemini gateway address: {error}"))?;
    let local_base_url = format!("http://{address}/{auth}");
    let plugins = pentect_agent::PluginMiddleware::from_env()?;
    let state = Arc::new(ProxyState {
        upstream,
        auth,
        client: crate::upstream::client("Gemini")?,
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
                let (socket, _) = accepted.map_err(|error| format!("Gemini gateway accept failed: {error}"))?;
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
                            diagnostic("connection-failed");
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
            "gemini",
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
                "gemini",
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
    if endpoint == GeminiEndpoint::Unknown && state.block_unknown_formats {
        return Err("unknown format blocked: Gemini endpoint is not supported; set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through".to_string());
    }
    let method = request.method().clone();
    let protected = endpoint.is_protected() && method == hyper::Method::POST;
    let is_stream = endpoint == GeminiEndpoint::StreamGenerateContent;
    let body_forbidden = endpoint == GeminiEndpoint::Models;
    if endpoint.is_protected() && method != hyper::Method::POST {
        return Err("unknown format blocked: Gemini model endpoints must use POST".to_string());
    }
    let upstream_url = crate::upstream::join_url(&state.upstream, path_and_query, "Gemini")?;
    let request_headers = request.headers().clone();
    let body = if protected || body_forbidden {
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
            Err(error) => return Err(format!("could not read Gemini request: {error}")),
        };
        if body_forbidden {
            if !body.is_empty() {
                return Err(
                    "request body blocked: Gemini models endpoints do not accept request bodies"
                        .to_string(),
                );
            }
            reqwest::Body::from(body)
        } else {
            let mut remote_budget = crate::remote_content::RemoteRequestBudget::default();
            let body =
                crate::cloud_code_http_proxy::resolve_google_remote_files(body, &mut remote_budget)
                    .await?;
            let protected = protect_request_body(
                &body,
                endpoint,
                &state.masker,
                &state.plugins,
                state.block_unknown_formats,
            )?;
            if let Some(response) = protected.local_response {
                if endpoint == GeminiEndpoint::StreamGenerateContent {
                    return Ok(text_response(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Plugin local responses are unavailable for streaming Gemini requests",
                    ));
                }
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .body(full_body(response))
                    .expect("local plugin response"));
            }
            reqwest::Body::from(protected.body)
        }
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
        .map_err(|error| reqwest_error_message("could not reach Gemini upstream", &error))?;
    let status = upstream.status();
    crate::gateway_diagnostics::record_upstream_status(
        "gemini",
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
        return Err("Gemini upstream returned an unsupported content encoding".to_string());
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
    if event_stream && status.is_success() && endpoint == GeminiEndpoint::StreamGenerateContent {
        return builder
            .body(streaming_response_body(
                upstream,
                Arc::clone(&state.plugins),
                state.block_unknown_formats,
            ))
            .map_err(|error| format!("could not build Gemini stream: {error}"));
    }
    if !endpoint.is_model_response() || !status.is_success() {
        return builder
            .body(passthrough_response_body(upstream))
            .map_err(|error| format!("could not build Gemini response: {error}"));
    }
    let Some(body) = read_response_capped(upstream).await? else {
        return Ok(text_response(
            StatusCode::BAD_GATEWAY,
            "Upstream response body too large",
        ));
    };
    let rewrite = rewrite_response_body(&body, &state.plugins, state.block_unknown_formats);
    let rewritten = apply_response_compatibility(body, state.block_unknown_formats, rewrite)?;
    builder
        .body(full_body(rewritten))
        .map_err(|error| format!("could not build Gemini response: {error}"))
}

fn apply_response_compatibility(
    original: Bytes,
    block_unknown_formats: bool,
    rewrite: Result<Bytes, String>,
) -> Result<Bytes, String> {
    match rewrite {
        Ok(rewritten) => Ok(rewritten),
        Err(error) if !block_unknown_formats && error.starts_with("unknown format blocked:") => {
            diagnostic("response-protection-skipped");
            Ok(original)
        }
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GeminiEndpoint {
    GenerateContent,
    StreamGenerateContent,
    CountTokens,
    EmbedContent,
    BatchEmbedContents,
    Models,
    Unknown,
}

impl GeminiEndpoint {
    fn diagnostic_name(self) -> &'static str {
        match self {
            Self::GenerateContent => "generate-content",
            Self::StreamGenerateContent => "stream-generate-content",
            Self::CountTokens => "count-tokens",
            Self::EmbedContent => "embed-content",
            Self::BatchEmbedContents => "batch-embed-contents",
            Self::Models => "models",
            Self::Unknown => "unknown",
        }
    }

    fn is_protected(self) -> bool {
        matches!(
            self,
            Self::GenerateContent
                | Self::StreamGenerateContent
                | Self::CountTokens
                | Self::EmbedContent
                | Self::BatchEmbedContents
        )
    }
    fn is_model_response(self) -> bool {
        matches!(self, Self::GenerateContent | Self::StreamGenerateContent)
    }
}

fn classify_endpoint(path_and_query: &str) -> GeminiEndpoint {
    let path = path_and_query.split('?').next().unwrap_or(path_and_query);
    let tuned_model_endpoint = path
        .strip_prefix("/v1beta/tunedModels/")
        .and_then(|route| route.split_once(':'))
        .and_then(|(resource, action)| {
            if resource.is_empty() || resource.contains('/') || action.contains(':') {
                return None;
            }
            match action {
                "streamGenerateContent" => Some(GeminiEndpoint::StreamGenerateContent),
                "generateContent" => Some(GeminiEndpoint::GenerateContent),
                _ => None,
            }
        });
    if let Some(endpoint) = tuned_model_endpoint {
        return endpoint;
    }
    let native_model_route = path.starts_with("/v1beta/models/") || path.starts_with("/v1/models/");
    if native_model_route && path.ends_with(":streamGenerateContent") {
        GeminiEndpoint::StreamGenerateContent
    } else if native_model_route && path.ends_with(":generateContent") {
        GeminiEndpoint::GenerateContent
    } else if native_model_route && path.ends_with(":countTokens") {
        GeminiEndpoint::CountTokens
    } else if native_model_route && path.ends_with(":embedContent") {
        GeminiEndpoint::EmbedContent
    } else if native_model_route && path.ends_with(":batchEmbedContents") {
        GeminiEndpoint::BatchEmbedContents
    } else if path.ends_with("/models") || path.contains("/models/") {
        GeminiEndpoint::Models
    } else {
        GeminiEndpoint::Unknown
    }
}

fn diagnostic_endpoint_name(request_path: &str, auth: &str) -> &'static str {
    authenticated_request_path(request_path, auth)
        .map(classify_endpoint)
        .unwrap_or(GeminiEndpoint::Unknown)
        .diagnostic_name()
}

struct ProtectedRequest {
    body: Bytes,
    local_response: Option<Bytes>,
}

fn protect_request_body(
    body: &Bytes,
    endpoint: GeminiEndpoint,
    masker: &Mutex<pentect_agent::ActiveToolOutputMasker>,
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    block_unknown_formats: bool,
) -> Result<ProtectedRequest, String> {
    let mut value: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) if block_unknown_formats => {
            return Err(format!(
                "unknown format blocked: Gemini request is not valid JSON ({error})"
            ));
        }
        Err(_) => {
            diagnostic("request-invalid-json");
            return Ok(ProtectedRequest {
                body: body.clone(),
                local_response: None,
            });
        }
    };
    let run = plugins
        .lock()
        .map_err(|_| "Gemini plugin lock was poisoned".to_string())?
        .run(
            pentect_agent::MiddlewareStage::Request,
            value,
            Some(serde_json::json!({"provider": "gemini", "transport": "http"})),
        )?;
    if run.stopped == Some(pentect_agent::StopOutcome::Block) {
        return Err(format!(
            "plugin blocked: {}",
            run.message.unwrap_or_else(|| "request blocked".to_string())
        ));
    }
    if run.stopped.is_some() {
        return serde_json::to_vec(&run.payload)
            .map(Bytes::from)
            .map(|local_response| ProtectedRequest {
                body: Bytes::new(),
                local_response: Some(local_response),
            })
            .map_err(|error| format!("could not encode plugin response: {error}"));
    }
    if block_unknown_formats && run.coverage == pentect_agent::MiddlewareCoverage::Partial {
        return Err(
            "unknown format blocked: a plugin reported partial Gemini request coverage".to_string(),
        );
    }
    value = run.payload;
    let inline_file_partial = {
        let plugins = plugins
            .lock()
            .map_err(|_| "Gemini plugin lock was poisoned".to_string())?;
        crate::http_files::run_google_inline_file_stages(&value, &plugins, "gemini", "http_json")
    }?;
    if block_unknown_formats && inline_file_partial {
        return Err(
            "unknown format blocked: a file plugin reported partial Gemini inline-file coverage"
                .to_string(),
        );
    }
    let mut masker = masker
        .lock()
        .map_err(|_| "Gemini masker lock was poisoned".to_string())?;
    if let Err(error) =
        mask_gemini_request(&mut value, endpoint, &mut masker, block_unknown_formats)
    {
        if !block_unknown_formats && error.starts_with("unknown format blocked:") {
            diagnostic("request-protection-skipped");
            return Ok(ProtectedRequest {
                body: body.clone(),
                local_response: None,
            });
        }
        return Err(error);
    }
    if endpoint.is_model_response() {
        inject_handle_contract(&mut value)?;
    }
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map(|body| ProtectedRequest {
            body,
            local_response: None,
        })
        .map_err(|error| format!("could not encode protected Gemini request: {error}"))
}

fn mask_gemini_request(
    value: &mut Value,
    endpoint: GeminiEndpoint,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    block_unknown_formats: bool,
) -> Result<(), String> {
    match endpoint {
        GeminiEndpoint::EmbedContent => {
            return mask_embed_content_request(value, masker, block_unknown_formats);
        }
        GeminiEndpoint::BatchEmbedContents => {
            return mask_batch_embed_contents_request(value, masker, block_unknown_formats);
        }
        _ => {}
    }
    let object = value
        .as_object_mut()
        .ok_or_else(|| "unknown format blocked: Gemini request must be an object".to_string())?;
    if let Some(tools) = object.get_mut("tools") {
        crate::model_definition::mask_model_definition(tools, "Gemini", masker)?;
    }
    let contents = object
        .get_mut("contents")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "unknown format blocked: Gemini contents must be an array".to_string())?;
    for content in contents {
        let external_content = content.get("role").and_then(Value::as_str) != Some("user");
        crate::cloud_code_http_proxy::mask_content(
            content,
            external_content,
            masker,
            block_unknown_formats,
        )?;
    }
    if let Some(system) = object.get_mut("systemInstruction") {
        crate::cloud_code_http_proxy::mask_content(system, true, masker, block_unknown_formats)?;
    }
    Ok(())
}

fn mask_embed_content_request(
    value: &mut Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    block_unknown_formats: bool,
) -> Result<(), String> {
    let object = value.as_object_mut().ok_or_else(|| {
        "unknown format blocked: Gemini embedContent request must be an object".to_string()
    })?;
    let content = object.get_mut("content").ok_or_else(|| {
        "unknown format blocked: Gemini embedContent content is required".to_string()
    })?;
    crate::cloud_code_http_proxy::mask_content(content, false, masker, block_unknown_formats)?;
    mask_embedding_title(object.get_mut("title"), masker)?;
    if let Some(config) = object.get_mut("embedContentConfig") {
        let config = config.as_object_mut().ok_or_else(|| {
            "unknown format blocked: Gemini embedContentConfig must be an object".to_string()
        })?;
        mask_embedding_title(config.get_mut("title"), masker)?;
    }
    Ok(())
}

fn mask_batch_embed_contents_request(
    value: &mut Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    block_unknown_formats: bool,
) -> Result<(), String> {
    let requests = value
        .as_object_mut()
        .and_then(|object| object.get_mut("requests"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            "unknown format blocked: Gemini batchEmbedContents requests must be an array"
                .to_string()
        })?;
    for request in requests {
        mask_embed_content_request(request, masker, block_unknown_formats)?;
    }
    Ok(())
}

fn mask_embedding_title(
    title: Option<&mut Value>,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    let Some(title) = title else {
        return Ok(());
    };
    let Value::String(title) = title else {
        return Err("unknown format blocked: Gemini embedding title must be a string".to_string());
    };
    crate::claude_http_proxy::mask_string(title, false, masker)?;
    Ok(())
}

fn inject_handle_contract(value: &mut Value) -> Result<(), String> {
    if !crate::claude_http_proxy::request_contains_masked_handle(value) {
        return Ok(());
    }
    let object = value
        .as_object_mut()
        .ok_or_else(|| "Gemini request must be an object".to_string())?;
    let system = object
        .entry("systemInstruction")
        .or_insert_with(|| serde_json::json!({"role": "system", "parts": []}));
    let system = system.as_object_mut().ok_or_else(|| {
        "unknown format blocked: Gemini systemInstruction must be an object".to_string()
    })?;
    let parts = system
        .entry("parts")
        .or_insert_with(|| Value::Array(Vec::new()));
    let parts = parts.as_array_mut().ok_or_else(|| {
        "unknown format blocked: Gemini systemInstruction.parts must be an array".to_string()
    })?;
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
) -> Result<Bytes, String> {
    let mut value: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) if block_unknown_formats => {
            return Err(format!(
                "unknown format blocked: Gemini response is not valid JSON ({error})"
            ));
        }
        Err(_) => return Ok(Bytes::copy_from_slice(body)),
    };
    let plugins = plugins
        .lock()
        .map_err(|_| "Gemini plugin lock was poisoned".to_string())?;
    let run = plugins.run(
        pentect_agent::MiddlewareStage::Response,
        value,
        Some(serde_json::json!({"provider": "gemini", "transport": "http"})),
    )?;
    crate::plugins::enforce_response_plugin_coverage(
        run.coverage,
        block_unknown_formats,
        "Gemini",
    )?;
    if run.stopped == Some(pentect_agent::StopOutcome::Block) {
        return Err(format!(
            "plugin blocked: {}",
            run.message
                .unwrap_or_else(|| "response blocked".to_string())
        ));
    }
    value = run.payload;
    validate_response(&value, block_unknown_formats)?;
    run_tool_plugins(&mut value, &plugins)?;
    let mut resolve = crate::claude_http_proxy::request_scoped_resolver();
    crate::cloud_code_http_proxy::resolve_function_calls(&mut value, &mut resolve)?;
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|error| format!("could not encode restored Gemini response: {error}"))
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
                    Some(serde_json::json!({"provider": "gemini", "transport": "http"})),
                )?;
                crate::plugins::enforce_tool_plugin_coverage(run.coverage, "Gemini")?;
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

fn validate_response(value: &Value, block_unknown_formats: bool) -> Result<(), String> {
    if !block_unknown_formats {
        return Ok(());
    }
    let response = value
        .as_object()
        .ok_or_else(|| "unknown format blocked: Gemini response must be an object".to_string())?;
    let Some(candidates) = response.get("candidates") else {
        const CANDIDATELESS_FIELDS: &[&str] = &[
            "promptFeedback",
            "usageMetadata",
            "modelVersion",
            "responseId",
            "modelStatus",
        ];
        if response.is_empty()
            || response
                .keys()
                .any(|key| !CANDIDATELESS_FIELDS.contains(&key.as_str()))
        {
            return Err(
                "unknown format blocked: Gemini response without candidates contains unsupported fields"
                    .to_string(),
            );
        }
        return Ok(());
    };
    let candidates = candidates.as_array().ok_or_else(|| {
        "unknown format blocked: Gemini response candidates must be an array".to_string()
    })?;
    for candidate in candidates {
        let Some(content) = candidate.get("content") else {
            continue;
        };
        let parts = content
            .get("parts")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                "unknown format blocked: Gemini response content.parts must be an array".to_string()
            })?;
        for part in parts {
            let object = part.as_object().ok_or_else(|| {
                "unknown format blocked: Gemini response part must be an object".to_string()
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
            if !DATA_FIELDS.iter().any(|key| object.contains_key(*key)) {
                return Err(
                    "unknown format blocked: Gemini response part is unsupported".to_string(),
                );
            }
            if let Some(key) = object.keys().find(|key| {
                !DATA_FIELDS.contains(&key.as_str()) && !METADATA_FIELDS.contains(&key.as_str())
            }) {
                return Err(format!(
                    "unknown format blocked: Gemini response part field '{key}' is unsupported"
                ));
            }
        }
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
                            "Gemini SSE event exceeded limit",
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
                        error,
                    ))));
                }
                None => {
                    state.finished = true;
                    match rewrite_pending_sse(
                        &mut state.pending,
                        &state.plugins,
                        state.block_unknown_formats,
                    ) {
                        Ok(Some(block)) => state.ready.push_back(Ok(Frame::data(block))),
                        Ok(None) => {}
                        Err(error) => state.ready.push_back(Err(Box::new(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            error,
                        )))),
                    }
                }
            }
        }
    });
    StreamBody::new(stream).boxed_unsync()
}

fn rewrite_pending_sse(
    pending: &mut Vec<u8>,
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    block_unknown_formats: bool,
) -> Result<Option<Bytes>, String> {
    if pending.is_empty() {
        return Ok(None);
    }
    let pending = std::mem::take(pending);
    rewrite_sse_block(&pending, plugins, block_unknown_formats).map(Some)
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
                "unknown format blocked: Gemini stream event is not UTF-8 ({error})"
            ));
        }
        Err(_) => return Ok(Bytes::copy_from_slice(block)),
    };
    let data = text
        .lines()
        .filter_map(|line| line.strip_prefix("data:").map(str::trim_start))
        .collect::<Vec<_>>();
    if data.is_empty() || data == ["[DONE]"] {
        return Ok(Bytes::copy_from_slice(block));
    }
    let joined = data.join("\n");
    let rewritten = rewrite_response_body(joined.as_bytes(), plugins, block_unknown_formats)?;
    let ending = if text.ends_with("\r\n\r\n") {
        "\r\n\r\n"
    } else {
        "\n\n"
    };
    let line_ending = if ending == "\r\n\r\n" { "\r\n" } else { "\n" };
    let mut out = Vec::with_capacity(block.len() + 32);
    for line in text
        .lines()
        .filter(|line| !line.starts_with("data:") && !line.is_empty())
    {
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(line_ending.as_bytes());
    }
    out.extend_from_slice(b"data: ");
    out.extend_from_slice(&rewritten);
    out.extend_from_slice(ending.as_bytes());
    Ok(Bytes::from(out))
}

fn passthrough_response_body(response: reqwest::Response) -> ProxyBody {
    let stream = response.bytes_stream().map(|chunk| {
        chunk
            .map(Frame::data)
            .map_err(|error| Box::new(error) as ProxyBodyError)
    });
    StreamBody::new(stream).boxed_unsync()
}

async fn read_response_capped(response: reqwest::Response) -> Result<Option<Bytes>, String> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|error| reqwest_error_message("could not read Gemini response", &error))?;
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
        .map(|index| index + 2);
    let crlf = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4);
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
            | "connection"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "keep-alive"
            | "accept-encoding"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
    )
}

fn should_forward_response_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "content-length"
            | "connection"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
            | "content-encoding"
            | "x-pentect-coverage"
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
        format!("{context}: request timed out")
    } else if error.is_connect() {
        format!("{context}: connection failed")
    } else {
        format!("{context}: upstream request failed")
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
        .expect("static response")
}

fn owned_text_response(status: StatusCode, text: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::copy_from_slice(text.as_bytes())))
        .expect("owned response")
}

fn random_auth_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        format!("OS CSPRNG unavailable for Gemini gateway authentication: {error}")
    })?;
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
            let home = std::env::temp_dir()
                .join(format!("pentect-gemini-e2e-{}-{nonce}", std::process::id()));
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

    fn mock_upstream() -> (
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
            let header_end = loop {
                let read = socket.read(&mut buffer).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
                if let Some(at) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break at + 4;
                }
            };
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
            let handle = first_handle(&body).expect("provider request contains a handle");
            body_tx.send(body).unwrap();
            let response = serde_json::json!({
                "candidates": [{"content": {"role": "model", "parts": [
                    {"text": handle},
                    {"functionCall": {"name": "shell", "args": {"token": handle}}}
                ]}}]
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

    fn mock_raw_response(response: String) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let read = socket.read(&mut buffer).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
                if let Some(at) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break at + 4;
                }
            };
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
            socket.write_all(response.as_bytes()).unwrap();
            socket.flush().unwrap();
        });
        (format!("http://{address}"), thread)
    }

    #[test]
    fn recognizes_supported_gemini_model_routes() {
        assert_eq!(
            classify_endpoint("/v1beta/models/gemini-2.5-pro:generateContent"),
            GeminiEndpoint::GenerateContent
        );
        assert_eq!(
            classify_endpoint("/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse"),
            GeminiEndpoint::StreamGenerateContent
        );
        assert_eq!(
            classify_endpoint("/v1beta/models/gemini-2.5-pro:countTokens"),
            GeminiEndpoint::CountTokens
        );
        assert_eq!(
            classify_endpoint("/v1beta/models/gemini-embedding-001:embedContent"),
            GeminiEndpoint::EmbedContent
        );
        assert_eq!(
            classify_endpoint("/v1beta/models/gemini-embedding-001:batchEmbedContents"),
            GeminiEndpoint::BatchEmbedContents
        );
        assert_eq!(
            classify_endpoint("/v1beta/tunedModels/customer-service:generateContent"),
            GeminiEndpoint::GenerateContent
        );
        assert_eq!(
            classify_endpoint("/v1beta/tunedModels/customer-service:streamGenerateContent?alt=sse"),
            GeminiEndpoint::StreamGenerateContent
        );
        assert_eq!(
            classify_endpoint("/v1beta/tunedModels/customer-service:countTokens"),
            GeminiEndpoint::Unknown
        );
        assert_eq!(
            classify_endpoint("/v1/tunedModels/customer-service:generateContent"),
            GeminiEndpoint::Unknown
        );
        assert_eq!(
            classify_endpoint(
                "/v1beta/tunedModels/customer-service/permissions/viewer:generateContent"
            ),
            GeminiEndpoint::Unknown
        );
        assert_eq!(
            classify_endpoint("/v1beta/tunedModels/:generateContent"),
            GeminiEndpoint::Unknown
        );
        assert_eq!(
            classify_endpoint("/v1beta/tunedModels/customer-service:other:generateContent"),
            GeminiEndpoint::Unknown
        );
        assert_eq!(
            classify_endpoint("/v1beta/cachedContents/cache:generateContent"),
            GeminiEndpoint::Unknown
        );
        assert_eq!(
            classify_endpoint("/v1internal:generateContent"),
            GeminiEndpoint::Unknown
        );
        assert_eq!(
            diagnostic_endpoint_name(
                "/token/v1beta/models/gemini-2.5-pro:generateContent",
                "token"
            ),
            "generate-content"
        );
        assert_eq!(
            diagnostic_endpoint_name(
                "/tokenx/v1beta/models/gemini-2.5-pro:generateContent",
                "token"
            ),
            "unknown"
        );
    }

    #[test]
    fn models_request_body_is_rejected_before_gemini_upstream() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let proxy =
            GeminiHttpProxyGuard::start_with_header_env("http://127.0.0.1:9".to_string(), &[])
                .unwrap();
        let client = reqwest::blocking::Client::new();

        for path in [
            "/v1beta/models",
            "/v1/models?pageSize=10",
            "/v1beta/models/gemini-test?view=full",
            "/v1/models/gemini-test",
        ] {
            let response = client
                .post(format!("{}{path}", proxy.base_url()))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(r#"{"note":"plaintext-must-not-leave"}"#)
                .send()
                .unwrap();
            assert_eq!(
                response.status(),
                reqwest::StatusCode::UNPROCESSABLE_ENTITY,
                "{path}"
            );
            assert!(
                response
                    .text()
                    .unwrap()
                    .contains("Gemini models endpoints do not accept request bodies"),
                "{path}"
            );
        }

        let empty = client
            .get(format!("{}/v1beta/models", proxy.base_url()))
            .send()
            .unwrap();
        assert_eq!(empty.status(), reqwest::StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn remote_file_data_uses_the_bounded_google_resolver() {
        let body = Bytes::from_static(
            br#"{"contents":[{"role":"user","parts":[{"fileData":{"mimeType":"text/plain","fileUri":"https://127.0.0.1/private"}}]}]}"#,
        );
        let mut budget = crate::remote_content::RemoteRequestBudget::default();
        let error = crate::cloud_code_http_proxy::resolve_google_remote_files(body, &mut budget)
            .await
            .unwrap_err();
        assert!(error.contains("non-public address"), "{error}");
    }

    #[test]
    fn response_restores_only_function_call_args() {
        let handle = "<<STRIPE_SECRET_KEY_a81f42c7d93>>";
        let mut value = serde_json::json!({
            "candidates": [{"content": {"parts": [
                {"text": handle},
                {"functionCall": {"name": "shell", "args": {"key": handle}}}
            ]}}]
        });
        let mut resolve = |text: &str| Ok(text.replace(handle, "sk_test_synthetic"));
        crate::cloud_code_http_proxy::resolve_function_calls(&mut value, &mut resolve).unwrap();
        assert_eq!(
            value["candidates"][0]["content"]["parts"][0]["text"],
            handle
        );
        assert_eq!(
            value["candidates"][0]["content"]["parts"][1]["functionCall"]["args"]["key"],
            "sk_test_synthetic"
        );
    }

    #[test]
    fn response_keeps_handles_when_the_memory_store_becomes_unavailable() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        drop(store);

        let handle = "<<STRIPE_SECRET_KEY_a81f42c7d93>>";
        let body = serde_json::to_vec(&serde_json::json!({
            "candidates": [{"content": {"parts": [
                {"functionCall": {"name": "shell", "args": {"key": handle}}}
            ]}}]
        }))
        .unwrap();
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let rewritten = rewrite_response_body(&body, &plugins, true).unwrap();
        let rewritten: Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(
            rewritten["candidates"][0]["content"]["parts"][0]["functionCall"]["args"]["key"],
            handle
        );
    }

    #[test]
    fn response_compatibility_only_passes_through_unknown_formats() {
        let original = Bytes::from_static(b"opaque upstream response");
        assert_eq!(
            apply_response_compatibility(
                original.clone(),
                false,
                Err("unknown format blocked: future Gemini envelope".to_string()),
            )
            .unwrap(),
            original
        );
        assert!(apply_response_compatibility(
            original.clone(),
            true,
            Err("unknown format blocked: future Gemini envelope".to_string()),
        )
        .is_err());
        assert!(apply_response_compatibility(
            original,
            false,
            Err("plugin blocked: policy denied the response".to_string()),
        )
        .is_err());
    }

    #[test]
    fn stream_endpoint_recovers_missing_content_type_and_reports_coverage() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let body = "data: {\"candidates\":[]}\n\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nX-Pentect-Coverage: none\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (upstream, thread) = mock_raw_response(response);
        let proxy = GeminiHttpProxyGuard::start_with_header_env(upstream, &[]).unwrap();

        let response = reqwest::blocking::Client::new()
            .post(format!(
                "{}/v1beta/models/gemini-test:streamGenerateContent?alt=sse",
                proxy.base_url()
            ))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(r#"{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}"#)
            .send()
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.headers()["x-pentect-coverage"], "full");
        assert_eq!(
            response
                .headers()
                .get_all("x-pentect-coverage")
                .iter()
                .count(),
            1
        );
        assert!(!response
            .headers()
            .contains_key(reqwest::header::CONTENT_ENCODING));
        assert_eq!(response.text().unwrap(), body);
        thread.join().unwrap();
    }

    #[test]
    fn gateway_replaces_the_child_google_key_before_upstream() {
        use std::io::{Read, Write};

        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let _google_keys = crate::EnvVarGuard::set_optional([
            ("GOOGLE_API_KEY", None),
            (
                "GOOGLE_GENERATIVE_AI_API_KEY",
                Some(std::ffi::OsString::from("generative-only-key")),
            ),
            ("GEMINI_API_KEY", None),
        ]);
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (headers_tx, headers_rx) = std::sync::mpsc::channel();
        let upstream = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let header_end = loop {
                let read = socket.read(&mut buffer).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
                if let Some(at) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break at + 4;
                }
            };
            headers_tx
                .send(String::from_utf8(request[..header_end].to_vec()).unwrap())
                .unwrap();
            let response = r#"{"candidates":[]}"#;
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
            socket.flush().unwrap();
        });

        let proxy = GeminiHttpProxyGuard::start_with_header_env_and_api_key(
            format!("http://{address}"),
            &[],
            crate::configured_google_api_key(),
        )
        .unwrap();
        reqwest::blocking::Client::new()
            .post(format!(
                "{}/v1beta/models/gemini-test:generateContent",
                proxy.base_url()
            ))
            .header("x-goog-api-key", "pentect-local")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(r#"{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}"#)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();

        let headers = headers_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        upstream.join().unwrap();
        assert!(
            headers
                .lines()
                .any(|line| line.eq_ignore_ascii_case("x-goog-api-key: generative-only-key")),
            "upstream did not receive the gateway-owned key"
        );
        assert!(!headers.contains("pentect-local"));
    }

    #[test]
    fn rejects_unknown_response_parts_by_default() {
        let value =
            serde_json::json!({"candidates": [{"content": {"parts": [{"futurePart": {}}]}}]});
        assert!(validate_response(&value, true)
            .unwrap_err()
            .starts_with("unknown format blocked:"));
        let mixed = serde_json::json!({"candidates": [{"content": {"parts": [{
            "text": "safe",
            "futurePart": {}
        }]}}]});
        assert!(validate_response(&mixed, true).is_err());
        assert!(validate_response(&value, false).is_ok());
    }

    #[test]
    fn strict_response_validation_accepts_known_candidate_free_metadata() {
        let blocked = serde_json::json!({
            "promptFeedback": {"blockReason": "SAFETY"},
            "usageMetadata": {"promptTokenCount": 4},
            "modelVersion": "gemini-test",
            "responseId": "response-test"
        });
        assert!(validate_response(&blocked, true).is_ok());
        assert!(validate_response(
            &serde_json::json!({"usageMetadata": {"totalTokenCount": 4}}),
            true
        )
        .is_ok());
        assert!(validate_response(&serde_json::json!({}), true).is_err());
        assert!(validate_response(
            &serde_json::json!({"futureResponseData": {"text": "unchecked"}}),
            true
        )
        .is_err());
        assert!(validate_response(&serde_json::json!({"candidates": {}}), true).is_err());
    }

    #[test]
    fn only_user_content_can_unmask_and_clean_requests_get_no_contract() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let secret = ["rpa_", "USERONLY", "ZYXWVUTS", "RQPONMLK", "1234567890"].concat();
        let keyed = format!("RUNPOD_API_KEY={secret}");
        let mut value = serde_json::json!({
            "systemInstruction": {"parts": [{"text": format!("unmask({keyed})")}]},
            "contents": [
                {"role": "model", "parts": [{"text": format!("unmask({keyed})")}]},
                {"role": "user", "parts": [{"text": format!("unmask({keyed})")}]}
            ]
        });
        let mut masker = pentect_agent::ActiveToolOutputMasker::new().unwrap();
        mask_gemini_request(
            &mut value,
            GeminiEndpoint::GenerateContent,
            &mut masker,
            true,
        )
        .unwrap();
        assert!(!value["systemInstruction"]["parts"][0]["text"]
            .as_str()
            .unwrap()
            .contains(&secret));
        assert!(!value["contents"][0]["parts"][0]["text"]
            .as_str()
            .unwrap()
            .contains(&secret));
        assert_eq!(value["contents"][1]["parts"][0]["text"], keyed);

        let mut clean = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
        });
        inject_handle_contract(&mut clean).unwrap();
        assert!(clean.get("systemInstruction").is_none());
    }

    #[test]
    fn embedding_requests_mask_direct_and_batched_content() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let secret = ["rpa_", "EMBED", "ZYXWVUTS", "RQPONMLK", "1234567890"].concat();
        let mut direct = serde_json::json!({
            "content": {"parts": [{"text": format!("RUNPOD_API_KEY={secret}")}]},
            "title": format!("RUNPOD_API_KEY={secret}"),
            "embedContentConfig": {"title": format!("RUNPOD_API_KEY={secret}")}
        });
        let mut masker = pentect_agent::ActiveToolOutputMasker::new().unwrap();
        mask_gemini_request(&mut direct, GeminiEndpoint::EmbedContent, &mut masker, true).unwrap();
        assert!(!direct.to_string().contains(&secret));
        assert!(direct.to_string().contains("<<RUNPOD_API_KEY_"));

        let mut batch = serde_json::json!({
            "requests": [
                {
                    "model": "models/gemini-embedding-001",
                    "content": {"parts": [{"text": format!("RUNPOD_API_KEY={secret}")}]}
                },
                {
                    "model": "models/gemini-embedding-001",
                    "content": {"parts": [{"text": format!("second RUNPOD_API_KEY={secret}")}]}
                }
            ]
        });
        mask_gemini_request(
            &mut batch,
            GeminiEndpoint::BatchEmbedContents,
            &mut masker,
            true,
        )
        .unwrap();
        assert!(!batch.to_string().contains(&secret));
        assert_eq!(batch["requests"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn embedding_gateway_never_forwards_plaintext_to_upstream() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let secret = ["rpa_", "GATEWAY", "ZYXWVUTS", "RQPONMLK", "1234567890"].concat();
        let (upstream, body_rx, thread) = mock_upstream();
        let proxy = GeminiHttpProxyGuard::start_with_header_env(upstream, &[]).unwrap();
        reqwest::blocking::Client::new()
            .post(format!(
                "{}/v1beta/models/gemini-embedding-001:embedContent",
                proxy.base_url()
            ))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "content": {"parts": [{
                        "text": format!("private RUNPOD_API_KEY={secret}")
                    }]}
                })
                .to_string(),
            )
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();

        let upstream_body = body_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        thread.join().unwrap();
        assert!(!upstream_body.contains(&secret));
        assert!(
            first_handle(&upstream_body).is_some(),
            "upstream body did not contain a protected handle: {upstream_body}"
        );
    }

    #[test]
    fn generate_content_gateway_masks_tool_definitions_before_upstream() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let secret = ["rpa_", "TOOLS", "ZYXWVUTS", "RQPONMLK", "1234567890"].concat();
        let (upstream, body_rx, thread) = mock_upstream();
        let proxy = GeminiHttpProxyGuard::start_with_header_env(upstream, &[]).unwrap();
        reqwest::blocking::Client::new()
            .post(format!(
                "{}/v1beta/models/gemini-test:generateContent",
                proxy.base_url()
            ))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "contents": [{"role": "user", "parts": [{"text": "use lookup"}]}],
                    "tools": [{"functionDeclarations": [{
                        "name": "lookup",
                        "description": format!("Use RUNPOD_API_KEY={secret}"),
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "token": {
                                    "type": "string",
                                    "default": format!("unmask(RUNPOD_API_KEY={secret})")
                                }
                            }
                        }
                    }]}]
                })
                .to_string(),
            )
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();

        let upstream_body = body_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        thread.join().unwrap();
        assert!(!upstream_body.contains(&secret));
        let protected: Value = serde_json::from_str(&upstream_body).unwrap();
        assert!(first_handle(
            protected["tools"][0]["functionDeclarations"][0]["description"]
                .as_str()
                .unwrap()
        )
        .is_some());
        assert!(first_handle(
            protected["tools"][0]["functionDeclarations"][0]["parameters"]["properties"]["token"]
                ["default"]
                .as_str()
                .unwrap()
        )
        .is_some());
    }

    #[test]
    fn malformed_embedding_requests_fail_closed() {
        let mut masker = pentect_agent::ActiveToolOutputMasker::new().unwrap();
        assert!(mask_gemini_request(
            &mut serde_json::json!({"content": "unchecked"}),
            GeminiEndpoint::EmbedContent,
            &mut masker,
            true,
        )
        .is_err());
        assert!(mask_gemini_request(
            &mut serde_json::json!({"requests": {}}),
            GeminiEndpoint::BatchEmbedContents,
            &mut masker,
            true,
        )
        .is_err());
    }

    #[test]
    fn model_and_tuned_model_boundaries_mask_prompt_and_restore_only_tool_args() {
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
        for path in [
            "/v1beta/models/gemini-test:generateContent",
            "/v1beta/tunedModels/customer-service:generateContent",
        ] {
            let (upstream, captured, thread) = mock_upstream();
            let proxy = GeminiHttpProxyGuard::start_with_header_env(upstream, &[]).unwrap();
            let response = reqwest::blocking::Client::new()
                .post(format!("{}{path}", proxy.base_url()))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(
                    serde_json::to_vec(&serde_json::json!({
                        "contents": [{"role": "user", "parts": [{
                            "text": format!("Use RUNPOD_API_KEY={secret}")
                        }]}]
                    }))
                    .unwrap(),
                )
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
            assert!(!request.contains(&secret), "plaintext reached {path}");
            let handle = first_handle(&request).unwrap();
            let protected_request: Value = serde_json::from_str(&request).unwrap();
            assert_eq!(
                protected_request["systemInstruction"]["parts"][0]["text"],
                HANDLE_CONTRACT
            );
            assert_eq!(
                response["candidates"][0]["content"]["parts"][0]["text"],
                handle
            );
            assert_eq!(
                response["candidates"][0]["content"]["parts"][1]["functionCall"]["args"]["token"],
                secret
            );
        }
    }

    #[test]
    fn compressed_upstream_responses_are_not_requested() {
        assert!(!should_forward_request_header("Accept-Encoding"));
        assert!(!should_forward_request_header("Proxy-Authorization"));
        assert!(!should_forward_response_header("Proxy-Authenticate"));
        assert!(!should_forward_response_header("Content-Encoding"));
        assert!(!should_forward_response_header("X-Pentect-Coverage"));
        assert!(should_forward_request_header("Accept"));
    }

    #[test]
    fn rewritten_crlf_sse_keeps_crlf_metadata_lines() {
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::from_env().unwrap());
        let rewritten = rewrite_sse_block(
            b"event: message\r\ndata: {\"candidates\":[]}\r\n\r\n",
            &plugins,
            true,
        )
        .unwrap();
        let rewritten = std::str::from_utf8(&rewritten).unwrap();
        assert!(
            rewritten.starts_with("event: message\r\ndata: "),
            "{rewritten:?}"
        );
        assert!(rewritten.ends_with("\r\n\r\n"), "{rewritten:?}");
    }

    #[test]
    fn unterminated_final_sse_event_is_processed_at_eof() {
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let mut pending = br#"data: {"candidates":[]}"#.to_vec();
        let rewritten = rewrite_pending_sse(&mut pending, &plugins, true)
            .unwrap()
            .unwrap();
        assert!(pending.is_empty());
        assert!(rewritten.ends_with(b"\n\n"));

        let mut malformed = b"data: {broken".to_vec();
        let error = rewrite_pending_sse(&mut malformed, &plugins, true).unwrap_err();
        assert!(malformed.is_empty());
        assert!(error.starts_with("unknown format blocked:"), "{error}");
    }
}
