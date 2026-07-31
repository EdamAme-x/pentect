//! OpenAI Responses API gateway used by unmodified Codex hosts.
//!
//! Model-bound prompts and local function outputs are masked on requests.
//! Completed client function-call arguments are resolved on responses. Local
//! UI and provider-generated text remain unchanged.

use futures_util::{stream, Stream, StreamExt};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Semaphore};
use zeroize::Zeroize;

const MAX_HTTP_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_PENDING_SSE_BYTES: usize = 8 * 1024 * 1024;
const HANDLE_CONTRACT: &str = "Values formatted as <<LABEL_HASH>> are opaque local secret handles. Copy a handle byte-for-byte into a client function call when that function needs the represented value. Do not alter, expand, guess, or expose it. Pentect resolves handles only in completed client function-call arguments.";

type ProxyBodyError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, ProxyBodyError>;
type UpstreamByteStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static>>;

pub(crate) struct OpenAiHttpProxyGuard {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl OpenAiHttpProxyGuard {
    pub(crate) fn start(upstream: String) -> Result<Self, String> {
        let upstream = parse_upstream_base(&upstream)?;
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
                        "could not start OpenAI HTTP gateway runtime: {error}"
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                if let Err(error) = run_proxy(upstream, thread_auth, ready_tx, shutdown_rx).await {
                    eprintln!("[pentect] OpenAI HTTP gateway stopped: {error}");
                }
            });
        });
        let base_url = ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| "OpenAI HTTP gateway did not start within 5 seconds".to_string())??;
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

impl Drop for OpenAiHttpProxyGuard {
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
    masker: Arc<Mutex<pentect_agent::ActiveToolOutputMasker>>,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
    files: Mutex<HashMap<String, crate::http_files::Coverage>>,
    requests: Arc<Semaphore>,
    block_unknown_formats: bool,
}

impl Drop for ProxyState {
    fn drop(&mut self) {
        self.auth.zeroize();
    }
}

async fn run_proxy(
    upstream: reqwest::Url,
    auth: String,
    ready_tx: mpsc::Sender<Result<String, String>>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|error| format!("could not bind OpenAI HTTP gateway: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("could not read OpenAI HTTP gateway address: {error}"))?;
    let local_base_url = format!("http://{address}/{auth}");
    let plugins = pentect_agent::PluginMiddleware::from_env()?;
    let state = Arc::new(ProxyState {
        upstream,
        auth,
        client: build_upstream_client()?,
        masker: Arc::new(Mutex::new(
            pentect_agent::ActiveToolOutputMasker::new_with_plugins(plugins.clone())?,
        )),
        plugins: Arc::new(Mutex::new(plugins)),
        files: Mutex::new(HashMap::new()),
        requests: Arc::new(Semaphore::new(32)),
        block_unknown_formats: pentect_agent::unknown_formats_should_block()?,
    });
    let _ = ready_tx.send(Ok(local_base_url));

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            accepted = listener.accept() => {
                let (socket, _) = accepted
                    .map_err(|error| format!("OpenAI HTTP gateway accept failed: {error}"))?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(socket);
                    let service = service_fn(move |request| {
                        proxy_request(request, Arc::clone(&state))
                    });
                    if let Err(error) = http1::Builder::new()
                        .max_buf_size(64 * 1024)
                        .max_headers(128)
                        .serve_connection(io, service)
                        .await
                    {
                        if !error.is_incomplete_message() {
                            eprintln!("[pentect] OpenAI HTTP gateway connection failed: {error}");
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

fn build_upstream_client() -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(60))
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .tcp_nodelay(true);
    if let Some(path) = std::env::var_os("PENTECT_OPENAI_CA_CERT") {
        let pem = std::fs::read(&path)
            .map_err(|_| "could not read PENTECT_OPENAI_CA_CERT".to_string())?;
        let certificate = reqwest::Certificate::from_pem(&pem)
            .map_err(|_| "PENTECT_OPENAI_CA_CERT is not a valid PEM certificate".to_string())?;
        builder = builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .map_err(|_| "could not build OpenAI HTTP gateway client".to_string())
}

async fn proxy_request(
    request: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<ProxyBody>, Infallible> {
    let Ok(_permit) = Arc::clone(&state.requests).try_acquire_owned() else {
        return Ok(text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Pentect gateway is busy",
        ));
    };
    match proxy_request_inner(request, &state).await {
        Ok(response) => Ok(response),
        Err(error) => {
            eprintln!("[pentect] OpenAI HTTP gateway request failed: {error}");
            let local_rejection = error.starts_with("image blocked:")
                || error.starts_with("document blocked:")
                || error.starts_with("remote ")
                || error.starts_with("OpenAI file ")
                || error.starts_with("file upload blocked:")
                || error.starts_with("Files API upload ")
                || error.starts_with("plugin blocked:")
                || error.starts_with("unknown format blocked:");
            Ok(if local_rejection {
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
    let method = request.method().clone();
    let responses_path = method == hyper::Method::POST && is_responses_path(path_and_query);
    let files_upload = method == hyper::Method::POST && is_files_collection_path(path_and_query);
    let upstream_url = join_upstream_url(&state.upstream, path_and_query)?;
    let headers = request.headers().clone();
    let mut request_coverage = None;
    let mut request_streaming = false;
    let body = if responses_path || files_upload {
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
            Err(error) => return Err(format!("could not read OpenAI request body: {error}")),
        };
        if body.is_empty() {
            reqwest::Body::from(body)
        } else if files_upload {
            let content_type = headers
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| "Files API upload is missing Content-Type".to_string())?
                .to_string();
            let masker = Arc::clone(&state.masker);
            let plugins = Arc::clone(&state.plugins);
            let protected = tokio::task::spawn_blocking(move || {
                let mut masker = masker
                    .lock()
                    .map_err(|_| "OpenAI request masker lock was poisoned".to_string())?;
                let plugins = plugins
                    .lock()
                    .map_err(|_| "OpenAI plugin lock was poisoned".to_string())?;
                crate::http_files::protect_multipart_upload_with_plugins(
                    &content_type,
                    &body,
                    &mut masker,
                    &plugins,
                )
            })
            .await
            .map_err(|_| "OpenAI file protection task failed".to_string())??;
            request_coverage = Some(protected.coverage);
            reqwest::Body::from(protected.body)
        } else {
            request_streaming = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|value| value.get("stream").and_then(Value::as_bool))
                .unwrap_or(false);
            let original = resolve_openai_file_references(body, state, &headers).await?;
            let original = resolve_openai_remote_files(original).await?;
            let masker = Arc::clone(&state.masker);
            let plugins = Arc::clone(&state.plugins);
            let files = state
                .files
                .lock()
                .map_err(|_| "OpenAI file registry lock was poisoned".to_string())?
                .clone();
            let block_unknown_formats = state.block_unknown_formats;
            let protected = tokio::task::spawn_blocking(move || {
                protect_openai_request_body(
                    &original,
                    &masker,
                    &plugins,
                    &files,
                    block_unknown_formats,
                )
            })
            .await
            .map_err(|_| "OpenAI request protection task failed".to_string())??;
            request_coverage = Some(protected.coverage);
            if let Some(response) = protected.local_response {
                return Ok(json_response(StatusCode::OK, response));
            }
            reqwest::Body::from(protected.body)
        }
    } else {
        let stream = request.into_body().into_data_stream().map(|chunk| {
            chunk.map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, error))
        });
        reqwest::Body::wrap_stream(stream)
    };

    let mut upstream_request = state.client.request(method, upstream_url);
    let connection_headers = connection_named_headers(&headers);
    for (name, value) in &headers {
        if ((!(responses_path || files_upload) && name == hyper::header::CONTENT_LENGTH)
            || should_forward_request_header(name.as_str()))
            && !connection_headers.contains(&name.as_str().to_ascii_lowercase())
        {
            upstream_request = upstream_request.header(name, value);
        }
    }
    let upstream = upstream_request
        .body(body)
        .send()
        .await
        .map_err(|error| reqwest_error_message("could not reach OpenAI upstream", &error))?;
    let status = upstream.status();
    let response_headers = upstream.headers().clone();
    if response_headers
        .get(hyper::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err("OpenAI upstream returned an unsupported content encoding".to_string());
    }
    let response_media_type = response_headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    // Some Responses-compatible upstreams omit Content-Type. The request's
    // explicit stream flag is authoritative in that case.
    let is_event_stream = response_media_type
        .is_some_and(|value| value.eq_ignore_ascii_case("text/event-stream"))
        || (responses_path && request_streaming && response_media_type.is_none());
    let is_json_response =
        response_media_type.is_some_and(|value| {
            value.eq_ignore_ascii_case("application/json")
                || value.to_ascii_lowercase().ends_with("+json")
        }) || (responses_path && !request_streaming && response_media_type.is_none());
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
        request_coverage
            .unwrap_or(crate::http_files::Coverage::None)
            .as_header(),
    );
    if is_event_stream || (!responses_path && !files_upload) {
        return builder
            .body(streaming_response_body(
                upstream,
                status.is_success() && responses_path && is_event_stream,
                Arc::clone(&state.plugins),
            ))
            .map_err(|error| format!("could not build OpenAI streaming response: {error}"));
    }

    let Some(response_body) = read_response_capped(upstream).await? else {
        return Ok(text_response(
            StatusCode::BAD_GATEWAY,
            "Upstream response body too large",
        ));
    };
    if files_upload && status.is_success() {
        if let (Some(coverage), Ok(value)) = (
            request_coverage,
            serde_json::from_slice::<Value>(&response_body),
        ) {
            if let Some(id) = value.get("id").and_then(Value::as_str) {
                let mut files = state
                    .files
                    .lock()
                    .map_err(|_| "OpenAI file registry lock was poisoned".to_string())?;
                crate::http_files::remember_file_coverage(&mut files, id.to_string(), coverage);
            }
        }
    }
    let response_body = if responses_path && status.is_success() && is_json_response {
        let response_body = run_response_plugins(response_body, &state.plugins, "openai")?;
        match rewrite_openai_json_response(&response_body) {
            Ok(rewritten) => Bytes::from(rewritten),
            Err(error) => {
                eprintln!("[pentect] OpenAI response restoration skipped: {error}");
                response_body
            }
        }
    } else {
        response_body
    };
    builder
        .body(full_body(response_body))
        .map_err(|error| format!("could not build OpenAI response: {error}"))
}

fn run_response_plugins(
    body: Bytes,
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    provider: &str,
) -> Result<Bytes, String> {
    let value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return Ok(body),
    };
    let plugins = plugins
        .lock()
        .map_err(|_| "OpenAI plugin lock was poisoned".to_string())?;
    let run = plugins.run(
        pentect_agent::MiddlewareStage::ProviderResponse,
        value,
        Some(serde_json::json!({"provider": provider, "transport": "http"})),
    )?;
    if run.stopped == Some(pentect_agent::StopOutcome::Block) {
        return Err(format!(
            "plugin blocked: {}",
            run.message
                .unwrap_or_else(|| "response blocked".to_string())
        ));
    }
    let mut payload = run.payload;
    run_openai_tool_plugins(&mut payload, &plugins)?;
    serde_json::to_vec(&payload)
        .map(Bytes::from)
        .map_err(|error| format!("could not encode plugin response payload: {error}"))
}

fn run_openai_tool_plugins(
    value: &mut Value,
    plugins: &pentect_agent::PluginMiddleware,
) -> Result<(), String> {
    match value {
        Value::Array(values) => {
            for value in values {
                run_openai_tool_plugins(value, plugins)?;
            }
        }
        Value::Object(object) => {
            let is_call = object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| {
                    matches!(
                        kind,
                        "function_call"
                            | "custom_tool_call"
                            | "response.function_call_arguments.done"
                            | "response.custom_tool_call_input.done"
                    )
                })
                && ["arguments", "input"]
                    .iter()
                    .any(|key| object.get(*key).is_some());
            if is_call {
                let run = plugins.run(
                    pentect_agent::MiddlewareStage::ToolCall,
                    Value::Object(object.clone()),
                    Some(serde_json::json!({"provider": "openai", "transport": "http"})),
                )?;
                if run.stopped == Some(pentect_agent::StopOutcome::Block) {
                    return Err(format!(
                        "plugin blocked: {}",
                        run.message
                            .unwrap_or_else(|| "tool call blocked".to_string())
                    ));
                }
                *object = run
                    .payload
                    .as_object()
                    .cloned()
                    .ok_or_else(|| "tool_call plugin payload must be an object".to_string())?;
            }
            for child in object.values_mut() {
                run_openai_tool_plugins(child, plugins)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct ProtectedJsonBody {
    body: Bytes,
    coverage: crate::http_files::Coverage,
    local_response: Option<Bytes>,
}

fn protect_openai_request_body(
    body: &Bytes,
    masker: &Mutex<pentect_agent::ActiveToolOutputMasker>,
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    files: &HashMap<String, crate::http_files::Coverage>,
    block_unknown_formats: bool,
) -> Result<ProtectedJsonBody, String> {
    let mut value: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) => {
            if block_unknown_formats {
                return Err(format!(
                    "unknown format blocked: OpenAI request is not valid JSON ({error}); set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through"
                ));
            }
            eprintln!("[pentect] OpenAI request protection skipped: invalid JSON: {error}");
            return Ok(ProtectedJsonBody {
                body: body.clone(),
                coverage: crate::http_files::Coverage::Partial,
                local_response: None,
            });
        }
    };
    let run = plugins
        .lock()
        .map_err(|_| "OpenAI plugin lock was poisoned".to_string())?
        .run(
            pentect_agent::MiddlewareStage::ProviderRequest,
            value,
            Some(serde_json::json!({"provider": "openai", "transport": "http"})),
        )?;
    let plugin_partial = run.coverage == pentect_agent::MiddlewareCoverage::Partial;
    value = run.payload;
    if let Some(outcome) = run.stopped {
        if outcome == pentect_agent::StopOutcome::Block {
            return Err(format!(
                "plugin blocked: {}",
                run.message.unwrap_or_else(|| "request blocked".to_string())
            ));
        }
        return serde_json::to_vec(&value)
            .map(|body| ProtectedJsonBody {
                body: Bytes::new(),
                coverage: crate::http_files::Coverage::Full,
                local_response: Some(Bytes::from(body)),
            })
            .map_err(|error| format!("could not encode plugin response: {error}"));
    }
    let unknown_content_kind = openai_request_unknown_content_kind(&value);
    let partial_schema = unknown_content_kind.is_some();
    if block_unknown_formats && (partial_schema || plugin_partial) {
        let detail = unknown_content_kind
            .map(|kind| format!("unsupported content type `{kind}`"))
            .unwrap_or_else(|| "plugin reported partial coverage".to_string());
        return Err(format!(
            "unknown format blocked: OpenAI request contains {detail}; set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through"
        ));
    }
    let mut masker = masker
        .lock()
        .map_err(|_| "OpenAI request masker lock was poisoned".to_string())?;
    if let Err(error) = mask_openai_request(&mut value, &mut masker, files) {
        if error.starts_with("image blocked:") || error.starts_with("document blocked:") {
            return Err(error);
        }
        eprintln!("[pentect] OpenAI request protection skipped: {error}");
        return Ok(ProtectedJsonBody {
            body: body.clone(),
            coverage: crate::http_files::Coverage::Partial,
            local_response: None,
        });
    }
    if crate::claude_http_proxy::value_contains_handle(&value) {
        inject_handle_contract(&mut value);
    }
    serde_json::to_vec(&value)
        .map(|body| ProtectedJsonBody {
            body: Bytes::from(body),
            coverage: if partial_schema || plugin_partial {
                crate::http_files::Coverage::Partial
            } else {
                crate::http_files::Coverage::Full
            },
            local_response: None,
        })
        .map_err(|error| format!("could not encode protected OpenAI request: {error}"))
}

async fn resolve_openai_file_references(
    body: Bytes,
    state: &ProxyState,
    request_headers: &hyper::HeaderMap,
) -> Result<Bytes, String> {
    let mut value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return Ok(body),
    };
    resolve_openai_file_reference_values(&mut value, state, request_headers).await?;
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|_| "could not encode resolved file reference".to_string())
}

fn resolve_openai_file_reference_values<'a>(
    value: &'a mut Value,
    state: &'a ProxyState,
    request_headers: &'a hyper::HeaderMap,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        match value {
            Value::Array(values) => {
                for value in values {
                    resolve_openai_file_reference_values(value, state, request_headers).await?;
                }
            }
            Value::Object(object) => {
                if object.get("type").and_then(Value::as_str) == Some("input_file") {
                    if let Some(file_id) = object
                        .get("file_id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                    {
                        let known = state
                            .files
                            .lock()
                            .map_err(|_| "OpenAI file registry lock was poisoned".to_string())?
                            .get(&file_id)
                            .copied();
                        if known == Some(crate::http_files::Coverage::Full) {
                            return Ok(());
                        }
                        let mut remote =
                            fetch_openai_file_content(&file_id, state, request_headers).await?;
                        let encoded = data_encoding::BASE64.encode(&remote.bytes);
                        remote.bytes.zeroize();
                        object.remove("file_id");
                        object.insert(
                            "file_data".to_string(),
                            Value::String(format!("data:{};base64,{encoded}", remote.media_type)),
                        );
                        object
                            .entry("filename".to_string())
                            .or_insert(Value::String(remote.filename));
                        return Ok(());
                    }
                }
                for value in object.values_mut() {
                    resolve_openai_file_reference_values(value, state, request_headers).await?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

async fn fetch_openai_file_content(
    file_id: &str,
    state: &ProxyState,
    request_headers: &hyper::HeaderMap,
) -> Result<crate::remote_content::RemoteContent, String> {
    if file_id.is_empty()
        || file_id.len() > 200
        || !file_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("OpenAI file ID is invalid".to_string());
    }
    let path = format!("/files/{file_id}/content");
    let url = join_upstream_url(&state.upstream, &path)?;
    let mut request = state.client.get(url);
    let connection_headers = connection_named_headers(request_headers);
    for (name, value) in request_headers {
        if should_forward_request_header(name.as_str())
            && !connection_headers.contains(&name.as_str().to_ascii_lowercase())
        {
            request = request.header(name, value);
        }
    }
    let response = request
        .send()
        .await
        .map_err(|error| reqwest_error_message("could not fetch OpenAI file", &error))?;
    if !response.status().is_success() {
        return Err(format!(
            "OpenAI file content returned HTTP {}",
            response.status().as_u16()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_HTTP_BODY_BYTES as u64)
    {
        return Err("OpenAI file is too large to inspect".to_string());
    }
    let media_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or("application/octet-stream")
        .trim()
        .to_string();
    let filename = response
        .headers()
        .get(reqwest::header::CONTENT_DISPOSITION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(';').find_map(|part| {
                let (name, value) = part.trim().split_once('=')?;
                name.eq_ignore_ascii_case("filename")
                    .then(|| value.trim_matches('"').to_string())
            })
        })
        .unwrap_or_else(|| format!("{file_id}.bin"));
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "OpenAI file body failed".to_string())?;
        if bytes.len().saturating_add(chunk.len()) > MAX_HTTP_BODY_BYTES {
            bytes.zeroize();
            return Err("OpenAI file is too large to inspect".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(crate::remote_content::RemoteContent {
        bytes,
        media_type,
        filename,
    })
}

async fn resolve_openai_remote_files(body: Bytes) -> Result<Bytes, String> {
    let mut value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return Ok(body),
    };
    resolve_openai_remote_file_values(&mut value).await?;
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|_| "could not encode resolved remote attachment".to_string())
}

fn resolve_openai_remote_file_values(
    value: &mut Value,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
    Box::pin(async move {
        match value {
            Value::Array(values) => {
                for value in values {
                    resolve_openai_remote_file_values(value).await?;
                }
            }
            Value::Object(object) => {
                let input_type = object.get("type").and_then(Value::as_str);
                if input_type == Some("input_file") {
                    if let Some(url) = object
                        .get("file_url")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                    {
                        let mut remote = crate::remote_content::fetch(&url).await?;
                        let encoded = data_encoding::BASE64.encode(&remote.bytes);
                        remote.bytes.zeroize();
                        object.remove("file_url");
                        object.insert(
                            "file_data".to_string(),
                            Value::String(format!("data:{};base64,{encoded}", remote.media_type)),
                        );
                        object
                            .entry("filename".to_string())
                            .or_insert(Value::String(remote.filename));
                        return Ok(());
                    }
                } else if input_type == Some("input_image") {
                    if let Some(url) = object
                        .get("image_url")
                        .and_then(Value::as_str)
                        .filter(|url| !url.starts_with("data:"))
                        .map(str::to_string)
                    {
                        let mut remote = crate::remote_content::fetch(&url).await?;
                        if !remote.media_type.starts_with("image/") {
                            remote.bytes.zeroize();
                            return Err("remote image URL did not return an image".to_string());
                        }
                        let encoded = data_encoding::BASE64.encode(&remote.bytes);
                        remote.bytes.zeroize();
                        object.insert(
                            "image_url".to_string(),
                            Value::String(format!("data:{};base64,{encoded}", remote.media_type)),
                        );
                        return Ok(());
                    }
                }
                for value in object.values_mut() {
                    resolve_openai_remote_file_values(value).await?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

fn openai_request_unknown_content_kind(value: &Value) -> Option<&str> {
    fn visit(value: &Value) -> Option<&str> {
        match value {
            Value::Array(items) => items.iter().find_map(visit),
            Value::Object(object) => {
                if let Some(kind) = object.get("type").and_then(Value::as_str) {
                    if !matches!(
                        kind,
                        "message"
                            | "additional_tools"
                            | "agent_message"
                            | "input_text"
                            | "output_text"
                            | "input_image"
                            | "input_file"
                            | "encrypted_content"
                            | "summary_text"
                            | "reasoning_text"
                            | "text"
                            | "local_shell_call"
                            | "function_call"
                            | "function_call_output"
                            | "custom_tool_call"
                            | "custom_tool_call_output"
                            | "tool_search_call"
                            | "tool_search_output"
                            | "web_search_call"
                            | "image_generation_call"
                            | "computer_call"
                            | "computer_call_output"
                            | "reasoning"
                            | "compaction"
                            | "compaction_summary"
                            | "compaction_trigger"
                            | "context_compaction"
                    ) {
                        return Some(kind);
                    }
                }
                ["content", "input", "output"]
                    .into_iter()
                    .filter_map(|key| object.get(key))
                    .find_map(visit)
            }
            _ => None,
        }
    }
    value.get("input").and_then(visit)
}

fn inject_handle_contract(value: &mut Value) {
    match value.get_mut("instructions") {
        Some(Value::String(instructions)) if !instructions.contains(HANDLE_CONTRACT) => {
            let existing = std::mem::take(instructions);
            *instructions = format!("{existing}\n\n{HANDLE_CONTRACT}");
        }
        Some(Value::Null) | None => {
            value["instructions"] = Value::String(HANDLE_CONTRACT.to_string());
        }
        _ => {}
    }
}

fn mask_openai_request(
    value: &mut Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    if let Some(input) = value.get_mut("input") {
        mask_openai_input(input, false, masker, files)?;
    }
    Ok(())
}

fn mask_openai_input(
    value: &mut Value,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    match value {
        Value::String(text) => mask_text(text, tool_result, masker),
        Value::Array(items) => {
            for item in items {
                mask_openai_input(item, tool_result, masker, files)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            let item_type = object
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            match item_type.as_str() {
                "function_call_output" | "custom_tool_call_output" => {
                    if let Some(output) = object.get_mut("output") {
                        mask_openai_input(output, true, masker, files)?;
                    }
                }
                "input_text" | "output_text" => {
                    if let Some(Value::String(text)) = object.get_mut("text") {
                        mask_text(text, tool_result, masker)?;
                    }
                }
                "input_image" => inspect_openai_image(object)?,
                "input_file" => inspect_openai_file(object, tool_result, masker, files)?,
                "message" => {
                    if let Some(content) = object.get_mut("content") {
                        mask_openai_input(content, tool_result, masker, files)?;
                    }
                }
                _ => {
                    for key in ["content", "text", "output"] {
                        if let Some(nested) = object.get_mut(key) {
                            mask_openai_input(nested, tool_result, masker, files)?;
                        }
                    }
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn inspect_openai_image(object: &mut serde_json::Map<String, Value>) -> Result<(), String> {
    let Some(Value::String(url)) = object.get_mut("image_url") else {
        return unscanned_image_policy();
    };
    let Some((metadata, encoded)) = url.split_once(',') else {
        return unscanned_image_policy();
    };
    if !metadata.starts_with("data:image/") || !metadata.ends_with(";base64") {
        return unscanned_image_policy();
    }
    if let Some(protected) = crate::claude_http_proxy::redact_inline_image_data(encoded)? {
        *url = format!("data:image/png;base64,{protected}");
    }
    Ok(())
}

fn inspect_openai_file(
    object: &mut serde_json::Map<String, Value>,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    if let Some(file_id) = object.get("file_id").and_then(Value::as_str) {
        if files.get(file_id) == Some(&crate::http_files::Coverage::Full) {
            return Ok(());
        }
        return crate::claude_http_proxy::enforce_unscanned_document_policy();
    }
    if object.get("file_url").is_some() {
        return crate::claude_http_proxy::enforce_unscanned_document_policy();
    }
    let Some(data) = object
        .get("file_data")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return crate::claude_http_proxy::enforce_unscanned_document_policy();
    };
    let (media_type, encoded) = data
        .split_once(',')
        .and_then(|(metadata, encoded)| {
            metadata
                .strip_prefix("data:")
                .and_then(|metadata| metadata.strip_suffix(";base64"))
                .map(|media_type| (media_type, encoded))
        })
        .unwrap_or(("application/octet-stream", data.as_str()));
    let filename = object
        .get("filename")
        .and_then(Value::as_str)
        .unwrap_or("attachment");
    if crate::http_files::supported_text_file(filename, Some(media_type)) {
        let mut bytes = data_encoding::BASE64
            .decode(encoded.as_bytes())
            .map_err(|_| "document blocked: invalid base64 text file".to_string())?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "document blocked: text file is not UTF-8".to_string())?;
        let mut protected = text.to_string();
        mask_text(&mut protected, tool_result, masker)?;
        bytes.zeroize();
        object.insert(
            "file_data".to_string(),
            Value::String(format!(
                "data:{media_type};base64,{}",
                data_encoding::BASE64.encode(protected.as_bytes())
            )),
        );
        protected.zeroize();
        return Ok(());
    }
    let source = serde_json::json!({
        "type": "base64",
        "media_type": media_type,
        "data": encoded,
    });
    crate::claude_http_proxy::inspect_base64_document(&source, tool_result, masker)
}

fn unscanned_image_policy() -> Result<(), String> {
    if pentect_agent::unscanned_images_should_block()? {
        Err("image blocked: image source could not be scanned".to_string())
    } else {
        Ok(())
    }
}

fn mask_text(
    text: &mut String,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    crate::claude_http_proxy::mask_string(text, tool_result, masker)
}

fn rewrite_openai_json_response(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|error| format!("OpenAI response was not valid JSON: {error}"))?;
    let mut resolve = crate::claude_http_proxy::request_scoped_resolver();
    rewrite_function_calls(&mut value, &mut resolve)?;
    serde_json::to_vec(&value)
        .map_err(|error| format!("could not encode restored OpenAI response: {error}"))
}

fn rewrite_function_calls<R>(value: &mut Value, resolve: &mut R) -> Result<(), String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    match value {
        Value::Array(values) => {
            for value in values {
                rewrite_function_calls(value, resolve)?;
            }
        }
        Value::Object(object) => {
            let is_function_call = object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| {
                    matches!(
                        kind,
                        "function_call"
                            | "custom_tool_call"
                            | "response.function_call_arguments.done"
                            | "response.custom_tool_call_input.done"
                    )
                });
            if is_function_call {
                let is_custom_call =
                    object
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| {
                            matches!(
                                kind,
                                "custom_tool_call" | "response.custom_tool_call_input.done"
                            )
                        });
                let tool_name = object
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| {
                        object
                            .get("item")
                            .and_then(|item| item.get("name"))
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    });
                for key in ["arguments", "input"] {
                    if let Some(Value::String(arguments)) = object.get_mut(key) {
                        *arguments = if is_custom_call && key == "input" {
                            // Custom tools carry completed free-form input rather than
                            // JSON arguments. Resolve only shell-safe token values so a
                            // represented value cannot inject syntax into the tool call.
                            crate::claude_http_proxy::resolve_shell_text_safely(arguments, resolve)?
                        } else {
                            crate::claude_http_proxy::resolve_tool_input_json(
                                arguments,
                                tool_name.as_deref(),
                                resolve,
                            )?
                        };
                    }
                }
            }
            if let Some(item) = object.get_mut("item") {
                rewrite_function_calls(item, resolve)?;
            }
            if let Some(response) = object.get_mut("response") {
                rewrite_function_calls(response, resolve)?;
            }
            if let Some(output) = object.get_mut("output") {
                rewrite_function_calls(output, resolve)?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn read_response_capped(response: reqwest::Response) -> Result<Option<Bytes>, String> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|error| reqwest_error_message("could not read OpenAI response", &error))?;
        if body.len().saturating_add(chunk.len()) > MAX_HTTP_BODY_BYTES {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(Bytes::from(body)))
}

struct StreamState {
    upstream: UpstreamByteStream,
    pending: Vec<u8>,
    ready: VecDeque<Result<Frame<Bytes>, ProxyBodyError>>,
    transform: bool,
    finished: bool,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
}

fn streaming_response_body(
    response: reqwest::Response,
    transform: bool,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
) -> ProxyBody {
    let state = StreamState {
        upstream: Box::pin(response.bytes_stream()),
        pending: Vec::new(),
        ready: VecDeque::new(),
        transform,
        finished: false,
        plugins,
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
                Some(Ok(chunk)) if !state.transform => {
                    return Some((Ok(Frame::data(chunk)), state));
                }
                Some(Ok(chunk)) => {
                    if state.pending.len().saturating_add(chunk.len()) > MAX_PENDING_SSE_BYTES {
                        eprintln!(
                            "[pentect] OpenAI SSE restoration disabled: event exceeded limit"
                        );
                        state.transform = false;
                        let mut pending = std::mem::take(&mut state.pending);
                        pending.extend_from_slice(&chunk);
                        state.ready.push_back(Ok(Frame::data(Bytes::from(pending))));
                        continue;
                    }
                    state.pending.extend_from_slice(&chunk);
                    while let Some(end) = first_sse_block_end(&state.pending) {
                        let block = state.pending.drain(..end).collect::<Vec<_>>();
                        match rewrite_openai_sse_block(&block, &state.plugins) {
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
                        reqwest_error_message("OpenAI upstream stream failed", &error),
                    ))));
                }
                None => {
                    state.finished = true;
                    if !state.pending.is_empty() {
                        state
                            .ready
                            .push_back(Ok(Frame::data(Bytes::from(std::mem::take(
                                &mut state.pending,
                            )))));
                    }
                }
            }
        }
    });
    StreamBody::new(stream).boxed_unsync()
}

fn rewrite_openai_sse_block(
    block: &[u8],
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
) -> Result<Bytes, String> {
    let Ok(text) = std::str::from_utf8(block) else {
        return Ok(Bytes::copy_from_slice(block));
    };
    let Some(data_line) = text.lines().find(|line| line.starts_with("data:")) else {
        return Ok(Bytes::copy_from_slice(block));
    };
    let data = data_line
        .strip_prefix("data:")
        .unwrap_or_default()
        .trim_start();
    if data == "[DONE]" {
        return Ok(Bytes::copy_from_slice(block));
    }
    let Ok(mut value) = serde_json::from_str::<Value>(data) else {
        return Ok(Bytes::copy_from_slice(block));
    };
    if !contains_completed_function_call(&value) {
        return Ok(Bytes::copy_from_slice(block));
    }
    let plugins = plugins
        .lock()
        .map_err(|_| "OpenAI plugin lock was poisoned".to_string())?;
    run_openai_tool_plugins(&mut value, &plugins)?;
    let mut resolve = crate::claude_http_proxy::request_scoped_resolver();
    if let Err(error) = rewrite_function_calls(&mut value, &mut resolve) {
        eprintln!("[pentect] OpenAI SSE restoration skipped: {error}");
        return Ok(Bytes::copy_from_slice(block));
    }
    let Ok(encoded) = serde_json::to_string(&value) else {
        return Ok(Bytes::copy_from_slice(block));
    };
    let mut replaced = false;
    let mut output = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if !replaced && line.trim_end_matches(['\r', '\n']).starts_with("data:") {
            output.push_str("data: ");
            output.push_str(&encoded);
            if line.ends_with("\r\n") {
                output.push_str("\r\n");
            } else if line.ends_with('\n') {
                output.push('\n');
            }
            replaced = true;
        } else {
            output.push_str(line);
        }
    }
    Ok(Bytes::from(output))
}

fn contains_completed_function_call(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(contains_completed_function_call),
        Value::Object(object) => {
            let is_completed_call =
                object
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| {
                        matches!(
                            kind,
                            "function_call"
                                | "custom_tool_call"
                                | "response.function_call_arguments.done"
                                | "response.custom_tool_call_input.done"
                        )
                    })
                    && ["arguments", "input"]
                        .into_iter()
                        .any(|key| object.get(key).is_some_and(Value::is_string));
            is_completed_call
                || ["item", "response", "output"].into_iter().any(|key| {
                    object
                        .get(key)
                        .is_some_and(contains_completed_function_call)
                })
        }
        _ => false,
    }
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

fn is_responses_path(path_and_query: &str) -> bool {
    path_and_query
        .split('?')
        .next()
        .is_some_and(|path| path.ends_with("/responses"))
}

fn is_files_collection_path(path_and_query: &str) -> bool {
    path_and_query
        .split('?')
        .next()
        .is_some_and(|path| path.ends_with("/files"))
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

fn parse_upstream_base(value: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(value.trim())
        .map_err(|_| "OpenAI upstream is not a valid URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("OpenAI upstream must use http or https and include a host".to_string());
    }
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err("OpenAI upstream must not contain credentials or a fragment".to_string());
    }
    if url.scheme() == "http"
        && !url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        })
        && std::env::var("PENTECT_ALLOW_INSECURE_UPSTREAM").as_deref() != Ok("1")
    {
        return Err(
            "remote OpenAI upstream must use https (set PENTECT_ALLOW_INSECURE_UPSTREAM=1 to override)"
                .to_string(),
        );
    }
    Ok(url)
}

fn join_upstream_url(base: &reqwest::Url, path_and_query: &str) -> Result<reqwest::Url, String> {
    let (request_path, request_query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, None), |(path, query)| (path, Some(query)));
    let base_query = base.query().map(str::to_string);
    let mut without_query = base.clone();
    without_query.set_query(None);
    let mut joined = without_query.as_str().trim_end_matches('/').to_string();
    if !request_path.starts_with('/') {
        joined.push('/');
    }
    joined.push_str(request_path);
    let mut joined = reqwest::Url::parse(&joined)
        .map_err(|_| "could not construct OpenAI upstream URL".to_string())?;
    let query = match (base_query.as_deref(), request_query) {
        (Some(base), Some(request)) if !base.is_empty() && !request.is_empty() => {
            Some(format!("{base}&{request}"))
        }
        (Some(base), _) if !base.is_empty() => Some(base.to_string()),
        (_, Some(request)) if !request.is_empty() => Some(request.to_string()),
        _ => None,
    };
    joined.set_query(query.as_deref());
    Ok(joined)
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
        .map_err(|error| format!("could not create OpenAI HTTP gateway token: {error}"))?;
    let token = data_encoding::HEXLOWER.encode(&bytes);
    bytes.zeroize();
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_responses_endpoint_is_transformed() {
        assert!(is_responses_path("/v1/responses"));
        assert!(is_responses_path(
            "/backend-api/codex/responses?stream=true"
        ));
        assert!(!is_responses_path("/v1/files"));
        assert!(!is_responses_path("/v1/responses/input_tokens"));
    }

    #[test]
    fn response_function_arguments_are_restored() {
        let input = br#"{"output":[{"type":"function_call","name":"shell","arguments":"{\"command\":\"echo <<SECRET_0123456789abcdef>>\"}"}]}"#;
        let mut value: Value = serde_json::from_slice(input).unwrap();
        let mut resolve =
            |text: &str| Ok(text.replace("<<SECRET_0123456789abcdef>>", "safe-secret-token"));
        rewrite_function_calls(&mut value, &mut resolve).unwrap();
        assert_eq!(
            value["output"][0]["arguments"],
            r#"{"command":"echo safe-secret-token"}"#
        );
    }

    #[test]
    fn completed_custom_tool_input_is_restored_but_text_is_not() {
        let mut value = serde_json::json!({
            "type": "response.output_item.done",
            "item": {
                "type": "custom_tool_call",
                "name": "exec_command",
                "input": "python hash.py <<SECRET_0123456789abcdef>>"
            },
            "visible_text": "keep <<SECRET_0123456789abcdef>>"
        });
        assert!(contains_completed_function_call(&value));
        let mut resolve =
            |text: &str| Ok(text.replace("<<SECRET_0123456789abcdef>>", "safe-secret-token"));
        rewrite_function_calls(&mut value, &mut resolve).unwrap();
        assert_eq!(value["item"]["input"], "python hash.py safe-secret-token");
        assert_eq!(value["visible_text"], "keep <<SECRET_0123456789abcdef>>");
    }

    #[test]
    fn unknown_openai_content_blocks_by_default_and_can_be_allowed() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let body = Bytes::from_static(br#"{"input":[{"type":"future_block","data":"opaque"}]}"#);
        let masker = Mutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::from_env().unwrap());
        let files = HashMap::new();
        let error = match protect_openai_request_body(&body, &masker, &plugins, &files, true) {
            Ok(_) => panic!("unknown OpenAI block should be rejected"),
            Err(error) => error,
        };
        assert!(error.starts_with("unknown format blocked:"), "{error}");
        assert!(error.contains("future_block"), "{error}");

        let allowed = protect_openai_request_body(&body, &masker, &plugins, &files, false).unwrap();
        assert_eq!(allowed.coverage, crate::http_files::Coverage::Partial);
        assert_eq!(
            serde_json::from_slice::<Value>(&allowed.body).unwrap(),
            serde_json::from_slice::<Value>(&body).unwrap()
        );
    }

    #[test]
    fn current_codex_response_items_are_known() {
        let value = serde_json::json!({
            "input": [
                {
                    "type": "additional_tools",
                    "role": "developer",
                    "tools": [{"type": "function", "name": "lookup"}]
                },
                {
                    "type": "agent_message",
                    "author": "agent",
                    "recipient": "user",
                    "content": [
                        {"type": "input_text", "text": "done"},
                        {"type": "encrypted_content", "encrypted_content": "opaque"}
                    ]
                },
                {
                    "type": "reasoning",
                    "summary": [{"type": "summary_text", "text": "summary"}],
                    "content": [
                        {"type": "reasoning_text", "text": "reasoning"},
                        {"type": "text", "text": "legacy"}
                    ]
                },
                {"type": "local_shell_call", "status": "completed", "action": {}},
                {"type": "tool_search_call", "execution": "server", "arguments": {}},
                {"type": "tool_search_output", "status": "completed", "execution": "server", "tools": []},
                {"type": "web_search_call", "status": "completed"},
                {"type": "image_generation_call", "status": "completed", "result": "opaque"},
                {"type": "compaction", "encrypted_content": "opaque"},
                {"type": "compaction_summary", "encrypted_content": "opaque"},
                {"type": "compaction_trigger"},
                {"type": "context_compaction", "encrypted_content": "opaque"}
            ]
        });
        assert_eq!(openai_request_unknown_content_kind(&value), None);

        let future = serde_json::json!({"input": [{"type": "future_block"}]});
        assert_eq!(
            openai_request_unknown_content_kind(&future),
            Some("future_block")
        );
    }

    #[test]
    fn malformed_openai_json_obeys_unknown_format_policy() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let body = Bytes::from_static(b"{not-json");
        let masker = Mutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::from_env().unwrap());
        let files = HashMap::new();
        assert!(protect_openai_request_body(&body, &masker, &plugins, &files, true).is_err());
        let allowed = protect_openai_request_body(&body, &masker, &plugins, &files, false).unwrap();
        assert_eq!(allowed.coverage, crate::http_files::Coverage::Partial);
        assert_eq!(allowed.body, body);
    }

    #[test]
    fn response_text_is_not_resolved() {
        let mut value = serde_json::json!({
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": "<<SECRET_0123456789abcdef>>"}]
            }]
        });
        let mut resolve = |text: &str| Ok(text.replace("<<SECRET_0123456789abcdef>>", "secret"));
        rewrite_function_calls(&mut value, &mut resolve).unwrap();
        assert_eq!(
            value["output"][0]["content"][0]["text"],
            "<<SECRET_0123456789abcdef>>"
        );
    }

    #[test]
    fn authenticated_path_does_not_accept_prefix_confusion() {
        assert_eq!(
            authenticated_request_path("/token/v1/responses", "token"),
            Some("/v1/responses")
        );
        assert_eq!(
            authenticated_request_path("/tokenx/v1/responses", "token"),
            None
        );
    }

    #[test]
    fn custom_upstream_keeps_base_path() {
        let base = parse_upstream_base("https://gateway.example/openai/v1").unwrap();
        let joined = join_upstream_url(&base, "/responses?stream=true").unwrap();
        assert_eq!(
            joined.as_str(),
            "https://gateway.example/openai/v1/responses?stream=true"
        );
    }

    #[test]
    fn untouched_sse_framing_is_preserved() {
        let input = b"event: response.output_text.delta\r\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\r\n\r\n";
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        assert_eq!(
            rewrite_openai_sse_block(input, &plugins).unwrap().as_ref(),
            input
        );
    }
}
