//! Anthropic Messages gateway used by the unmodified Claude Code host.
//!
//! Security boundary:
//! - outbound model-visible text and client tool results are masked;
//! - inbound assistant text stays masked unless the user opts into local restoration;
//! - only completed client `tool_use.input` values are resolved;
//! - unknown events and incomplete/invalid tool JSON remain unresolved.
//!
//! The local host and its tools are trusted to handle plaintext. The remote
//! model provider is not. This intentionally replaces Claude hook overrides;
//! it does not attempt to redact Claude Code's local UI or local logs.

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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex as StdMutex};
use std::thread;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Semaphore};
use zeroize::Zeroize;

use crate::handle_contract::HANDLE_CONTRACT;

const MAX_HTTP_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_PENDING_SSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_INLINE_PDF_BYTES: usize = 8 * 1024 * 1024;
const MAX_EXTRACTED_PDF_TEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_OUTPUT_HANDLE_BYTES: usize = 512;
static WARNED_UNKNOWN_CONTENT_BLOCK: AtomicBool = AtomicBool::new(false);
static WARNED_UNKNOWN_ENDPOINT: AtomicBool = AtomicBool::new(false);
static WARNED_PROVIDER_MCP_CREDENTIALS: AtomicBool = AtomicBool::new(false);

#[derive(Default)]
pub(crate) struct OutputTextRestorer {
    pending: String,
}

impl OutputTextRestorer {
    pub(crate) fn push<R>(&mut self, chunk: &str, resolve: &mut R) -> Result<String, String>
    where
        R: FnMut(&str) -> Result<String, String>,
    {
        self.pending.push_str(chunk);
        let mut input = std::mem::take(&mut self.pending);
        let mut output = String::with_capacity(input.len());
        loop {
            let Some(start) = input.find("<<") else {
                if input.ends_with('<') {
                    let split = input.len() - 1;
                    output.push_str(&input[..split]);
                    self.pending.push('<');
                } else {
                    output.push_str(&input);
                }
                return Ok(output);
            };
            output.push_str(&input[..start]);
            input.drain(..start);
            let Some(close) = input[2..].find(">>") else {
                if input.len() <= MAX_OUTPUT_HANDLE_BYTES {
                    self.pending = input;
                    return Ok(output);
                }
                output.push_str("<<");
                input.drain(..2);
                continue;
            };
            let end = close + 4;
            if end > MAX_OUTPUT_HANDLE_BYTES {
                output.push_str("<<");
                input.drain(..2);
                continue;
            }
            output.push_str(&resolve(&input[..end])?);
            input.drain(..end);
        }
    }

    pub(crate) fn finish(&mut self) -> String {
        std::mem::take(&mut self.pending)
    }
}

fn diagnostic(event: &str, kind: &str, endpoint: &str, retryable: bool) {
    pentect_agent::record_http_diagnostic_activity(
        "claude",
        event,
        kind,
        endpoint,
        "HTTP",
        None,
        retryable,
        env!("CARGO_PKG_VERSION"),
    );
}

type ProxyBodyError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, ProxyBodyError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnthropicEndpoint {
    Messages,
    CountTokens,
    MessageBatches,
    Complete,
    Files,
    Models,
    Health,
    Unknown,
}

impl AnthropicEndpoint {
    fn diagnostic_name(self) -> &'static str {
        match self {
            Self::Messages => "messages",
            Self::CountTokens => "count-tokens",
            Self::MessageBatches => "message-batches",
            Self::Complete => "complete",
            Self::Files => "files",
            Self::Models => "models",
            Self::Health => "health",
            Self::Unknown => "unknown",
        }
    }

    fn supports_streaming_request(self) -> bool {
        matches!(self, Self::Messages | Self::Complete)
    }
}

fn anthropic_request_streaming(endpoint: AnthropicEndpoint, body: &[u8]) -> bool {
    endpoint.supports_streaming_request()
        && serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| value.get("stream").and_then(Value::as_bool))
            .unwrap_or(false)
}

pub(crate) struct ClaudeHttpProxyGuard {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ClaudeHttpProxyGuard {
    #[cfg(test)]
    pub(crate) fn start(upstream: String) -> Result<Self, String> {
        Self::start_with_header_env(upstream, &[])
    }

    pub(crate) fn start_with_header_env(
        upstream: String,
        header_env: &[String],
    ) -> Result<Self, String> {
        let upstream = parse_upstream_base(&upstream)?;
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
                    crate::gateway_diagnostics::record(
                        "claude",
                        "gateway-stopped",
                        "runtime",
                        crate::gateway_diagnostics::RequestContext {
                            endpoint: "gateway",
                            method: "HTTP",
                        },
                        None,
                        false,
                    );
                    let _ = ready_tx.send(Err(format!(
                        "could not start Claude HTTP proxy runtime: {error}"
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                if let Err(error) =
                    run_proxy(upstream, headers, thread_auth, ready_tx, shutdown_rx).await
                {
                    crate::gateway_diagnostics::record(
                        "claude",
                        "gateway-stopped",
                        "runtime",
                        crate::gateway_diagnostics::RequestContext {
                            endpoint: "gateway",
                            method: "HTTP",
                        },
                        None,
                        false,
                    );
                    let _ = error;
                }
            });
        });
        let base_url = ready_rx
            .recv_timeout(crate::GATEWAY_STARTUP_TIMEOUT)
            .map_err(|_| "Claude HTTP proxy did not start within 30 seconds".to_string())??;
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

impl Drop for ClaudeHttpProxyGuard {
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
    masker: Arc<StdMutex<pentect_agent::ActiveToolOutputMasker>>,
    plugins: Arc<StdMutex<pentect_agent::PluginMiddleware>>,
    files: StdMutex<HashMap<String, crate::http_files::Coverage>>,
    file_attestations: crate::http_files::FileAttestationStore,
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
        .map_err(|error| format!("could not bind Claude HTTP proxy: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("could not read Claude HTTP proxy address: {error}"))?;
    let local_base_url = format!("http://{address}/{auth}");
    let client = build_upstream_client()?;
    let plugins = pentect_agent::PluginMiddleware::from_env()?;
    let state = Arc::new(ProxyState {
        upstream,
        auth,
        client,
        masker: Arc::new(StdMutex::new(
            pentect_agent::ActiveToolOutputMasker::new_with_plugins(plugins.clone())?,
        )),
        plugins: Arc::new(StdMutex::new(plugins)),
        files: StdMutex::new(HashMap::new()),
        file_attestations: crate::http_files::FileAttestationStore::open_default()?,
        requests: Arc::new(Semaphore::new(32)),
        block_unknown_formats: pentect_agent::unknown_formats_should_block()?,
        headers,
    });
    // Keep authentication in the base URL path. Claude settings can replace
    // ANTHROPIC_CUSTOM_HEADERS after process start, so a header token is not
    // a reliable local boundary. The random path is stripped before upstream
    // forwarding and is never sent to the provider.
    let _ = ready_tx.send(Ok(local_base_url));

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|error| format!("Claude HTTP proxy accept failed: {error}"))?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let service = service_fn(move |request| proxy_request(request, Arc::clone(&state)));
                    let mut builder = http1::Builder::new();
                    builder.max_buf_size(64 * 1024).max_headers(128);
                    if let Err(error) = builder.serve_connection(io, service).await {
                        if !error.is_incomplete_message() {
                            crate::gateway_diagnostics::record(
                                "claude",
                                "connection-failed",
                                "client-connection",
                                crate::gateway_diagnostics::RequestContext {
                                    endpoint: "gateway",
                                    method: "HTTP",
                                },
                                None,
                                true,
                            );
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

fn build_upstream_client() -> Result<reqwest::Client, String> {
    crate::upstream::client("Anthropic Messages")
}

async fn proxy_request(
    request: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<ProxyBody>, Infallible> {
    let context = crate::gateway_diagnostics::RequestContext {
        endpoint: classify_anthropic_endpoint(
            request
                .uri()
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/"),
        )
        .diagnostic_name(),
        method: crate::gateway_diagnostics::method_name(request.method()),
    };
    let Ok(_permit) = Arc::clone(&state.requests).try_acquire_owned() else {
        crate::gateway_diagnostics::record(
            "claude",
            "gateway-busy",
            "capacity",
            context,
            Some(StatusCode::SERVICE_UNAVAILABLE.as_u16()),
            true,
        );
        return Ok(text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Pentect proxy is busy",
        ));
    };
    match proxy_request_inner(request, &state).await {
        Ok(response) => Ok(response),
        Err(error) => {
            let local_rejection = crate::gateway_diagnostics::is_local_rejection(&error);
            let response_status = if local_rejection {
                StatusCode::UNPROCESSABLE_ENTITY
            } else {
                StatusCode::BAD_GATEWAY
            };
            crate::gateway_diagnostics::record_request_failure(
                "claude",
                context,
                &error,
                response_status.as_u16(),
            );
            Ok(if local_rejection {
                owned_text_response(StatusCode::UNPROCESSABLE_ENTITY, &error)
            } else {
                text_response(StatusCode::BAD_GATEWAY, "Pentect proxy request failed")
            })
        }
    }
}

async fn proxy_request_inner(
    request: Request<Incoming>,
    state: &ProxyState,
) -> Result<Response<ProxyBody>, String> {
    let request_path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let Some(path_and_query) = authenticated_request_path(request_path_and_query, &state.auth)
    else {
        return Ok(text_response(StatusCode::FORBIDDEN, "Forbidden"));
    };

    let endpoint = classify_anthropic_endpoint(path_and_query);
    enforce_known_anthropic_endpoint(endpoint, state.block_unknown_formats)?;
    let method = request.method().clone();
    let path_and_query = path_and_query.to_string();
    let upstream_url = join_upstream_url(&state.upstream, &path_and_query)?;
    let headers = request.headers().clone();
    let credential_material = state.headers.credential_scope_material(&headers);
    let account_scope = state.file_attestations.account_scope(&credential_material);
    let messages_path = endpoint == AnthropicEndpoint::Messages;
    let batch_create = endpoint == AnthropicEndpoint::MessageBatches
        && method == hyper::Method::POST
        && path_and_query
            .split('?')
            .next()
            .is_some_and(|path| path.ends_with("/v1/messages/batches"));
    let protected_request = matches!(
        endpoint,
        AnthropicEndpoint::Messages | AnthropicEndpoint::CountTokens
    ) || (endpoint == AnthropicEndpoint::Complete
        && method == hyper::Method::POST)
        || batch_create;
    let files_upload = endpoint == AnthropicEndpoint::Files
        && method == hyper::Method::POST
        && path_and_query
            .split('?')
            .next()
            .is_some_and(|path| path.ends_with("/v1/files"));
    let body_forbidden = endpoint == AnthropicEndpoint::Models;
    let mut request_coverage = None;
    let body = if protected_request || files_upload || body_forbidden {
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
            Err(error) => return Err(format!("could not read Claude request body: {error}")),
        };
        if body_forbidden && !body.is_empty() {
            return Err(
                "request body blocked: Anthropic models endpoints do not accept request bodies"
                    .to_string(),
            );
        }
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
                    .map_err(|_| "Claude request masker lock was poisoned".to_string())?;
                let plugins = plugins
                    .lock()
                    .map_err(|_| "Claude plugin lock was poisoned".to_string())?;
                crate::http_files::protect_multipart_upload_with_plugins(
                    &content_type,
                    &body,
                    &mut masker,
                    &plugins,
                )
            })
            .await
            .map_err(|_| "Claude file protection task failed".to_string())??;
            request_coverage = Some(protected.coverage);
            reqwest::Body::from(protected.body)
        } else {
            let request_streaming = anthropic_request_streaming(endpoint, &body);
            let mut remote_budget = crate::remote_content::RemoteRequestBudget::default();
            let body = resolve_anthropic_remote_content(body, &mut remote_budget).await?;
            hydrate_anthropic_attested_files(&body, &account_scope, state).await?;
            let masker = Arc::clone(&state.masker);
            let plugins = Arc::clone(&state.plugins);
            let files = {
                let registry = state
                    .files
                    .lock()
                    .map_err(|_| "Claude file registry lock was poisoned".to_string())?;
                crate::http_files::scoped_file_coverages(&registry, &account_scope)
            };
            let block_unknown_formats = state.block_unknown_formats;
            let protected = tokio::task::spawn_blocking(move || {
                protect_anthropic_request_body(
                    &body,
                    &masker,
                    &plugins,
                    &files,
                    endpoint,
                    block_unknown_formats,
                )
            })
            .await
            .map_err(|_| "Claude request protection task failed".to_string())??;
            request_coverage = Some(protected.coverage);
            if let Some(response) = protected.local_response {
                if request_streaming {
                    return Ok(text_response(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Plugin local responses are unavailable for streaming Anthropic requests",
                    ));
                }
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

    let mut upstream_request = state.client.request(method.clone(), upstream_url);
    let connection_headers = connection_named_headers(&headers);
    for (name, value) in &headers {
        if state.headers.forward_incoming_header(name.as_str())
            && ((!(protected_request || files_upload || body_forbidden)
                && name == hyper::header::CONTENT_LENGTH)
                || should_forward_request_header(name.as_str()))
            && !connection_headers.contains(&name.as_str().to_ascii_lowercase())
        {
            upstream_request = upstream_request.header(name, value);
        }
    }
    upstream_request = state.headers.apply(upstream_request);
    let upstream_response = upstream_request
        .body(body)
        .send()
        .await
        .map_err(|error| reqwest_error_message("could not reach Claude upstream", &error))?;
    let status = upstream_response.status();
    crate::gateway_diagnostics::record_upstream_status(
        "claude",
        crate::gateway_diagnostics::RequestContext {
            endpoint: endpoint.diagnostic_name(),
            method: crate::gateway_diagnostics::method_name(&method),
        },
        status,
    );
    let response_headers = upstream_response.headers().clone();
    if response_headers
        .get(hyper::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err("Claude upstream returned an unsupported content encoding".to_string());
    }
    let is_event_stream = response_headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"));
    let restore_output = pentect_agent::output_restore_enabled()?;
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
    if is_event_stream || (!messages_path && !files_upload) {
        let transform = status.is_success() && messages_path && is_event_stream;
        return builder
            .body(streaming_response_body(
                upstream_response,
                transform,
                Arc::clone(&state.plugins),
                restore_output,
            ))
            .map_err(|error| format!("could not build Claude streaming response: {error}"));
    }

    let Some(response_body) = read_response_capped(upstream_response).await? else {
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
                if state
                    .file_attestations
                    .remember_async(
                        "anthropic",
                        state.upstream.as_str(),
                        &account_scope,
                        id,
                        coverage,
                    )
                    .await
                    .is_err()
                {
                    diagnostic("file-attestation-unavailable", "storage", "files", true);
                } else if let Ok(mut files) = state.files.lock() {
                    crate::http_files::remember_scoped_file_coverage(
                        &mut files,
                        &account_scope,
                        id.to_string(),
                        coverage,
                    );
                } else {
                    diagnostic("file-registry-unavailable", "storage", "files", true);
                }
            }
        }
    }
    let response_body = if status.is_success() && messages_path {
        let response_body = run_response_plugins(response_body, &state.plugins)?;
        match rewrite_anthropic_json_response(&response_body, restore_output) {
            Ok(rewritten) => Bytes::from(rewritten),
            Err(_error) => {
                diagnostic("response-restore-skipped", "protection", "messages", false);
                response_body
            }
        }
    } else {
        response_body
    };
    builder
        .body(full_body(response_body))
        .map_err(|error| format!("could not build Claude proxy response: {error}"))
}

fn run_response_plugins(
    body: Bytes,
    plugins: &StdMutex<pentect_agent::PluginMiddleware>,
) -> Result<Bytes, String> {
    let value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return Ok(body),
    };
    let plugins = plugins
        .lock()
        .map_err(|_| "Claude plugin lock was poisoned".to_string())?;
    let run = plugins.run(
        pentect_agent::MiddlewareStage::Response,
        value,
        Some(serde_json::json!({"provider": "anthropic", "transport": "http"})),
    )?;
    if run.stopped == Some(pentect_agent::StopOutcome::Block) {
        return Err(format!(
            "plugin blocked: {}",
            run.message
                .unwrap_or_else(|| "response blocked".to_string())
        ));
    }
    let mut payload = run.payload;
    run_anthropic_tool_plugins(&mut payload, &plugins)?;
    serde_json::to_vec(&payload)
        .map(Bytes::from)
        .map_err(|error| format!("could not encode plugin response payload: {error}"))
}

fn run_anthropic_tool_plugins(
    value: &mut Value,
    plugins: &pentect_agent::PluginMiddleware,
) -> Result<(), String> {
    match value {
        Value::Array(values) => {
            for value in values {
                run_anthropic_tool_plugins(value, plugins)?;
            }
        }
        Value::Object(object) => {
            if object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(anthropic_tool_block_type)
                && object.get("input").is_some()
            {
                let run = plugins.run(
                    pentect_agent::MiddlewareStage::ToolCall,
                    Value::Object(object.clone()),
                    Some(serde_json::json!({"provider": "anthropic", "transport": "http"})),
                )?;
                crate::plugins::enforce_tool_plugin_coverage(run.coverage, "Claude")?;
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
                run_anthropic_tool_plugins(child, plugins)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn anthropic_tool_block_type(block_type: &str) -> bool {
    matches!(block_type, "tool_use" | "mcp_tool_use" | "server_tool_use")
}

async fn resolve_anthropic_remote_content(
    body: Bytes,
    budget: &mut crate::remote_content::RemoteRequestBudget,
) -> Result<Bytes, String> {
    let mut value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return Ok(body),
    };
    resolve_anthropic_remote_values(&mut value, budget).await?;
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|_| "could not encode resolved remote attachment".to_string())
}

fn resolve_anthropic_remote_values<'a>(
    value: &'a mut Value,
    budget: &'a mut crate::remote_content::RemoteRequestBudget,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        match value {
            Value::Array(values) => {
                for value in values {
                    resolve_anthropic_remote_values(value, budget).await?;
                }
            }
            Value::Object(object) => {
                let block_type = object
                    .get("type")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                if matches!(block_type.as_deref(), Some("document" | "image")) {
                    if let Some(source) = object.get_mut("source").and_then(Value::as_object_mut) {
                        if source.get("type").and_then(Value::as_str) == Some("url") {
                            if let Some(url) = source
                                .get("url")
                                .and_then(Value::as_str)
                                .map(str::to_string)
                            {
                                let mut remote =
                                    crate::remote_content::fetch_with_budget(&url, budget).await?;
                                if block_type.as_deref() == Some("document")
                                    && crate::http_files::supported_text_file(
                                        &remote.filename,
                                        Some(&remote.media_type),
                                    )
                                {
                                    let text =
                                        std::str::from_utf8(&remote.bytes).map_err(|_| {
                                            "remote text attachment is not UTF-8".to_string()
                                        })?;
                                    *source = serde_json::Map::from_iter([
                                        ("type".to_string(), Value::String("text".to_string())),
                                        ("data".to_string(), Value::String(text.to_string())),
                                    ]);
                                } else {
                                    let encoded = data_encoding::BASE64.encode(&remote.bytes);
                                    *source = serde_json::Map::from_iter([
                                        ("type".to_string(), Value::String("base64".to_string())),
                                        (
                                            "media_type".to_string(),
                                            Value::String(remote.media_type),
                                        ),
                                        ("data".to_string(), Value::String(encoded)),
                                    ]);
                                }
                                remote.bytes.zeroize();
                                return Ok(());
                            }
                        }
                    }
                }
                for value in object.values_mut() {
                    resolve_anthropic_remote_values(value, budget).await?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

async fn hydrate_anthropic_attested_files(
    body: &[u8],
    account_scope: &str,
    state: &ProxyState,
) -> Result<(), String> {
    hydrate_anthropic_attested_files_from_sources(
        body,
        &state.files,
        &state.file_attestations,
        state.upstream.as_str(),
        account_scope,
    )
    .await
}

async fn hydrate_anthropic_attested_files_from_sources(
    body: &[u8],
    files: &StdMutex<HashMap<String, crate::http_files::Coverage>>,
    attestations: &crate::http_files::FileAttestationStore,
    upstream: &str,
    account_scope: &str,
) -> Result<(), String> {
    let attestations = attestations.clone();
    let body = body.to_vec();
    let upstream = upstream.to_string();
    let scope_for_task = account_scope.to_string();
    let coverages = tokio::task::spawn_blocking(move || {
        attestations.coverages_in_json(&body, "anthropic", &upstream, &scope_for_task)
    })
    .await
    .map_err(|_| "Claude file attestation task failed".to_string())??;
    for (id, coverage) in coverages {
        let mut registry = files
            .lock()
            .map_err(|_| "Claude file registry lock was poisoned".to_string())?;
        if crate::http_files::scoped_file_coverage(&registry, account_scope, &id).is_none() {
            crate::http_files::remember_scoped_file_coverage(
                &mut registry,
                account_scope,
                id,
                coverage,
            );
        }
    }
    Ok(())
}

struct ProtectedJsonBody {
    body: Bytes,
    coverage: crate::http_files::Coverage,
    local_response: Option<Bytes>,
}

fn protect_anthropic_request_body(
    body: &Bytes,
    masker: &StdMutex<pentect_agent::ActiveToolOutputMasker>,
    plugins: &StdMutex<pentect_agent::PluginMiddleware>,
    files: &HashMap<String, crate::http_files::Coverage>,
    endpoint: AnthropicEndpoint,
    block_unknown_formats: bool,
) -> Result<ProtectedJsonBody, String> {
    let mut value: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) => {
            if block_unknown_formats {
                return Err(format!(
                    "unknown format blocked: Anthropic request is not valid JSON ({error}); set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through"
                ));
            }
            diagnostic("request-invalid-json", "protocol", "messages", false);
            return Ok(ProtectedJsonBody {
                body: body.clone(),
                coverage: crate::http_files::Coverage::Partial,
                local_response: None,
            });
        }
    };
    let run = plugins
        .lock()
        .map_err(|_| "Claude plugin lock was poisoned".to_string())?
        .run(
            pentect_agent::MiddlewareStage::Request,
            value,
            Some(serde_json::json!({"provider": "anthropic", "transport": "http"})),
        )?;
    let mut plugin_partial = run.coverage == pentect_agent::MiddlewareCoverage::Partial;
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
    plugin_partial |= {
        let plugins = plugins
            .lock()
            .map_err(|_| "Claude plugin lock was poisoned".to_string())?;
        crate::http_files::run_anthropic_inline_file_stages(
            &value,
            &plugins,
            "anthropic",
            "http_json",
        )
    }?;
    let unknown_content_kind = anthropic_request_unknown_content_kind(&value, endpoint);
    let partial_schema = unknown_content_kind.is_some();
    if block_unknown_formats && (partial_schema || plugin_partial) {
        let detail = unknown_content_kind
            .map(|kind| format!("unsupported content type `{kind}`"))
            .unwrap_or_else(|| "plugin reported partial coverage".to_string());
        return Err(format!(
            "unknown format blocked: Anthropic request contains {detail}; set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through"
        ));
    }
    warn_provider_mcp_credentials(&value, endpoint);
    // Image handling deliberately follows the existing image policy. With
    // the default image.unscanned="block", an uninspectable image is an
    // error; users can explicitly choose allow in configuration.
    redact_anthropic_base64_images(&mut value, files, endpoint)?;
    let mut masker = masker
        .lock()
        .map_err(|_| "Claude request masker lock was poisoned".to_string())?;
    if let Err(error) = mask_anthropic_request(&mut value, &mut masker, files, endpoint) {
        // Explicit media-policy decisions are not detector failures. Letting
        // them enter the general fail-open path would send the very PDF/image
        // that the configured policy rejected.
        if is_media_policy_rejection(&error) {
            return Err(error);
        }
        if block_unknown_formats {
            return Err(format!(
                "Anthropic request blocked: content inspection is unavailable ({error})"
            ));
        }
        diagnostic(
            "request-protection-skipped",
            "protection",
            "messages",
            false,
        );
        return Ok(ProtectedJsonBody {
            body: body.clone(),
            coverage: crate::http_files::Coverage::Partial,
            local_response: None,
        });
    }
    inject_handle_contract(&mut value, endpoint);
    match serde_json::to_vec(&value) {
        Ok(protected) => Ok(ProtectedJsonBody {
            body: Bytes::from(protected),
            coverage: if partial_schema || plugin_partial {
                crate::http_files::Coverage::Partial
            } else {
                crate::http_files::Coverage::Full
            },
            local_response: None,
        }),
        Err(_error) => {
            diagnostic("request-encode-skipped", "protocol", "messages", false);
            Ok(ProtectedJsonBody {
                body: body.clone(),
                coverage: crate::http_files::Coverage::Partial,
                local_response: None,
            })
        }
    }
}

fn anthropic_request_unknown_content_kind(
    value: &Value,
    endpoint: AnthropicEndpoint,
) -> Option<&str> {
    if endpoint == AnthropicEndpoint::MessageBatches {
        let Some(requests) = value.get("requests").and_then(Value::as_array) else {
            return Some("<invalid message batch>");
        };
        for request in requests {
            let Some(params) = request.get("params").filter(|params| params.is_object()) else {
                return Some("<invalid message batch request>");
            };
            if let Some(kind) =
                anthropic_request_unknown_content_kind(params, AnthropicEndpoint::Messages)
            {
                return Some(kind);
            }
        }
        return None;
    }
    if endpoint == AnthropicEndpoint::Complete {
        return (!value.get("prompt").is_some_and(Value::is_string))
            .then_some("<invalid completion prompt>");
    }
    let mut roots = Vec::new();
    if let Some(system) = value.get("system") {
        roots.push(system);
    }
    if let Some(messages) = value.get("messages").and_then(Value::as_array) {
        roots.extend(messages.iter().filter_map(|message| message.get("content")));
    }
    roots
        .into_iter()
        .find_map(anthropic_content_unknown_block_kind)
}

fn anthropic_content_unknown_block_kind(value: &Value) -> Option<&str> {
    let blocks = value.as_array()?;
    blocks.iter().find_map(|block| {
        let Some(kind) = block.get("type").and_then(Value::as_str) else {
            return Some("<missing>");
        };
        let known = matches!(
            kind,
            "text"
                | "tool_result"
                | "tool_use"
                | "document"
                | "search_result"
                | "image"
                | "thinking"
                | "redacted_thinking"
                | "server_tool_use"
                | "mcp_tool_use"
                | "mcp_tool_result"
                | "tool_search_tool_result"
                | "web_search_tool_result"
                | "web_fetch_tool_result"
                | "code_execution_tool_result"
                | "bash_code_execution_tool_result"
                | "text_editor_code_execution_tool_result"
                | "connector_text"
                | "fallback"
        );
        if !known {
            return Some(kind);
        }
        if matches!(kind, "tool_result" | "mcp_tool_result") {
            return block
                .get("content")
                .and_then(anthropic_content_unknown_block_kind);
        }
        None
    })
}

fn is_media_policy_rejection(error: &str) -> bool {
    error.starts_with("document blocked:") || error.starts_with("image blocked:")
}

fn warn_provider_mcp_credentials(value: &Value, endpoint: AnthropicEndpoint) {
    let forwarded = if endpoint == AnthropicEndpoint::MessageBatches {
        value
            .get("requests")
            .and_then(Value::as_array)
            .is_some_and(|requests| {
                requests.iter().any(|request| {
                    request
                        .get("params")
                        .is_some_and(provider_mcp_credentials_present)
                })
            })
    } else {
        provider_mcp_credentials_present(value)
    };
    if forwarded && !WARNED_PROVIDER_MCP_CREDENTIALS.swap(true, Ordering::Relaxed) {
        diagnostic(
            "provider-mcp-credential-forwarded",
            "credential-forwarding",
            "messages",
            false,
        );
    }
}

fn provider_mcp_credentials_present(value: &Value) -> bool {
    value
        .get("mcp_servers")
        .and_then(Value::as_array)
        .is_some_and(|servers| {
            servers.iter().any(|server| {
                server
                    .get("authorization_token")
                    .and_then(Value::as_str)
                    .is_some_and(|token| !token.is_empty())
            })
        })
}

fn inject_handle_contract(value: &mut Value, endpoint: AnthropicEndpoint) {
    if endpoint == AnthropicEndpoint::MessageBatches {
        if let Some(requests) = value.get_mut("requests").and_then(Value::as_array_mut) {
            for request in requests {
                if let Some(params) = request.get_mut("params") {
                    inject_handle_contract(params, AnthropicEndpoint::Messages);
                }
            }
        }
        return;
    }
    if !request_contains_masked_handle(value) {
        return;
    }
    if endpoint == AnthropicEndpoint::Complete {
        if let Some(prompt) = value
            .get_mut("prompt")
            .and_then(|prompt| prompt.as_str())
            .map(str::to_owned)
        {
            if !prompt.contains(HANDLE_CONTRACT) {
                value["prompt"] = Value::String(format!("{prompt}\n\n{HANDLE_CONTRACT}"));
            }
        }
        return;
    }
    let contract = serde_json::json!({
        "type": "text",
        "text": HANDLE_CONTRACT,
    });
    match value.get_mut("system") {
        Some(Value::Array(blocks)) => {
            let already_present = blocks.iter().any(|block| {
                block.get("type").and_then(Value::as_str) == Some("text")
                    && block.get("text").and_then(Value::as_str) == Some(HANDLE_CONTRACT)
            });
            if !already_present {
                blocks.push(contract);
            }
        }
        Some(Value::String(system)) => {
            let existing = std::mem::take(system);
            value["system"] = Value::Array(vec![
                serde_json::json!({"type": "text", "text": existing}),
                contract,
            ]);
        }
        Some(Value::Null) | None => {
            value["system"] = Value::Array(vec![contract]);
        }
        // Preserve unknown future system representations rather than making
        // an otherwise valid request unusable.
        Some(_) => {}
    }
}

pub(crate) fn request_contains_masked_handle(value: &Value) -> bool {
    match value {
        Value::String(text) => pentect_agent::contains_pentect_masked_handle(text),
        Value::Array(values) => values.iter().any(request_contains_masked_handle),
        Value::Object(object) => object.values().any(request_contains_masked_handle),
        _ => false,
    }
}

type UpstreamByteStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static>>;
type HandleResolver = Box<dyn FnMut(&str) -> Result<String, String> + Send>;

async fn read_response_capped(response: reqwest::Response) -> Result<Option<Bytes>, String> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            reqwest_error_message("could not read Claude upstream response", &error)
        })?;
        if body.len().saturating_add(chunk.len()) > MAX_HTTP_BODY_BYTES {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(Bytes::from(body)))
}

struct TransformedStreamState {
    upstream: UpstreamByteStream,
    transformer: SseStreamTransformer<HandleResolver>,
    ready: VecDeque<Result<Frame<Bytes>, ProxyBodyError>>,
    finished: bool,
}

fn streaming_response_body(
    response: reqwest::Response,
    transform: bool,
    plugins: Arc<StdMutex<pentect_agent::PluginMiddleware>>,
    restore_output: bool,
) -> ProxyBody {
    if !transform {
        let stream = response.bytes_stream().map(|item| {
            item.map(Frame::data)
                .map_err(|error| Box::new(reqwest_stream_error(&error)) as ProxyBodyError)
        });
        return StreamBody::new(stream).boxed_unsync();
    }

    let state = TransformedStreamState {
        upstream: Box::pin(response.bytes_stream()),
        transformer: SseStreamTransformer::new(
            Box::new(request_scoped_resolver()),
            Some(plugins),
            restore_output,
        ),
        ready: VecDeque::new(),
        finished: false,
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
                Some(Ok(chunk)) => match state.transformer.push(&chunk) {
                    Ok(chunks) => state
                        .ready
                        .extend(chunks.into_iter().map(|chunk| Ok(Frame::data(chunk)))),
                    Err(error) => {
                        state.finished = true;
                        state.ready.push_back(Err(Box::new(io::Error::new(
                            io::ErrorKind::InvalidData,
                            error,
                        ))));
                    }
                },
                Some(Err(error)) => {
                    state.finished = true;
                    state
                        .ready
                        .push_back(Err(Box::new(reqwest_stream_error(&error))));
                }
                None => {
                    state.finished = true;
                    match state.transformer.finish() {
                        Ok(chunks) => state
                            .ready
                            .extend(chunks.into_iter().map(|chunk| Ok(Frame::data(chunk)))),
                        Err(error) => state.ready.push_back(Err(Box::new(io::Error::new(
                            io::ErrorKind::InvalidData,
                            error,
                        )))),
                    }
                }
            }
        }
    });
    StreamBody::new(stream).boxed_unsync()
}

pub(crate) struct SseStreamTransformer<R> {
    resolve: R,
    pending: Vec<u8>,
    tool_buffer: Option<ToolStreamBuffer>,
    terminated: bool,
    max_pending_bytes: usize,
    plugins: Option<Arc<StdMutex<pentect_agent::PluginMiddleware>>>,
    restore_output: bool,
    output_text: HashMap<(u64, &'static str), OutputTextRestorer>,
    tool_plugin_context: SseToolPluginContext,
}

#[derive(Clone, Copy)]
struct SseToolPluginContext {
    provider: &'static str,
    transport: &'static str,
    label: &'static str,
}

const ANTHROPIC_HTTP_SSE_CONTEXT: SseToolPluginContext = SseToolPluginContext {
    provider: "anthropic",
    transport: "http_sse",
    label: "Claude",
};

const CLAUDE_APP_SSE_CONTEXT: SseToolPluginContext = SseToolPluginContext {
    provider: "claude",
    transport: "desktop-http",
    label: "Claude App",
};

struct ToolStreamBuffer {
    active: HashSet<u64>,
    bytes: Vec<u8>,
}

enum SseToolBoundary {
    Start { index: u64 },
    Stop(u64),
    Other,
}

impl<R> SseStreamTransformer<R>
where
    R: FnMut(&str) -> Result<String, String>,
{
    fn new(
        resolve: R,
        plugins: Option<Arc<StdMutex<pentect_agent::PluginMiddleware>>>,
        restore_output: bool,
    ) -> Self {
        Self::new_with_context(resolve, plugins, restore_output, ANTHROPIC_HTTP_SSE_CONTEXT)
    }

    pub(crate) fn new_for_claude_app(
        resolve: R,
        plugins: Arc<StdMutex<pentect_agent::PluginMiddleware>>,
        restore_output: bool,
        max_pending_bytes: usize,
    ) -> Self {
        let mut transformer = Self::new_with_context(
            resolve,
            Some(plugins),
            restore_output,
            CLAUDE_APP_SSE_CONTEXT,
        );
        transformer.max_pending_bytes = max_pending_bytes;
        transformer
    }

    fn new_with_context(
        resolve: R,
        plugins: Option<Arc<StdMutex<pentect_agent::PluginMiddleware>>>,
        restore_output: bool,
        tool_plugin_context: SseToolPluginContext,
    ) -> Self {
        Self {
            resolve,
            pending: Vec::new(),
            tool_buffer: None,
            terminated: false,
            max_pending_bytes: MAX_PENDING_SSE_BYTES,
            plugins,
            restore_output,
            output_text: HashMap::new(),
            tool_plugin_context,
        }
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Vec<Bytes>, String> {
        if self.terminated {
            return Ok(Vec::new());
        }
        if self.pending.len().saturating_add(chunk.len()) > self.max_pending_bytes {
            diagnostic("sse-event-limit", "limit", "messages", false);
            return Err("Anthropic SSE event exceeded inspection limit".to_string());
        }
        self.pending.extend_from_slice(chunk);
        let mut output = Vec::new();
        while let Some(end) = first_sse_block_end(&self.pending) {
            let block = self.pending.drain(..end).collect::<Vec<_>>();
            self.process_block(block, &mut output)?;
            if self.terminated {
                self.pending.clear();
                break;
            }
        }
        Ok(output)
    }

    pub(crate) fn finish(&mut self) -> Result<Vec<Bytes>, String> {
        if self.terminated {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            self.process_block(pending, &mut output)?;
        }
        if self.tool_buffer.take().is_some() {
            return Err("Anthropic SSE tool input ended before content_block_stop".to_string());
        }
        output.extend(self.finish_output_text());
        Ok(output)
    }

    fn finish_output_text(&mut self) -> Vec<Bytes> {
        let mut streams = self.output_text.drain().collect::<Vec<_>>();
        streams.sort_by_key(|((index, field), _)| (*index, *field));
        streams
            .into_iter()
            .filter_map(|((index, field), mut restorer)| {
                let pending = restorer.finish();
                if pending.is_empty() {
                    return None;
                }
                let delta_type = anthropic_output_delta_type(field)?;
                Some(Bytes::from(render_sse(&[SseBlock {
                    event: Some("content_block_delta".to_string()),
                    data: Some(serde_json::json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": delta_type, (field): pending},
                    })),
                    passthrough: Vec::new(),
                }])))
            })
            .collect()
    }

    fn process_block(&mut self, block: Vec<u8>, output: &mut Vec<Bytes>) -> Result<(), String> {
        if self.tool_buffer.is_some() {
            match sse_control_event(&block) {
                SseControlEvent::Ping => {
                    output.push(Bytes::from(block));
                    return Ok(());
                }
                SseControlEvent::Error => {
                    self.tool_buffer.take();
                    output.push(Bytes::from(block));
                    self.terminated = true;
                    return Ok(());
                }
                SseControlEvent::Other => {}
            }
            if self
                .tool_buffer
                .as_ref()
                .expect("tool buffer exists")
                .bytes
                .len()
                .saturating_add(block.len())
                > self.max_pending_bytes
            {
                diagnostic("sse-tool-limit", "limit", "messages", false);
                return Err("Anthropic SSE tool input exceeded inspection limit".to_string());
            }
            let boundary = sse_tool_boundary(&block);
            let tools = self.tool_buffer.as_mut().expect("tool buffer exists");
            match boundary {
                SseToolBoundary::Start { index } => {
                    tools.active.insert(index);
                }
                SseToolBoundary::Stop(index) => {
                    tools.active.remove(&index);
                }
                SseToolBoundary::Other => {}
            }
            tools.bytes.extend_from_slice(&block);
            if tools.active.is_empty() {
                let tools = self.tool_buffer.take().expect("tool buffer exists");
                let rewritten = std::str::from_utf8(&tools.bytes)
                    .map_err(|error| format!("Claude tool SSE was not UTF-8: {error}"))
                    .and_then(|text| {
                        rewrite_anthropic_sse_with_tool_context(
                            text,
                            None,
                            &mut self.resolve,
                            self.plugins.as_deref(),
                            self.tool_plugin_context,
                        )
                    })?;
                output.push(Bytes::from(rewritten));
            }
            return Ok(());
        }

        match sse_tool_boundary(&block) {
            SseToolBoundary::Start { index } => {
                self.tool_buffer = Some(ToolStreamBuffer {
                    active: HashSet::from([index]),
                    bytes: block,
                });
            }
            _ if self.restore_output => {
                match rewrite_anthropic_output_sse_block(
                    &block,
                    &mut self.output_text,
                    &mut self.resolve,
                )? {
                    Some(rewritten) => output.push(Bytes::from(rewritten)),
                    None => output.push(Bytes::from(block)),
                }
            }
            _ => output.push(Bytes::from(block)),
        }
        Ok(())
    }
}

fn rewrite_anthropic_output_sse_block<R>(
    block: &[u8],
    streams: &mut HashMap<(u64, &'static str), OutputTextRestorer>,
    resolve: &mut R,
) -> Result<Option<Vec<u8>>, String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    let Ok(text) = std::str::from_utf8(block) else {
        return Ok(None);
    };
    let mut blocks = parse_sse(text);
    let Some(parsed) = blocks.first_mut() else {
        return Ok(None);
    };
    let Some(data) = parsed.data.as_mut() else {
        return Ok(None);
    };
    let event_type = data.get("type").and_then(Value::as_str).map(str::to_owned);
    let Some(index) = data.get("index").and_then(Value::as_u64) else {
        return Ok(None);
    };
    match event_type.as_deref() {
        Some("content_block_start") => {
            let Some(content) = data.get_mut("content_block").and_then(Value::as_object_mut) else {
                return Ok(None);
            };
            let field = match content.get("type").and_then(Value::as_str) {
                Some("text") => "text",
                Some("thinking") => "thinking",
                _ => return Ok(None),
            };
            if let Some(Value::String(value)) = content.get_mut(field) {
                *value = streams
                    .entry((index, field))
                    .or_default()
                    .push(value, resolve)?;
            }
        }
        Some("content_block_delta") => {
            let Some(delta) = data.get_mut("delta").and_then(Value::as_object_mut) else {
                return Ok(None);
            };
            let field = match delta.get("type").and_then(Value::as_str) {
                Some("text_delta") => "text",
                Some("thinking_delta") => "thinking",
                _ => return Ok(None),
            };
            if let Some(Value::String(value)) = delta.get_mut(field) {
                *value = streams
                    .entry((index, field))
                    .or_default()
                    .push(value, resolve)?;
            }
        }
        Some("content_block_stop") => {
            let mut prefixes = Vec::new();
            for field in ["text", "thinking"] {
                let Some(mut restorer) = streams.remove(&(index, field)) else {
                    continue;
                };
                let pending = restorer.finish();
                if !pending.is_empty() {
                    let delta_type = anthropic_output_delta_type(field).expect("known field");
                    prefixes.push(SseBlock {
                        event: Some("content_block_delta".to_string()),
                        data: Some(serde_json::json!({
                            "type": "content_block_delta",
                            "index": index,
                            "delta": {"type": delta_type, (field): pending},
                        })),
                        passthrough: Vec::new(),
                    });
                }
            }
            if !prefixes.is_empty() {
                return Ok(Some(
                    format!("{}{}", render_sse(&prefixes), render_sse(&blocks)).into_bytes(),
                ));
            }
        }
        _ => return Ok(None),
    }
    Ok(Some(render_sse(&blocks).into_bytes()))
}

fn anthropic_output_delta_type(field: &str) -> Option<&'static str> {
    match field {
        "text" => Some("text_delta"),
        "thinking" => Some("thinking_delta"),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SseControlEvent {
    Ping,
    Error,
    Other,
}

fn sse_control_event(block: &[u8]) -> SseControlEvent {
    let Ok(text) = std::str::from_utf8(block) else {
        return SseControlEvent::Other;
    };
    let event = text.lines().find_map(|line| {
        line.trim_end_matches('\r')
            .strip_prefix("event:")
            .map(str::trim)
    });
    let data_type = sse_json_data(text)
        .and_then(|data| data.get("type").and_then(Value::as_str).map(str::to_owned));
    match (event, data_type.as_deref()) {
        (Some("ping"), _) | (_, Some("ping")) => SseControlEvent::Ping,
        (Some("error"), _) | (_, Some("error")) => SseControlEvent::Error,
        _ => SseControlEvent::Other,
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

fn sse_tool_boundary(block: &[u8]) -> SseToolBoundary {
    let Ok(text) = std::str::from_utf8(block) else {
        return SseToolBoundary::Other;
    };
    let Some(data) = sse_json_data(text) else {
        return SseToolBoundary::Other;
    };
    let event_type = data.get("type").and_then(Value::as_str);
    let Some(index) = data.get("index").and_then(Value::as_u64) else {
        return SseToolBoundary::Other;
    };
    if event_type == Some("content_block_start")
        && data
            .get("content_block")
            .and_then(|content| content.get("type"))
            .and_then(Value::as_str)
            == Some("tool_use")
    {
        SseToolBoundary::Start { index }
    } else if event_type == Some("content_block_stop") {
        SseToolBoundary::Stop(index)
    } else {
        SseToolBoundary::Other
    }
}

fn mask_anthropic_request(
    value: &mut Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    files: &HashMap<String, crate::http_files::Coverage>,
    endpoint: AnthropicEndpoint,
) -> Result<(), String> {
    if endpoint == AnthropicEndpoint::MessageBatches {
        let requests = value
            .get_mut("requests")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "message batch requires a requests array".to_string())?;
        for request in requests {
            let params = request
                .get_mut("params")
                .filter(|params| params.is_object())
                .ok_or_else(|| "message batch request requires params".to_string())?;
            mask_anthropic_request(params, masker, files, AnthropicEndpoint::Messages)?;
        }
        return Ok(());
    }
    if endpoint == AnthropicEndpoint::Complete {
        let prompt = value
            .get_mut("prompt")
            .and_then(|prompt| prompt.as_str())
            .ok_or_else(|| "completion request requires a string prompt".to_string())?
            .to_string();
        let mut protected = prompt;
        mask_string(&mut protected, false, masker)?;
        value["prompt"] = Value::String(protected);
        return Ok(());
    }
    // Anthropic system content is client/provider-authored. It must be
    // protected, but prompt-only unmask markers are not trusted here.
    if let Some(system) = value.get_mut("system") {
        mask_content(system, true, masker, files)?;
    }
    if let Some(messages) = value.get_mut("messages").and_then(Value::as_array_mut) {
        for message in messages {
            let external_content = message.get("role").and_then(Value::as_str) != Some("user");
            if let Some(content) = message.get_mut("content") {
                mask_content(content, external_content, masker, files)?;
            }
        }
    }
    // Tool descriptions and input schemas are model-visible and can be
    // generated from local MCP/editor state. Apply the same bounded traversal
    // used by the OpenAI boundary; keys remain structural and unchanged.
    if let Some(tools) = value.get_mut("tools") {
        crate::model_definition::mask_model_definition(tools, "Anthropic", masker)?;
    }
    Ok(())
}

fn redact_anthropic_base64_images(
    value: &mut Value,
    files: &HashMap<String, crate::http_files::Coverage>,
    endpoint: AnthropicEndpoint,
) -> Result<(), String> {
    if endpoint == AnthropicEndpoint::MessageBatches {
        let requests = value
            .get_mut("requests")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "message batch requires a requests array".to_string())?;
        for request in requests {
            let params = request
                .get_mut("params")
                .filter(|params| params.is_object())
                .ok_or_else(|| "message batch request requires params".to_string())?;
            redact_anthropic_base64_images(params, files, AnthropicEndpoint::Messages)?;
        }
        return Ok(());
    }
    if endpoint == AnthropicEndpoint::Complete {
        return Ok(());
    }
    if let Some(system) = value.get_mut("system") {
        redact_content_images(system, files)?;
    }
    if let Some(messages) = value.get_mut("messages").and_then(Value::as_array_mut) {
        for message in messages {
            if let Some(content) = message.get_mut("content") {
                redact_content_images(content, files)?;
            }
        }
    }
    Ok(())
}

fn redact_content_images(
    content: &mut Value,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    let Value::Array(blocks) = content else {
        return Ok(());
    };
    let original = std::mem::take(blocks);
    for mut block in original {
        let note = match block.get("type").and_then(Value::as_str) {
            Some("image") => redact_base64_image_block(&mut block, files)?,
            Some("tool_result" | "mcp_tool_result") => {
                if let Some(nested) = block.get_mut("content") {
                    redact_content_images(nested, files)?;
                }
                None
            }
            _ => None,
        };
        blocks.push(block);
        if let Some(text) = note {
            blocks.push(serde_json::json!({"type": "text", "text": text}));
        }
    }
    Ok(())
}

fn redact_base64_image_block(
    block: &mut Value,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<Option<String>, String> {
    let block_unscanned = || -> Result<Option<String>, String> {
        if pentect_agent::unscanned_images_should_block()? {
            Err("image blocked: image source could not be scanned".to_string())
        } else {
            Ok(None)
        }
    };
    let Some(source) = block.get_mut("source") else {
        return block_unscanned();
    };
    match source.get("type").and_then(Value::as_str) {
        Some("base64") => {}
        Some("file" | "file_id" | "file_reference")
            if source
                .get("file_id")
                .or_else(|| source.get("id"))
                .and_then(Value::as_str)
                .is_some_and(|id| files.get(id) == Some(&crate::http_files::Coverage::Full)) =>
        {
            return Ok(None);
        }
        // URL sources have already been replaced by the constrained remote
        // fetcher. Unknown Files API references follow the media policy.
        Some("url" | "file") | Some("file_id") | Some("file_reference") | None => {
            return block_unscanned();
        }
        Some(_) => return block_unscanned(),
    }
    let Some(encoded) = source.get("data").and_then(Value::as_str) else {
        return block_unscanned();
    };
    let Some(protected) = redact_inline_image_data(encoded)? else {
        // A successfully scanned image with no detected secret is unchanged.
        // The runtime returns an error for unscannable images when policy is
        // block, so `None` here is the clean-image result.
        return Ok(None);
    };
    source["data"] = Value::String(protected.data);
    source["media_type"] = Value::String("image/png".to_string());
    Ok(Some(protected.note))
}

pub(crate) struct ProtectedInlineImage {
    pub(crate) data: String,
    pub(crate) note: String,
}

pub(crate) fn redact_inline_image_data(
    encoded: &str,
) -> Result<Option<ProtectedInlineImage>, String> {
    let mut bytes = match data_encoding::BASE64.decode(encoded.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return if pentect_agent::unscanned_images_should_block()? {
                Err("image blocked: image source could not be scanned".to_string())
            } else {
                Ok(None)
            };
        }
    };
    let redacted = pentect_agent::redact_image_bytes_into_active_memory_store(&bytes);
    bytes.zeroize();
    let Some(mut redacted) = redacted? else {
        return Ok(None);
    };
    let protected = data_encoding::BASE64.encode(&redacted.bytes);
    redacted.bytes.zeroize();
    Ok(Some(ProtectedInlineImage {
        data: protected,
        note: redacted.note,
    }))
}

fn mask_content(
    value: &mut Value,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    match value {
        Value::String(text) => mask_string(text, tool_result, masker),
        Value::Array(blocks) => {
            for block in blocks {
                let block_type = block
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                match block_type {
                    "text" => {
                        if let Some(text) = block.get_mut("text") {
                            let Some(text) = text.as_str() else {
                                continue;
                            };
                            let mut protected = text.to_string();
                            mask_string(&mut protected, tool_result, masker)?;
                            block["text"] = Value::String(protected);
                        }
                    }
                    "tool_result" | "mcp_tool_result" => {
                        if let Some(content) = block.get_mut("content") {
                            mask_content(content, true, masker, files)?;
                        }
                    }
                    "tool_use" | "mcp_tool_use" | "server_tool_use" => {
                        if let Some(input) = block.get_mut("input") {
                            mask_value_strings(input, masker)?;
                        }
                    }
                    "code_execution_tool_result"
                    | "bash_code_execution_tool_result"
                    | "text_editor_code_execution_tool_result" => {
                        if let Some(content) = block.get_mut("content") {
                            mask_execution_result_content(content, masker)?;
                        }
                        // Older beta clients used `output` directly instead of
                        // the current typed `content` result object.
                        if let Some(output) = block.get_mut("output") {
                            mask_value_strings(output, masker)?;
                        }
                    }
                    "document" => mask_document_block(block, tool_result, masker, files)?,
                    "search_result" => {
                        mask_named_text(block, "title", tool_result, masker)?;
                        // UrlDetector preserves ordinary public URLs while
                        // protecting internal authorities, credentials and
                        // sensitive query/path components.
                        mask_named_text(block, "source", tool_result, masker)?;
                        if let Some(content) = block.get_mut("content") {
                            mask_content(content, tool_result, masker, files)?;
                        }
                    }
                    // These blocks are provider-produced or binary protocol
                    // payloads. They are either handled by the media pass
                    // above or intentionally remain opaque here.
                    "image"
                    | "thinking"
                    | "redacted_thinking"
                    | "tool_search_tool_result"
                    | "web_search_tool_result"
                    | "web_fetch_tool_result"
                    | "connector_text"
                    | "fallback" => {}
                    _ => {
                        if !WARNED_UNKNOWN_CONTENT_BLOCK.swap(true, Ordering::Relaxed) {
                            diagnostic("unknown-content-block", "protocol", "messages", false);
                        }
                    }
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn mask_execution_result_content(
    content: &mut Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    let result_type = content
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match result_type {
        "bash_code_execution_result" | "code_execution_result" => {
            mask_named_text(content, "stdout", true, masker)?;
            mask_named_text(content, "stderr", true, masker)?;
        }
        "encrypted_code_execution_result" => {
            // `encrypted_stdout` is provider state and must remain byte-for-byte
            // intact for a paused server-tool turn to resume.
            mask_named_text(content, "stderr", true, masker)?;
        }
        "text_editor_code_execution_view_result" => {
            if content.get("file_type").and_then(Value::as_str) == Some("text") {
                mask_named_text(content, "content", true, masker)?;
            }
        }
        "text_editor_code_execution_str_replace_result" => {
            if let Some(lines) = content.get_mut("lines") {
                mask_value_strings(lines, masker)?;
            }
        }
        "text_editor_code_execution_tool_result_error" => {
            mask_named_text(content, "error_message", true, masker)?;
        }
        _ => {}
    }
    Ok(())
}

fn mask_document_block(
    block: &mut Value,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    mask_named_text(block, "title", tool_result, masker)?;
    mask_named_text(block, "context", tool_result, masker)?;
    let Some(source) = block.get_mut("source") else {
        return Ok(());
    };
    match source.get("type").and_then(Value::as_str) {
        Some("text") => mask_named_text(source, "data", tool_result, masker),
        Some("content") => {
            if let Some(content) = source.get_mut("content") {
                mask_content(content, tool_result, masker, files)?;
            }
            Ok(())
        }
        Some("base64") => inspect_base64_document(source, tool_result, masker),
        // URL sources have already been replaced by the constrained remote
        // fetcher. Unknown Files API references follow the media policy.
        Some("file" | "file_id" | "file_reference")
            if source
                .get("file_id")
                .or_else(|| source.get("id"))
                .and_then(Value::as_str)
                .is_some_and(|id| files.get(id) == Some(&crate::http_files::Coverage::Full)) =>
        {
            Ok(())
        }
        Some("url" | "file" | "file_id" | "file_reference") | None => {
            enforce_unscanned_document_policy()
        }
        Some(_) => enforce_unscanned_document_policy(),
    }
}

pub(crate) fn inspect_base64_document(
    source: &Value,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    let media_type = source
        .get("media_type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !media_type.eq_ignore_ascii_case("application/pdf") {
        return enforce_unscanned_document_policy();
    }
    let Some(encoded) = source.get("data").and_then(Value::as_str) else {
        return enforce_unscanned_document_policy();
    };
    let mut bytes = match data_encoding::BASE64.decode(encoded.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => return enforce_unscanned_document_policy(),
    };
    if bytes.len() > MAX_INLINE_PDF_BYTES {
        bytes.zeroize();
        return enforce_unscanned_document_policy();
    }
    // PDF parsers operate on attacker-controlled binary structures. Keep a
    // strict input/output budget and contain parser panics inside the blocking
    // protection task; an OOM cannot be recovered, so oversized inputs never
    // enter the parser.
    let extracted = std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(&bytes));
    bytes.zeroize();
    let Ok(Ok(mut text)) = extracted else {
        return enforce_unscanned_document_policy();
    };
    if text.len() > MAX_EXTRACTED_PDF_TEXT_BYTES || text.trim().is_empty() {
        text.zeroize();
        return enforce_unscanned_document_policy();
    }
    let original = text.clone();
    mask_string(&mut text, tool_result, masker)?;
    let contains_secret = text != original;
    text.zeroize();
    let mut original = original;
    original.zeroize();
    if contains_secret {
        return Err("document blocked: secret text detected in PDF".to_string());
    }
    // Extracted text does not cover embedded images, attachments, scripts or
    // every metadata/object encoding. Treat even a clean extraction as an
    // unscanned binary document unless the user explicitly allows it.
    enforce_unscanned_document_policy()
}

pub(crate) fn enforce_unscanned_document_policy() -> Result<(), String> {
    if pentect_agent::unscanned_images_should_block()? {
        Err("document blocked: document could not be scanned".to_string())
    } else {
        Ok(())
    }
}

fn mask_named_text(
    object: &mut Value,
    key: &str,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    let Some(text) = object.get(key).and_then(Value::as_str) else {
        return Ok(());
    };
    let mut protected = text.to_string();
    mask_string(&mut protected, tool_result, masker)?;
    object[key] = Value::String(protected);
    Ok(())
}

pub(crate) fn mask_string(
    text: &mut String,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    let masked = if tool_result {
        masker.mask_tool_output(text)?
    } else {
        masker.mask_prompt_text(text)?
    };
    *text = masked.ok_or_else(|| "content inspection is unavailable".to_string())?;
    Ok(())
}

pub(crate) fn mask_value_strings(
    value: &mut Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    match value {
        Value::String(text) => mask_string(text, false, masker),
        Value::Array(values) => {
            for value in values {
                mask_value_strings(value, masker)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for value in object.values_mut() {
                mask_value_strings(value, masker)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn rewrite_anthropic_json_response(body: &[u8], restore_output: bool) -> Result<Vec<u8>, String> {
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|error| format!("Claude response was not valid JSON: {error}"))?;
    let mut resolve = request_scoped_resolver();
    restore_anthropic_json_value(&mut value, restore_output, &mut resolve)?;
    serde_json::to_vec(&value)
        .map_err(|error| format!("could not encode restored Claude response: {error}"))
}

pub(crate) fn restore_anthropic_json_value<R>(
    value: &mut Value,
    restore_output: bool,
    resolve: &mut R,
) -> Result<(), String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    if let Some(content) = value.get_mut("content").and_then(Value::as_array_mut) {
        for block in content {
            if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                let tool_name = block.get("name").and_then(Value::as_str).map(str::to_owned);
                if let Some(input) = block.get_mut("input") {
                    resolve_tool_input_value(input, tool_name.as_deref(), resolve)?;
                }
            } else if restore_output && block.get("type").and_then(Value::as_str) == Some("text") {
                if let Some(Value::String(text)) = block.get_mut("text") {
                    *text = resolve(text)?;
                }
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct SseBlock {
    event: Option<String>,
    data: Option<Value>,
    passthrough: Vec<String>,
}

#[derive(Default)]
struct PendingToolInput {
    name: Option<String>,
    chunks: Vec<(usize, String)>,
}

#[cfg(test)]
fn rewrite_anthropic_sse(input: &str) -> Result<String, String> {
    rewrite_anthropic_sse_with(input, &mut resolve_known_text)
}

#[cfg(test)]
fn rewrite_anthropic_sse_with<R>(input: &str, resolve: &mut R) -> Result<String, String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    rewrite_anthropic_sse_with_tool_name(input, None, resolve, None)
}

#[cfg(test)]
fn rewrite_anthropic_sse_with_tool_name<R>(
    input: &str,
    forced_tool_name: Option<&str>,
    resolve: &mut R,
    plugins: Option<&StdMutex<pentect_agent::PluginMiddleware>>,
) -> Result<String, String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    rewrite_anthropic_sse_with_tool_context(
        input,
        forced_tool_name,
        resolve,
        plugins,
        ANTHROPIC_HTTP_SSE_CONTEXT,
    )
}

fn rewrite_anthropic_sse_with_tool_context<R>(
    input: &str,
    forced_tool_name: Option<&str>,
    resolve: &mut R,
    plugins: Option<&StdMutex<pentect_agent::PluginMiddleware>>,
    plugin_context: SseToolPluginContext,
) -> Result<String, String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    let mut blocks = parse_sse(input);
    let mut tool_indices = HashSet::new();
    let mut pending: HashMap<u64, PendingToolInput> = HashMap::new();

    for block_index in 0..blocks.len() {
        let Some(data) = blocks[block_index].data.as_ref() else {
            continue;
        };
        let event_type = data.get("type").and_then(Value::as_str);
        let index = data.get("index").and_then(Value::as_u64);
        if event_type == Some("content_block_start")
            && data
                .get("content_block")
                .and_then(|block| block.get("type"))
                .and_then(Value::as_str)
                == Some("tool_use")
        {
            if let Some(index) = index {
                tool_indices.insert(index);
                let entry = pending.entry(index).or_default();
                entry.name = forced_tool_name.map(str::to_owned).or_else(|| {
                    data.get("content_block")
                        .and_then(|block| block.get("name"))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                });
            }
            continue;
        }
        if event_type == Some("content_block_delta") {
            let Some(index) = index.filter(|index| tool_indices.contains(index)) else {
                continue;
            };
            if data
                .get("delta")
                .and_then(|delta| delta.get("type"))
                .and_then(Value::as_str)
                == Some("input_json_delta")
            {
                let chunk = data
                    .get("delta")
                    .and_then(|delta| delta.get("partial_json"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                pending
                    .entry(index)
                    .or_default()
                    .chunks
                    .push((block_index, chunk));
            }
            continue;
        }
        if event_type == Some("content_block_stop") {
            let Some(index) = index.filter(|index| tool_indices.remove(index)) else {
                continue;
            };
            let Some(tool) = pending.remove(&index) else {
                continue;
            };
            let mut joined = tool
                .chunks
                .iter()
                .map(|(_, chunk)| chunk.as_str())
                .collect::<String>();
            if let Some(plugins) = plugins {
                let input_value: Value = serde_json::from_str(&joined)
                    .map_err(|error| format!("tool input is invalid JSON: {error}"))?;
                let tool_call = serde_json::json!({
                    "type": "tool_use",
                    "name": tool.name,
                    "input": input_value,
                });
                let run = plugins
                    .lock()
                    .map_err(|_| "plugin middleware: lock was poisoned".to_string())?
                    .run(
                        pentect_agent::MiddlewareStage::ToolCall,
                        tool_call,
                        Some(serde_json::json!({
                            "provider": plugin_context.provider,
                            "transport": plugin_context.transport,
                        })),
                    )
                    .map_err(|error| format!("plugin middleware: {error}"))?;
                crate::plugins::enforce_tool_plugin_coverage(run.coverage, plugin_context.label)?;
                if run.stopped == Some(pentect_agent::StopOutcome::Block) {
                    return Err(format!(
                        "plugin middleware: blocked: {}",
                        run.message
                            .unwrap_or_else(|| "tool call blocked".to_string())
                    ));
                }
                let input = run.payload.get("input").ok_or_else(|| {
                    "plugin middleware: tool_call payload requires input".to_string()
                })?;
                joined = serde_json::to_string(input)
                    .map_err(|error| format!("plugin middleware: encode failed: {error}"))?;
            }
            let resolved = resolve_tool_input_json(&joined, tool.name.as_deref(), resolve)?;
            for (position, (chunk_index, _)) in tool.chunks.iter().enumerate() {
                if let Some(partial_json) = blocks[*chunk_index]
                    .data
                    .as_mut()
                    .and_then(|data| data.get_mut("delta"))
                    .and_then(|delta| delta.get_mut("partial_json"))
                {
                    *partial_json = Value::String(if position == 0 {
                        resolved.clone()
                    } else {
                        String::new()
                    });
                }
            }
        }
    }
    Ok(render_sse(&blocks))
}

fn parse_sse(input: &str) -> Vec<SseBlock> {
    input
        .replace("\r\n", "\n")
        .split("\n\n")
        .filter(|block| !block.is_empty())
        .map(|block| {
            let mut parsed = SseBlock::default();
            let mut data_lines = Vec::new();
            for line in block.lines() {
                if let Some(event) = line.strip_prefix("event:") {
                    parsed.event = Some(event.trim_start().to_string());
                } else if let Some(data) = line.strip_prefix("data:") {
                    data_lines.push(data.trim_start().to_string());
                } else {
                    parsed.passthrough.push(line.to_string());
                }
            }
            if !data_lines.is_empty() {
                match serde_json::from_str(&data_lines.join("\n")) {
                    Ok(value) => parsed.data = Some(value),
                    Err(_) => parsed
                        .passthrough
                        .extend(data_lines.into_iter().map(|data| format!("data: {data}"))),
                }
            }
            parsed
        })
        .collect()
}

fn sse_json_data(input: &str) -> Option<Value> {
    let data = input
        .lines()
        .filter_map(|line| {
            line.trim_end_matches('\r')
                .strip_prefix("data:")
                .map(str::trim_start)
        })
        .collect::<Vec<_>>();
    (!data.is_empty())
        .then(|| serde_json::from_str(&data.join("\n")).ok())
        .flatten()
}

fn render_sse(blocks: &[SseBlock]) -> String {
    let mut output = String::new();
    for block in blocks {
        if let Some(event) = &block.event {
            output.push_str("event: ");
            output.push_str(event);
            output.push('\n');
        }
        if let Some(data) = &block.data {
            output.push_str("data: ");
            output.push_str(&serde_json::to_string(data).expect("JSON value is serializable"));
            output.push('\n');
        }
        for line in &block.passthrough {
            output.push_str(line);
            output.push('\n');
        }
        output.push('\n');
    }
    output
}

fn resolve_value_strings_with<R>(value: &mut Value, resolve: &mut R) -> Result<(), String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    match value {
        Value::String(text) => {
            *text = resolve(text)?;
            Ok(())
        }
        Value::Array(values) => {
            for value in values {
                resolve_value_strings_with(value, resolve)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for value in object.values_mut() {
                resolve_value_strings_with(value, resolve)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) fn resolve_tool_input_json<R>(
    input: &str,
    tool_name: Option<&str>,
    resolve: &mut R,
) -> Result<String, String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    let Ok(mut value) = serde_json::from_str::<Value>(input) else {
        // Fine-grained tool streaming can end with invalid JSON. Keep handles
        // inert rather than resolving into a malformed or injectable payload.
        return Ok(input.to_string());
    };
    resolve_tool_input_value(&mut value, tool_name, resolve)?;
    serde_json::to_string(&value)
        .map_err(|error| format!("could not encode restored Claude tool input: {error}"))
}

fn resolve_tool_input_value<R>(
    value: &mut Value,
    tool_name: Option<&str>,
    resolve: &mut R,
) -> Result<(), String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    if is_free_form_shell_tool(tool_name) {
        let allow_direct_posix_secrets = !cfg!(windows)
            && !tool_name.is_some_and(|name| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "powershell" | "pwsh" | "cmd"
                )
            });
        let environment_syntax = match tool_name.map(|name| name.to_ascii_lowercase()) {
            Some(name) if matches!(name.as_str(), "powershell" | "pwsh") => {
                ShellEnvironmentSyntax::PowerShell
            }
            Some(name) if name == "cmd" => ShellEnvironmentSyntax::Cmd,
            _ if cfg!(windows) => ShellEnvironmentSyntax::PowerShell,
            _ => ShellEnvironmentSyntax::Posix,
        };
        if let Some(object) = value.as_object_mut() {
            for key in ["command", "script", "code"] {
                if let Some(Value::String(text)) = object.get_mut(key) {
                    *text = match pentect_agent::wrap_shell_command_from_active_memory_store(
                        tool_name.unwrap_or("shell"),
                        text,
                    )? {
                        Some(wrapped) => wrapped,
                        None => resolve_shell_text_safely_with_context(
                            text,
                            allow_direct_posix_secrets,
                            environment_syntax,
                            resolve,
                        )?,
                    };
                }
            }
            // Non-command metadata is structured data and remains safe to
            // resolve through JSON serialization.
            for (key, nested) in object {
                if !matches!(key.as_str(), "command" | "script" | "code") {
                    resolve_value_strings_with(nested, resolve)?;
                }
            }
            return Ok(());
        }
    }
    resolve_value_strings_with(value, resolve)
}

pub(crate) fn is_free_form_shell_tool(name: Option<&str>) -> bool {
    name.is_some_and(|name| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "bash" | "shell" | "powershell" | "pwsh" | "cmd" | "exec_command" | "shell_command"
        )
    })
}

pub(crate) fn resolve_shell_text_safely<R>(text: &str, resolve: &mut R) -> Result<String, String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    if let Some(wrapped) =
        pentect_agent::wrap_shell_command_from_active_memory_store("exec_command", text)?
    {
        return Ok(wrapped);
    }
    let environment_syntax = if cfg!(windows) {
        ShellEnvironmentSyntax::PowerShell
    } else {
        ShellEnvironmentSyntax::Posix
    };
    resolve_shell_text_safely_with_context(text, !cfg!(windows), environment_syntax, resolve)
}

fn resolve_shell_text_safely_with_context<R>(
    text: &str,
    allow_direct_posix_secrets: bool,
    environment_syntax: ShellEnvironmentSyntax,
    resolve: &mut R,
) -> Result<String, String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut environment = Vec::new();
    while let Some((start, end)) = next_shell_secret_reference(rest) {
        let absolute_start = text.len().saturating_sub(rest.len()).saturating_add(start);
        out.push_str(&rest[..start]);
        let reference = &rest[start..end];
        let resolved = resolve(reference)?;
        if resolved == reference {
            out.push_str(&resolved);
        } else if let Some((syntax, name)) = shell_environment_reference(reference) {
            environment.push((syntax, name.to_string(), resolved));
            out.push_str(reference);
        } else if shell_safe_secret_token(&resolved) {
            out.push_str(&resolved);
        } else if direct_secret_is_safe_in_shell_context(
            text,
            absolute_start,
            end - start,
            &resolved,
            allow_direct_posix_secrets,
        ) {
            if text.as_bytes().get(absolute_start.wrapping_sub(1)) == Some(&b'\'')
                && text.as_bytes().get(absolute_start + end - start) == Some(&b'\'')
            {
                out.push_str(&resolved.replace('\'', "'\\''"));
            } else {
                out.push_str(&resolved);
            }
        } else if !resolved
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n'))
            && (environment_syntax != ShellEnvironmentSyntax::Cmd
                || shell_safe_secret_token(&resolved))
            && pentect_core::parse_placeholder(reference).is_ok()
        {
            let parts = pentect_core::parse_placeholder(reference)
                .expect("placeholder was validated in the branch condition");
            let name = format!("PENTECT_{}_{}", parts.label, parts.hash);
            environment.push((environment_syntax, name.clone(), resolved));
            match environment_syntax {
                ShellEnvironmentSyntax::PowerShell => out.push_str(&format!("$env:{name}")),
                ShellEnvironmentSyntax::Posix => out.push_str(&format!("${{{name}}}")),
                ShellEnvironmentSyntax::Cmd => out.push_str(&format!("%{name}%")),
            }
        } else {
            diagnostic("shell-secret-unresolved", "resolution", "tool-input", false);
            out.push_str(reference);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    Ok(inject_shell_environment(out, environment))
}

fn direct_secret_is_safe_in_shell_context(
    command: &str,
    start: usize,
    length: usize,
    value: &str,
    allow_single_quoted_value: bool,
) -> bool {
    if value
        .chars()
        .any(|character| matches!(character, '\0' | '\r' | '\n'))
    {
        return false;
    }
    let bytes = command.as_bytes();
    if allow_single_quoted_value
        && start > 0
        && bytes.get(start - 1) == Some(&b'\'')
        && bytes.get(start + length) == Some(&b'\'')
    {
        return true;
    }
    inside_quoted_here_document(command, start)
}

fn inside_quoted_here_document(command: &str, position: usize) -> bool {
    for (marker, quote) in [("<<'", '\''), ("<<\"", '"')] {
        let mut search_from = 0usize;
        while let Some(relative) = command[search_from..position].find(marker) {
            let marker_start = search_from + relative;
            let delimiter_start = marker_start + marker.len();
            let Some(delimiter_end_relative) = command[delimiter_start..position].find(quote)
            else {
                break;
            };
            let delimiter_end = delimiter_start + delimiter_end_relative;
            let delimiter = &command[delimiter_start..delimiter_end];
            if delimiter.is_empty()
                || delimiter.len() > 64
                || !delimiter
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                search_from = delimiter_end.saturating_add(1);
                continue;
            }
            let Some(content_start_relative) = command[delimiter_end + 1..].find('\n') else {
                break;
            };
            let content_start = delimiter_end + 1 + content_start_relative + 1;
            let closing = format!("\n{delimiter}");
            let Some(content_end_relative) = command[content_start..].find(&closing) else {
                break;
            };
            let content_end = content_start + content_end_relative;
            if position >= content_start && position < content_end {
                return true;
            }
            search_from = delimiter_end.saturating_add(1);
        }
    }
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShellEnvironmentSyntax {
    PowerShell,
    Posix,
    Cmd,
}

fn shell_environment_reference(reference: &str) -> Option<(ShellEnvironmentSyntax, &str)> {
    if reference
        .as_bytes()
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"$env:"))
        && reference.len() > 5
    {
        return Some((ShellEnvironmentSyntax::PowerShell, &reference[5..]));
    }
    if let Some(name) = reference
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
    {
        return Some((ShellEnvironmentSyntax::Posix, name));
    }
    if let Some(name) = reference.strip_prefix('$') {
        return Some((ShellEnvironmentSyntax::Posix, name));
    }
    reference
        .strip_prefix('%')
        .and_then(|value| value.strip_suffix('%'))
        .map(|name| (ShellEnvironmentSyntax::Cmd, name))
}

fn inject_shell_environment(
    command: String,
    bindings: Vec<(ShellEnvironmentSyntax, String, String)>,
) -> String {
    let Some(syntax) = bindings.first().map(|binding| binding.0) else {
        return command;
    };
    let mut unique = std::collections::BTreeMap::new();
    for (binding_syntax, name, value) in bindings {
        if binding_syntax == syntax {
            unique.insert(name.to_ascii_lowercase(), (name, value));
        }
    }
    match syntax {
        ShellEnvironmentSyntax::PowerShell => {
            let prefix = unique
                .into_values()
                .map(|(name, value)| format!("$env:{name} = '{}'; ", value.replace('\'', "''")))
                .collect::<String>();
            format!("{prefix}{command}")
        }
        ShellEnvironmentSyntax::Posix => {
            let assignments = unique
                .into_values()
                .map(|(name, value)| format!("{name}='{}'", value.replace('\'', "'\\''")))
                .collect::<Vec<_>>()
                .join(" ");
            format!("export {assignments}; {command}")
        }
        ShellEnvironmentSyntax::Cmd => {
            let assignments = unique
                .into_values()
                .filter_map(|(name, value)| {
                    if shell_safe_secret_token(&value) {
                        Some(format!("set \"{name}={value}\" && "))
                    } else {
                        diagnostic("cmd-binding-skipped", "resolution", "tool-input", false);
                        None
                    }
                })
                .collect::<String>();
            format!("{assignments}{command}")
        }
    }
}

fn next_shell_secret_reference(text: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    for start in 0..bytes.len() {
        if bytes[start..].starts_with(b"<<") {
            if let Some(close) = text[start + 2..].find(">>") {
                let end = start + 2 + close + 2;
                if pentect_core::parse_placeholder(&text[start..end]).is_ok() {
                    return Some((start, end));
                }
            }
        }
        if bytes[start] == b'$' {
            if bytes
                .get(start..start.saturating_add(5))
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"$env:"))
            {
                let name_start = start + 5;
                let end = shell_env_name_end(bytes, name_start);
                if end > name_start {
                    return Some((start, end));
                }
            } else if bytes.get(start + 1) == Some(&b'{') {
                let name_start = start + 2;
                let end = shell_env_name_end(bytes, name_start);
                if end > name_start && bytes.get(end) == Some(&b'}') {
                    return Some((start, end + 1));
                }
            } else {
                let name_start = start + 1;
                let end = shell_env_name_end(bytes, name_start);
                if end > name_start {
                    return Some((start, end));
                }
            }
        }
        if bytes[start] == b'%' {
            let name_start = start + 1;
            let end = shell_env_name_end(bytes, name_start);
            if end > name_start && bytes.get(end) == Some(&b'%') {
                return Some((start, end + 1));
            }
        }
    }
    None
}

fn shell_env_name_end(bytes: &[u8], mut end: usize) -> usize {
    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
        end += 1;
    }
    end
}

fn shell_safe_secret_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'+' | b'=')
        })
}

#[cfg(test)]
fn resolve_known_text(text: &str) -> Result<String, String> {
    match pentect_agent::resolve_known_text_from_active_memory_store(text) {
        Ok(Some(resolved)) => Ok(resolved),
        Ok(None) => Ok(text.to_string()),
        Err(_error) => {
            diagnostic(
                "tool-input-restore-skipped",
                "resolution",
                "tool-input",
                false,
            );
            Ok(text.to_string())
        }
    }
}

pub(crate) fn request_scoped_resolver() -> impl FnMut(&str) -> Result<String, String> + Send {
    let resolver = pentect_agent::ActiveMemoryStoreResolver::new();
    move |text| match &resolver {
        Ok(resolver) => match resolver.resolve_known_text(text) {
            Ok(Some(resolved)) => Ok(resolved),
            Ok(None) => Ok(text.to_string()),
            Err(_error) => {
                diagnostic(
                    "tool-input-restore-skipped",
                    "resolution",
                    "tool-input",
                    false,
                );
                Ok(text.to_string())
            }
        },
        Err(_error) => {
            diagnostic(
                "tool-input-restore-skipped",
                "resolution",
                "tool-input",
                false,
            );
            Ok(text.to_string())
        }
    }
}

fn parse_upstream_base(value: &str) -> Result<reqwest::Url, String> {
    crate::upstream::parse_base(value, "Anthropic Messages")
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

fn reqwest_stream_error(error: &reqwest::Error) -> io::Error {
    let message = reqwest_error_message("Claude upstream stream failed", error);
    io::Error::new(io::ErrorKind::ConnectionAborted, message)
}

fn join_upstream_url(base: &reqwest::Url, path_and_query: &str) -> Result<reqwest::Url, String> {
    crate::upstream::join_url(base, path_and_query, "Anthropic Messages")
}

fn classify_anthropic_endpoint(path_and_query: &str) -> AnthropicEndpoint {
    let path = path_and_query.split('?').next().unwrap_or(path_and_query);
    if path.ends_with("/v1/messages") {
        AnthropicEndpoint::Messages
    } else if path.ends_with("/v1/messages/count_tokens") {
        AnthropicEndpoint::CountTokens
    } else if path.ends_with("/v1/messages/batches") || path.contains("/v1/messages/batches/") {
        AnthropicEndpoint::MessageBatches
    } else if path.ends_with("/v1/complete") {
        AnthropicEndpoint::Complete
    } else if path.ends_with("/v1/files") || path.contains("/v1/files/") {
        AnthropicEndpoint::Files
    } else if path.ends_with("/v1/models") || path.contains("/v1/models/") {
        AnthropicEndpoint::Models
    } else if path == "/api/hello" {
        AnthropicEndpoint::Health
    } else {
        AnthropicEndpoint::Unknown
    }
}

fn enforce_known_anthropic_endpoint(
    endpoint: AnthropicEndpoint,
    block_unknown_formats: bool,
) -> Result<(), String> {
    if endpoint != AnthropicEndpoint::Unknown {
        return Ok(());
    }
    if block_unknown_formats {
        return Err("unknown format blocked: Anthropic endpoint is not supported; set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through".to_string());
    }
    if !WARNED_UNKNOWN_ENDPOINT.swap(true, Ordering::Relaxed) {
        diagnostic("unknown-endpoint", "protocol", "unknown", false);
    }
    Ok(())
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
        .map_err(|error| format!("could not create Claude HTTP proxy token: {error}"))?;
    let token = data_encoding::HEXLOWER.encode(&bytes);
    bytes.zeroize();
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn uploaded_file_coverage_is_reused_after_anthropic_registry_restart() {
        const SCOPE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pentect-anthropic-attestation-{}-{nonce}",
            std::process::id()
        ));
        let store = crate::http_files::FileAttestationStore::open(&root).unwrap();
        store
            .remember(
                "anthropic",
                "https://gateway.example",
                SCOPE,
                "file-restart",
                crate::http_files::Coverage::Full,
            )
            .unwrap();
        drop(store);

        let reopened = crate::http_files::FileAttestationStore::open(&root).unwrap();
        let files = StdMutex::new(HashMap::new());
        hydrate_anthropic_attested_files_from_sources(
            br#"{"messages":[{"content":[{"type":"document","source":{"type":"file","file_id":"file-restart"}}]}]}"#,
            &files,
            &reopened,
            "https://gateway.example",
            SCOPE,
        )
        .await
        .unwrap();
        assert_eq!(
            crate::http_files::scoped_file_coverage(&files.lock().unwrap(), SCOPE, "file-restart"),
            Some(crate::http_files::Coverage::Full)
        );
        let other_files = StdMutex::new(HashMap::new());
        hydrate_anthropic_attested_files_from_sources(
            br#"{"file_id":"file-restart"}"#,
            &other_files,
            &reopened,
            "https://other.example",
            SCOPE,
        )
        .await
        .unwrap();
        assert!(other_files.lock().unwrap().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

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
                "pentect-cli-http-e2e-{}-{nonce}",
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

    #[derive(Clone, Copy)]
    enum MockProvider {
        Anthropic,
        OpenAi,
        OpenAiChat,
    }

    fn first_valid_handle(text: &str) -> Option<&str> {
        let mut offset = 0usize;
        while let Some(start_rel) = text[offset..].find("<<") {
            let start = offset + start_rel;
            let end = start + 2 + text[start + 2..].find(">>")? + 2;
            let candidate = &text[start..end];
            if pentect_core::parse_placeholder(candidate).is_ok() {
                return Some(candidate);
            }
            offset = end;
        }
        None
    }

    fn first_openai_file(body: &str) -> Option<(String, String, String)> {
        fn visit(value: &Value) -> Option<(String, String, String)> {
            match value {
                Value::Array(values) => values.iter().find_map(visit),
                Value::Object(object) => {
                    if let Some(data) = object.get("file_data").and_then(Value::as_str) {
                        let (metadata, encoded) = data.split_once(',')?;
                        let media_type = metadata
                            .strip_prefix("data:")?
                            .strip_suffix(";base64")?
                            .to_string();
                        let decoded = data_encoding::BASE64.decode(encoded.as_bytes()).ok()?;
                        let decoded = std::str::from_utf8(&decoded).ok()?;
                        if let Some(handle) = first_valid_handle(decoded) {
                            let filename = object.get("filename")?.as_str()?.to_string();
                            return Some((handle.to_string(), media_type, filename));
                        }
                    }
                    object.values().find_map(visit)
                }
                _ => None,
            }
        }

        serde_json::from_str(body)
            .ok()
            .and_then(|value| visit(&value))
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
        use std::io::Read;

        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 8192];
        let header_end = loop {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0, "client closed before sending HTTP headers");
            request.extend_from_slice(&buffer[..read]);
            if let Some(at) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while request.len() - header_end < content_length {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0, "client closed before sending HTTP body");
            request.extend_from_slice(&buffer[..read]);
        }
        (
            headers,
            request[header_end..header_end + content_length].to_vec(),
        )
    }

    fn mock_upstream(
        provider: MockProvider,
    ) -> (
        String,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::Write;

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (body_tx, body_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (_, body) = read_http_request(&mut stream);
            let body = String::from_utf8(body).unwrap();
            let handle = first_valid_handle(&body)
                .expect("provider should receive a valid Pentect handle")
                .to_string();
            body_tx.send(body).unwrap();

            let (response, content_type) = match provider {
                MockProvider::Anthropic => (
                    serde_json::to_vec(&serde_json::json!({
                        "id": "msg_test",
                        "type": "message",
                        "role": "assistant",
                        "content": [{
                            "type": "tool_use",
                            "id": "tool_test",
                            "name": "SafeTool",
                            "input": {"token": handle}
                        }],
                        "model": "test",
                        "stop_reason": "tool_use",
                        "usage": {"input_tokens": 1, "output_tokens": 1}
                    }))
                    .unwrap(),
                    Some("application/json"),
                ),
                MockProvider::OpenAi => {
                    let event = serde_json::json!({
                        "type": "response.output_item.done",
                        "item": {
                            "type": "custom_tool_call",
                            "name": "exec_command",
                            "input": format!("python hash.py {handle}")
                        }
                    });
                    (
                        format!("event: response.output_item.done\ndata: {event}\n\n").into_bytes(),
                        None,
                    )
                }
                MockProvider::OpenAiChat => {
                    let arguments = format!(r#"{{"command":"echo {handle}"}}"#);
                    let split = arguments.len() / 2;
                    let first = serde_json::json!({
                        "id": "chat_test",
                        "object": "chat.completion.chunk",
                        "choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [{
                            "index": 0, "id": "call_test", "type": "function",
                            "function": {"name": "shell", "arguments": &arguments[..split]}
                        }]}, "finish_reason": null}]
                    });
                    let second = serde_json::json!({
                        "id": "chat_test",
                        "object": "chat.completion.chunk",
                        "choices": [{"index": 0, "delta": {"tool_calls": [{
                            "index": 0, "function": {"arguments": &arguments[split..]}
                        }]}, "finish_reason": null}]
                    });
                    let finish = serde_json::json!({
                        "id": "chat_test",
                        "object": "chat.completion.chunk",
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]
                    });
                    (
                        format!(
                            "data: {first}\n\ndata: {second}\n\ndata: {finish}\n\ndata: [DONE]\n\n"
                        )
                        .into_bytes(),
                        Some("text/event-stream"),
                    )
                }
            };
            write!(stream, "HTTP/1.1 200 OK\r\n").unwrap();
            if let Some(content_type) = content_type {
                write!(stream, "Content-Type: {content_type}\r\n").unwrap();
            }
            write!(
                stream,
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(&response).unwrap();
            stream.flush().unwrap();
        });
        (format!("http://{address}"), body_rx, thread)
    }

    fn mock_openai_file_upstream(
        file_body: String,
    ) -> (
        String,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::Write;

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (body_tx, body_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let (mut file_stream, _) = listener.accept().unwrap();
            let (file_headers, file_request_body) = read_http_request(&mut file_stream);
            assert!(file_headers.starts_with("GET /files/file-test/content "));
            assert!(file_headers
                .lines()
                .any(|line| line.eq_ignore_ascii_case("authorization: bearer synthetic-test")));
            assert!(file_request_body.is_empty());
            write!(
                file_stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"notes.txt\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                file_body.len()
            )
            .unwrap();
            file_stream.write_all(file_body.as_bytes()).unwrap();
            file_stream.flush().unwrap();

            let (mut response_stream, _) = listener.accept().unwrap();
            let (_, body) = read_http_request(&mut response_stream);
            let body = String::from_utf8(body).unwrap();
            let handle = first_openai_file(&body)
                .expect("provider should receive a handle for fetched file content")
                .0;
            body_tx.send(body).unwrap();
            let event = serde_json::json!({
                "type": "response.output_item.done",
                "item": {
                    "type": "custom_tool_call",
                    "name": "exec_command",
                    "input": format!("python hash.py {handle}")
                }
            });
            let response = format!("event: response.output_item.done\ndata: {event}\n\n");
            write!(
                response_stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
            response_stream.flush().unwrap();
        });
        (format!("http://{address}"), body_rx, thread)
    }

    #[test]
    fn provider_boundary_masks_plaintext_and_restores_only_tool_arguments() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        // Build the synthetic credential at runtime so repository scanners do
        // not mistake test data for a committed live credential.
        let secret = [
            "rpa_",
            "ZYXWVUTS",
            "RQPONMLK",
            "JIHGFEDC",
            "BA098765",
            "4321fedcba",
        ]
        .concat();
        let dotenv = format!("RUNPOD_API_KEY={secret}\n");
        let mut probe = pentect_agent::ActiveToolOutputMasker::new().unwrap();
        let protected = probe.mask_prompt_text(&dotenv).unwrap().unwrap();
        assert!(
            !protected.contains(secret.as_str()),
            "dotenv probe was not masked"
        );
        assert!(first_valid_handle(&protected).is_some());

        let (anthropic_upstream, anthropic_request, anthropic_thread) =
            mock_upstream(MockProvider::Anthropic);
        let anthropic_proxy = ClaudeHttpProxyGuard::start(anthropic_upstream).unwrap();
        let anthropic_response: Value = reqwest::blocking::Client::new()
            .post(format!("{}/v1/messages", anthropic_proxy.base_url()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({
                "model": "test",
                "max_tokens": 32,
                "messages": [{
                    "role": "user",
                    "content": format!("Use this dotenv value:\nRUNPOD_API_KEY={secret}\n")
                }]
                }))
                .unwrap(),
            )
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .bytes()
            .map(|body| serde_json::from_slice(&body).unwrap())
            .unwrap();
        let provider_body = anthropic_request
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        assert!(!provider_body.contains(secret.as_str()));
        assert!(first_valid_handle(&provider_body).is_some());
        assert_eq!(anthropic_response["content"][0]["input"]["token"], secret);
        drop(anthropic_proxy);
        anthropic_thread.join().unwrap();

        let (openai_upstream, openai_request, openai_thread) = mock_upstream(MockProvider::OpenAi);
        let openai_proxy =
            crate::openai_http_proxy::OpenAiHttpProxyGuard::start(openai_upstream).unwrap();
        let openai_response = reqwest::blocking::Client::new()
            .post(format!("{}/v1/responses", openai_proxy.base_url()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({
                "model": "test",
                "stream": true,
                "input": format!("Use this dotenv value:\nRUNPOD_API_KEY={secret}\n")
                }))
                .unwrap(),
            )
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .unwrap();
        let provider_body = openai_request
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        assert!(!provider_body.contains(secret.as_str()));
        assert!(first_valid_handle(&provider_body).is_some());
        assert!(
            !openai_response.contains(secret.as_str()),
            "{openai_response}"
        );
        assert!(!openai_response.contains("<<PENTECT_E2E_TOKEN_"));
        assert!(openai_response.contains("script-b64"), "{openai_response}");
        drop(openai_proxy);
        openai_thread.join().unwrap();

        let (chat_upstream, chat_request, chat_thread) = mock_upstream(MockProvider::OpenAiChat);
        let chat_proxy =
            crate::openai_http_proxy::OpenAiHttpProxyGuard::start(chat_upstream).unwrap();
        let chat_response = reqwest::blocking::Client::new()
            .post(format!("{}/v1/chat/completions", chat_proxy.base_url()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({
                    "model": "test",
                    "stream": true,
                    "messages": [{
                        "role": "user",
                        "content": format!("Use this dotenv value:\nRUNPOD_API_KEY={secret}\n")
                    }]
                }))
                .unwrap(),
            )
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .unwrap();
        let provider_body = chat_request
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        assert!(!provider_body.contains(secret.as_str()));
        assert!(first_valid_handle(&provider_body).is_some());
        assert!(!chat_response.contains(secret.as_str()), "{chat_response}");
        assert!(
            first_valid_handle(&chat_response).is_none(),
            "{chat_response}"
        );
        assert!(chat_response.contains("script-b64"), "{chat_response}");
        drop(chat_proxy);
        chat_thread.join().unwrap();

        for provider in [MockProvider::OpenAi, MockProvider::Anthropic] {
            let (upload_upstream, upload_request, upload_thread) = mock_upstream(provider);
            let (upload_url, guard): (String, Box<dyn std::any::Any>) = match provider {
                MockProvider::OpenAi => {
                    let guard =
                        crate::openai_http_proxy::OpenAiHttpProxyGuard::start(upload_upstream)
                            .unwrap();
                    (format!("{}/v1/files", guard.base_url()), Box::new(guard))
                }
                MockProvider::Anthropic => {
                    let guard = ClaudeHttpProxyGuard::start(upload_upstream).unwrap();
                    (format!("{}/v1/files", guard.base_url()), Box::new(guard))
                }
                MockProvider::OpenAiChat => unreachable!("chat mock is not used for uploads"),
            };
            let boundary = "pentect-provider-boundary";
            let upload_body = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nuser_data\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secrets.env\"\r\nContent-Type: text/plain\r\n\r\n{dotenv}\r\n--{boundary}--\r\n"
            );
            reqwest::blocking::Client::new()
                .post(upload_url)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(upload_body)
                .send()
                .unwrap()
                .error_for_status()
                .unwrap();
            let provider_body = upload_request
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            assert!(!provider_body.contains(secret.as_str()));
            assert!(first_valid_handle(&provider_body).is_some());
            drop(guard);
            upload_thread.join().unwrap();
        }

        let (file_upstream, file_request, file_thread) = mock_openai_file_upstream(dotenv.clone());
        let file_proxy =
            crate::openai_http_proxy::OpenAiHttpProxyGuard::start(file_upstream).unwrap();
        let file_response = reqwest::blocking::Client::new()
            .post(format!("{}/v1/responses", file_proxy.base_url()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::AUTHORIZATION, "Bearer synthetic-test")
            .body(
                serde_json::to_vec(&serde_json::json!({
                    "model": "test",
                    "stream": true,
                    "input": [{
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_file", "file_id": "file-test"}]
                    }]
                }))
                .unwrap(),
            )
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .unwrap();
        let provider_body = file_request
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        assert!(!provider_body.contains(secret.as_str()));
        let (handle, media_type, filename) = first_openai_file(&provider_body)
            .expect("provider should receive the sanitized file and metadata");
        assert_eq!(media_type, "text/plain");
        assert_eq!(filename, "notes.txt");
        assert!(!file_response.contains(secret.as_str()), "{file_response}");
        assert!(!file_response.contains(&handle), "{file_response}");
        assert!(file_response.contains("script-b64"), "{file_response}");
        drop(file_proxy);
        file_thread.join().unwrap();
    }

    #[test]
    fn sse_parser_preserves_normal_text() {
        let input = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello <<SECRET_deadbeef>>\"}}\n\n"
        );
        let output = rewrite_anthropic_sse(input).unwrap();
        assert!(output.contains("hello <<SECRET_deadbeef>>"));
    }

    #[test]
    fn multiline_sse_data_is_joined_for_parsing_control_and_tool_boundaries() {
        let start = concat!(
            "event: content_block_start\r\n",
            "data: {\"type\":\"content_block_start\",\r\n",
            "data: \"index\":4,\"content_block\":{\"type\":\"tool_use\",\"name\":\"Bash\",\"input\":{}}}\r\n\r\n"
        );
        let blocks = parse_sse(start);
        assert_eq!(blocks[0].data.as_ref().unwrap()["index"], 4);
        assert!(matches!(
            sse_tool_boundary(start.as_bytes()),
            SseToolBoundary::Start { index: 4 }
        ));

        let ping = "event: message\ndata: {\"type\":\ndata: \"ping\"}\n\n";
        assert_eq!(sse_control_event(ping.as_bytes()), SseControlEvent::Ping);
    }

    #[test]
    fn streaming_thinking_restores_handles_split_across_events() {
        let events = [
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"before <<CHAR\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"GE_0123456789abcdef>> after\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        ];
        let mut transformer = SseStreamTransformer::new(
            |text: &str| Ok(text.replace("<<CHARGE_0123456789abcdef>>", "local-value")),
            None,
            true,
        );
        let mut output = Vec::new();
        for event in events {
            output.extend(transformer.push(event.as_bytes()).unwrap());
        }
        let output = join_bytes(output);
        assert!(output.contains("local-value"), "{output}");
        assert!(!output.contains("<<CHARGE_"), "{output}");
        assert!(output.contains("thinking_delta"), "{output}");
        assert!(output.contains("\"thinking\""), "{output}");
    }

    #[test]
    fn known_anthropic_endpoints_are_classified_before_forwarding() {
        assert_eq!(
            classify_anthropic_endpoint("/v1/messages"),
            AnthropicEndpoint::Messages
        );
        assert_eq!(
            classify_anthropic_endpoint("/v1/messages/count_tokens?beta=1"),
            AnthropicEndpoint::CountTokens
        );
        assert_eq!(
            classify_anthropic_endpoint("/v1/messages/count_tokens"),
            AnthropicEndpoint::CountTokens
        );
        assert_eq!(
            classify_anthropic_endpoint("/v1/files/file_123?beta=files-api"),
            AnthropicEndpoint::Files
        );
        assert_eq!(
            classify_anthropic_endpoint("/v1/models/model_123"),
            AnthropicEndpoint::Models
        );
        assert_eq!(
            classify_anthropic_endpoint("/api/hello"),
            AnthropicEndpoint::Health
        );
        assert_eq!(
            classify_anthropic_endpoint("/v1/messages/batches"),
            AnthropicEndpoint::MessageBatches
        );
        assert_eq!(
            classify_anthropic_endpoint("/v1/messages/batches/msgbatch_123/results"),
            AnthropicEndpoint::MessageBatches
        );
        assert_eq!(
            classify_anthropic_endpoint("/v1/complete"),
            AnthropicEndpoint::Complete
        );
        assert!(enforce_known_anthropic_endpoint(AnthropicEndpoint::Unknown, true).is_err());
        assert!(enforce_known_anthropic_endpoint(AnthropicEndpoint::Unknown, false).is_ok());
    }

    #[test]
    fn models_request_body_is_rejected_before_anthropic_upstream() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let proxy = ClaudeHttpProxyGuard::start("http://127.0.0.1:9".to_string()).unwrap();
        let secret = ["rpa_", "MODELROUTE", "BODYMUST", "NOTLEAVE", "1234567890"].concat();

        let client = reqwest::blocking::Client::new();
        for path in ["/v1/models", "/v1/models/model_test"] {
            let response = client
                .post(format!("{}{path}", proxy.base_url()))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(serde_json::json!({"note": secret}).to_string())
                .send()
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
            assert!(response
                .text()
                .unwrap()
                .contains("models endpoints do not accept request bodies"));
        }

        let empty_get = client
            .get(format!("{}/v1/models", proxy.base_url()))
            .send()
            .unwrap();
        assert_eq!(empty_get.status(), reqwest::StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn anthropic_tools_mask_model_visible_descriptions_and_schemas() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let secret = ["AKIA", "CSVC3FV5", "KQHYWH8A"].concat();
        let mut request = serde_json::json!({
            "model": "test",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "use the lookup tool"}],
            "tools": [{
                "name": "lookup",
                "description": format!("Use credential {secret}"),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": format!("Query with {secret}")
                        }
                    }
                }
            }]
        });
        let mut masker = pentect_agent::ActiveToolOutputMasker::new().unwrap();

        mask_anthropic_request(
            &mut request,
            &mut masker,
            &HashMap::new(),
            AnthropicEndpoint::Messages,
        )
        .unwrap();

        let tools = &request["tools"];
        assert!(!tools.to_string().contains(&secret), "{tools}");
        assert!(first_valid_handle(tools[0]["description"].as_str().unwrap()).is_some());
        assert!(first_valid_handle(
            tools[0]["input_schema"]["properties"]["query"]["description"]
                .as_str()
                .unwrap()
        )
        .is_some());
        assert_eq!(tools[0]["name"], "lookup");
        assert_eq!(tools[0]["input_schema"]["type"], "object");
        assert_eq!(request["messages"][0]["content"], "use the lookup tool");
    }

    #[test]
    fn legacy_complete_streaming_requests_use_the_local_response_guard() {
        let streaming = br#"{"stream":true}"#;
        assert!(anthropic_request_streaming(
            AnthropicEndpoint::Messages,
            streaming
        ));
        assert!(anthropic_request_streaming(
            AnthropicEndpoint::Complete,
            streaming
        ));
        assert!(!anthropic_request_streaming(
            AnthropicEndpoint::CountTokens,
            streaming
        ));
        assert!(!anthropic_request_streaming(
            AnthropicEndpoint::Complete,
            br#"{"stream":false}"#
        ));
    }

    #[test]
    fn local_auth_path_is_exact_and_removed_before_forwarding() {
        let token = "0123456789abcdef";
        assert_eq!(
            authenticated_request_path("/0123456789abcdef/v1/messages?beta=1", token),
            Some("/v1/messages?beta=1")
        );
        assert_eq!(
            authenticated_request_path("/0123456789abcdef", token),
            Some("/")
        );
        assert_eq!(
            authenticated_request_path("/0123456789abcdefevil/v1/messages", token),
            None
        );
        assert_eq!(
            authenticated_request_path("/wrong/v1/messages", token),
            None
        );
    }

    #[test]
    fn handle_contract_is_stable_preserves_system_and_is_not_duplicated() {
        let mut request = serde_json::json!({
            "system": "existing",
            "messages": [{"role": "user", "content": "use <<SECRET_0123456789abcdef>>"}]
        });
        inject_handle_contract(&mut request, AnthropicEndpoint::Messages);
        assert_eq!(request["system"][0]["text"], "existing");
        assert_eq!(request["system"][1]["text"], HANDLE_CONTRACT);
        inject_handle_contract(&mut request, AnthropicEndpoint::Messages);
        assert_eq!(request["system"].as_array().unwrap().len(), 2);

        let mut empty = serde_json::json!({"messages": []});
        inject_handle_contract(&mut empty, AnthropicEndpoint::Messages);
        assert!(empty.get("system").is_none());
    }

    #[test]
    fn handle_contract_is_added_only_when_a_handle_is_present() {
        let mut clean = serde_json::json!({
            "system": "existing",
            "messages": [{"role": "user", "content": "hello"}]
        });
        inject_handle_contract(&mut clean, AnthropicEndpoint::Messages);
        assert_eq!(clean["system"], "existing");

        let mut protected = serde_json::json!({
            "system": "existing",
            "messages": [{
                "role": "user",
                "content": "use <<SECRET_0123456789abcdef>>"
            }]
        });
        inject_handle_contract(&mut protected, AnthropicEndpoint::Messages);
        assert_eq!(protected["system"][0]["text"], "existing");
        assert_eq!(protected["system"][1]["text"], HANDLE_CONTRACT);
    }

    #[test]
    fn unknown_anthropic_content_blocks_by_default_and_can_be_allowed() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let body = Bytes::from_static(
            br#"{"messages":[{"role":"user","content":[{"type":"future_block","data":"opaque"}]}]}"#,
        );
        let masker = StdMutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let plugins = StdMutex::new(pentect_agent::PluginMiddleware::from_env().unwrap());
        let files = HashMap::new();
        let error = match protect_anthropic_request_body(
            &body,
            &masker,
            &plugins,
            &files,
            AnthropicEndpoint::Messages,
            true,
        ) {
            Ok(_) => panic!("unknown Anthropic block should be rejected"),
            Err(error) => error,
        };
        assert!(error.starts_with("unknown format blocked:"), "{error}");
        assert!(error.contains("future_block"), "{error}");

        let allowed = protect_anthropic_request_body(
            &body,
            &masker,
            &plugins,
            &files,
            AnthropicEndpoint::Messages,
            false,
        )
        .unwrap();
        assert_eq!(allowed.coverage, crate::http_files::Coverage::Partial);
        let allowed: Value = serde_json::from_slice(&allowed.body).unwrap();
        let original: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(allowed["messages"], original["messages"]);
        assert!(allowed.get("system").is_none());
    }

    #[test]
    fn current_anthropic_response_blocks_are_known() {
        let value = serde_json::json!({
            "messages": [{
                "role": "assistant",
                "content": [
                    {"type": "tool_search_tool_result", "tool_use_id": "srvtoolu_1", "content": {}},
                    {"type": "connector_text", "text": "working"},
                    {"type": "fallback", "from": {"model": "a"}, "to": {"model": "b"}}
                ]
            }]
        });
        assert_eq!(
            anthropic_request_unknown_content_kind(&value, AnthropicEndpoint::Messages),
            None
        );
    }

    #[test]
    fn malformed_anthropic_json_obeys_unknown_format_policy() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let body = Bytes::from_static(b"{not-json");
        let masker = StdMutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let plugins = StdMutex::new(pentect_agent::PluginMiddleware::from_env().unwrap());
        let files = HashMap::new();
        assert!(protect_anthropic_request_body(
            &body,
            &masker,
            &plugins,
            &files,
            AnthropicEndpoint::Messages,
            true,
        )
        .is_err());
        let allowed = protect_anthropic_request_body(
            &body,
            &masker,
            &plugins,
            &files,
            AnthropicEndpoint::Messages,
            false,
        )
        .unwrap();
        assert_eq!(allowed.coverage, crate::http_files::Coverage::Partial);
        assert_eq!(allowed.body, body);
    }

    #[test]
    fn batch_and_legacy_completion_prompts_are_masked_at_their_real_boundaries() {
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
        let masker = StdMutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let plugins = StdMutex::new(pentect_agent::PluginMiddleware::from_env().unwrap());
        let files = HashMap::new();

        let batch = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "requests": [{
                    "custom_id": "request-1",
                    "params": {
                        "model": "test",
                        "max_tokens": 8,
                        "messages": [{
                            "role": "user",
                            "content": format!("RUNPOD_API_KEY={secret}")
                        }]
                    }
                }]
            }))
            .unwrap(),
        );
        let protected = protect_anthropic_request_body(
            &batch,
            &masker,
            &plugins,
            &files,
            AnthropicEndpoint::MessageBatches,
            true,
        )
        .unwrap();
        let protected: Value = serde_json::from_slice(&protected.body).unwrap();
        assert!(!protected.to_string().contains(&secret));
        assert!(first_valid_handle(
            protected["requests"][0]["params"]["messages"][0]["content"]
                .as_str()
                .unwrap()
        )
        .is_some());
        assert!(protected.get("system").is_none());
        assert_eq!(
            protected["requests"][0]["params"]["system"][0]["text"],
            HANDLE_CONTRACT
        );

        let completion = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "model": "test",
                "max_tokens_to_sample": 8,
                "prompt": format!("RUNPOD_API_KEY={secret}")
            }))
            .unwrap(),
        );
        let protected = protect_anthropic_request_body(
            &completion,
            &masker,
            &plugins,
            &files,
            AnthropicEndpoint::Complete,
            true,
        )
        .unwrap();
        let protected: Value = serde_json::from_slice(&protected.body).unwrap();
        let prompt = protected["prompt"].as_str().unwrap();
        assert!(!prompt.contains(&secret));
        assert!(first_valid_handle(prompt).is_some());
        assert!(prompt.contains(HANDLE_CONTRACT));
        assert!(protected.get("system").is_none());
    }

    #[test]
    fn mcp_and_execution_history_masks_only_plaintext_payload_fields() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let secret = ["AKIA", "CSVC3FV5", "KQHYWH8A"].concat();
        let encrypted = "opaque-provider-state-must-not-change";
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "model": "test",
                "max_tokens": 8,
                "messages": [
                    {"role": "assistant", "content": [
                        {"type": "mcp_tool_use", "id": "mcp_1", "name": "read_file", "server_name": "files", "input": {"path": secret}},
                        {"type": "server_tool_use", "id": "srv_1", "name": "code_execution", "input": {"code": secret}}
                    ]},
                    {"role": "user", "content": [
                        {"type": "mcp_tool_result", "tool_use_id": "mcp_1", "content": [{"type": "text", "text": secret}]},
                        {"type": "bash_code_execution_tool_result", "tool_use_id": "bash_1", "content": {"type": "bash_code_execution_result", "content": [], "return_code": 0, "stdout": secret, "stderr": secret}},
                        {"type": "code_execution_tool_result", "tool_use_id": "code_1", "content": {"type": "encrypted_code_execution_result", "content": [], "return_code": 0, "encrypted_stdout": encrypted, "stderr": secret}},
                        {"type": "text_editor_code_execution_tool_result", "tool_use_id": "edit_1", "content": {"type": "text_editor_code_execution_view_result", "file_type": "text", "content": secret}},
                        {"type": "text_editor_code_execution_tool_result", "tool_use_id": "edit_2", "content": {"type": "text_editor_code_execution_str_replace_result", "lines": [secret]}},
                        {"type": "bash_code_execution_tool_result", "tool_use_id": "legacy_1", "output": secret}
                    ]}
                ]
            }))
            .unwrap(),
        );
        let masker = StdMutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let plugins = StdMutex::new(pentect_agent::PluginMiddleware::from_env().unwrap());
        let protected = protect_anthropic_request_body(
            &body,
            &masker,
            &plugins,
            &HashMap::new(),
            AnthropicEndpoint::Messages,
            true,
        )
        .unwrap();
        let protected: Value = serde_json::from_slice(&protected.body).unwrap();
        assert!(!protected.to_string().contains(&secret), "{protected}");
        assert_eq!(
            protected["messages"][1]["content"][2]["content"]["encrypted_stdout"],
            encrypted
        );
    }

    #[test]
    fn mcp_tool_result_images_enter_the_unscanned_image_policy() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = TestEnv::install(&store);
        let mut content = serde_json::json!([{
            "type": "mcp_tool_result",
            "tool_use_id": "mcp_1",
            "content": [{"type": "image", "source": {"type": "file_id", "file_id": "unknown"}}]
        }]);
        assert_eq!(
            redact_content_images(&mut content, &HashMap::new()).unwrap_err(),
            "image blocked: image source could not be scanned"
        );
    }

    #[test]
    fn custom_upstream_keeps_base_path_and_merges_queries() {
        let base = parse_upstream_base("https://gateway.example/anthropic?tenant=one").unwrap();
        let joined = join_upstream_url(&base, "/v1/messages?beta=two").unwrap();
        assert_eq!(
            joined.as_str(),
            "https://gateway.example/anthropic/v1/messages?tenant=one&beta=two"
        );
    }

    #[test]
    fn invalid_upstream_schemes_and_fragments_are_rejected() {
        assert!(parse_upstream_base("file:///tmp/socket").is_err());
        assert!(parse_upstream_base("https://gateway.example/#fragment").is_err());
        assert!(parse_upstream_base("https://user:password@gateway.example").is_err());
        assert!(parse_upstream_base("http://127.0.0.1:8080").is_ok());
    }

    #[test]
    fn restored_tool_values_are_json_escaped_and_invalid_json_stays_inert() {
        let mut resolve =
            |text: &str| Ok(text.replace("<<SECRET_one>>", "quoted \" value\\with\nnewline"));
        let restored = resolve_tool_input_json(
            r#"{"command":"use <<SECRET_one>>","nested":["<<SECRET_one>>"]}"#,
            None,
            &mut resolve,
        )
        .unwrap();
        let value: Value = serde_json::from_str(&restored).unwrap();
        assert_eq!(
            value["command"],
            Value::String("use quoted \" value\\with\nnewline".to_string())
        );
        assert_eq!(
            value["nested"][0],
            Value::String("quoted \" value\\with\nnewline".to_string())
        );

        let invalid = r#"{"command":"<<SECRET_one>>"#;
        assert_eq!(
            resolve_tool_input_json(invalid, None, &mut resolve).unwrap(),
            invalid
        );
    }

    #[test]
    fn sse_tool_input_is_reassembled_and_resolved_without_touching_text() {
        let input = concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool_1\",\"name\":\"Bash\",\"input\":{}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"curl <<SE\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"CRET_deadbeefdeadbeef>>\\\"}\"}}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"text_delta\",\"text\":\"keep <<SECRET_deadbeefdeadbeef>>\"}}\n\n"
        );
        let mut resolve =
            |text: &str| Ok(text.replace("<<SECRET_deadbeefdeadbeef>>", "actual-secret"));
        let output = rewrite_anthropic_sse_with(input, &mut resolve).unwrap();
        assert!(output.contains("actual-secret"));
        assert!(output.contains("keep <<SECRET_deadbeefdeadbeef>>"));
    }

    #[test]
    fn streaming_text_passes_as_soon_as_an_event_is_complete() {
        let event = concat!(
            "event: content_block_delta\r\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\r\n\r\n"
        );
        let mut transformer =
            SseStreamTransformer::new(|text: &str| Ok(text.to_string()), None, false);
        let split = event.len() - 2;
        assert!(transformer
            .push(&event.as_bytes()[..split])
            .unwrap()
            .is_empty());
        let output = transformer.push(&event.as_bytes()[split..]).unwrap();
        assert_eq!(output, vec![Bytes::from(event)]);
    }

    #[test]
    fn oversized_streaming_event_fails_closed_without_emitting_pending_bytes() {
        let mut transformer =
            SseStreamTransformer::new(|text: &str| Ok(text.to_string()), None, false);
        transformer.max_pending_bytes = 4;

        let error = transformer.push(b"12345").unwrap_err();
        assert_eq!(error, "Anthropic SSE event exceeded inspection limit");
    }

    #[test]
    fn oversized_streaming_tool_input_fails_closed() {
        let start = concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"input\":{}}}\n\n"
        );
        let delta = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n"
        );
        let mut transformer =
            SseStreamTransformer::new(|text: &str| Ok(text.to_string()), None, false);
        transformer.max_pending_bytes = start.len().max(delta.len());

        assert!(transformer.push(start.as_bytes()).unwrap().is_empty());
        let error = transformer.push(delta.as_bytes()).unwrap_err();
        assert_eq!(error, "Anthropic SSE tool input exceeded inspection limit");
    }

    #[test]
    fn enabled_streaming_text_restores_handles_split_across_events() {
        let start = concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"
        );
        let first = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"before <<CHAR\"}}\n\n"
        );
        let second = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"GE_0123456789abcdef>> after\"}}\n\n"
        );
        let stop = concat!(
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
        );
        let mut transformer = SseStreamTransformer::new(
            |text: &str| Ok(text.replace("<<CHARGE_0123456789abcdef>>", "local-value")),
            None,
            true,
        );
        let mut output = transformer.push(start.as_bytes()).unwrap();
        output.extend(transformer.push(first.as_bytes()).unwrap());
        output.extend(transformer.push(second.as_bytes()).unwrap());
        output.extend(transformer.push(stop.as_bytes()).unwrap());
        let output = join_bytes(output);
        assert!(output.contains("local-value"), "{output}");
        assert!(!output.contains("<<CHARGE_"), "{output}");
    }

    #[test]
    fn streaming_tool_is_held_then_resolved_across_http_chunks() {
        let start = concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool_1\",\"name\":\"Bash\",\"input\":{}}}\n\n"
        );
        let delta_one = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"use <<SE\"}}\n\n"
        );
        let delta_two = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"CRET_deadbeefdeadbeef>>\\\"}\"}}\n\n"
        );
        let stop = concat!(
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n"
        );
        let mut transformer = SseStreamTransformer::new(
            |text: &str| Ok(text.replace("<<SECRET_deadbeefdeadbeef>>", "actual-secret")),
            None,
            false,
        );
        assert!(transformer.push(start.as_bytes()).unwrap().is_empty());
        assert!(transformer.push(delta_one.as_bytes()).unwrap().is_empty());
        let split = delta_two.len() / 2;
        assert!(transformer
            .push(&delta_two.as_bytes()[..split])
            .unwrap()
            .is_empty());
        assert!(transformer
            .push(&delta_two.as_bytes()[split..])
            .unwrap()
            .is_empty());
        let output = transformer.push(stop.as_bytes()).unwrap();
        let output = join_bytes(output);
        assert!(output.contains("actual-secret"));
        assert!(!output.contains("<<SECRET_deadbeefdeadbeef>>"));
    }

    #[test]
    fn parallel_tool_blocks_are_buffered_and_resolved_by_index() {
        let before_last_stop = concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool_1\",\"name\":\"Bash\",\"input\":{}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool_2\",\"name\":\"Bash\",\"input\":{}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"echo <<SECRET_1111111111111111>>\\\"}\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"echo <<SECRET_2222222222222222>>\\\"}\"}}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":2}\n\n"
        );
        let last_stop = concat!(
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n"
        );
        let mut transformer = SseStreamTransformer::new(
            |text: &str| {
                Ok(text
                    .replace("<<SECRET_1111111111111111>>", "first")
                    .replace("<<SECRET_2222222222222222>>", "second"))
            },
            None,
            false,
        );
        assert!(transformer
            .push(before_last_stop.as_bytes())
            .unwrap()
            .is_empty());
        let output = join_bytes(transformer.push(last_stop.as_bytes()).unwrap());
        assert!(output.contains("echo first"), "{output}");
        assert!(output.contains("echo second"), "{output}");
        assert!(!output.contains("<<SECRET_"), "{output}");
        assert!(
            output.find("tool_1").unwrap() < output.find("tool_2").unwrap(),
            "{output}"
        );
    }

    #[test]
    fn streaming_tool_restore_failure_aborts_without_emitting_unresolved_input() {
        let input = concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"name\":\"Bash\",\"input\":{}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"use <<SECRET_deadbeefdeadbeef>>\\\"}\"}}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n"
        );
        let mut transformer =
            SseStreamTransformer::new(|_| Err("memory store unavailable".to_string()), None, false);
        let error = transformer.push(input.as_bytes()).unwrap_err();
        assert!(error.contains("memory store unavailable"), "{error}");
    }

    #[test]
    fn interrupted_tool_stream_fails_closed_without_emitting_handles() {
        let incomplete = concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":3,\"content_block\":{\"type\":\"tool_use\",\"input\":{}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":3,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"key\\\":\\\"<<SECRET_deadbeef>>\"}}\n\n"
        );
        let mut transformer = SseStreamTransformer::new(
            |text: &str| Ok(text.replace("<<SECRET_deadbeef>>", "must-not-appear")),
            None,
            false,
        );
        assert!(transformer.push(incomplete.as_bytes()).unwrap().is_empty());
        let error = transformer.finish().unwrap_err();
        assert!(error.contains("ended before content_block_stop"), "{error}");
    }

    #[test]
    fn unterminated_final_sse_event_is_processed_at_eof() {
        let event = concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"<<SECRET_deadbeef>>\"}}"
        );
        let mut transformer = SseStreamTransformer::new(
            |text: &str| Ok(text.replace("<<SECRET_deadbeef>>", "local-value")),
            None,
            true,
        );
        let output = transformer.push(event.as_bytes()).unwrap();
        assert!(join_bytes(output).contains("content_block_start"));
        let output = join_bytes(transformer.finish().unwrap());
        assert!(output.contains("local-value"), "{output}");
        assert!(!output.contains("<<SECRET_deadbeef>>"), "{output}");
    }

    #[test]
    fn sequential_tool_blocks_are_resolved_independently() {
        let tool = |index: u64, handle: &str| {
            format!(
                "event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":{index},\"content_block\":{{\"type\":\"tool_use\",\"input\":{{}}}}}}\n\n\
                 event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":{index},\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":\"{{\\\"value\\\":\\\"{handle}\\\"}}\"}}}}\n\n\
                 event: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":{index}}}\n\n"
            )
        };
        let mut transformer = SseStreamTransformer::new(
            |text: &str| {
                Ok(text
                    .replace("<<SECRET_one>>", "first")
                    .replace("<<SECRET_two>>", "second"))
            },
            None,
            false,
        );
        let mut output = transformer
            .push(tool(1, "<<SECRET_one>>").as_bytes())
            .unwrap();
        output.extend(
            transformer
                .push(tool(2, "<<SECRET_two>>").as_bytes())
                .unwrap(),
        );
        let output = join_bytes(output);
        assert!(output.contains("first"));
        assert!(output.contains("second"));
        assert!(!output.contains("<<SECRET_"));
    }

    #[test]
    fn error_during_tool_input_discards_unresolved_data_and_terminates_stream() {
        let start = concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"name\":\"Bash\",\"input\":{}}}\n\n"
        );
        let delta = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"key\\\":\\\"<<SECRET_deadbeef>>\"}}\n\n"
        );
        let ping = "event: ping\ndata: {\"type\":\"ping\"}\n\n";
        let error =
            "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\"}}\n\n";
        let after_error = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let mut transformer = SseStreamTransformer::new(
            |text: &str| Ok(text.replace("<<SECRET_deadbeef>>", "must-not-appear")),
            None,
            false,
        );
        assert!(transformer.push(start.as_bytes()).unwrap().is_empty());
        assert!(transformer.push(delta.as_bytes()).unwrap().is_empty());
        assert_eq!(join_bytes(transformer.push(ping.as_bytes()).unwrap()), ping);
        assert_eq!(
            join_bytes(transformer.push(error.as_bytes()).unwrap()),
            error
        );
        assert!(transformer.push(after_error.as_bytes()).unwrap().is_empty());
        assert!(transformer.finish().unwrap().is_empty());
    }

    #[test]
    fn shell_tool_only_resolves_conservative_token_values() {
        let mut safe =
            |text: &str| Ok(text.replace("<<SECRET_0123456789abcdef>>", "abc_DEF-123+/="));
        let restored = resolve_tool_input_json(
            r#"{"command":"curl <<SECRET_0123456789abcdef>>"}"#,
            Some("Bash"),
            &mut safe,
        )
        .unwrap();
        assert!(restored.contains("abc_DEF-123+/="));

        let dangerous_value = "quoted \"; Remove-Item x\nnext";
        let mut dangerous =
            |text: &str| Ok(text.replace("<<SECRET_fedcba9876543210>>", dangerous_value));
        let restored = resolve_tool_input_json(
            r#"{"command":"echo <<SECRET_fedcba9876543210>>"}"#,
            Some("PowerShell"),
            &mut dangerous,
        )
        .unwrap();
        assert!(restored.contains("<<SECRET_fedcba9876543210>>"));
        assert!(!restored.contains(dangerous_value));

        let sudo_password = "fixture@password!";
        let mut sudo =
            |text: &str| Ok(text.replace("<<KEYED_SECRET_a2c25e122d2e002f>>", sudo_password));
        let heredoc = resolve_shell_text_safely(
            "sudo -S cat ./ROOT_ONLY.txt <<'EOF'\n<<KEYED_SECRET_a2c25e122d2e002f>>\nEOF",
            &mut sudo,
        )
        .unwrap();
        assert!(
            heredoc.contains(&format!("\n{sudo_password}\nEOF")),
            "{heredoc}"
        );
        assert!(!heredoc.contains("<<KEYED_SECRET_a2c25e122d2e002f>>"));

        let windows_heredoc = resolve_shell_text_safely_with_context(
            "sudo -S cat ./ROOT_ONLY.txt <<'EOF'\n<<KEYED_SECRET_a2c25e122d2e002f>>\nEOF",
            false,
            ShellEnvironmentSyntax::PowerShell,
            &mut sudo,
        )
        .unwrap();
        assert!(
            windows_heredoc.contains(&format!("\n{sudo_password}\nEOF")),
            "{windows_heredoc}"
        );
        assert!(!windows_heredoc.contains("$env:"), "{windows_heredoc}");
        assert!(
            !windows_heredoc.contains("<<KEYED_SECRET_a2c25e122d2e002f>>"),
            "{windows_heredoc}"
        );

        let single_quoted = resolve_shell_text_safely(
            "sudo -S cat ./ROOT_ONLY.txt <<< '<<KEYED_SECRET_a2c25e122d2e002f>>'",
            &mut sudo,
        )
        .unwrap();
        assert!(single_quoted.contains("<<< 'fixture@password!'"));

        let env_name = "PENTECT_STRIPE_SECRET_KEY_a81f42c7d933";
        let secret = ["sk", "live", "51Qx7K9mN2vR4aBcD8eF"].join("_");
        let mut env = |text: &str| {
            Ok(match text {
                "$env:PENTECT_STRIPE_SECRET_KEY_a81f42c7d933"
                | "${PENTECT_STRIPE_SECRET_KEY_a81f42c7d933}"
                | "$PENTECT_STRIPE_SECRET_KEY_a81f42c7d933"
                | "%PENTECT_STRIPE_SECRET_KEY_a81f42c7d933%" => secret.clone(),
                _ => text.to_string(),
            })
        };
        for (reference, expected_prefix) in [
            (
                format!("$env:{env_name}"),
                format!("$env:{env_name} = '{secret}'; "),
            ),
            (
                format!("${{{env_name}}}"),
                format!("export {env_name}='{secret}'; "),
            ),
            (
                format!("${env_name}"),
                format!("export {env_name}='{secret}'; "),
            ),
            (
                format!("%{env_name}%"),
                format!("set \"{env_name}={secret}\" && "),
            ),
        ] {
            let restored = resolve_shell_text_safely(
                &format!("curl -u {reference}: https://api.stripe.com"),
                &mut env,
            )
            .unwrap();
            assert!(restored.contains(&secret), "{restored}");
            assert!(restored.starts_with(&expected_prefix), "{restored}");
            assert!(restored.contains(&reference), "{restored}");
        }

        let powershell = resolve_shell_text_safely(
            &format!("[Text.Encoding]::UTF8.GetBytes($env:{env_name})"),
            &mut env,
        )
        .unwrap();
        assert!(
            powershell.ends_with(&format!("[Text.Encoding]::UTF8.GetBytes($env:{env_name})")),
            "{powershell}"
        );

        let codex = resolve_tool_input_json(
            &format!(r#"{{"command":"[Text.Encoding]::UTF8.GetBytes($env:{env_name})"}}"#),
            Some("exec_command"),
            &mut env,
        )
        .unwrap();
        let codex: Value = serde_json::from_str(&codex).unwrap();
        let codex = codex["command"].as_str().unwrap();
        assert!(
            codex.starts_with(&format!(
                "$env:{env_name} = 'sk_live_51Qx7K9mN2vR4aBcD8eF'; "
            )),
            "{codex}"
        );

        let handle = "<<KEYED_SECRET_a2c25e122d2e002f>>";
        let direct_secret = "fixture key with @ and 'quote'";
        let mut direct = |text: &str| Ok(text.replace(handle, direct_secret));
        let powershell = resolve_tool_input_json(
            &format!(
                r#"{{"command":"Invoke-RestMethod http://127.0.0.1/check -Headers @{{ Authorization = \"Bearer {handle}\" }}"}}"#
            ),
            Some("PowerShell"),
            &mut direct,
        )
        .unwrap();
        let powershell: Value = serde_json::from_str(&powershell).unwrap();
        let command = powershell["command"].as_str().unwrap();
        assert!(
            command.starts_with(
                "$env:PENTECT_KEYED_SECRET_a2c25e122d2e002f = 'fixture key with @ and ''quote'''; "
            ),
            "{command}"
        );
        assert!(
            command
                .contains("Authorization = \"Bearer $env:PENTECT_KEYED_SECRET_a2c25e122d2e002f\""),
            "{command}"
        );
        assert!(!command.contains(handle), "{command}");
    }

    #[test]
    fn media_policy_rejections_never_enter_general_fail_open() {
        assert!(is_media_policy_rejection(
            "document blocked: secret text detected in PDF"
        ));
        assert!(is_media_policy_rejection(
            "image blocked: image source could not be scanned"
        ));
        assert!(!is_media_policy_rejection(
            "detector temporarily unavailable"
        ));
    }

    #[test]
    fn all_anthropic_tool_use_block_types_enter_tool_middleware() {
        for block_type in ["tool_use", "mcp_tool_use", "server_tool_use"] {
            assert!(anthropic_tool_block_type(block_type), "{block_type}");
        }
        assert!(!anthropic_tool_block_type("tool_result"));
        assert!(!anthropic_tool_block_type("mcp_tool_result"));
    }

    fn join_bytes(chunks: Vec<Bytes>) -> String {
        String::from_utf8(
            chunks
                .into_iter()
                .flat_map(|chunk| chunk.to_vec())
                .collect(),
        )
        .unwrap()
    }
}
