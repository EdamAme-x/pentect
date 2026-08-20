//! OpenAI Responses and Chat Completions gateway used by unmodified clients.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Semaphore};
use zeroize::Zeroize;

use crate::handle_contract::HANDLE_CONTRACT;

const MAX_HTTP_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_PENDING_SSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CHAT_TOOL_CALLS: usize = 1024;
static WARNED_UNKNOWN_ENDPOINT: AtomicBool = AtomicBool::new(false);

fn proxy_diagnostic(reason: &str) {
    pentect_agent::record_diagnostic_activity("openai", reason);
}

type ProxyBodyError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, ProxyBodyError>;
type UpstreamByteStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static>>;

pub(crate) struct OpenAiHttpProxyGuard {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
    failure: Arc<Mutex<Option<String>>>,
}

impl OpenAiHttpProxyGuard {
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
        let failure = Arc::new(Mutex::new(None));
        let thread_failure = Arc::clone(&failure);
        let thread = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    if let Ok(mut failure) = thread_failure.lock() {
                        *failure = Some(format!("runtime initialization failed: {error}"));
                    }
                    let _ = ready_tx.send(Err(format!(
                        "could not start OpenAI HTTP gateway runtime: {error}"
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                if let Err(error) =
                    run_proxy(upstream, headers, thread_auth, ready_tx, shutdown_rx).await
                {
                    if let Ok(mut failure) = thread_failure.lock() {
                        *failure = Some(error);
                    }
                    proxy_diagnostic("gateway-stopped");
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
            failure,
        })
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(crate) fn failure_reason(&self) -> Option<String> {
        self.failure.lock().ok().and_then(|failure| failure.clone())
    }

    pub(crate) fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
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
        file_attestations: crate::http_files::FileAttestationStore::open_default()?,
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
                            let _ = error;
                            proxy_diagnostic("connection-failed");
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

fn build_upstream_client() -> Result<reqwest::Client, String> {
    crate::upstream::client("OpenAI Responses")
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
            proxy_diagnostic("request-failed");
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
    let endpoint = classify_openai_endpoint(path_and_query);
    enforce_known_openai_endpoint(endpoint, state.block_unknown_formats)?;
    if method == hyper::Method::GET
        && endpoint == OpenAiEndpoint::Responses
        && request
            .headers()
            .get(hyper::header::UPGRADE)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"))
    {
        // Codex treats 426 as the supported signal to disable Responses
        // WebSockets for this session and retry through HTTP/SSE. Pentect then
        // protects the ordinary POST /responses request below.
        return Ok(text_response(
            StatusCode::UPGRADE_REQUIRED,
            "Pentect uses protected HTTP Responses",
        ));
    }
    let responses_path = method == hyper::Method::POST && endpoint == OpenAiEndpoint::Responses;
    let chat_path = method == hyper::Method::POST && endpoint == OpenAiEndpoint::ChatCompletions;
    let responses_response = matches!(
        endpoint,
        OpenAiEndpoint::Responses | OpenAiEndpoint::ResponsesResource
    );
    let chat_response = endpoint == OpenAiEndpoint::ChatCompletions;
    let protected_request = method == hyper::Method::POST
        && matches!(
            endpoint,
            OpenAiEndpoint::Responses
                | OpenAiEndpoint::InputTokens
                | OpenAiEndpoint::ChatCompletions
        );
    let files_upload = method == hyper::Method::POST && endpoint == OpenAiEndpoint::FilesCollection;
    let upstream_url = join_upstream_url(&state.upstream, path_and_query)?;
    let headers = request.headers().clone();
    let credential_material = state.headers.credential_scope_material(&headers);
    let account_scope = state.file_attestations.account_scope(&credential_material);
    let mut request_coverage = None;
    let mut request_streaming = false;
    let body = if protected_request || files_upload {
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
            let mut remote_budget = crate::remote_content::RemoteRequestBudget::default();
            let original = resolve_openai_file_references(
                body,
                state,
                &headers,
                &account_scope,
                &mut remote_budget,
            )
            .await?;
            let original = resolve_openai_remote_files(original, &mut remote_budget).await?;
            let masker = Arc::clone(&state.masker);
            let plugins = Arc::clone(&state.plugins);
            let files = {
                let registry = state
                    .files
                    .lock()
                    .map_err(|_| "OpenAI file registry lock was poisoned".to_string())?;
                crate::http_files::scoped_file_coverages(&registry, &account_scope)
            };
            let block_unknown_formats = state.block_unknown_formats;
            let protected = tokio::task::spawn_blocking(move || {
                protect_openai_request_body(
                    &original,
                    &masker,
                    &plugins,
                    &files,
                    if chat_path {
                        OpenAiRequestDialect::ChatCompletions
                    } else {
                        OpenAiRequestDialect::Responses
                    },
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
        if state.headers.forward_incoming_header(name.as_str())
            && ((!(protected_request || files_upload) && name == hyper::header::CONTENT_LENGTH)
                || should_forward_request_header(name.as_str()))
            && !connection_headers.contains(&name.as_str().to_ascii_lowercase())
        {
            upstream_request = upstream_request.header(name, value);
        }
    }
    upstream_request = state.headers.apply(upstream_request);
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
        || ((responses_path || chat_path) && request_streaming && response_media_type.is_none());
    let is_json_response = response_media_type.is_some_and(|value| {
        value.eq_ignore_ascii_case("application/json")
            || value.to_ascii_lowercase().ends_with("+json")
    }) || ((responses_response || chat_response)
        && !request_streaming
        && response_media_type.is_none());
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
    if is_event_stream || (!(responses_response || chat_response) && !files_upload) {
        return builder
            .body(streaming_response_body(
                upstream,
                if status.is_success() && responses_path && is_event_stream {
                    StreamTransform::Responses
                } else if status.is_success() && chat_path && is_event_stream {
                    StreamTransform::ChatCompletions
                } else {
                    StreamTransform::None
                },
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
                if state
                    .file_attestations
                    .remember_async(
                        "openai",
                        state.upstream.as_str(),
                        &account_scope,
                        id,
                        coverage,
                    )
                    .await
                    .is_err()
                {
                    eprintln!(
                        "[pentect] file attestation unavailable; uploaded file remains untrusted"
                    );
                } else if let Ok(mut files) = state.files.lock() {
                    crate::http_files::remember_scoped_file_coverage(
                        &mut files,
                        &account_scope,
                        id.to_string(),
                        coverage,
                    );
                } else {
                    eprintln!("[pentect] uploaded file registry unavailable; persistent attestation retained");
                }
            }
        }
    }
    let response_body =
        if (responses_response || chat_response) && status.is_success() && is_json_response {
            let response_body = run_response_plugins(response_body, &state.plugins, "openai")?;
            let rewritten = if chat_response {
                rewrite_chat_completions_json_response(&response_body)
            } else {
                rewrite_openai_json_response(&response_body)
            };
            match rewritten {
                Ok(rewritten) => Bytes::from(rewritten),
                Err(error) => {
                    let _ = error;
                    proxy_diagnostic("response-restore-skipped");
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
        pentect_agent::MiddlewareStage::Response,
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
            let responses_call = object
                .get("type")
                .and_then(|value| value.as_str())
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
            let chat_call = object.get("type").and_then(Value::as_str) == Some("function")
                && object
                    .get("function")
                    .and_then(Value::as_object)
                    .is_some_and(|function| function.get("arguments").is_some());
            let is_call = responses_call || chat_call;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenAiRequestDialect {
    Responses,
    ChatCompletions,
}

fn protect_openai_request_body(
    body: &Bytes,
    masker: &Mutex<pentect_agent::ActiveToolOutputMasker>,
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    files: &HashMap<String, crate::http_files::Coverage>,
    dialect: OpenAiRequestDialect,
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
            let _ = error;
            proxy_diagnostic("request-invalid-json");
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
            pentect_agent::MiddlewareStage::Request,
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
    let unknown_content_kind = openai_request_unknown_content_kind(&value, dialect);
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
        if block_unknown_formats {
            return Err(format!(
                "unknown format blocked: OpenAI request could not be fully inspected ({error}); set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through"
            ));
        }
        let _ = error;
        proxy_diagnostic("request-protection-skipped");
        return Ok(ProtectedJsonBody {
            body: body.clone(),
            coverage: crate::http_files::Coverage::Partial,
            local_response: None,
        });
    }
    inject_handle_contract(&mut value);
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
    account_scope: &str,
    budget: &mut crate::remote_content::RemoteRequestBudget,
) -> Result<Bytes, String> {
    let mut value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return Ok(body),
    };
    resolve_openai_file_reference_values(&mut value, state, request_headers, account_scope, budget)
        .await?;
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|_| "could not encode resolved file reference".to_string())
}

fn resolve_openai_file_reference_values<'a>(
    value: &'a mut Value,
    state: &'a ProxyState,
    request_headers: &'a hyper::HeaderMap,
    account_scope: &'a str,
    budget: &'a mut crate::remote_content::RemoteRequestBudget,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        match value {
            Value::Array(values) => {
                for value in values {
                    resolve_openai_file_reference_values(
                        value,
                        state,
                        request_headers,
                        account_scope,
                        budget,
                    )
                    .await?;
                }
            }
            Value::Object(object) => {
                if object.get("type").and_then(Value::as_str) == Some("file") {
                    let file_id = object
                        .get("file")
                        .and_then(Value::as_object)
                        .and_then(|file| file.get("file_id"))
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    if let Some(file_id) = file_id {
                        let known =
                            known_openai_file_coverage(state, account_scope, &file_id).await?;
                        if known != Some(crate::http_files::Coverage::Full) {
                            let mut remote =
                                fetch_openai_file_content(&file_id, state, request_headers, budget)
                                    .await?;
                            let encoded = data_encoding::BASE64.encode(&remote.bytes);
                            remote.bytes.zeroize();
                            if let Some(file) =
                                object.get_mut("file").and_then(Value::as_object_mut)
                            {
                                file.remove("file_id");
                                file.insert(
                                    "file_data".to_string(),
                                    Value::String(format!(
                                        "data:{};base64,{encoded}",
                                        remote.media_type
                                    )),
                                );
                                file.entry("filename".to_string())
                                    .or_insert(Value::String(remote.filename));
                            }
                        }
                        return Ok(());
                    }
                }
                if object.get("type").and_then(Value::as_str) == Some("input_file") {
                    if let Some(file_id) = object
                        .get("file_id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                    {
                        let known =
                            known_openai_file_coverage(state, account_scope, &file_id).await?;
                        if known == Some(crate::http_files::Coverage::Full) {
                            return Ok(());
                        }
                        let mut remote =
                            fetch_openai_file_content(&file_id, state, request_headers, budget)
                                .await?;
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
                    resolve_openai_file_reference_values(
                        value,
                        state,
                        request_headers,
                        account_scope,
                        budget,
                    )
                    .await?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

async fn known_openai_file_coverage(
    state: &ProxyState,
    account_scope: &str,
    file_id: &str,
) -> Result<Option<crate::http_files::Coverage>, String> {
    known_openai_file_coverage_from_sources(
        &state.files,
        &state.file_attestations,
        state.upstream.as_str(),
        account_scope,
        file_id,
    )
    .await
}

async fn known_openai_file_coverage_from_sources(
    files: &Mutex<HashMap<String, crate::http_files::Coverage>>,
    attestations: &crate::http_files::FileAttestationStore,
    upstream: &str,
    account_scope: &str,
    file_id: &str,
) -> Result<Option<crate::http_files::Coverage>, String> {
    let in_memory = {
        let registry = files
            .lock()
            .map_err(|_| "OpenAI file registry lock was poisoned".to_string())?;
        crate::http_files::scoped_file_coverage(&registry, account_scope, file_id)
    };
    if let Some(coverage) = in_memory {
        return Ok(Some(coverage));
    }
    let attestations = attestations.clone();
    let upstream = upstream.to_string();
    let account_scope = account_scope.to_string();
    let file_id = file_id.to_string();
    let task_scope = account_scope.clone();
    let task_file_id = file_id.clone();
    let coverage = tokio::task::spawn_blocking(move || {
        attestations.coverage("openai", &upstream, &task_scope, &task_file_id)
    })
    .await
    .map_err(|_| "OpenAI file attestation task failed".to_string())??;
    if let Some(coverage) = coverage {
        let mut files = files
            .lock()
            .map_err(|_| "OpenAI file registry lock was poisoned".to_string())?;
        crate::http_files::remember_scoped_file_coverage(
            &mut files,
            &account_scope,
            file_id,
            coverage,
        );
    }
    Ok(coverage)
}

async fn fetch_openai_file_content(
    file_id: &str,
    state: &ProxyState,
    request_headers: &hyper::HeaderMap,
    budget: &mut crate::remote_content::RemoteRequestBudget,
) -> Result<crate::remote_content::RemoteContent, String> {
    if file_id.is_empty()
        || file_id.len() > 200
        || !file_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("OpenAI file ID is invalid".to_string());
    }
    budget.begin()?;
    let path = format!("/files/{file_id}/content");
    let url = join_upstream_url(&state.upstream, &path)?;
    let mut request = state.client.get(url);
    let connection_headers = connection_named_headers(request_headers);
    for (name, value) in request_headers {
        if state.headers.forward_incoming_header(name.as_str())
            && should_forward_request_header(name.as_str())
            && !connection_headers.contains(&name.as_str().to_ascii_lowercase())
        {
            request = request.header(name, value);
        }
    }
    request = state.headers.apply(request);
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
    if let Some(length) = response.content_length() {
        budget.check_declared_size(length)?;
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
        if let Err(error) = budget.consume(chunk.len()) {
            bytes.zeroize();
            return Err(error);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(crate::remote_content::RemoteContent {
        bytes,
        media_type,
        filename,
    })
}

async fn resolve_openai_remote_files(
    body: Bytes,
    budget: &mut crate::remote_content::RemoteRequestBudget,
) -> Result<Bytes, String> {
    let mut value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return Ok(body),
    };
    resolve_openai_remote_file_values(&mut value, budget).await?;
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|_| "could not encode resolved remote attachment".to_string())
}

fn resolve_openai_remote_file_values<'a>(
    value: &'a mut Value,
    budget: &'a mut crate::remote_content::RemoteRequestBudget,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        match value {
            Value::Array(values) => {
                for value in values {
                    resolve_openai_remote_file_values(value, budget).await?;
                }
            }
            Value::Object(object) => {
                let input_type = object.get("type").and_then(Value::as_str);
                if input_type == Some("image_url") {
                    let url = object
                        .get("image_url")
                        .and_then(Value::as_object)
                        .and_then(|image| image.get("url"))
                        .and_then(Value::as_str)
                        .filter(|url| !url.starts_with("data:"))
                        .map(str::to_string);
                    if let Some(url) = url {
                        let mut remote =
                            crate::remote_content::fetch_with_budget(&url, budget).await?;
                        if !remote.media_type.starts_with("image/") {
                            remote.bytes.zeroize();
                            return Err("remote image URL did not return an image".to_string());
                        }
                        let encoded = data_encoding::BASE64.encode(&remote.bytes);
                        remote.bytes.zeroize();
                        if let Some(image) =
                            object.get_mut("image_url").and_then(Value::as_object_mut)
                        {
                            image.insert(
                                "url".to_string(),
                                Value::String(format!(
                                    "data:{};base64,{encoded}",
                                    remote.media_type
                                )),
                            );
                        }
                        return Ok(());
                    }
                }
                if input_type == Some("input_file") {
                    if let Some(url) = object
                        .get("file_url")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                    {
                        let mut remote =
                            crate::remote_content::fetch_with_budget(&url, budget).await?;
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
                        let mut remote =
                            crate::remote_content::fetch_with_budget(&url, budget).await?;
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
                    resolve_openai_remote_file_values(value, budget).await?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

fn openai_request_unknown_content_kind(
    value: &Value,
    dialect: OpenAiRequestDialect,
) -> Option<&str> {
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
    match dialect {
        OpenAiRequestDialect::Responses => value
            .get("input")
            .map(visit)
            .unwrap_or(Some("missing input")),
        OpenAiRequestDialect::ChatCompletions => value
            .get("messages")
            .map(visit_chat_messages)
            .unwrap_or(Some("missing messages")),
    }
}

fn visit_chat_messages(value: &Value) -> Option<&str> {
    let Some(messages) = value.as_array() else {
        return Some("messages must be an array");
    };
    for message in messages {
        let Some(object) = message.as_object() else {
            return Some("non-object message");
        };
        let Some(content) = object.get("content") else {
            continue;
        };
        let Value::Array(parts) = content else {
            if !content.is_string() && !content.is_null() {
                return Some("non-text message content");
            }
            continue;
        };
        for part in parts {
            let Some(kind) = part.get("type").and_then(Value::as_str) else {
                return Some("untyped message content");
            };
            if !matches!(
                kind,
                "text" | "image_url" | "input_text" | "input_image" | "file" | "refusal"
            ) {
                return Some(kind);
            }
        }
    }
    None
}

fn inject_handle_contract(value: &mut Value) {
    if value.get("messages").is_some() {
        inject_chat_handle_contract(value);
        return;
    }
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

fn inject_chat_handle_contract(value: &mut Value) {
    let Some(messages) = value.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    if let Some(message) = messages.iter_mut().find(|message| {
        message
            .get("role")
            .and_then(Value::as_str)
            .is_some_and(|role| matches!(role, "system" | "developer"))
    }) {
        match message.get_mut("content") {
            Some(Value::String(content)) => {
                if !content.contains(HANDLE_CONTRACT) {
                    content.push_str("\n\n");
                    content.push_str(HANDLE_CONTRACT);
                }
                return;
            }
            Some(Value::Array(parts)) => {
                if !parts.iter().any(|part| {
                    part.get("text")
                        .and_then(Value::as_str)
                        .is_some_and(|text| text.contains(HANDLE_CONTRACT))
                }) {
                    parts.push(serde_json::json!({"type": "text", "text": HANDLE_CONTRACT}));
                }
                return;
            }
            _ => {}
        }
    }
    messages.insert(
        0,
        serde_json::json!({"role": "system", "content": HANDLE_CONTRACT}),
    );
}

fn mask_openai_request(
    value: &mut Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    if let Some(Value::String(instructions)) = value.get_mut("instructions") {
        mask_text(instructions, false, masker)?;
    }
    if let Some(input) = value.get_mut("input") {
        mask_openai_input(input, false, masker, files)?;
    }
    if let Some(messages) = value.get_mut("messages") {
        mask_chat_messages(messages, masker, files)?;
    }
    // Tool descriptions and JSON Schemas are sent to the model too. MCP and
    // editor integrations commonly generate them from local state, so they
    // must cross the same masking boundary as messages. Keys are structural;
    // every string value is potentially model-visible text.
    for field in ["tools", "functions", "response_format"] {
        if let Some(definition) = value.get_mut(field) {
            let mut nodes = 0_usize;
            mask_model_definition(definition, 0, &mut nodes, masker)?;
        }
    }
    Ok(())
}

fn mask_model_definition(
    value: &mut Value,
    depth: usize,
    nodes: &mut usize,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    const MAX_DEFINITION_DEPTH: usize = 64;
    const MAX_DEFINITION_NODES: usize = 65_536;
    if depth > MAX_DEFINITION_DEPTH {
        return Err("OpenAI model definition exceeds nesting limit".to_string());
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| "OpenAI model definition is too large".to_string())?;
    if *nodes > MAX_DEFINITION_NODES {
        return Err("OpenAI model definition exceeds item limit".to_string());
    }
    match value {
        Value::String(text) => mask_text(text, false, masker),
        Value::Array(items) => {
            for item in items {
                mask_model_definition(item, depth + 1, nodes, masker)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for item in object.values_mut() {
                mask_model_definition(item, depth + 1, nodes, masker)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn mask_chat_messages(
    value: &mut Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    let Some(messages) = value.as_array_mut() else {
        return Err("OpenAI Chat Completions messages must be an array".to_string());
    };
    for message in messages {
        let Some(object) = message.as_object_mut() else {
            return Err("OpenAI Chat Completions message must be an object".to_string());
        };
        let tool_result = object.get("role").and_then(Value::as_str) == Some("tool");
        if let Some(content) = object.get_mut("content") {
            mask_chat_content(content, tool_result, masker, files)?;
        }
        if let Some(tool_calls) = object.get_mut("tool_calls").and_then(Value::as_array_mut) {
            for call in tool_calls {
                if let Some(arguments) = call
                    .get_mut("function")
                    .and_then(Value::as_object_mut)
                    .and_then(|function| function.get_mut("arguments"))
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
                {
                    let mut protected = arguments;
                    mask_text(&mut protected, true, masker)?;
                    call["function"]["arguments"] = Value::String(protected);
                }
            }
        }
    }
    Ok(())
}

fn mask_chat_content(
    value: &mut Value,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    match value {
        Value::String(text) => mask_text(text, tool_result, masker),
        Value::Null => Ok(()),
        Value::Array(parts) => {
            for part in parts {
                let Some(object) = part.as_object_mut() else {
                    return Err(
                        "OpenAI Chat Completions content part must be an object".to_string()
                    );
                };
                match object
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                {
                    "text" | "input_text" => {
                        if let Some(Value::String(text)) = object.get_mut("text") {
                            mask_text(text, tool_result, masker)?;
                        }
                    }
                    "image_url" => inspect_chat_image(object)?,
                    "input_image" => inspect_openai_image(object)?,
                    "file" => {
                        let Some(file) = object.get_mut("file").and_then(Value::as_object_mut)
                        else {
                            return Err("OpenAI Chat Completions file part is invalid".to_string());
                        };
                        inspect_openai_file(file, tool_result, masker, files)?;
                    }
                    "refusal" => {
                        if let Some(Value::String(text)) = object.get_mut("refusal") {
                            mask_text(text, tool_result, masker)?;
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        }
        _ => Err("OpenAI Chat Completions content has an unsupported shape".to_string()),
    }
}

fn inspect_chat_image(object: &mut serde_json::Map<String, Value>) -> Result<(), String> {
    let Some(image) = object.get_mut("image_url").and_then(Value::as_object_mut) else {
        return unscanned_image_policy();
    };
    let Some(Value::String(url)) = image.get_mut("url") else {
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
                .and_then(|value| value.as_str())
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

fn rewrite_chat_completions_json_response(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|error| format!("OpenAI Chat Completions response was not valid JSON: {error}"))?;
    let mut resolve = crate::claude_http_proxy::request_scoped_resolver();
    rewrite_chat_tool_calls(&mut value, &mut resolve)?;
    serde_json::to_vec(&value)
        .map_err(|error| format!("could not encode restored Chat Completions response: {error}"))
}

fn rewrite_chat_tool_calls<R>(value: &mut Value, resolve: &mut R) -> Result<(), String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    let Some(choices) = value.get_mut("choices").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    for choice in choices {
        let Some(message) = choice.get_mut("message").and_then(Value::as_object_mut) else {
            continue;
        };
        let Some(calls) = message.get_mut("tool_calls").and_then(Value::as_array_mut) else {
            continue;
        };
        for call in calls {
            let tool_name = call
                .get("function")
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let Some(arguments) = call
                .get_mut("function")
                .and_then(Value::as_object_mut)
                .and_then(|function| function.get_mut("arguments"))
                .and_then(|value| value.as_str())
                .map(str::to_owned)
            else {
                continue;
            };
            let restored = crate::claude_http_proxy::resolve_tool_input_json(
                &arguments,
                tool_name.as_deref(),
                resolve,
            )?;
            call["function"]["arguments"] = Value::String(restored);
        }
    }
    Ok(())
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
    transform: StreamTransform,
    chat: ChatStreamState,
    finished: bool,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamTransform {
    None,
    Responses,
    ChatCompletions,
}

fn streaming_response_body(
    response: reqwest::Response,
    transform: StreamTransform,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
) -> ProxyBody {
    let state = StreamState {
        upstream: Box::pin(response.bytes_stream()),
        pending: Vec::new(),
        ready: VecDeque::new(),
        transform,
        chat: ChatStreamState::default(),
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
                Some(Ok(chunk)) if state.transform == StreamTransform::None => {
                    return Some((Ok(Frame::data(chunk)), state));
                }
                Some(Ok(chunk)) => {
                    if state.pending.len().saturating_add(chunk.len()) > MAX_PENDING_SSE_BYTES {
                        if state.transform == StreamTransform::ChatCompletions
                            && !state.chat.calls.is_empty()
                        {
                            state.finished = true;
                            state.ready.push_back(Err(Box::new(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "OpenAI Chat Completions tool input exceeded limit",
                            ))));
                            continue;
                        }
                        proxy_diagnostic("sse-event-limit");
                        state.transform = StreamTransform::None;
                        let mut pending = std::mem::take(&mut state.pending);
                        pending.extend_from_slice(&chunk);
                        state.ready.push_back(Ok(Frame::data(Bytes::from(pending))));
                        continue;
                    }
                    state.pending.extend_from_slice(&chunk);
                    while let Some(end) = first_sse_block_end(&state.pending) {
                        let block = state.pending.drain(..end).collect::<Vec<_>>();
                        let rewritten = match state.transform {
                            StreamTransform::Responses => {
                                rewrite_openai_sse_block(&block, &state.plugins)
                                    .map(|block| vec![block])
                            }
                            StreamTransform::ChatCompletions => {
                                state.chat.rewrite_block(&block, &state.plugins)
                            }
                            StreamTransform::None => Ok(vec![Bytes::from(block)]),
                        };
                        match rewritten {
                            Ok(blocks) => {
                                for block in blocks {
                                    if !block.is_empty() {
                                        state.ready.push_back(Ok(Frame::data(block)));
                                    }
                                }
                            }
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

#[derive(Default)]
struct ChatStreamState {
    calls: HashMap<(u64, u64), ChatStreamCall>,
    buffered_bytes: usize,
}

#[derive(Default)]
struct ChatStreamCall {
    id: String,
    kind: String,
    name: String,
    arguments: String,
}

impl ChatStreamCall {
    fn buffered_len(&self) -> usize {
        self.id.len() + self.kind.len() + self.name.len() + self.arguments.len()
    }
}

impl ChatStreamState {
    fn rewrite_block(
        &mut self,
        block: &[u8],
        plugins: &Mutex<pentect_agent::PluginMiddleware>,
    ) -> Result<Vec<Bytes>, String> {
        let Ok(text) = std::str::from_utf8(block) else {
            return Ok(vec![Bytes::copy_from_slice(block)]);
        };
        let Some(data) = sse_data(text) else {
            return Ok(vec![Bytes::copy_from_slice(block)]);
        };
        if data == "[DONE]" {
            if self.calls.is_empty() {
                return Ok(vec![Bytes::copy_from_slice(block)]);
            }
            return Err(
                "OpenAI Chat Completions stream ended before its tool call completed".to_string(),
            );
        }
        let Ok(mut value) = serde_json::from_str::<Value>(data) else {
            return Ok(vec![Bytes::copy_from_slice(block)]);
        };
        let mut has_tool_delta = false;
        let mut completed_choices = Vec::new();
        if let Some(choices) = value.get_mut("choices").and_then(Value::as_array_mut) {
            for choice in choices {
                let choice_index = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
                if choice
                    .get("finish_reason")
                    .is_some_and(|reason| !reason.is_null())
                {
                    completed_choices.push(choice_index);
                }
                let Some(delta) = choice.get_mut("delta").and_then(Value::as_object_mut) else {
                    continue;
                };
                let Some(tool_calls) = delta
                    .remove("tool_calls")
                    .and_then(|calls| calls.as_array().cloned())
                else {
                    continue;
                };
                has_tool_delta = true;
                for call in tool_calls {
                    let call_index = call.get("index").and_then(Value::as_u64).unwrap_or(0);
                    let key = (choice_index, call_index);
                    if !self.calls.contains_key(&key) && self.calls.len() >= MAX_CHAT_TOOL_CALLS {
                        return Err(
                            "OpenAI Chat Completions produced too many tool calls".to_string()
                        );
                    }
                    let entry = self.calls.entry(key).or_default();
                    if let Some(id) = call.get("id").and_then(Value::as_str) {
                        if entry.id.is_empty() {
                            entry.id.push_str(id);
                            self.buffered_bytes = self.buffered_bytes.saturating_add(id.len());
                        }
                    }
                    if let Some(kind) = call.get("type").and_then(Value::as_str) {
                        if entry.kind.is_empty() {
                            entry.kind.push_str(kind);
                            self.buffered_bytes = self.buffered_bytes.saturating_add(kind.len());
                        }
                    }
                    if let Some(function) = call.get("function") {
                        if let Some(name) = function.get("name").and_then(Value::as_str) {
                            if entry.name.is_empty() {
                                entry.name.push_str(name);
                                self.buffered_bytes =
                                    self.buffered_bytes.saturating_add(name.len());
                            }
                        }
                        if let Some(arguments) = function.get("arguments").and_then(Value::as_str) {
                            entry.arguments.push_str(arguments);
                            self.buffered_bytes =
                                self.buffered_bytes.saturating_add(arguments.len());
                        }
                    }
                    if self.buffered_bytes > MAX_PENDING_SSE_BYTES {
                        return Err("OpenAI Chat Completions tool input exceeded limit".to_string());
                    }
                }
            }
        }

        let mut output = Vec::new();
        for choice_index in completed_choices {
            if self.calls.keys().any(|(choice, _)| *choice == choice_index) {
                output.push(self.completed_tool_block(text, &value, choice_index, plugins)?);
            }
        }
        let keep_original = !has_tool_delta || chat_chunk_has_visible_delta(&value);
        if keep_original {
            output.push(encode_sse_value(text, &value)?);
        }
        Ok(output)
    }

    fn completed_tool_block(
        &mut self,
        template: &str,
        envelope: &Value,
        choice_index: u64,
        plugins: &Mutex<pentect_agent::PluginMiddleware>,
    ) -> Result<Bytes, String> {
        let mut indexes = self
            .calls
            .keys()
            .filter_map(|(choice, index)| (*choice == choice_index).then_some(*index))
            .collect::<Vec<_>>();
        indexes.sort_unstable();
        let mut calls = Vec::with_capacity(indexes.len());
        let plugins = plugins
            .lock()
            .map_err(|_| "OpenAI plugin lock was poisoned".to_string())?;
        let mut resolve = crate::claude_http_proxy::request_scoped_resolver();
        for index in indexes {
            let call = self
                .calls
                .remove(&(choice_index, index))
                .unwrap_or_default();
            self.buffered_bytes = self.buffered_bytes.saturating_sub(call.buffered_len());
            let mut plugin_call = serde_json::json!({
                "type": "function_call",
                "name": call.name,
                "arguments": call.arguments,
            });
            run_openai_tool_plugins(&mut plugin_call, &plugins)?;
            let name = plugin_call
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let arguments = plugin_call
                .get("arguments")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let arguments = crate::claude_http_proxy::resolve_tool_input_json(
                arguments,
                Some(name),
                &mut resolve,
            )?;
            calls.push(serde_json::json!({
                "index": index,
                "id": call.id,
                "type": if call.kind.is_empty() { "function" } else { call.kind.as_str() },
                "function": {"name": name, "arguments": arguments}
            }));
        }
        let mut completed = envelope.clone();
        completed["choices"] = serde_json::json!([{
            "index": choice_index,
            "delta": {"tool_calls": calls},
            "finish_reason": null
        }]);
        encode_sse_value(template, &completed)
    }
}

fn chat_chunk_has_visible_delta(value: &Value) -> bool {
    value
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| {
            choices.iter().any(|choice| {
                choice
                    .get("finish_reason")
                    .is_some_and(|reason| !reason.is_null())
                    || choice
                        .get("delta")
                        .and_then(Value::as_object)
                        .is_some_and(|delta| !delta.is_empty())
            })
        })
}

fn sse_data(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.strip_prefix("data:").map(str::trim_start))
}

fn encode_sse_value(template: &str, value: &Value) -> Result<Bytes, String> {
    let encoded = serde_json::to_string(value)
        .map_err(|error| format!("could not encode OpenAI SSE event: {error}"))?;
    let mut replaced = false;
    let mut output = String::with_capacity(template.len() + encoded.len());
    for line in template.split_inclusive('\n') {
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
        let _ = error;
        proxy_diagnostic("sse-restore-skipped");
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenAiEndpoint {
    Responses,
    ResponsesResource,
    InputTokens,
    ChatCompletions,
    FilesCollection,
    Files,
    Models,
    Health,
    Unknown,
}

fn classify_openai_endpoint(path_and_query: &str) -> OpenAiEndpoint {
    let path = path_and_query.split('?').next().unwrap_or(path_and_query);
    if path.ends_with("/responses/input_tokens") {
        OpenAiEndpoint::InputTokens
    } else if path.ends_with("/responses") {
        OpenAiEndpoint::Responses
    } else if path.contains("/responses/") {
        OpenAiEndpoint::ResponsesResource
    } else if path.ends_with("/chat/completions") {
        OpenAiEndpoint::ChatCompletions
    } else if path.ends_with("/files") {
        OpenAiEndpoint::FilesCollection
    } else if path.contains("/files/") {
        OpenAiEndpoint::Files
    } else if path.ends_with("/models") || path.contains("/models/") {
        OpenAiEndpoint::Models
    } else if path == "/api/hello" {
        OpenAiEndpoint::Health
    } else {
        OpenAiEndpoint::Unknown
    }
}

fn enforce_known_openai_endpoint(
    endpoint: OpenAiEndpoint,
    block_unknown_formats: bool,
) -> Result<(), String> {
    if endpoint != OpenAiEndpoint::Unknown {
        return Ok(());
    }
    if block_unknown_formats {
        return Err("unknown format blocked: OpenAI endpoint is not supported; set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through".to_string());
    }
    if !WARNED_UNKNOWN_ENDPOINT.swap(true, Ordering::Relaxed) {
        proxy_diagnostic("unknown-endpoint");
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

fn parse_upstream_base(value: &str) -> Result<reqwest::Url, String> {
    crate::upstream::parse_base(value, "OpenAI Responses")
}

fn join_upstream_url(base: &reqwest::Url, path_and_query: &str) -> Result<reqwest::Url, String> {
    crate::upstream::join_url(base, path_and_query, "OpenAI Responses")
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

    struct ProviderBoundaryTestEnv {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
        home: std::path::PathBuf,
        process_host_candidate: Option<std::path::PathBuf>,
    }

    impl ProviderBoundaryTestEnv {
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
                "pentect-openai-provider-boundary-{}-{nonce}",
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

    impl Drop for ProviderBoundaryTestEnv {
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
        let mut offset = 0;
        while let Some(relative_start) = text[offset..].find("<<") {
            let start = offset + relative_start;
            let end = start + text[start..].find(">>")? + 2;
            let candidate = &text[start..end];
            if candidate != "<<LABEL_HASH>>" {
                return Some(candidate.to_string());
            }
            offset = end;
        }
        None
    }

    fn mock_chat_upstream() -> (
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
            let mut buffer = [0_u8; 4096];
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
                "id": "chatcmpl_pentect_test",
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": handle,
                        "tool_calls": [{
                            "id": "call_pentect_test",
                            "type": "function",
                            "function": {
                                "name": "shell",
                                "arguments": serde_json::json!({
                                    "command": format!("echo {handle}")
                                }).to_string()
                            }
                        }]
                    },
                    "finish_reason": "tool_calls"
                }]
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

    #[test]
    fn codex_websocket_upgrade_falls_back_to_protected_http() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let proxy = OpenAiHttpProxyGuard::start("http://127.0.0.1:9".to_string()).unwrap();

        let response = reqwest::blocking::Client::new()
            .get(format!("{}/responses", proxy.base_url()))
            .header(reqwest::header::CONNECTION, "Upgrade")
            .header(reqwest::header::UPGRADE, "websocket")
            .send()
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::UPGRADE_REQUIRED);
    }

    #[test]
    fn provider_boundary_masks_chat_requests_and_restores_only_tool_arguments() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let secret = [
            "rpa_",
            "ZYXWVUTS",
            "RQPONMLK",
            "JIHGFEDC",
            "BA098765",
            "4321fedcba",
        ]
        .concat();
        let (upstream, captured, thread) = mock_chat_upstream();
        let proxy = OpenAiHttpProxyGuard::start(upstream).unwrap();
        let response = reqwest::blocking::Client::new()
            .post(format!("{}/v1/chat/completions", proxy.base_url()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({
                    "model": "test",
                    "messages": [{
                        "role": "user",
                        "content": format!("Use RUNPOD_API_KEY={secret}")
                    }],
                    "tools": [{
                        "type": "function",
                        "function": {
                            "name": "shell",
                            "description": format!("Local helper configured with {secret}"),
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "command": {
                                        "type": "string",
                                        "examples": [format!("echo {secret}")]
                                    }
                                }
                            }
                        }
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
        let response: Value = serde_json::from_str(&response).unwrap();
        let request = captured
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        thread.join().unwrap();
        assert!(!request.contains(&secret));
        let handle = first_handle(&request).unwrap();
        assert!(request.matches(&handle).count() >= 3);
        let protected_request: Value = serde_json::from_str(&request).unwrap();
        assert_eq!(protected_request["messages"][0]["content"], HANDLE_CONTRACT);
        assert_eq!(response["choices"][0]["message"]["content"], handle);
        let arguments = response["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        let arguments: Value = serde_json::from_str(arguments).unwrap();
        assert!(
            arguments["command"].as_str().is_some_and(|command| {
                command
                    .strip_prefix("echo ")
                    .is_some_and(|value| value == secret)
            }),
            "trusted shell argument was not restored"
        );
    }

    #[tokio::test]
    async fn uploaded_file_coverage_is_reused_after_openai_registry_restart() {
        const SCOPE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pentect-openai-attestation-{}-{nonce}",
            std::process::id()
        ));
        let store = crate::http_files::FileAttestationStore::open(&root).unwrap();
        store
            .remember(
                "openai",
                "https://gateway.example/v1",
                SCOPE,
                "file-restart",
                crate::http_files::Coverage::Full,
            )
            .unwrap();
        drop(store);

        let reopened = crate::http_files::FileAttestationStore::open(&root).unwrap();
        let files = Mutex::new(HashMap::new());
        assert_eq!(
            known_openai_file_coverage_from_sources(
                &files,
                &reopened,
                "https://gateway.example/v1",
                SCOPE,
                "file-restart",
            )
            .await
            .unwrap(),
            Some(crate::http_files::Coverage::Full)
        );
        assert_eq!(
            crate::http_files::scoped_file_coverage(&files.lock().unwrap(), SCOPE, "file-restart"),
            Some(crate::http_files::Coverage::Full)
        );
        assert_eq!(
            known_openai_file_coverage_from_sources(
                &Mutex::new(HashMap::new()),
                &reopened,
                "https://other.example/v1",
                SCOPE,
                "file-restart",
            )
            .await
            .unwrap(),
            None
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn known_openai_endpoints_are_classified_before_forwarding() {
        assert_eq!(
            classify_openai_endpoint("/v1/responses"),
            OpenAiEndpoint::Responses
        );
        assert_eq!(
            classify_openai_endpoint("/backend-api/codex/responses?stream=true"),
            OpenAiEndpoint::Responses
        );
        assert_eq!(
            classify_openai_endpoint("/v1/responses/input_tokens"),
            OpenAiEndpoint::InputTokens
        );
        assert_eq!(
            classify_openai_endpoint("/v1/chat/completions"),
            OpenAiEndpoint::ChatCompletions
        );
        assert_eq!(
            classify_openai_endpoint("/v1/responses/resp_123"),
            OpenAiEndpoint::ResponsesResource
        );
        assert_eq!(
            classify_openai_endpoint("/v1/responses/resp_123/cancel"),
            OpenAiEndpoint::ResponsesResource
        );
        assert_eq!(
            classify_openai_endpoint("/v1/responses/resp_123/input_items"),
            OpenAiEndpoint::ResponsesResource
        );
        assert_eq!(
            classify_openai_endpoint("/v1/files"),
            OpenAiEndpoint::FilesCollection
        );
        assert_eq!(
            classify_openai_endpoint("/v1/unknown"),
            OpenAiEndpoint::Unknown
        );
        assert!(enforce_known_openai_endpoint(OpenAiEndpoint::Unknown, true).is_err());
        assert!(enforce_known_openai_endpoint(OpenAiEndpoint::Unknown, false).is_ok());
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
    fn chat_response_tool_arguments_are_restored_without_touching_text() {
        let mut value = serde_json::json!({
            "choices": [{"message": {
                "content": "keep <<SECRET_0123456789abcdef>>",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "shell",
                        "arguments": "{\"command\":\"echo <<SECRET_0123456789abcdef>>\"}"
                    }
                }]
            }}]
        });
        let mut resolve =
            |text: &str| Ok(text.replace("<<SECRET_0123456789abcdef>>", "safe-secret-token"));
        rewrite_chat_tool_calls(&mut value, &mut resolve).unwrap();
        assert_eq!(
            value["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"],
            r#"{"command":"echo safe-secret-token"}"#
        );
        assert_eq!(
            value["choices"][0]["message"]["content"],
            "keep <<SECRET_0123456789abcdef>>"
        );
    }

    #[test]
    fn chat_stream_buffers_fragmented_tool_json_until_completion() {
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let mut state = ChatStreamState::default();
        let first = format!(
            "data: {}\n\n",
            serde_json::json!({
                "id": "chat_1", "choices": [{"index": 0, "delta": {
                    "role": "assistant", "tool_calls": [{"index": 0, "id": "call_1",
                    "type": "function", "function": {"name": "shell", "arguments": "{\"command\":\"echo "}}]
                }, "finish_reason": null}]
            })
        );
        let second = format!(
            "data: {}\n\n",
            serde_json::json!({
                "id": "chat_1", "choices": [{"index": 0, "delta": {
                    "tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                    "function": {"name": "shell", "arguments": "ok\"}"}}]
                }, "finish_reason": null}]
            })
        );
        let finish = format!(
            "data: {}\n\n",
            serde_json::json!({
                "id": "chat_1", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]
            })
        );
        let first_out = state.rewrite_block(first.as_bytes(), &plugins).unwrap();
        assert_eq!(first_out.len(), 1);
        assert!(!String::from_utf8_lossy(&first_out[0]).contains("tool_calls"));
        assert!(state
            .rewrite_block(second.as_bytes(), &plugins)
            .unwrap()
            .is_empty());
        let finished = state.rewrite_block(finish.as_bytes(), &plugins).unwrap();
        assert_eq!(finished.len(), 2);
        let completed = String::from_utf8_lossy(&finished[0]);
        assert!(completed.contains("call_1"), "{completed}");
        assert!(!completed.contains("call_1call_1"), "{completed}");
        assert!(!completed.contains("shellshell"), "{completed}");
        assert!(
            completed.contains(r#"{\"command\":\"echo ok\"}"#),
            "{completed}"
        );
        assert!(state.calls.is_empty());
        assert_eq!(state.buffered_bytes, 0);
    }

    #[test]
    fn chat_messages_receive_the_handle_contract_without_replacing_user_text() {
        let mut value = serde_json::json!({
            "model": "gpt-5",
            "messages": [{"role": "user", "content": "use <<SECRET_0123456789abcdef>>"}]
        });
        inject_handle_contract(&mut value);
        assert_eq!(value["messages"][1]["role"], "user");
        assert_eq!(
            value["messages"][1]["content"],
            "use <<SECRET_0123456789abcdef>>"
        );
        assert_eq!(value["messages"][0]["content"], HANDLE_CONTRACT);
    }

    #[test]
    fn chat_array_system_content_receives_the_contract_once() {
        let mut value = serde_json::json!({
            "messages": [{
                "role": "developer",
                "content": [{"type": "text", "text": "Existing instructions"}]
            }]
        });
        inject_chat_handle_contract(&mut value);
        inject_chat_handle_contract(&mut value);
        let parts = value["messages"][0]["content"].as_array().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1]["text"], HANDLE_CONTRACT);
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
        let error = match protect_openai_request_body(
            &body,
            &masker,
            &plugins,
            &files,
            OpenAiRequestDialect::Responses,
            true,
        ) {
            Ok(_) => panic!("unknown OpenAI block should be rejected"),
            Err(error) => error,
        };
        assert!(error.starts_with("unknown format blocked:"), "{error}");
        assert!(error.contains("future_block"), "{error}");

        let allowed = protect_openai_request_body(
            &body,
            &masker,
            &plugins,
            &files,
            OpenAiRequestDialect::Responses,
            false,
        )
        .unwrap();
        assert_eq!(allowed.coverage, crate::http_files::Coverage::Partial);
        let allowed: Value = serde_json::from_slice(&allowed.body).unwrap();
        let original: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(allowed["input"], original["input"]);
        assert_eq!(allowed["instructions"], HANDLE_CONTRACT);
    }

    #[test]
    fn unknown_chat_content_and_missing_messages_are_classified() {
        let future = serde_json::json!({
            "messages": [{"role": "user", "content": [{"type": "future_media"}]}]
        });
        assert_eq!(
            openai_request_unknown_content_kind(&future, OpenAiRequestDialect::ChatCompletions),
            Some("future_media")
        );
        assert_eq!(
            openai_request_unknown_content_kind(
                &serde_json::json!({"model": "test"}),
                OpenAiRequestDialect::ChatCompletions
            ),
            Some("missing messages")
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
        assert_eq!(
            openai_request_unknown_content_kind(&value, OpenAiRequestDialect::Responses),
            None
        );

        let future = serde_json::json!({"input": [{"type": "future_block"}]});
        assert_eq!(
            openai_request_unknown_content_kind(&future, OpenAiRequestDialect::Responses),
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
        assert!(protect_openai_request_body(
            &body,
            &masker,
            &plugins,
            &files,
            OpenAiRequestDialect::Responses,
            true,
        )
        .is_err());
        let allowed = protect_openai_request_body(
            &body,
            &masker,
            &plugins,
            &files,
            OpenAiRequestDialect::Responses,
            false,
        )
        .unwrap();
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
