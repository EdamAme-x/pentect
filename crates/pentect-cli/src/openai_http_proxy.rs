//! OpenAI Responses and Chat Completions gateway used by unmodified clients.
//!
//! Model-bound prompts and local function outputs are masked on requests.
//! Completed client function-call arguments are resolved on responses. Local
//! Provider-generated text restores known handles for the local user unless
//! user or project policy opts out.

use futures_util::{stream, Stream, StreamExt};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::io::{self, Read};
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
    let (kind, retryable) = match reason {
        "gateway-stopped" => ("runtime", false),
        "connection-failed" => ("client-connection", true),
        "request-invalid-json" | "request-content-encoding-skipped" | "unknown-endpoint" => {
            ("protocol", false)
        }
        "request-protection-skipped" | "response-restore-skipped" | "sse-restore-skipped" => {
            ("protection", false)
        }
        "file-attestation-unavailable" | "file-registry-unavailable" => ("storage", true),
        "sse-event-limit" => ("limit", false),
        _ => ("unclassified", false),
    };
    pentect_agent::record_http_diagnostic_activity(
        "openai",
        reason,
        kind,
        "gateway",
        "HTTP",
        None,
        retryable,
        env!("CARGO_PKG_VERSION"),
    );
}

type ProxyBodyError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, ProxyBodyError>;
type UpstreamByteStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static>>;
type HandleResolver = Box<dyn FnMut(&str) -> Result<String, String> + Send>;

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
        Self::start_with_header_env_and_bearer_env(upstream, header_env, None)
    }

    pub(crate) fn start_with_header_env_and_bearer_env(
        upstream: String,
        header_env: &[String],
        bearer_env: Option<&str>,
    ) -> Result<Self, String> {
        let upstream = parse_upstream_base(&upstream)?;
        let headers = crate::upstream::header_overrides_with_bearer_env(header_env, bearer_env)?;
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
            .recv_timeout(crate::GATEWAY_STARTUP_TIMEOUT)
            .map_err(|_| "OpenAI HTTP gateway did not start within 30 seconds".to_string())??;
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
    let initialized = initialize_proxy(upstream, headers, auth).await;
    let (listener, state, local_base_url) = match initialized {
        Ok(initialized) => initialized,
        Err(error) => {
            let _ = ready_tx.send(Err(error));
            return Err("gateway initialization failed".to_string());
        }
    };
    let _ = ready_tx.send(Ok(local_base_url));

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            accepted = listener.accept() => {
                let (socket, _) = accepted
                    .map_err(|_| "gateway listener failed".to_string())?;
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

async fn initialize_proxy(
    upstream: reqwest::Url,
    headers: crate::upstream::HeaderOverrides,
    auth: String,
) -> Result<(TcpListener, Arc<ProxyState>, String), String> {
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
    Ok((listener, state, local_base_url))
}

fn build_upstream_client() -> Result<reqwest::Client, String> {
    crate::upstream::client("OpenAI Responses")
}

async fn proxy_request(
    request: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<ProxyBody>, Infallible> {
    let context = crate::gateway_diagnostics::RequestContext {
        endpoint: classify_openai_endpoint(
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
            "openai",
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
            let local_rejection = crate::gateway_diagnostics::is_local_rejection(&error);
            let response_status = if local_rejection {
                StatusCode::UNPROCESSABLE_ENTITY
            } else {
                StatusCode::BAD_GATEWAY
            };
            crate::gateway_diagnostics::record_request_failure(
                "openai",
                context,
                &error,
                response_status.as_u16(),
            );
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
    let completions_path = method == hyper::Method::POST && endpoint == OpenAiEndpoint::Completions;
    let standalone_search_path =
        method == hyper::Method::POST && endpoint == OpenAiEndpoint::StandaloneSearch;
    let embeddings_path = method == hyper::Method::POST && endpoint == OpenAiEndpoint::Embeddings;
    let image_generation_path =
        method == hyper::Method::POST && endpoint == OpenAiEndpoint::ImageGeneration;
    let audio_speech_path =
        method == hyper::Method::POST && endpoint == OpenAiEndpoint::AudioSpeech;
    let responses_response = matches!(
        endpoint,
        OpenAiEndpoint::Responses | OpenAiEndpoint::ResponsesResource
    );
    let chat_response = endpoint == OpenAiEndpoint::ChatCompletions;
    let completions_response = endpoint == OpenAiEndpoint::Completions;
    let protected_request = method == hyper::Method::POST
        && matches!(
            endpoint,
            OpenAiEndpoint::Responses
                | OpenAiEndpoint::InputTokens
                | OpenAiEndpoint::ChatCompletions
                | OpenAiEndpoint::Completions
                | OpenAiEndpoint::StandaloneSearch
                | OpenAiEndpoint::Embeddings
                | OpenAiEndpoint::ImageGeneration
                | OpenAiEndpoint::AudioSpeech
        );
    let files_upload = method == hyper::Method::POST && endpoint == OpenAiEndpoint::FilesCollection;
    let audio_upload = method == hyper::Method::POST
        && matches!(
            endpoint,
            OpenAiEndpoint::AudioTranscription | OpenAiEndpoint::AudioTranslation
        );
    let upstream_url = join_upstream_url(&state.upstream, path_and_query)?;
    let headers = request.headers().clone();
    let credential_material = state.headers.credential_scope_material(&headers);
    let account_scope = state.file_attestations.account_scope(&credential_material);
    let mut request_coverage = None;
    let mut request_streaming = false;
    let mut inspect_protected_request = protected_request;
    let body = if protected_request || files_upload || audio_upload {
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
        let body = if protected_request {
            let original = body.clone();
            match decode_openai_request_body(body, &headers) {
                Ok(body) => body,
                Err(RequestBodyDecodeError::TooLarge) => {
                    return Ok(text_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Request body too large after decompression",
                    ));
                }
                Err(RequestBodyDecodeError::Invalid(error)) if state.block_unknown_formats => {
                    return Err(error);
                }
                Err(RequestBodyDecodeError::Invalid(_)) => {
                    proxy_diagnostic("request-content-encoding-skipped");
                    inspect_protected_request = false;
                    original
                }
            }
        } else {
            body
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
        } else if audio_upload {
            let content_type = headers
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| "OpenAI audio upload is missing Content-Type".to_string())?
                .to_string();
            let masker = Arc::clone(&state.masker);
            let plugins = Arc::clone(&state.plugins);
            let block_unknown_formats = state.block_unknown_formats;
            let protected = tokio::task::spawn_blocking(move || {
                let mut masker = masker
                    .lock()
                    .map_err(|_| "OpenAI request masker lock was poisoned".to_string())?;
                let plugins = plugins
                    .lock()
                    .map_err(|_| "OpenAI plugin lock was poisoned".to_string())?;
                crate::http_files::protect_audio_multipart_upload_with_plugins(
                    &content_type,
                    &body,
                    &mut masker,
                    &plugins,
                    block_unknown_formats,
                )
            })
            .await
            .map_err(|_| "OpenAI audio protection task failed".to_string())??;
            request_coverage = Some(protected.coverage);
            reqwest::Body::from(protected.body)
        } else if !inspect_protected_request {
            request_coverage = Some(crate::http_files::Coverage::Partial);
            reqwest::Body::from(body)
        } else {
            request_streaming = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|value| value.get("stream").and_then(Value::as_bool))
                .unwrap_or(false);
            let original = if embeddings_path {
                body
            } else {
                let mut remote_budget = crate::remote_content::RemoteRequestBudget::default();
                let original = resolve_openai_file_references(
                    body,
                    state,
                    &headers,
                    &account_scope,
                    &mut remote_budget,
                )
                .await?;
                resolve_openai_remote_files(original, &mut remote_budget).await?
            };
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
                    } else if completions_path {
                        OpenAiRequestDialect::Completions
                    } else if standalone_search_path {
                        OpenAiRequestDialect::StandaloneSearch
                    } else if embeddings_path {
                        OpenAiRequestDialect::Embeddings
                    } else if image_generation_path {
                        OpenAiRequestDialect::ImageGeneration
                    } else if audio_speech_path {
                        OpenAiRequestDialect::AudioSpeech
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
                if request_streaming {
                    return Ok(text_response(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Plugin local responses are unavailable for streaming OpenAI requests",
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
            && ((!(protected_request || files_upload || audio_upload)
                && name == hyper::header::CONTENT_LENGTH)
                || should_forward_request_header(name.as_str()))
            && (!inspect_protected_request || name != hyper::header::CONTENT_ENCODING)
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
    crate::gateway_diagnostics::record_upstream_status(
        "openai",
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
        || ((responses_path || chat_path || completions_path)
            && request_streaming
            && response_media_type.is_none());
    let is_json_response = response_media_type.is_some_and(|value| {
        value.eq_ignore_ascii_case("application/json")
            || value.to_ascii_lowercase().ends_with("+json")
    }) || ((responses_response || chat_response || completions_response)
        && !request_streaming
        && response_media_type.is_none());
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
    if is_event_stream
        || (!(responses_response || chat_response || completions_response) && !files_upload)
    {
        return builder
            .body(streaming_response_body(
                upstream,
                if status.is_success() && responses_path && is_event_stream {
                    StreamTransform::Responses
                } else if status.is_success() && chat_path && is_event_stream {
                    StreamTransform::ChatCompletions
                } else if status.is_success() && completions_path && is_event_stream {
                    StreamTransform::Completions
                } else {
                    StreamTransform::None
                },
                Arc::clone(&state.plugins),
                restore_output,
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
                    proxy_diagnostic("file-attestation-unavailable");
                } else if let Ok(mut files) = state.files.lock() {
                    crate::http_files::remember_scoped_file_coverage(
                        &mut files,
                        &account_scope,
                        id.to_string(),
                        coverage,
                    );
                } else {
                    proxy_diagnostic("file-registry-unavailable");
                }
            }
        }
    }
    let response_body = if (responses_response || chat_response || completions_response)
        && status.is_success()
        && is_json_response
    {
        let response_body = run_response_plugins(response_body, &state.plugins, "openai")?;
        let rewritten = if chat_response {
            rewrite_chat_completions_json_response(&response_body, restore_output)
        } else if completions_response {
            rewrite_completions_json_response(&response_body, restore_output)
        } else {
            rewrite_openai_json_response(&response_body, restore_output)
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
    let mut payload = run_response_plugins_value(value, plugins, provider)?;
    let plugins = plugins
        .lock()
        .map_err(|_| "OpenAI plugin lock was poisoned".to_string())?;
    run_openai_tool_plugins(&mut payload, &plugins)?;
    serde_json::to_vec(&payload)
        .map(Bytes::from)
        .map_err(|error| format!("could not encode plugin response payload: {error}"))
}

fn run_response_plugins_value(
    value: Value,
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    provider: &str,
) -> Result<Value, String> {
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
    Ok(run.payload)
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
            let chat_call = match object.get("type").and_then(Value::as_str) {
                Some("function") => chat_tool_payload_exists(object, "function"),
                Some("custom" | "custom_tool_call") => chat_tool_payload_exists(object, "custom"),
                _ => false,
            };
            let is_call = responses_call || chat_call;
            if is_call {
                run_openai_tool_plugin(object, plugins)?;
            }
            if let Some(legacy) = object
                .get_mut("function_call")
                .and_then(Value::as_object_mut)
            {
                if ["arguments", "input"]
                    .into_iter()
                    .any(|key| legacy.contains_key(key))
                {
                    run_openai_tool_plugin(legacy, plugins)?;
                }
            }
            for child in object.values_mut() {
                run_openai_tool_plugins(child, plugins)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn chat_tool_payload_exists(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_object)
        .is_some_and(|payload| {
            ["arguments", "input"]
                .into_iter()
                .any(|key| payload.contains_key(key))
        })
}

fn run_openai_tool_plugin(
    object: &mut serde_json::Map<String, Value>,
    plugins: &pentect_agent::PluginMiddleware,
) -> Result<(), String> {
    let run = plugins.run(
        pentect_agent::MiddlewareStage::ToolCall,
        Value::Object(object.clone()),
        Some(serde_json::json!({"provider": "openai", "transport": "http"})),
    )?;
    crate::plugins::enforce_tool_plugin_coverage(run.coverage, "OpenAI")?;
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
    Ok(())
}

struct ProtectedJsonBody {
    body: Bytes,
    coverage: crate::http_files::Coverage,
    local_response: Option<Bytes>,
}

enum RequestBodyDecodeError {
    Invalid(String),
    TooLarge,
}

fn decode_openai_request_body(
    body: Bytes,
    headers: &hyper::HeaderMap,
) -> Result<Bytes, RequestBodyDecodeError> {
    let Some(encoding) = headers.get(hyper::header::CONTENT_ENCODING) else {
        return Ok(body);
    };
    let encoding = encoding.to_str().map_err(|_| {
        RequestBodyDecodeError::Invalid(
            "unknown format blocked: OpenAI request Content-Encoding is not valid text".to_string(),
        )
    })?;
    if encoding.eq_ignore_ascii_case("identity") {
        return Ok(body);
    }
    if !encoding.eq_ignore_ascii_case("zstd") {
        return Err(RequestBodyDecodeError::Invalid(format!(
            "unknown format blocked: OpenAI request uses unsupported Content-Encoding '{encoding}'"
        )));
    }

    let decoder = zstd::stream::read::Decoder::new(body.as_ref()).map_err(|error| {
        RequestBodyDecodeError::Invalid(format!(
            "unknown format blocked: OpenAI zstd request could not be decoded ({error})"
        ))
    })?;
    let mut decoded = Vec::new();
    decoder
        .take(MAX_HTTP_BODY_BYTES as u64 + 1)
        .read_to_end(&mut decoded)
        .map_err(|error| {
            RequestBodyDecodeError::Invalid(format!(
                "unknown format blocked: OpenAI zstd request could not be decoded ({error})"
            ))
        })?;
    if decoded.len() > MAX_HTTP_BODY_BYTES {
        return Err(RequestBodyDecodeError::TooLarge);
    }
    Ok(Bytes::from(decoded))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenAiRequestDialect {
    Responses,
    ChatCompletions,
    Completions,
    StandaloneSearch,
    Embeddings,
    ImageGeneration,
    AudioSpeech,
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
    let mask_result = match dialect {
        OpenAiRequestDialect::Embeddings => mask_embeddings_request(&mut value, &mut masker),
        OpenAiRequestDialect::ImageGeneration => {
            mask_json_string_field(&mut value, "prompt", true, &mut masker)
        }
        OpenAiRequestDialect::AudioSpeech => {
            mask_json_string_field(&mut value, "input", true, &mut masker).and_then(|_| {
                mask_json_string_field(&mut value, "instructions", false, &mut masker)
            })
        }
        _ => mask_openai_request(&mut value, &mut masker, files),
    };
    if let Err(error) = mask_result {
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
    if matches!(
        dialect,
        OpenAiRequestDialect::Responses
            | OpenAiRequestDialect::ChatCompletions
            | OpenAiRequestDialect::Completions
    ) {
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
        OpenAiRequestDialect::Completions => completions_unknown_shape(value),
        OpenAiRequestDialect::StandaloneSearch => standalone_search_unknown_shape(value, visit),
        OpenAiRequestDialect::Embeddings => embeddings_unknown_shape(value),
        OpenAiRequestDialect::ImageGeneration => required_string_shape(value, "prompt"),
        OpenAiRequestDialect::AudioSpeech => required_string_shape(value, "input").or_else(|| {
            value
                .get("instructions")
                .filter(|instructions| !instructions.is_string())
                .map(|_| "non-string optional instructions")
        }),
    }
}

fn required_string_shape(value: &Value, field: &str) -> Option<&'static str> {
    let Some(object) = value.as_object() else {
        return Some("non-object request");
    };
    match object.get(field) {
        Some(Value::String(_)) => None,
        Some(_) => Some("non-string required text"),
        None => Some("missing required text"),
    }
}

fn completions_unknown_shape(value: &Value) -> Option<&str> {
    let Some(prompt) = value.as_object().and_then(|object| object.get("prompt")) else {
        return Some("missing completion prompt");
    };
    match prompt {
        Value::String(_) => None,
        Value::Array(items) if items.iter().all(Value::is_string) => None,
        Value::Array(items) if items.iter().all(Value::is_u64) => None,
        Value::Array(items)
            if items.iter().all(|item| {
                item.as_array()
                    .is_some_and(|tokens| tokens.iter().all(Value::is_u64))
            }) =>
        {
            None
        }
        _ => Some("unsupported completion prompt"),
    }
}

fn embeddings_unknown_shape(value: &Value) -> Option<&str> {
    let Some(input) = value.as_object().and_then(|object| object.get("input")) else {
        return Some("missing embeddings input");
    };
    if is_supported_embeddings_input(input) {
        None
    } else {
        Some("unsupported embeddings input")
    }
}

fn is_supported_embeddings_input(input: &Value) -> bool {
    match input {
        Value::String(_) => true,
        Value::Array(items) => {
            items.iter().all(Value::is_string)
                || items.iter().all(Value::is_u64)
                || items.iter().all(|item| {
                    item.as_array()
                        .is_some_and(|tokens| tokens.iter().all(Value::is_u64))
                })
        }
        _ => false,
    }
}

fn standalone_search_unknown_shape<'a>(
    value: &'a Value,
    visit_input: impl Fn(&'a Value) -> Option<&'a str>,
) -> Option<&'a str> {
    let Some(object) = value.as_object() else {
        return Some("non-object search request");
    };
    const TOP_LEVEL_FIELDS: &[&str] = &[
        "id",
        "model",
        "reasoning",
        "input",
        "commands",
        "settings",
        "max_output_tokens",
    ];
    if object
        .keys()
        .any(|field| !TOP_LEVEL_FIELDS.contains(&field.as_str()))
    {
        return Some("unknown search field");
    }
    if !object.get("id").is_some_and(Value::is_string)
        || !object.get("model").is_some_and(Value::is_string)
    {
        return Some("invalid search identity");
    }
    if !object.contains_key("input") && !object.contains_key("commands") {
        return Some("missing search input");
    }
    if let Some(input) = object.get("input") {
        if let Some(kind) = visit_input(input) {
            return Some(kind);
        }
    }
    let commands_value = object.get("commands")?;
    let Some(commands) = commands_value.as_object() else {
        return Some("invalid search commands");
    };
    const COMMAND_FIELDS: &[&str] = &[
        "search_query",
        "image_query",
        "open",
        "click",
        "find",
        "screenshot",
        "finance",
        "weather",
        "sports",
        "time",
        "response_length",
    ];
    commands
        .keys()
        .any(|field| !COMMAND_FIELDS.contains(&field.as_str()))
        .then_some("unknown search command")
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
    if !request_contains_masked_handle(value) {
        return;
    }
    if value.get("messages").is_some() {
        inject_chat_handle_contract(value);
        return;
    }
    if let Some(prompt) = value.get_mut("prompt") {
        inject_completion_handle_contract(prompt);
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

fn inject_completion_handle_contract(prompt: &mut Value) {
    match prompt {
        Value::String(text) if !text.contains(HANDLE_CONTRACT) => {
            text.push_str("\n\n");
            text.push_str(HANDLE_CONTRACT);
        }
        Value::Array(items) if items.iter().all(Value::is_string) => {
            for item in items {
                inject_completion_handle_contract(item);
            }
        }
        _ => {}
    }
}

fn request_contains_masked_handle(value: &Value) -> bool {
    match value {
        Value::String(text) => pentect_agent::contains_pentect_masked_handle(text),
        Value::Array(values) => values.iter().any(request_contains_masked_handle),
        Value::Object(object) => object.values().any(request_contains_masked_handle),
        _ => false,
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
        // Instructions are supplied by the client or provider, not authored by
        // the current user. Prompt-only unmask markers must never take effect
        // here.
        mask_text(instructions, true, masker)?;
    }
    if let Some(input) = value.get_mut("input") {
        mask_openai_input(input, false, masker, files)?;
    }
    if let Some(messages) = value.get_mut("messages") {
        mask_chat_messages(messages, masker, files)?;
    }
    if let Some(prompt) = value.get_mut("prompt") {
        mask_completion_prompt(prompt, masker)?;
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
    // Standalone search commands are derived from the current user request.
    // Scan every string because queries and location/filter values do not use
    // Responses content blocks.
    for (field, external_content) in [
        ("commands", false),
        ("settings", false),
        ("reasoning", true),
    ] {
        if let Some(search_value) = value.get_mut(field) {
            let mut nodes = 0_usize;
            mask_search_value(search_value, external_content, 0, &mut nodes, masker)?;
        }
    }
    Ok(())
}

fn mask_completion_prompt(
    prompt: &mut Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    match prompt {
        Value::String(text) => mask_text(text, false, masker),
        Value::Array(items) if items.iter().all(Value::is_string) => {
            for item in items {
                let Value::String(text) = item else {
                    unreachable!("completion prompt shape checked before masking")
                };
                mask_text(text, false, masker)?;
            }
            Ok(())
        }
        Value::Array(items)
            if items.iter().all(Value::is_u64)
                || items.iter().all(|item| {
                    item.as_array()
                        .is_some_and(|tokens| tokens.iter().all(Value::is_u64))
                }) =>
        {
            Ok(())
        }
        _ => Err("OpenAI completion prompt has an unsupported shape".to_string()),
    }
}

fn mask_json_string_field(
    value: &mut Value,
    field: &str,
    required: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| "OpenAI media request is not an object".to_string())?;
    let Some(value) = object.get_mut(field) else {
        return if required {
            Err(format!("OpenAI media request is missing {field}"))
        } else {
            Ok(())
        };
    };
    let Value::String(text) = value else {
        return Err(format!("OpenAI media request {field} is not text"));
    };
    mask_text(text, false, masker)
}

fn mask_embeddings_request(
    value: &mut Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    let input = value
        .as_object_mut()
        .and_then(|object| object.get_mut("input"))
        .ok_or_else(|| "OpenAI embeddings request is missing input".to_string())?;
    match input {
        Value::String(text) => mask_text(text, false, masker),
        Value::Array(items) if items.iter().all(Value::is_string) => {
            for item in items {
                let Value::String(text) = item else {
                    unreachable!("array shape checked before masking")
                };
                mask_text(text, false, masker)?;
            }
            Ok(())
        }
        Value::Array(items)
            if items.iter().all(Value::is_u64)
                || items.iter().all(|item| {
                    item.as_array()
                        .is_some_and(|tokens| tokens.iter().all(Value::is_u64))
                }) =>
        {
            Ok(())
        }
        _ => Err("OpenAI embeddings input has an unsupported shape".to_string()),
    }
}

fn mask_search_value(
    value: &mut Value,
    external_content: bool,
    depth: usize,
    nodes: &mut usize,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    const MAX_SEARCH_DEPTH: usize = 64;
    const MAX_SEARCH_NODES: usize = 65_536;
    if depth > MAX_SEARCH_DEPTH {
        return Err("OpenAI search request exceeds nesting limit".to_string());
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| "OpenAI search request is too large".to_string())?;
    if *nodes > MAX_SEARCH_NODES {
        return Err("OpenAI search request exceeds item limit".to_string());
    }
    match value {
        Value::String(text) => mask_text(text, external_content, masker),
        Value::Array(items) => {
            for item in items {
                mask_search_value(item, external_content, depth + 1, nodes, masker)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for item in object.values_mut() {
                mask_search_value(item, external_content, depth + 1, nodes, masker)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
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
        // Tool definitions can originate from an MCP server or extension.
        // Treat them as external content so they cannot opt out of masking.
        Value::String(text) => mask_text(text, true, masker),
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
        // Only the current user's message may use unmask()/unpentect(). System,
        // developer, assistant, and tool history can be externally controlled.
        let external_content = object.get("role").and_then(Value::as_str) != Some("user");
        if let Some(content) = object.get_mut("content") {
            mask_chat_content(content, external_content, masker, files)?;
        }
        if let Some(function_call) = object
            .get_mut("function_call")
            .and_then(Value::as_object_mut)
        {
            mask_chat_tool_payload(function_call, masker)?;
        }
        if let Some(tool_calls) = object.get_mut("tool_calls").and_then(Value::as_array_mut) {
            for call in tool_calls {
                for key in ["function", "custom"] {
                    if let Some(payload) = call.get_mut(key).and_then(Value::as_object_mut) {
                        mask_chat_tool_payload(payload, masker)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn mask_chat_tool_payload(
    payload: &mut serde_json::Map<String, Value>,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    for key in ["arguments", "input"] {
        if let Some(Value::String(value)) = payload.get_mut(key) {
            mask_text(value, true, masker)?;
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
            let original = std::mem::take(parts);
            for mut part in original {
                let Some(object) = part.as_object_mut() else {
                    return Err(
                        "OpenAI Chat Completions content part must be an object".to_string()
                    );
                };
                let note = match object
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                {
                    "text" | "input_text" => {
                        if let Some(Value::String(text)) = object.get_mut("text") {
                            mask_text(text, tool_result, masker)?;
                        }
                        None
                    }
                    "image_url" => inspect_chat_image(object)?,
                    "input_image" => inspect_openai_image(object)?,
                    "file" => {
                        let Some(file) = object.get_mut("file").and_then(Value::as_object_mut)
                        else {
                            return Err("OpenAI Chat Completions file part is invalid".to_string());
                        };
                        inspect_openai_file(file, tool_result, masker, files)?;
                        None
                    }
                    "refusal" => {
                        if let Some(Value::String(text)) = object.get_mut("refusal") {
                            mask_text(text, tool_result, masker)?;
                        }
                        None
                    }
                    _ => None,
                };
                parts.push(part);
                if let Some(text) = note {
                    parts.push(serde_json::json!({"type": "text", "text": text}));
                }
            }
            Ok(())
        }
        _ => Err("OpenAI Chat Completions content has an unsupported shape".to_string()),
    }
}

fn inspect_chat_image(
    object: &mut serde_json::Map<String, Value>,
) -> Result<Option<String>, String> {
    let Some(image) = object.get_mut("image_url").and_then(Value::as_object_mut) else {
        return unscanned_image_policy().map(|_| None);
    };
    let Some(Value::String(url)) = image.get_mut("url") else {
        return unscanned_image_policy().map(|_| None);
    };
    let Some((metadata, encoded)) = url.split_once(',') else {
        return unscanned_image_policy().map(|_| None);
    };
    if !metadata.starts_with("data:image/") || !metadata.ends_with(";base64") {
        return unscanned_image_policy().map(|_| None);
    }
    if let Some(protected) = crate::claude_http_proxy::redact_inline_image_data(encoded)? {
        *url = format!("data:image/png;base64,{}", protected.data);
        return Ok(Some(protected.note));
    }
    Ok(None)
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
            let original = std::mem::take(items);
            for mut item in original {
                let note = if item.get("type").and_then(Value::as_str) == Some("input_image") {
                    match item.as_object_mut() {
                        Some(object) => inspect_openai_image(object)?,
                        None => None,
                    }
                } else {
                    mask_openai_input(&mut item, tool_result, masker, files)?;
                    None
                };
                items.push(item);
                if let Some(text) = note {
                    items.push(serde_json::json!({"type": "input_text", "text": text}));
                }
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
                "function_call" | "custom_tool_call" => {
                    // Previous assistant tool calls are sent back to the model as
                    // conversation history. Their locally restored arguments can
                    // contain secrets, so protect both Responses API call shapes.
                    for key in ["arguments", "input"] {
                        if let Some(Value::String(arguments)) = object.get_mut(key) {
                            mask_text(arguments, true, masker)?;
                        }
                    }
                }
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
                "input_image" => {
                    let _ = inspect_openai_image(object)?;
                }
                "input_file" => inspect_openai_file(object, tool_result, masker, files)?,
                "message" => {
                    let external_content =
                        object.get("role").and_then(Value::as_str) != Some("user");
                    if let Some(content) = object.get_mut("content") {
                        mask_openai_input(content, external_content, masker, files)?;
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

fn inspect_openai_image(
    object: &mut serde_json::Map<String, Value>,
) -> Result<Option<String>, String> {
    let Some(Value::String(url)) = object.get_mut("image_url") else {
        return unscanned_image_policy().map(|_| None);
    };
    let Some((metadata, encoded)) = url.split_once(',') else {
        return unscanned_image_policy().map(|_| None);
    };
    if !metadata.starts_with("data:image/") || !metadata.ends_with(";base64") {
        return unscanned_image_policy().map(|_| None);
    }
    if let Some(protected) = crate::claude_http_proxy::redact_inline_image_data(encoded)? {
        *url = format!("data:image/png;base64,{}", protected.data);
        return Ok(Some(protected.note));
    }
    Ok(None)
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

fn rewrite_openai_json_response(body: &[u8], restore_output: bool) -> Result<Vec<u8>, String> {
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|error| format!("OpenAI response was not valid JSON: {error}"))?;
    let mut resolve = crate::claude_http_proxy::request_scoped_resolver();
    rewrite_function_calls(&mut value, &mut resolve)?;
    if restore_output {
        restore_openai_output_text(&mut value, &mut resolve)?;
    }
    serde_json::to_vec(&value)
        .map_err(|error| format!("could not encode restored OpenAI response: {error}"))
}

fn rewrite_chat_completions_json_response(
    body: &[u8],
    restore_output: bool,
) -> Result<Vec<u8>, String> {
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|error| format!("OpenAI Chat Completions response was not valid JSON: {error}"))?;
    let mut resolve = crate::claude_http_proxy::request_scoped_resolver();
    rewrite_chat_tool_calls(&mut value, &mut resolve)?;
    if restore_output {
        restore_chat_output_text(&mut value, &mut resolve)?;
    }
    serde_json::to_vec(&value)
        .map_err(|error| format!("could not encode restored Chat Completions response: {error}"))
}

fn rewrite_completions_json_response(body: &[u8], restore_output: bool) -> Result<Vec<u8>, String> {
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|error| format!("OpenAI Completions response was not valid JSON: {error}"))?;
    if restore_output {
        let mut resolve = crate::claude_http_proxy::request_scoped_resolver();
        restore_completion_output_text(&mut value, &mut resolve)?;
    }
    serde_json::to_vec(&value)
        .map_err(|error| format!("could not encode restored Completions response: {error}"))
}

fn restore_completion_output_text<R>(value: &mut Value, resolve: &mut R) -> Result<(), String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    let Some(choices) = value.get_mut("choices").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    for choice in choices {
        if let Some(Value::String(text)) = choice.get_mut("text") {
            *text = resolve(text)?;
        }
    }
    Ok(())
}

fn restore_openai_output_text<R>(value: &mut Value, resolve: &mut R) -> Result<(), String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    match value {
        Value::Array(values) => {
            for value in values {
                restore_openai_output_text(value, resolve)?;
            }
        }
        Value::Object(object) => {
            let restores_text = matches!(
                object.get("type").and_then(Value::as_str),
                Some("output_text" | "summary_text" | "reasoning_text")
            );
            if restores_text {
                if let Some(Value::String(text)) = object.get_mut("text") {
                    *text = resolve(text)?;
                }
            }
            for key in ["output", "content", "summary", "response", "item"] {
                if let Some(value) = object.get_mut(key) {
                    restore_openai_output_text(value, resolve)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn restore_chat_output_text<R>(value: &mut Value, resolve: &mut R) -> Result<(), String>
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
        if let Some(content) = message.get_mut("content") {
            match content {
                Value::String(text) => *text = resolve(text)?,
                Value::Array(parts) => {
                    for part in parts {
                        if part.get("type").and_then(Value::as_str) == Some("text") {
                            if let Some(Value::String(text)) = part.get_mut("text") {
                                *text = resolve(text)?;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        for field in ["reasoning_content", "reasoning"] {
            if let Some(Value::String(text)) = message.get_mut(field) {
                *text = resolve(text)?;
            }
        }
    }
    Ok(())
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
                        *arguments = if is_custom_call
                            && key == "input"
                            && crate::claude_http_proxy::is_free_form_shell_tool(
                                tool_name.as_deref(),
                            ) {
                            // Custom tools carry completed free-form input rather than
                            // JSON arguments. Only tools whose complete input is a shell
                            // program may receive shell environment injection. In
                            // particular, `functions.exec` carries JavaScript that can
                            // invoke nested tools; prepending `export` to it both breaks
                            // the program and can expose a protected value in a syntax
                            // error.
                            crate::claude_http_proxy::resolve_shell_text_safely(arguments, resolve)?
                        } else if is_custom_call
                            && key == "input"
                            && is_javascript_orchestrator_tool(tool_name.as_deref())
                        {
                            resolve_javascript_orchestrator_tools(arguments, resolve)?
                        } else if is_custom_call && key == "input" {
                            arguments.clone()
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

fn is_javascript_orchestrator_tool(name: Option<&str>) -> bool {
    name.is_some_and(|name| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "exec" | "functions.exec"
        )
    })
}

#[derive(Debug)]
enum JavaScriptTokenKind {
    Identifier(String),
    String(String),
    Punctuation(char),
}

#[derive(Debug)]
struct JavaScriptToken {
    kind: JavaScriptTokenKind,
    start: usize,
    end: usize,
}

/// Restore only literal arguments of recognized nested local tools.
///
/// Codex's `functions.exec` custom tool carries JavaScript which then invokes
/// local tools. The nested calls are not separate provider events, so this HTTP
/// boundary must handle them without treating the complete JavaScript program
/// as a shell script. Unsupported syntax remains inert.
fn resolve_javascript_orchestrator_tools<R>(source: &str, resolve: &mut R) -> Result<String, String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    let tokens = tokenize_javascript_for_local_tools(source);
    let mut replacements = Vec::<(usize, usize, String)>::new();
    let mut index = 0;
    while index + 4 < tokens.len() {
        let Some(tool) = nested_local_tool_at(&tokens, index) else {
            index += 1;
            continue;
        };
        let object_index = index + 4;
        if !token_is_punctuation(&tokens[object_index], '{') {
            index += 1;
            continue;
        }
        let wanted_key = match tool {
            "exec_command" => "cmd",
            "write_stdin" => "chars",
            _ => unreachable!("nested_local_tool_at returns only known tools"),
        };
        let mut brace_depth = 0usize;
        let mut cursor = object_index;
        while cursor < tokens.len() {
            match tokens[cursor].kind {
                JavaScriptTokenKind::Punctuation('{') => brace_depth += 1,
                JavaScriptTokenKind::Punctuation('}') => {
                    if brace_depth == 0 {
                        break;
                    }
                    brace_depth -= 1;
                    if brace_depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            if brace_depth == 1 && cursor + 2 < tokens.len() {
                let key_matches = match &tokens[cursor].kind {
                    JavaScriptTokenKind::Identifier(key) | JavaScriptTokenKind::String(key) => {
                        key == wanted_key
                    }
                    _ => false,
                };
                if key_matches && token_is_punctuation(&tokens[cursor + 1], ':') {
                    if let JavaScriptTokenKind::String(value) = &tokens[cursor + 2].kind {
                        let restored = if tool == "exec_command" {
                            crate::claude_http_proxy::resolve_shell_text_safely(value, resolve)?
                        } else {
                            resolve(value)?
                        };
                        if restored != *value {
                            let encoded = serde_json::to_string(&restored).map_err(|error| {
                                format!("could not encode restored nested tool input: {error}")
                            })?;
                            replacements.push((
                                tokens[cursor + 2].start,
                                tokens[cursor + 2].end,
                                encoded,
                            ));
                        }
                        cursor += 2;
                    }
                }
            }
            cursor += 1;
        }
        index = cursor.saturating_add(1);
    }
    if replacements.is_empty() {
        return Ok(source.to_string());
    }
    replacements.sort_unstable_by_key(|replacement| replacement.0);
    replacements.dedup_by_key(|replacement| replacement.0);
    let mut output = source.to_string();
    for (start, end, replacement) in replacements.into_iter().rev() {
        output.replace_range(start..end, &replacement);
    }
    Ok(output)
}

fn nested_local_tool_at(tokens: &[JavaScriptToken], index: usize) -> Option<&'static str> {
    if !token_is_identifier(tokens.get(index)?, "tools")
        || !token_is_punctuation(tokens.get(index + 1)?, '.')
        || !token_is_punctuation(tokens.get(index + 3)?, '(')
    {
        return None;
    }
    match &tokens.get(index + 2)?.kind {
        JavaScriptTokenKind::Identifier(name) if name == "exec_command" => Some("exec_command"),
        JavaScriptTokenKind::Identifier(name) if name == "write_stdin" => Some("write_stdin"),
        _ => None,
    }
}

fn token_is_identifier(token: &JavaScriptToken, expected: &str) -> bool {
    matches!(&token.kind, JavaScriptTokenKind::Identifier(value) if value == expected)
}

fn token_is_punctuation(token: &JavaScriptToken, expected: char) -> bool {
    matches!(token.kind, JavaScriptTokenKind::Punctuation(value) if value == expected)
}

fn tokenize_javascript_for_local_tools(source: &str) -> Vec<JavaScriptToken> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            continue;
        }
        if bytes[index] == b'"' {
            let start = index;
            index += 1;
            while index < bytes.len() {
                match bytes[index] {
                    b'\\' => index = (index + 2).min(bytes.len()),
                    b'"' => {
                        index += 1;
                        break;
                    }
                    _ => index += 1,
                }
            }
            if index <= bytes.len() {
                if let Ok(value) = serde_json::from_str::<String>(&source[start..index]) {
                    tokens.push(JavaScriptToken {
                        kind: JavaScriptTokenKind::String(value),
                        start,
                        end: index,
                    });
                }
            }
            continue;
        }
        if matches!(bytes[index], b'\'' | b'`') {
            // Single-quoted and template literals can contain interpolation and
            // JavaScript-specific escapes. Skip them entirely instead of risking
            // code injection; Codex's nested tool objects use JSON string syntax.
            let quote = bytes[index];
            index += 1;
            while index < bytes.len() {
                match bytes[index] {
                    b'\\' => index = (index + 2).min(bytes.len()),
                    value if value == quote => {
                        index += 1;
                        break;
                    }
                    _ => index += 1,
                }
            }
            continue;
        }
        if bytes[index].is_ascii_alphabetic() || matches!(bytes[index], b'_' | b'$') {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'$'))
            {
                index += 1;
            }
            tokens.push(JavaScriptToken {
                kind: JavaScriptTokenKind::Identifier(source[start..index].to_string()),
                start,
                end: index,
            });
            continue;
        }
        let character = bytes[index] as char;
        if ".(){}[]:,".contains(character) {
            tokens.push(JavaScriptToken {
                kind: JavaScriptTokenKind::Punctuation(character),
                start: index,
                end: index + 1,
            });
        }
        index += 1;
    }
    tokens
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
    completions: CompletionStreamState,
    finished: bool,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
    restore_output: bool,
    output_text: HashMap<String, crate::claude_http_proxy::OutputTextRestorer>,
    output_resolve: HandleResolver,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamTransform {
    None,
    Responses,
    ChatCompletions,
    Completions,
}

fn streaming_response_body(
    response: reqwest::Response,
    transform: StreamTransform,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
    restore_output: bool,
) -> ProxyBody {
    let state = StreamState {
        upstream: Box::pin(response.bytes_stream()),
        pending: Vec::new(),
        ready: VecDeque::new(),
        transform,
        chat: ChatStreamState::default(),
        completions: CompletionStreamState::default(),
        finished: false,
        plugins,
        restore_output,
        output_text: HashMap::new(),
        output_resolve: Box::new(crate::claude_http_proxy::request_scoped_resolver()),
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
                        proxy_diagnostic("sse-event-limit");
                        state.finished = true;
                        state.ready.push_back(Err(Box::new(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "OpenAI SSE event exceeded inspection limit",
                        ))));
                        continue;
                    }
                    state.pending.extend_from_slice(&chunk);
                    while let Some(end) = first_sse_block_end(&state.pending) {
                        let block = state.pending.drain(..end).collect::<Vec<_>>();
                        let block = match run_sse_response_plugins(&block, &state.plugins) {
                            Ok(block) => block,
                            Err(error) => {
                                state.finished = true;
                                state.ready.push_back(Err(Box::new(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    error,
                                ))));
                                break;
                            }
                        };
                        let rewritten = match state.transform {
                            StreamTransform::Responses => rewrite_openai_sse_block(
                                &block,
                                &state.plugins,
                                state.restore_output,
                                &mut state.output_text,
                                &mut state.output_resolve,
                            ),
                            StreamTransform::ChatCompletions => state.chat.rewrite_block(
                                &block,
                                &state.plugins,
                                state.restore_output,
                                &mut state.output_resolve,
                            ),
                            StreamTransform::Completions => state.completions.rewrite_block(
                                &block,
                                state.restore_output,
                                &mut state.output_resolve,
                            ),
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
                    if state.transform == StreamTransform::ChatCompletions {
                        match state.chat.finish_output_text("data: {}\n\n") {
                            Ok(blocks) => {
                                for block in blocks {
                                    state.ready.push_back(Ok(Frame::data(block)));
                                }
                            }
                            Err(error) => state.ready.push_back(Err(Box::new(io::Error::new(
                                io::ErrorKind::InvalidData,
                                error,
                            )))),
                        }
                    } else if state.transform == StreamTransform::Completions {
                        match state.completions.finish_output_text("data: {}\n\n") {
                            Ok(blocks) => {
                                for block in blocks {
                                    state.ready.push_back(Ok(Frame::data(block)));
                                }
                            }
                            Err(error) => state.ready.push_back(Err(Box::new(io::Error::new(
                                io::ErrorKind::InvalidData,
                                error,
                            )))),
                        }
                    }
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
struct CompletionStreamState {
    output_text: HashMap<u64, crate::claude_http_proxy::OutputTextRestorer>,
}

impl CompletionStreamState {
    fn rewrite_block(
        &mut self,
        block: &[u8],
        restore_output: bool,
        resolve: &mut HandleResolver,
    ) -> Result<Vec<Bytes>, String> {
        let Ok(template) = std::str::from_utf8(block) else {
            return Ok(vec![Bytes::copy_from_slice(block)]);
        };
        let Some(data) = sse_data(template) else {
            return Ok(vec![Bytes::copy_from_slice(block)]);
        };
        if data == "[DONE]" {
            let mut output = self.finish_output_text(template)?;
            output.push(Bytes::copy_from_slice(block));
            return Ok(output);
        }
        let Ok(mut value) = serde_json::from_str::<Value>(data.as_ref()) else {
            return Ok(vec![Bytes::copy_from_slice(block)]);
        };
        if restore_output {
            let mut finished = Vec::new();
            if let Some(choices) = value.get_mut("choices").and_then(Value::as_array_mut) {
                for choice in choices {
                    let Some(choice) = choice.as_object_mut() else {
                        continue;
                    };
                    let index = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
                    if let Some(Value::String(text)) = choice.get_mut("text") {
                        *text = self
                            .output_text
                            .entry(index)
                            .or_default()
                            .push(text, resolve)?;
                    }
                    if choice
                        .get("finish_reason")
                        .is_some_and(|reason| !reason.is_null())
                    {
                        finished.push(index);
                    }
                }
            }
            for index in finished {
                if let Some(mut restorer) = self.output_text.remove(&index) {
                    let pending = restorer.finish();
                    if !pending.is_empty() {
                        if let Some(choice) = value
                            .get_mut("choices")
                            .and_then(Value::as_array_mut)
                            .and_then(|choices| {
                                choices.iter_mut().find(|choice| {
                                    choice.as_object().is_some_and(|choice| {
                                        choice.get("index").and_then(Value::as_u64).unwrap_or(0)
                                            == index
                                    })
                                })
                            })
                        {
                            let text = choice
                                .as_object_mut()
                                .expect("choice object was selected above")
                                .entry("text")
                                .or_insert_with(|| Value::String(String::new()));
                            if let Value::String(text) = text {
                                text.push_str(&pending);
                            }
                        }
                    }
                }
            }
        }
        Ok(vec![encode_sse_value(template, &value)?])
    }

    fn finish_output_text(&mut self, template: &str) -> Result<Vec<Bytes>, String> {
        let mut pending = self.output_text.drain().collect::<Vec<_>>();
        pending.sort_by_key(|(index, _)| *index);
        pending
            .into_iter()
            .filter_map(|(index, mut restorer)| {
                let text = restorer.finish();
                (!text.is_empty()).then_some((index, text))
            })
            .map(|(index, text)| {
                encode_sse_value(
                    template,
                    &serde_json::json!({
                        "choices": [{"index": index, "text": text, "finish_reason": Value::Null}]
                    }),
                )
            })
            .collect()
    }
}

#[derive(Default)]
struct ChatStreamState {
    calls: HashMap<(u64, u64), ChatStreamCall>,
    buffered_bytes: usize,
    output_text: HashMap<(u64, &'static str), crate::claude_http_proxy::OutputTextRestorer>,
    last_envelope: Option<Value>,
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
        restore_output: bool,
        resolve: &mut HandleResolver,
    ) -> Result<Vec<Bytes>, String> {
        let Ok(text) = std::str::from_utf8(block) else {
            return Ok(vec![Bytes::copy_from_slice(block)]);
        };
        let Some(data) = sse_data(text) else {
            return Ok(vec![Bytes::copy_from_slice(block)]);
        };
        if data == "[DONE]" {
            let mut output = self.finish_output_text(text)?;
            if !self.calls.is_empty() {
                let envelope = self.last_envelope.take().ok_or_else(|| {
                    "OpenAI Chat Completions stream ended without a tool call envelope".to_string()
                })?;
                let mut choices = self
                    .calls
                    .keys()
                    .map(|(choice, _)| *choice)
                    .collect::<Vec<_>>();
                choices.sort_unstable();
                choices.dedup();
                for choice in choices {
                    output.push(self.completed_tool_block(text, &envelope, choice, plugins)?);
                }
            }
            output.push(Bytes::copy_from_slice(block));
            return Ok(output);
        }
        let Ok(mut value) = serde_json::from_str::<Value>(data.as_ref()) else {
            return Ok(vec![Bytes::copy_from_slice(block)]);
        };
        let mut has_tool_delta = false;
        let mut completed_choices = Vec::new();
        if let Some(choices) = value.get_mut("choices").and_then(Value::as_array_mut) {
            for choice in choices {
                let choice_index = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
                let choice_finished = choice
                    .get("finish_reason")
                    .is_some_and(|reason| !reason.is_null());
                if choice_finished {
                    completed_choices.push(choice_index);
                }
                let Some(delta) = choice.get_mut("delta").and_then(Value::as_object_mut) else {
                    continue;
                };
                if restore_output {
                    for field in ["content", "reasoning_content", "reasoning"] {
                        if let Some(Value::String(content)) = delta.get_mut(field) {
                            *content = self
                                .output_text
                                .entry((choice_index, field))
                                .or_default()
                                .push(content, resolve)?;
                        }
                    }
                    if choice_finished {
                        for field in ["content", "reasoning_content", "reasoning"] {
                            if let Some(mut restorer) =
                                self.output_text.remove(&(choice_index, field))
                            {
                                let pending = restorer.finish();
                                if !pending.is_empty() {
                                    let content = delta
                                        .entry(field.to_string())
                                        .or_insert_with(|| Value::String(String::new()));
                                    if let Value::String(content) = content {
                                        content.push_str(&pending);
                                    }
                                }
                            }
                        }
                    }
                }
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
        self.last_envelope = Some(value.clone());
        if keep_original {
            output.push(encode_sse_value(text, &value)?);
        }
        Ok(output)
    }

    fn finish_output_text(&mut self, template: &str) -> Result<Vec<Bytes>, String> {
        let mut pending = self.output_text.drain().collect::<Vec<_>>();
        pending.sort_by_key(|((choice_index, field), _)| (*choice_index, *field));
        let mut output = Vec::new();
        for ((choice_index, field), mut restorer) in pending {
            let text = restorer.finish();
            if text.is_empty() {
                continue;
            }
            let mut delta = serde_json::Map::new();
            delta.insert(field.to_string(), Value::String(text));
            let value = serde_json::json!({
                "choices": [{
                    "index": choice_index,
                    "delta": Value::Object(delta),
                    "finish_reason": Value::Null,
                }]
            });
            output.push(encode_sse_value(template, &value)?);
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

fn sse_data(text: &str) -> Option<Cow<'_, str>> {
    let mut lines = text
        .lines()
        .filter_map(|line| line.strip_prefix("data:").map(str::trim_start));
    let first = lines.next()?;
    let Some(second) = lines.next() else {
        return Some(Cow::Borrowed(first));
    };
    let mut joined = String::with_capacity(first.len() + second.len() + 1);
    joined.push_str(first);
    joined.push('\n');
    joined.push_str(second);
    for line in lines {
        joined.push('\n');
        joined.push_str(line);
    }
    Some(Cow::Owned(joined))
}

fn run_sse_response_plugins(
    block: &[u8],
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
) -> Result<Vec<u8>, String> {
    let Ok(text) = std::str::from_utf8(block) else {
        return Ok(block.to_vec());
    };
    let Some(data) = sse_data(text) else {
        return Ok(block.to_vec());
    };
    if data == "[DONE]" {
        return Ok(block.to_vec());
    }
    let Ok(value) = serde_json::from_str::<Value>(data.as_ref()) else {
        return Ok(block.to_vec());
    };
    let payload = run_response_plugins_value(value, plugins, "openai")?;
    encode_sse_value(text, &payload).map(|bytes| bytes.to_vec())
}

fn encode_sse_value(template: &str, value: &Value) -> Result<Bytes, String> {
    encode_sse_value_for_event(template, value, None)
}

fn encode_sse_value_for_event(
    template: &str,
    value: &Value,
    event: Option<&str>,
) -> Result<Bytes, String> {
    let encoded = serde_json::to_string(value)
        .map_err(|error| format!("could not encode OpenAI SSE event: {error}"))?;
    let mut replaced = false;
    let mut output = String::with_capacity(template.len() + encoded.len());
    for line in template.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if let Some(event) = event.filter(|_| trimmed.starts_with("event:")) {
            output.push_str("event: ");
            output.push_str(event);
            if line.ends_with("\r\n") {
                output.push_str("\r\n");
            } else if line.ends_with('\n') {
                output.push('\n');
            }
        } else if trimmed.starts_with("data:") {
            if !replaced {
                output.push_str("data: ");
                output.push_str(&encoded);
                if line.ends_with("\r\n") {
                    output.push_str("\r\n");
                } else if line.ends_with('\n') {
                    output.push('\n');
                }
                replaced = true;
            }
        } else {
            output.push_str(line);
        }
    }
    Ok(Bytes::from(output))
}

fn rewrite_openai_sse_block(
    block: &[u8],
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    restore_output: bool,
    output_text: &mut HashMap<String, crate::claude_http_proxy::OutputTextRestorer>,
    resolve: &mut HandleResolver,
) -> Result<Vec<Bytes>, String> {
    let Ok(text) = std::str::from_utf8(block) else {
        return Ok(vec![Bytes::copy_from_slice(block)]);
    };
    let Some(data) = sse_data(text) else {
        return Ok(vec![Bytes::copy_from_slice(block)]);
    };
    if data == "[DONE]" {
        return Ok(vec![Bytes::copy_from_slice(block)]);
    }
    let Ok(mut value) = serde_json::from_str::<Value>(data.as_ref()) else {
        return Ok(vec![Bytes::copy_from_slice(block)]);
    };
    if matches!(
        value.get("type").and_then(Value::as_str),
        Some("response.function_call_arguments.delta" | "response.custom_tool_call_input.delta")
    ) {
        return Ok(Vec::new());
    }
    let completed_function_call = contains_completed_function_call(&value);
    let output_event = restore_output && contains_openai_output_text(&value);
    if !completed_function_call && !output_event {
        return Ok(vec![Bytes::copy_from_slice(block)]);
    }
    if completed_function_call {
        let plugins = plugins
            .lock()
            .map_err(|_| "OpenAI plugin lock was poisoned".to_string())?;
        run_openai_tool_plugins(&mut value, &plugins)?;
    }
    if let Err(error) = rewrite_function_calls(&mut value, resolve) {
        let _ = error;
        proxy_diagnostic("sse-restore-skipped");
        return Ok(vec![Bytes::copy_from_slice(block)]);
    }
    let mut output = Vec::new();
    if let Some(delta) = completed_openai_call_delta(&value) {
        let event = delta.get("type").and_then(Value::as_str);
        output.push(encode_sse_value_for_event(text, &delta, event)?);
    }
    if output_event {
        for prefix in restore_openai_sse_output_text(&mut value, output_text, resolve)? {
            let event = prefix.get("type").and_then(Value::as_str);
            output.push(encode_sse_value_for_event(text, &prefix, event)?);
        }
    }
    output.push(encode_sse_value(text, &value)?);
    Ok(output)
}

fn completed_openai_call_delta(value: &Value) -> Option<Value> {
    let (done_type, field, delta_type) = match value.get("type").and_then(Value::as_str)? {
        "response.function_call_arguments.done" => (
            "response.function_call_arguments.done",
            "arguments",
            "response.function_call_arguments.delta",
        ),
        "response.custom_tool_call_input.done" => (
            "response.custom_tool_call_input.done",
            "input",
            "response.custom_tool_call_input.delta",
        ),
        _ => return None,
    };
    let mut delta = value.clone();
    let object = delta.as_object_mut()?;
    if object.get("type").and_then(Value::as_str) != Some(done_type) {
        return None;
    }
    let completed = object.remove(field)?.as_str()?.to_string();
    object.insert("type".to_string(), Value::String(delta_type.to_string()));
    object.insert("delta".to_string(), Value::String(completed));
    Some(delta)
}

fn contains_openai_output_text(value: &Value) -> bool {
    matches!(
        value.get("type").and_then(Value::as_str),
        Some("response.output_text.delta" | "response.output_text.done" | "response.completed")
    )
}

fn openai_output_stream_key(value: &Value) -> String {
    if let Some(item_id) = value.get("item_id").and_then(Value::as_str) {
        return format!(
            "{item_id}:{}",
            value
                .get("content_index")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        );
    }
    format!(
        "{}:{}",
        value
            .get("output_index")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        value
            .get("content_index")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    )
}

fn restore_openai_sse_output_text<R>(
    value: &mut Value,
    streams: &mut HashMap<String, crate::claude_http_proxy::OutputTextRestorer>,
    resolve: &mut R,
) -> Result<Vec<Value>, String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    let mut prefixes = Vec::new();
    let event_type = value.get("type").and_then(Value::as_str).map(str::to_owned);
    match event_type.as_deref() {
        Some("response.output_text.delta") => {
            let key = openai_output_stream_key(value);
            if let Some(Value::String(delta)) = value.get_mut("delta") {
                *delta = streams.entry(key).or_default().push(delta, resolve)?;
            }
        }
        Some("response.output_text.done") => {
            let key = openai_output_stream_key(value);
            if let Some(mut restorer) = streams.remove(&key) {
                let pending = restorer.finish();
                if !pending.is_empty() {
                    let mut prefix = value.clone();
                    if let Some(object) = prefix.as_object_mut() {
                        object.insert(
                            "type".to_string(),
                            Value::String("response.output_text.delta".to_string()),
                        );
                        object.remove("text");
                        object.insert("delta".to_string(), Value::String(pending));
                    }
                    prefixes.push(prefix);
                }
            }
            if let Some(Value::String(text)) = value.get_mut("text") {
                *text = resolve(text)?;
            }
        }
        Some("response.completed") => {
            if let Some(response) = value.get_mut("response") {
                restore_openai_output_text(response, resolve)?;
            }
            streams.clear();
        }
        _ => {}
    }
    Ok(prefixes)
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
    StandaloneSearch,
    ChatCompletions,
    Completions,
    Embeddings,
    ImageGeneration,
    AudioSpeech,
    AudioTranscription,
    AudioTranslation,
    FilesCollection,
    Files,
    Models,
    Health,
    Unknown,
}

impl OpenAiEndpoint {
    fn diagnostic_name(self) -> &'static str {
        match self {
            Self::Responses => "responses",
            Self::ResponsesResource => "responses-resource",
            Self::InputTokens => "input-tokens",
            Self::StandaloneSearch => "standalone-search",
            Self::ChatCompletions => "chat-completions",
            Self::Completions => "completions",
            Self::Embeddings => "embeddings",
            Self::ImageGeneration => "image-generation",
            Self::AudioSpeech => "audio-speech",
            Self::AudioTranscription => "audio-transcription",
            Self::AudioTranslation => "audio-translation",
            Self::FilesCollection => "files-collection",
            Self::Files => "files",
            Self::Models => "models",
            Self::Health => "health",
            Self::Unknown => "unknown",
        }
    }
}

fn classify_openai_endpoint(path_and_query: &str) -> OpenAiEndpoint {
    let path = path_and_query.split('?').next().unwrap_or(path_and_query);
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if path.ends_with("/responses/input_tokens") {
        OpenAiEndpoint::InputTokens
    } else if matches!(
        segments.as_slice(),
        ["v1", "alpha", "search"] | ["backend-api", "codex", "alpha", "search"]
    ) {
        OpenAiEndpoint::StandaloneSearch
    } else if path.ends_with("/responses") {
        OpenAiEndpoint::Responses
    } else if is_known_openai_resource_path(&segments, "responses") {
        OpenAiEndpoint::ResponsesResource
    } else if path.ends_with("/chat/completions") {
        OpenAiEndpoint::ChatCompletions
    } else if matches!(
        segments.as_slice(),
        ["completions"] | ["v1", "completions"] | ["backend-api", "codex", "completions"]
    ) {
        OpenAiEndpoint::Completions
    } else if matches!(
        segments.as_slice(),
        ["v1", "embeddings"] | ["backend-api", "codex", "embeddings"]
    ) {
        OpenAiEndpoint::Embeddings
    } else if matches!(
        segments.as_slice(),
        ["images", "generations"] | ["v1", "images", "generations"]
    ) {
        OpenAiEndpoint::ImageGeneration
    } else if matches!(
        segments.as_slice(),
        ["audio", "speech"] | ["v1", "audio", "speech"]
    ) {
        OpenAiEndpoint::AudioSpeech
    } else if matches!(
        segments.as_slice(),
        ["audio", "transcriptions"] | ["v1", "audio", "transcriptions"]
    ) {
        OpenAiEndpoint::AudioTranscription
    } else if matches!(
        segments.as_slice(),
        ["audio", "translations"] | ["v1", "audio", "translations"]
    ) {
        OpenAiEndpoint::AudioTranslation
    } else if path.ends_with("/files") {
        OpenAiEndpoint::FilesCollection
    } else if is_known_openai_resource_path(&segments, "files") {
        OpenAiEndpoint::Files
    } else if path.ends_with("/models") || is_known_openai_resource_path(&segments, "models") {
        OpenAiEndpoint::Models
    } else if path == "/api/hello" {
        OpenAiEndpoint::Health
    } else {
        OpenAiEndpoint::Unknown
    }
}

fn is_known_openai_resource_path(segments: &[&str], collection: &str) -> bool {
    let Some(collection_index) = segments.iter().position(|segment| *segment == collection) else {
        return false;
    };
    if collection_index + 1 >= segments.len() {
        return false;
    }

    // Accepted model API roots are the public /v1 form and Codex's observed
    // /backend-api/codex form. Do not accept a collection name buried under an
    // arbitrary unknown path, because those requests bypass collection body
    // protection and take the resource passthrough path.
    matches!(
        &segments[..collection_index],
        [.., "v1"] | [.., "backend-api", "codex"]
    )
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

    #[cfg(windows)]
    #[test]
    fn powershell_direct_handle_reaches_local_authorization_header() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = "<<KEYED_SECRET_a2c25e122d2e002f>>";
        let secret = "fixture key with @ and 'quote'";
        let input = serde_json::json!({
            "command": format!(
                "Invoke-WebRequest -UseBasicParsing http://{address}/check -Headers @{{ Authorization = \"Bearer {handle}\" }} | Out-Null"
            )
        })
        .to_string();
        let mut resolve = |text: &str| Ok(text.replace(handle, secret));
        let restored = crate::claude_http_proxy::resolve_tool_input_json(
            &input,
            Some("PowerShell"),
            &mut resolve,
        )
        .unwrap();
        let command = serde_json::from_str::<Value>(&restored).unwrap()["command"]
            .as_str()
            .unwrap()
            .to_string();

        let child = std::thread::spawn(move || {
            std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &command])
                .status()
                .unwrap()
        });
        let (mut socket, _) = listener.accept().unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 1024];
        while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = socket.read(&mut buffer).unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&buffer[..read]);
        }
        let request = String::from_utf8(bytes).unwrap();
        socket
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();

        assert!(child.join().unwrap().success());
        assert!(
            request.contains(&format!("Authorization: Bearer {secret}")),
            "{request}"
        );
        assert!(!request.contains(handle), "{request}");
    }

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
                "HOME",
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
            std::env::set_var("HOME", &home);
            std::env::set_var("LOCALAPPDATA", &home);
            let mut environment = Self {
                saved,
                home,
                process_host_candidate: None,
            };
            environment.process_host_candidate = Some(
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
            environment
        }

        fn set(&mut self, name: &'static str, value: &str) {
            self.saved.push((name, std::env::var_os(name)));
            std::env::set_var(name, value);
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

    #[test]
    fn only_current_user_content_can_use_unmask_markers() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let secret = ["rpa_", "USERONLY", "ZYXWVUTS", "RQPONMLK", "1234567890"].concat();
        let keyed_secret = format!("RUNPOD_API_KEY={secret}");
        let mut masker = pentect_agent::ActiveToolOutputMasker::new().unwrap();
        let mut messages = serde_json::json!([
            {"role": "system", "content": format!("unmask({keyed_secret})")},
            {"role": "assistant", "content": format!("unmask({keyed_secret})")},
            {"role": "tool", "content": format!("unmask({keyed_secret})")},
            {"role": "user", "content": format!("unmask({keyed_secret})")}
        ]);

        mask_chat_messages(&mut messages, &mut masker, &HashMap::new()).unwrap();

        for index in 0..3 {
            let content = messages[index]["content"].as_str().unwrap();
            assert!(
                !content.contains(&secret),
                "external role leaked at {index}"
            );
            assert!(
                content.contains("<<"),
                "external role was not masked at {index}"
            );
        }
        assert_eq!(messages[3]["content"], Value::String(keyed_secret));

        let mut definition = serde_json::json!({
            "description": format!("unmask({})", messages[3]["content"].as_str().unwrap())
        });
        let mut nodes = 0;
        mask_model_definition(&mut definition, 0, &mut nodes, &mut masker).unwrap();
        let description = definition["description"].as_str().unwrap();
        assert!(!description.contains(messages[3]["content"].as_str().unwrap()));
        assert!(description.contains("<<"));
    }

    #[test]
    fn chat_history_masks_legacy_function_and_custom_tool_payloads() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let secret = ["rpa_", "CHATTOOLS", "ZYXWVUTS", "RQPONMLK", "1234567890"].concat();
        let payload =
            |prefix: &str| format!(r#"{{\"command\":\"{prefix} RUNPOD_API_KEY={secret}\"}}"#);
        let mut messages = serde_json::json!([{
            "role": "assistant",
            "function_call": {
                "name": "legacy",
                "arguments": payload("legacy")
            },
            "tool_calls": [{
                "id": "function-1",
                "type": "function",
                "function": {
                    "name": "modern",
                    "arguments": payload("modern")
                }
            }, {
                "id": "custom-1",
                "type": "custom",
                "custom": {
                    "name": "custom",
                    "arguments": payload("custom-arguments"),
                    "input": payload("custom-input")
                }
            }]
        }]);
        let mut masker = pentect_agent::ActiveToolOutputMasker::new().unwrap();

        mask_chat_messages(&mut messages, &mut masker, &HashMap::new()).unwrap();

        for path in [
            &messages[0]["function_call"]["arguments"],
            &messages[0]["tool_calls"][0]["function"]["arguments"],
            &messages[0]["tool_calls"][1]["custom"]["arguments"],
            &messages[0]["tool_calls"][1]["custom"]["input"],
        ] {
            let protected = path.as_str().unwrap();
            assert!(!protected.contains(&secret), "{protected}");
            assert!(protected.contains("<<"), "{protected}");
        }
    }

    #[test]
    fn startup_reports_pre_ready_plugin_failure_without_timeout() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let name = "PENTECT_PLUGIN_BINARIES";
        let previous = std::env::var_os(name);
        let missing = std::env::temp_dir().join(format!(
            "pentect-missing-plugin-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var(name, &missing);
        let started = std::time::Instant::now();
        let result = OpenAiHttpProxyGuard::start("https://example.test/v1".to_string());
        match previous {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }

        let error = match result {
            Ok(_) => panic!("missing plugin must fail gateway startup"),
            Err(error) => error,
        };
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        assert!(
            error.contains("plugin") || error.contains("WebAssembly"),
            "{error}"
        );
    }

    fn mock_chat_upstream() -> (
        String,
        std::sync::mpsc::Receiver<(String, String)>,
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
            let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
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
            body_tx.send((headers.to_string(), body)).unwrap();
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
    fn provider_boundary_masks_chat_requests_and_restores_local_assistant_output() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let mut env = ProviderBoundaryTestEnv::install(&store);
        env.set("PENTECT_TEST_OPENAI_PROVIDER_KEY", "provider-test-key");
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
        let proxy = OpenAiHttpProxyGuard::start_with_header_env_and_bearer_env(
            upstream,
            &[],
            Some("PENTECT_TEST_OPENAI_PROVIDER_KEY"),
        )
        .unwrap();
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
        let (headers, request) = captured
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        thread.join().unwrap();
        assert!(
            headers
                .lines()
                .any(|line| line.eq_ignore_ascii_case("authorization: Bearer provider-test-key")),
            "provider bearer header did not reach the upstream"
        );
        assert!(!request.contains(&secret), "{request}");
        let handle = first_handle(&request).unwrap();
        assert!(request.matches(&handle).count() >= 3);
        let protected_request: Value = serde_json::from_str(&request).unwrap();
        assert_eq!(protected_request["messages"][0]["content"], HANDLE_CONTRACT);
        assert_eq!(response["choices"][0]["message"]["content"], secret);
        let arguments = response["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        let arguments: Value = serde_json::from_str(arguments).unwrap();
        let command = arguments["command"].as_str().unwrap();
        assert!(!command.contains(&secret), "{command}");
        assert!(!command.contains(&handle), "{command}");
        assert!(command.contains("script-b64"), "{command}");
    }

    #[test]
    fn provider_boundary_masks_current_codex_prompt_shape_with_keyed_and_vendor_detectors() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let password = ["test-pentect", "-password-284-provider"].concat();
        let openrouter = [
            "sk-or-v1-",
            "fedcba9876543210fedcba9876543210",
            "fedcba9876543210fedcba9876543210",
        ]
        .concat();
        let (upstream, captured, thread) = mock_chat_upstream();
        let proxy = OpenAiHttpProxyGuard::start(upstream).unwrap();

        reqwest::blocking::Client::new()
            .post(format!("{}/responses", proxy.base_url()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({
                    "model": "test",
                    "input": [{
                        "type": "message",
                        "role": "user",
                        "content": [{
                            "type": "input_text",
                            "text": format!(
                                "Audit fixture: sudo password is {password} and OPENROUTER_API_KEY={openrouter}."
                            )
                        }]
                    }],
                    "stream": false
                }))
                .unwrap(),
            )
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();

        let (_, request) = captured
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        thread.join().unwrap();
        assert!(!request.contains(&password), "password reached upstream");
        assert!(
            !request.contains(&openrouter),
            "OpenRouter key reached upstream"
        );
        assert!(
            request.contains("<<KEYED_SECRET_"),
            "keyed-secret handle did not reach upstream"
        );
        assert!(
            request.matches("<<").count() >= 2,
            "expected prompt handles did not reach upstream"
        );
    }

    #[test]
    fn provider_boundary_masks_responses_tool_call_history() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let secret = ["rpa_", "TOOLHISTORY", "ZYXWVUTS", "RQPONMLK", "1234567890"].concat();
        let (upstream, captured, thread) = mock_chat_upstream();
        let proxy = OpenAiHttpProxyGuard::start(upstream).unwrap();

        reqwest::blocking::Client::new()
            .post(format!("{}/responses", proxy.base_url()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({
                    "model": "test",
                    "input": [
                        {
                            "type": "function_call",
                            "name": "shell",
                            "arguments": serde_json::json!({
                                "command": format!("export RUNPOD_API_KEY={secret}")
                            }).to_string()
                        },
                        {
                            "type": "custom_tool_call",
                            "name": "exec_command",
                            "input": format!("curl -H 'Authorization: Bearer {secret}' localhost")
                        }
                    ],
                    "stream": false
                }))
                .unwrap(),
            )
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();

        let (_, request) = captured
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        thread.join().unwrap();
        assert!(!request.contains(&secret), "tool history reached upstream");
        let protected: Value = serde_json::from_str(&request).unwrap();
        for (index, key) in [(0, "arguments"), (1, "input")] {
            let value = protected["input"][index][key].as_str().unwrap();
            assert!(value.contains("<<"), "unmasked {key}: {value}");
        }
    }

    #[test]
    fn provider_boundary_decodes_codex_zstd_requests_before_protection() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let secret = [
            "rpa_",
            "ABCDEFGHIJKLMNOP",
            "QRSTUVWXYZ012345",
            "6789abcdefghijkl",
        ]
        .concat();
        let payload = serde_json::to_vec(&serde_json::json!({
            "model": "test",
            "input": format!("Use RUNPOD_API_KEY={secret}"),
            "stream": false
        }))
        .unwrap();
        let compressed = zstd::stream::encode_all(std::io::Cursor::new(payload), 3).unwrap();
        let (upstream, captured, thread) = mock_chat_upstream();
        let proxy = OpenAiHttpProxyGuard::start(upstream).unwrap();

        reqwest::blocking::Client::new()
            .post(format!("{}/responses", proxy.base_url()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::CONTENT_ENCODING, "zstd")
            .body(compressed)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();

        let (headers, request) = captured
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        thread.join().unwrap();
        assert!(!headers.to_ascii_lowercase().contains("content-encoding:"));
        assert!(!request.contains(&secret));
        assert!(first_handle(&request).is_some());
        serde_json::from_str::<Value>(&request).unwrap();
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
            classify_openai_endpoint("/v1/alpha/search"),
            OpenAiEndpoint::StandaloneSearch
        );
        assert_eq!(
            classify_openai_endpoint("/backend-api/codex/alpha/search?client=codex"),
            OpenAiEndpoint::StandaloneSearch
        );
        assert_eq!(
            classify_openai_endpoint("/v1/chat/completions"),
            OpenAiEndpoint::ChatCompletions
        );
        assert_eq!(
            classify_openai_endpoint("/v1/images/generations"),
            OpenAiEndpoint::ImageGeneration
        );
        assert_eq!(
            classify_openai_endpoint("/v1/audio/speech"),
            OpenAiEndpoint::AudioSpeech
        );
        assert_eq!(
            classify_openai_endpoint("/v1/audio/transcriptions"),
            OpenAiEndpoint::AudioTranscription
        );
        assert_eq!(
            classify_openai_endpoint("/v1/audio/translations"),
            OpenAiEndpoint::AudioTranslation
        );
        assert_eq!(
            classify_openai_endpoint("/v1/completions"),
            OpenAiEndpoint::Completions
        );
        assert_eq!(
            classify_openai_endpoint("/completions?stream=true"),
            OpenAiEndpoint::Completions
        );
        assert_eq!(
            classify_openai_endpoint("/v1/embeddings"),
            OpenAiEndpoint::Embeddings
        );
        assert_eq!(
            classify_openai_endpoint("/backend-api/codex/embeddings"),
            OpenAiEndpoint::Embeddings
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
        for disguised in [
            "/v1/unknown/responses/resp_123",
            "/v1/unknown/files/file_123",
            "/v1/unknown/models/model_123",
            "/v1/unknown/alpha/search",
            "/backend-api/unknown/alpha/search",
        ] {
            assert_eq!(
                classify_openai_endpoint(disguised),
                OpenAiEndpoint::Unknown,
                "disguised resource path was accepted: {disguised}"
            );
        }
        assert_eq!(
            classify_openai_endpoint("/backend-api/codex/responses/resp_123"),
            OpenAiEndpoint::ResponsesResource
        );
        assert!(enforce_known_openai_endpoint(OpenAiEndpoint::Unknown, true).is_err());
        assert!(enforce_known_openai_endpoint(OpenAiEndpoint::Unknown, false).is_ok());
    }

    #[test]
    fn media_requests_mask_text_without_rewriting_protocol_fields() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let secret = ["rpa_", "MEDIA", "ZYXWVUTS", "RQPONMLK", "1234567890"].concat();
        let keyed = format!("RUNPOD_API_KEY={secret}");
        let masker = Mutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());

        let image = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "model": "gpt-image-1",
                "prompt": format!("draw {keyed}"),
                "size": "1024x1024"
            }))
            .unwrap(),
        );
        let protected = protect_openai_request_body(
            &image,
            &masker,
            &plugins,
            &HashMap::new(),
            OpenAiRequestDialect::ImageGeneration,
            true,
        )
        .unwrap();
        let image: Value = serde_json::from_slice(&protected.body).unwrap();
        assert_eq!(image["model"], "gpt-image-1");
        assert_eq!(image["size"], "1024x1024");
        assert!(!image["prompt"].as_str().unwrap().contains(&secret));
        assert!(image.get("instructions").is_none());

        let speech = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "model": "gpt-4o-mini-tts",
                "voice": "alloy",
                "input": format!("say {keyed}"),
                "instructions": format!("style {keyed}")
            }))
            .unwrap(),
        );
        let protected = protect_openai_request_body(
            &speech,
            &masker,
            &plugins,
            &HashMap::new(),
            OpenAiRequestDialect::AudioSpeech,
            true,
        )
        .unwrap();
        let speech: Value = serde_json::from_slice(&protected.body).unwrap();
        assert_eq!(speech["voice"], "alloy");
        assert!(!speech["input"].as_str().unwrap().contains(&secret));
        assert!(!speech["instructions"].as_str().unwrap().contains(&secret));
    }

    #[test]
    fn provider_boundary_masks_image_and_speech_requests_before_upstream() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let secret = ["rpa_", "UPSTREAM", "ZYXWVUTS", "RQPONMLK", "1234567890"].concat();

        for (path, body) in [
            (
                "images/generations",
                serde_json::json!({
                    "model": "gpt-image-1",
                    "prompt": format!("draw RUNPOD_API_KEY={secret}")
                }),
            ),
            (
                "audio/speech",
                serde_json::json!({
                    "model": "gpt-4o-mini-tts",
                    "voice": "alloy",
                    "input": format!("say RUNPOD_API_KEY={secret}")
                }),
            ),
        ] {
            let (upstream, captured, thread) = mock_chat_upstream();
            let proxy = OpenAiHttpProxyGuard::start(upstream).unwrap();
            reqwest::blocking::Client::new()
                .post(format!("{}/{path}", proxy.base_url()))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&body).unwrap())
                .send()
                .unwrap()
                .error_for_status()
                .unwrap();
            let (headers, request) = captured
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            thread.join().unwrap();
            assert!(headers.contains(&format!("POST /{path} ")), "{headers}");
            assert!(!request.contains(&secret), "{path} leaked to upstream");
            assert!(request.contains("<<KEYED_SECRET_"), "{request}");
        }
    }

    #[test]
    fn audio_uploads_fail_closed_or_mask_prompt_in_compatibility_mode() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let secret = ["rpa_", "AUDIO", "ZYXWVUTS", "RQPONMLK", "1234567890"].concat();
        let body = Bytes::from(format!(
            "--boundary\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ngpt-4o-transcribe\r\n--boundary\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nRUNPOD_API_KEY={secret}\r\n--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"voice.wav\"\r\nContent-Type: audio/wav\r\n\r\nRIFF-audio-bytes\r\n--boundary--\r\n"
        ));
        let plugins = pentect_agent::PluginMiddleware::default();

        let mut masker = pentect_agent::ActiveToolOutputMasker::new().unwrap();
        let error = match crate::http_files::protect_audio_multipart_upload_with_plugins(
            "multipart/form-data; boundary=boundary",
            &body,
            &mut masker,
            &plugins,
            true,
        ) {
            Ok(_) => panic!("strict mode unexpectedly allowed uninspected audio"),
            Err(error) => error,
        };
        assert!(error.starts_with("unknown format blocked:"), "{error}");

        let mut masker = pentect_agent::ActiveToolOutputMasker::new().unwrap();
        let protected = crate::http_files::protect_audio_multipart_upload_with_plugins(
            "multipart/form-data; boundary=boundary",
            &body,
            &mut masker,
            &plugins,
            false,
        )
        .unwrap();
        assert_eq!(protected.coverage, crate::http_files::Coverage::Partial);
        let protected = String::from_utf8(protected.body.to_vec()).unwrap();
        assert!(!protected.contains(&secret));
        assert!(protected.contains("<<"));
        assert!(protected.contains("RIFF-audio-bytes"));
    }

    #[test]
    fn legacy_completion_prompts_and_output_are_protected_at_their_schema_boundaries() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let secret = ["rpa_", "LEGACYOPENAI", "ZYXWVUTS", "RQPONMLK", "1234567890"].concat();
        let mut prompt = serde_json::json!([
            format!("RUNPOD_API_KEY={secret}"),
            format!("repeat RUNPOD_API_KEY={secret}")
        ]);
        let mut masker = pentect_agent::ActiveToolOutputMasker::new().unwrap();

        mask_completion_prompt(&mut prompt, &mut masker).unwrap();
        assert!(!prompt.to_string().contains(&secret));
        assert!(prompt
            .as_array()
            .unwrap()
            .iter()
            .all(|item| pentect_agent::contains_pentect_masked_handle(item.as_str().unwrap())));
        inject_completion_handle_contract(&mut prompt);
        assert!(prompt
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item.as_str().unwrap().contains(HANDLE_CONTRACT)));

        let mut response = serde_json::json!({
            "choices": [{"index": 0, "text": "before <<KEYED_SECRET_test>> after"}]
        });
        restore_completion_output_text(&mut response, &mut |text| {
            Ok(text.replace("<<KEYED_SECRET_test>>", "restored"))
        })
        .unwrap();
        assert_eq!(response["choices"][0]["text"], "before restored after");
    }

    #[test]
    fn legacy_completion_stream_restores_handles_split_across_deltas() {
        let mut state = CompletionStreamState::default();
        let mut resolve: HandleResolver =
            Box::new(|text| Ok(text.replace("<<KEYED_SECRET_split>>", "restored")));
        let first = state
            .rewrite_block(
                b"data: {\"choices\":[{\"index\":0,\"text\":\"before <<KEYED_\",\"finish_reason\":null}]}\n\n",
                true,
                &mut resolve,
            )
            .unwrap();
        let second = state
            .rewrite_block(
                b"data: {\"choices\":[{\"index\":0,\"text\":\"SECRET_split>> after\",\"finish_reason\":\"stop\"}]}\n\n",
                true,
                &mut resolve,
            )
            .unwrap();
        let output = first
            .into_iter()
            .chain(second)
            .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
            .collect::<String>();
        assert!(output.contains("before "), "{output}");
        assert!(output.contains("restored after"), "{output}");
        assert!(!output.contains("KEYED_SECRET_split"), "{output}");
    }

    #[test]
    fn embeddings_mask_text_without_changing_token_inputs() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let masker = Mutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::from_env().unwrap());
        let text = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "model": "text-embedding-3-small",
                "input": ["OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX"]
            }))
            .unwrap(),
        );
        let protected = protect_openai_request_body(
            &text,
            &masker,
            &plugins,
            &HashMap::new(),
            OpenAiRequestDialect::Embeddings,
            true,
        )
        .unwrap();
        let text: Value = serde_json::from_slice(&protected.body).unwrap();
        assert!(text["input"][0]
            .as_str()
            .unwrap()
            .contains("<<OPENAI_API_KEY_"));
        assert!(text.get("instructions").is_none());

        let mut tokens = serde_json::json!({
            "model": "text-embedding-3-small",
            "input": [[1, 2, 3], [4, 5]]
        });
        let original = tokens.clone();
        mask_embeddings_request(&mut tokens, &mut masker.lock().unwrap()).unwrap();
        assert_eq!(tokens, original);
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
    fn nonstream_reasoning_text_is_restored_without_touching_encrypted_content() {
        let handle = "<<SECRET_0123456789abcdef>>";
        let mut response = serde_json::json!({
            "output": [{
                "type": "reasoning",
                "encrypted_content": handle,
                "summary": [{"type": "summary_text", "text": handle}],
                "content": [{"type": "reasoning_text", "text": handle}]
            }]
        });
        let mut resolve = |text: &str| Ok(text.replace(handle, "local-value"));
        restore_openai_output_text(&mut response, &mut resolve).unwrap();
        assert_eq!(response["output"][0]["summary"][0]["text"], "local-value");
        assert_eq!(response["output"][0]["content"][0]["text"], "local-value");
        assert_eq!(response["output"][0]["encrypted_content"], handle);

        let mut chat = serde_json::json!({
            "choices": [{"message": {
                "content": handle,
                "reasoning_content": handle,
                "reasoning": handle
            }}]
        });
        restore_chat_output_text(&mut chat, &mut resolve).unwrap();
        let message = &chat["choices"][0]["message"];
        assert_eq!(message["content"], "local-value");
        assert_eq!(message["reasoning_content"], "local-value");
        assert_eq!(message["reasoning"], "local-value");
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
        let mut resolve: HandleResolver = Box::new(|text: &str| Ok(text.to_string()));
        let first_out = state
            .rewrite_block(first.as_bytes(), &plugins, false, &mut resolve)
            .unwrap();
        assert_eq!(first_out.len(), 1);
        assert!(!String::from_utf8_lossy(&first_out[0]).contains("tool_calls"));
        assert!(state
            .rewrite_block(second.as_bytes(), &plugins, false, &mut resolve)
            .unwrap()
            .is_empty());
        let finished = state
            .rewrite_block(finish.as_bytes(), &plugins, false, &mut resolve)
            .unwrap();
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
    fn chat_stream_done_flushes_tool_calls_without_finish_reason() {
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let mut state = ChatStreamState::default();
        let chunk = format!(
            "data: {}\n\n",
            serde_json::json!({
                "id": "chat_1", "model": "test", "choices": [{"index": 0, "delta": {
                    "tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                    "function": {"name": "run_command", "arguments": "{\"cmd\":\"ls\"}"}}]
                }, "finish_reason": null}]
            })
        );
        let mut resolve: HandleResolver = Box::new(|text: &str| Ok(text.to_string()));
        assert!(state
            .rewrite_block(chunk.as_bytes(), &plugins, false, &mut resolve)
            .unwrap()
            .is_empty());

        let finished = state
            .rewrite_block(b"data: [DONE]\n\n", &plugins, false, &mut resolve)
            .unwrap();
        assert_eq!(finished.len(), 2);
        let tool_call = String::from_utf8_lossy(&finished[0]);
        assert!(tool_call.contains("call_1"), "{tool_call}");
        assert!(tool_call.contains("run_command"), "{tool_call}");
        assert!(tool_call.contains(r#"{\"cmd\":\"ls\"}"#), "{tool_call}");
        assert_eq!(finished[1], Bytes::from_static(b"data: [DONE]\n\n"));
        assert!(state.calls.is_empty());
        assert_eq!(state.buffered_bytes, 0);
    }

    #[test]
    fn chat_stream_restores_reasoning_and_flushes_it_on_finish() {
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let mut state = ChatStreamState::default();
        let mut resolve: HandleResolver =
            Box::new(|text: &str| Ok(text.replace("<<CHARGE_0123456789abcdef>>", "local-value")));
        let blocks = [
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"before <<CHAR\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"GE_0123456789abcdef>> after\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        ];
        let mut output = String::new();
        for block in blocks {
            for rewritten in state
                .rewrite_block(block.as_bytes(), &plugins, true, &mut resolve)
                .unwrap()
            {
                output.push_str(std::str::from_utf8(&rewritten).unwrap());
            }
        }
        assert!(output.contains("local-value"), "{output}");
        assert!(!output.contains("<<CHARGE_"), "{output}");
        assert!(output.contains("reasoning_content"), "{output}");
    }

    #[test]
    fn chat_stream_done_flushes_buffered_trailing_text() {
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let mut state = ChatStreamState::default();
        let mut resolve: HandleResolver = Box::new(|text: &str| Ok(text.to_string()));
        let chunk = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"trailing text\"},\"finish_reason\":null}]}\n\n";
        let first = state
            .rewrite_block(chunk, &plugins, true, &mut resolve)
            .unwrap();
        let done = state
            .rewrite_block(b"data: [DONE]\n\n", &plugins, true, &mut resolve)
            .unwrap();
        let output = first
            .iter()
            .chain(&done)
            .map(|block| std::str::from_utf8(block).unwrap())
            .collect::<String>();
        assert!(output.contains("trailing text"), "{output}");
        assert!(output.ends_with("data: [DONE]\n\n"), "{output:?}");
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
    fn javascript_orchestrator_restores_only_nested_local_tool_arguments() {
        for name in ["exec", "functions.exec"] {
            let input = concat!(
                "const decoy = \"tools.write_stdin({chars:\\\"<<SECRET_0123456789abcdef>>\\\"})\"; ",
                "const first = await tools.exec_command({cmd:\"curl -H \\\"Authorization: Bearer ${PENTECT_SECRET_0123456789abcdef}\\\" http://127.0.0.1/check\"}); ",
                "const second = await tools.write_stdin({session_id:7,chars:\"<<SECRET_0123456789abcdef>>\\n\"}); text(first); text(second)"
            );
            let mut value = serde_json::json!({
                "type": "response.output_item.done",
                "item": {
                    "type": "custom_tool_call",
                    "name": name,
                    "input": input
                }
            });
            let mut resolve = |text: &str| -> Result<String, String> {
                Ok(text
                    .replace(
                        "${PENTECT_SECRET_0123456789abcdef}",
                        "secret with 'quote' and newline\n",
                    )
                    .replace(
                        "<<SECRET_0123456789abcdef>>",
                        "secret with 'quote' and newline\n",
                    ))
            };
            rewrite_function_calls(&mut value, &mut resolve).unwrap();
            let rewritten = value["item"]["input"].as_str().unwrap();
            assert!(rewritten.contains("export PENTECT_SECRET_0123456789abcdef="));
            assert!(rewritten.contains("secret with 'quote' and newline\\n\\n"));
            assert!(rewritten.contains(&format!(
                "chars:{}",
                serde_json::to_string("secret with 'quote' and newline\n\n").unwrap()
            )));
            assert!(rewritten.contains(
                "const decoy = \"tools.write_stdin({chars:\\\"<<SECRET_0123456789abcdef>>\\\"})\""
            ));
            assert!(!rewritten.starts_with("export "));
        }
    }

    #[test]
    fn javascript_orchestrator_leaves_dynamic_and_unknown_calls_inert() {
        let input = concat!(
            "tools.exec_command({cmd: dynamicCommand});",
            "tools.apply_patch({patch:\"<<SECRET_0123456789abcdef>>\"});",
            "tools.write_stdin({chars:`<<SECRET_0123456789abcdef>>`})"
        );
        let mut resolve = |_text: &str| -> Result<String, String> {
            panic!("unsupported JavaScript forms must remain inert")
        };
        assert_eq!(
            resolve_javascript_orchestrator_tools(input, &mut resolve).unwrap(),
            input
        );
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
        assert!(allowed.get("instructions").is_none());
    }

    #[test]
    fn standalone_codex_search_shape_is_protected_without_response_instructions() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let secret = [
            "sk-or-v1-",
            "fedcba9876543210fedcba9876543210",
            "fedcba9876543210fedcba9876543210",
        ]
        .concat();
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "id": "search-session",
                "model": "gpt-test",
                "input": "Find official documentation",
                "commands": {
                    "search_query": [{
                        "q": format!("OpenAI docs; OPENROUTER_API_KEY={secret}"),
                        "domains": ["openai.com"]
                    }],
                    "response_length": "short"
                },
                "reasoning": {"summary": format!("unmask({secret})")},
                "settings": {"search_context_size": "low"},
                "max_output_tokens": 2500
            }))
            .unwrap(),
        );
        let masker = Mutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::from_env().unwrap());
        let protected = protect_openai_request_body(
            &body,
            &masker,
            &plugins,
            &HashMap::new(),
            OpenAiRequestDialect::StandaloneSearch,
            true,
        )
        .unwrap();
        let protected: Value = serde_json::from_slice(&protected.body).unwrap();
        let query = protected["commands"]["search_query"][0]["q"]
            .as_str()
            .unwrap();
        assert!(!query.contains(&secret), "{query}");
        assert!(query.contains("<<KEYED_SECRET_"), "{query}");
        let reasoning = protected["reasoning"]["summary"].as_str().unwrap();
        assert!(!reasoning.contains(&secret), "{reasoning}");
        assert!(reasoning.contains("<<KEYED_SECRET_"), "{reasoning}");
        assert!(protected.get("instructions").is_none());
    }

    #[test]
    fn provider_boundary_forwards_codex_standalone_search_after_masking() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = ProviderBoundaryTestEnv::install(&store);
        let secret = [
            "sk-or-v1-",
            "fedcba9876543210fedcba9876543210",
            "fedcba9876543210fedcba9876543210",
        ]
        .concat();
        let (upstream, captured, thread) = mock_chat_upstream();
        let proxy = OpenAiHttpProxyGuard::start(upstream).unwrap();

        let response = reqwest::blocking::Client::new()
            .post(format!(
                "{}/backend-api/codex/alpha/search",
                proxy.base_url()
            ))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({
                    "id": "search-session",
                    "model": "gpt-test",
                    "commands": {"search_query": [{
                        "q": format!("OpenAI docs; OPENROUTER_API_KEY={secret}")
                    }]}
                }))
                .unwrap(),
            )
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();
        assert_eq!(response.headers()["x-pentect-coverage"], "full");

        let (headers, request) = captured
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        thread.join().unwrap();
        assert!(
            headers.starts_with("POST /backend-api/codex/alpha/search "),
            "{headers}"
        );
        assert!(!request.contains(&secret), "{request}");
        assert!(request.contains("<<KEYED_SECRET_"), "{request}");
    }

    #[test]
    fn unknown_standalone_search_commands_remain_fail_closed() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let body = Bytes::from_static(
            br#"{"id":"search-session","model":"gpt-test","commands":{"future_search":[]}}"#,
        );
        let masker = Mutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::from_env().unwrap());
        let error = match protect_openai_request_body(
            &body,
            &masker,
            &plugins,
            &HashMap::new(),
            OpenAiRequestDialect::StandaloneSearch,
            true,
        ) {
            Ok(_) => panic!("unknown standalone search command should be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("unknown search command"), "{error}");
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
    fn enabled_response_text_restores_known_handles_only() {
        let mut value = serde_json::json!({
            "output": [{
                "type": "message",
                "content": [{
                    "type": "output_text",
                    "text": "use <<CHARGE_0123456789abcdef>> and <<UNKNOWN_0123456789abcdef>>"
                }]
            }]
        });
        let mut resolve =
            |text: &str| Ok(text.replace("<<CHARGE_0123456789abcdef>>", "local-value"));
        restore_openai_output_text(&mut value, &mut resolve).unwrap();
        assert_eq!(
            value["output"][0]["content"][0]["text"],
            "use local-value and <<UNKNOWN_0123456789abcdef>>"
        );
    }

    #[test]
    fn enabled_openai_stream_restores_a_handle_split_across_events() {
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let mut streams = HashMap::new();
        let mut resolve: HandleResolver =
            Box::new(|text: &str| Ok(text.replace("<<CHARGE_0123456789abcdef>>", "local-value")));
        let first = b"data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"content_index\":0,\"delta\":\"before <<CHAR\"}\n\n";
        let second = b"data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"content_index\":0,\"delta\":\"GE_0123456789abcdef>> after\"}\n\n";
        let first =
            rewrite_openai_sse_block(first, &plugins, true, &mut streams, &mut resolve).unwrap();
        let second =
            rewrite_openai_sse_block(second, &plugins, true, &mut streams, &mut resolve).unwrap();
        let output = first
            .into_iter()
            .chain(second)
            .flat_map(|block| block.to_vec())
            .collect::<Vec<_>>();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("local-value"), "{output}");
        assert!(!output.contains("<<CHARGE_"), "{output}");
    }

    #[test]
    fn openai_output_text_done_flushes_buffered_delta_text() {
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let mut streams = HashMap::new();
        let mut resolve: HandleResolver = Box::new(|text: &str| Ok(text.to_string()));
        let first = rewrite_openai_sse_block(
            b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"content_index\":0,\"delta\":\"trailing text\"}\n\n",
            &plugins,
            true,
            &mut streams,
            &mut resolve,
        )
        .unwrap();
        let done = rewrite_openai_sse_block(
            b"event: response.output_text.done\ndata: {\"type\":\"response.output_text.done\",\"item_id\":\"msg_1\",\"content_index\":0,\"text\":\"trailing text\"}\n\n",
            &plugins,
            true,
            &mut streams,
            &mut resolve,
        )
        .unwrap();
        let output = first
            .into_iter()
            .chain(done)
            .map(|block| String::from_utf8(block.to_vec()).unwrap())
            .collect::<String>();
        assert!(output.contains("trailing text"), "{output}");
        assert!(
            output.contains("event: response.output_text.delta\n"),
            "{output}"
        );
        assert!(
            output.contains("event: response.output_text.done\n"),
            "{output}"
        );
        assert!(streams.is_empty());
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
    fn multiline_sse_data_is_joined_and_reencoded_once() {
        let input = concat!(
            "event: response.function_call_arguments.done\r\n",
            "data: {\"type\":\"response.function_call_arguments.done\",\r\n",
            "data: \"arguments\":\"{\\\"command\\\":\\\"echo <<SECRET_0123456789abcdef>>\\\"}\"}\r\n",
            "\r\n",
        );
        assert_eq!(
            sse_data(input).unwrap(),
            concat!(
                "{\"type\":\"response.function_call_arguments.done\",\n",
                "\"arguments\":\"{\\\"command\\\":\\\"echo <<SECRET_0123456789abcdef>>\\\"}\"}",
            )
        );

        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let mut streams = HashMap::new();
        let mut resolve: HandleResolver =
            Box::new(|text: &str| Ok(text.replace("<<SECRET_0123456789abcdef>>", "local-value")));
        let delta = rewrite_openai_sse_block(
            b"event: response.function_call_arguments.delta\r\ndata: {\"type\":\"response.function_call_arguments.delta\",\"delta\":\"untrusted\"}\r\n\r\n",
            &plugins,
            false,
            &mut streams,
            &mut resolve,
        )
        .unwrap();
        assert!(delta.is_empty());
        let rewritten = rewrite_openai_sse_block(
            input.as_bytes(),
            &plugins,
            false,
            &mut streams,
            &mut resolve,
        )
        .unwrap();
        assert_eq!(rewritten.len(), 2);
        let rewritten = rewritten
            .into_iter()
            .map(|block| String::from_utf8(block.to_vec()).unwrap())
            .collect::<String>();
        assert_eq!(rewritten.matches("data:").count(), 2, "{rewritten}");
        assert!(rewritten.contains("local-value"), "{rewritten}");
        assert!(!rewritten.contains("<<SECRET_"), "{rewritten}");
        assert!(
            rewritten.starts_with("event: response.function_call_arguments.delta\r\ndata: "),
            "{rewritten:?}"
        );
        assert!(
            rewritten.contains("event: response.function_call_arguments.done\r\ndata: "),
            "{rewritten:?}"
        );
        assert!(rewritten.ends_with("\r\n\r\n"), "{rewritten:?}");
    }

    #[test]
    fn untouched_sse_framing_is_preserved() {
        let input = b"event: response.output_text.delta\r\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\r\n\r\n";
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let mut streams = HashMap::new();
        let mut resolve: HandleResolver = Box::new(|text: &str| Ok(text.to_string()));
        assert_eq!(
            rewrite_openai_sse_block(input, &plugins, false, &mut streams, &mut resolve,)
                .unwrap()
                .as_slice(),
            &[Bytes::copy_from_slice(input)]
        );
    }
}
