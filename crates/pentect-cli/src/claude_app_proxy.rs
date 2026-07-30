//! Explicit HTTPS proxy PoC for the unmodified Claude Desktop application.
//!
//! The root CA and its signing key exist only in memory. Claude Desktop is
//! launched with Chromium's SPKI allow-list, so this does not modify the OS
//! certificate store. Chat completion bodies are protected in memory and are
//! never logged. Claude Code children inherit the Anthropic HTTP gateway.

use futures_util::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Limited, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, PublicKeyData,
};
use sha2::{Digest, Sha256};
#[cfg(debug_assertions)]
use std::collections::HashSet;
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroize;

type ProxyBodyError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, ProxyBodyError>;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 128;
const MAX_CHAT_BODY_BYTES: usize = 32 * 1024 * 1024;
const HANDLE_CONTRACT: &str = "Values formatted as <<LABEL_HASH>> are opaque local capability handles. Copy a handle byte-for-byte into a client tool call when the tool needs the represented value. Do not alter, expand, guess, or expose it.";

pub(crate) fn cmd_claude_app(args: &[String]) -> i32 {
    match run_claude_app(args) {
        Ok(status) => status.code().unwrap_or(0),
        Err(error) => {
            eprintln!("[pentect] {error}");
            2
        }
    }
}

fn run_claude_app(args: &[String]) -> Result<std::process::ExitStatus, String> {
    let options = ClaudeAppOptions::parse(args)?;
    let app = options.app.unwrap_or_else(default_claude_app_path);
    if options.dry_run {
        println!("{}", app.display());
        return Ok(success_status());
    }
    if !app.is_file() {
        return Err(format!(
            "Claude Desktop was not found at '{}'; pass --app PATH",
            app.display()
        ));
    }
    if claude_desktop_is_running(&app) {
        return Err(
            "Claude Desktop is already running; quit it before `pentect claude-app` so Chromium can apply the private proxy settings"
                .to_string(),
        );
    }

    let anthropic = crate::claude_http_proxy::ClaudeHttpProxyGuard::start(
        options
            .upstream
            .unwrap_or_else(|| "https://api.anthropic.com".to_string()),
    )?;
    let proxy = ClaudeAppProxyGuard::start()?;
    let user_data_dir = claude_user_data_dir()?;
    eprintln!(
        "[pentect] Claude App gateway ready at {}",
        proxy.proxy_url()
    );
    eprintln!("[pentect] Chat and Claude Code model traffic is protected; bodies are not logged");

    let mut command = Command::new(&app);
    command
        .arg(format!("--proxy-server={}", proxy.proxy_url()))
        .arg(format!(
            "--ignore-certificate-errors-spki-list={}",
            proxy.spki_hash()
        ))
        .arg(format!("--user-data-dir={}", user_data_dir.display()))
        .env("ANTHROPIC_BASE_URL", anthropic.base_url())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start Claude Desktop: {error}"))?;
    let status = child
        .wait()
        .map_err(|error| format!("could not wait for Claude Desktop: {error}"))?;
    drop(proxy);
    drop(anthropic);
    Ok(status)
}

#[derive(Debug)]
struct ClaudeAppOptions {
    app: Option<PathBuf>,
    upstream: Option<String>,
    dry_run: bool,
}

impl ClaudeAppOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut app = None;
        let mut upstream = None;
        let mut dry_run = false;
        let mut index = 2;
        while index < args.len() {
            match args[index].as_str() {
                "--app" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--app requires a value".to_string())?;
                    app = Some(PathBuf::from(value));
                    index += 2;
                }
                "--dry-run" => {
                    dry_run = true;
                    index += 1;
                }
                "--upstream" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--upstream requires a value".to_string())?;
                    upstream = Some(value.clone());
                    index += 2;
                }
                value => return Err(format!("unknown claude-app option: {value}")),
            }
        }
        Ok(Self {
            app,
            upstream,
            dry_run,
        })
    }
}

struct ClaudeAppProxyGuard {
    proxy_url: String,
    spki_hash: String,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ClaudeAppProxyGuard {
    fn start() -> Result<Self, String> {
        let authority = CertificateAuthority::new()?;
        let spki_hash = authority.spki_hash.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let thread = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!(
                        "could not start Claude App proxy runtime: {error}"
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                if let Err(error) = run_proxy(authority, ready_tx, shutdown_rx).await {
                    eprintln!("[pentect] Claude App proxy stopped: {error}");
                }
            });
        });
        let proxy_url = ready_rx
            .recv_timeout(STARTUP_TIMEOUT)
            .map_err(|_| "Claude App proxy did not start within 5 seconds".to_string())??;
        Ok(Self {
            proxy_url,
            spki_hash,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    fn proxy_url(&self) -> &str {
        &self.proxy_url
    }

    fn spki_hash(&self) -> &str {
        &self.spki_hash
    }
}

impl Drop for ClaudeAppProxyGuard {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.proxy_url.zeroize();
        self.spki_hash.zeroize();
    }
}

struct CertificateAuthority {
    issuer: CertifiedIssuer<'static, KeyPair>,
    spki_hash: String,
}

impl CertificateAuthority {
    fn new() -> Result<Self, String> {
        let key = KeyPair::generate()
            .map_err(|error| format!("could not generate Claude App proxy CA key: {error}"))?;
        let spki = key.subject_public_key_info();
        let spki_hash = data_encoding::BASE64.encode(&Sha256::digest(spki));
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|error| format!("could not create Claude App proxy CA: {error}"))?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "Pentect ephemeral Claude App proxy");
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let issuer = CertifiedIssuer::self_signed(params, key)
            .map_err(|error| format!("could not sign Claude App proxy CA: {error}"))?;
        Ok(Self { issuer, spki_hash })
    }

    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let key = KeyPair::generate()
            .map_err(|error| format!("could not generate certificate for {host}: {error}"))?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|error| format!("could not create certificate for {host}: {error}"))?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, host);
        params.distinguished_name = distinguished_name;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|error| format!("could not sign certificate for {host}: {error}"))?;
        let private_key = PrivatePkcs8KeyDer::from(key.serialize_der());
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![
                    CertificateDer::from(certificate.der().to_vec()),
                    self.issuer.der().clone(),
                ],
                private_key.into(),
            )
            .map_err(|error| format!("could not configure TLS for {host}: {error}"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

struct ProxyState {
    authority: CertificateAuthority,
    server_configs: Mutex<HashMap<String, Arc<ServerConfig>>>,
    client: reqwest::Client,
    masker: Arc<Mutex<pentect_agent::ActiveToolOutputMasker>>,
}

impl ProxyState {
    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let mut configs = self
            .server_configs
            .lock()
            .map_err(|_| "Claude App certificate cache is unavailable".to_string())?;
        if let Some(config) = configs.get(host) {
            return Ok(Arc::clone(config));
        }
        let config = self.authority.server_config(host)?;
        configs.insert(host.to_string(), Arc::clone(&config));
        Ok(config)
    }
}

async fn run_proxy(
    authority: CertificateAuthority,
    ready_tx: mpsc::Sender<Result<String, String>>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|error| format!("could not bind Claude App proxy: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("could not read Claude App proxy address: {error}"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .tcp_nodelay(true)
        .build()
        .map_err(|error| format!("could not build Claude App upstream client: {error}"))?;
    let state = Arc::new(ProxyState {
        authority,
        server_configs: Mutex::new(HashMap::new()),
        client,
        masker: Arc::new(Mutex::new(pentect_agent::ActiveToolOutputMasker::new()?)),
    });
    let _ = ready_tx.send(Ok(format!("http://{address}")));

    let connections = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|error| format!("Claude App proxy accept failed: {error}"))?;
                let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _permit = permit;
                    let service = service_fn(move |request| {
                        connect_request(request, Arc::clone(&state))
                    });
                    let io = hyper_util::rt::TokioIo::new(stream);
                    if let Err(error) = http1::Builder::new()
                        .max_buf_size(64 * 1024)
                        .max_headers(128)
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await
                    {
                        eprintln!("[pentect] Claude App proxy connection failed: {error}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn connect_request(
    mut request: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<ProxyBody>, Infallible> {
    if request.method() != Method::CONNECT {
        return Ok(empty_response(StatusCode::METHOD_NOT_ALLOWED));
    }
    let Some(authority) = request.uri().authority().cloned() else {
        return Ok(empty_response(StatusCode::BAD_REQUEST));
    };
    let host = authority.host().to_ascii_lowercase();
    let port = authority.port_u16().unwrap_or(443);
    let upgraded = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        let result = async {
            let upgraded = upgraded
                .await
                .map_err(|error| format!("CONNECT upgrade failed: {error}"))?;
            let stream = hyper_util::rt::TokioIo::new(upgraded);
            if should_inspect(&host, port) {
                serve_inspected(stream, host, state).await
            } else {
                tunnel(stream, authority.as_str()).await
            }
        }
        .await;
        if let Err(error) = result {
            eprintln!("[pentect] Claude App tunnel failed: {error}");
        }
    });
    Ok(empty_response(StatusCode::OK))
}

fn should_inspect(host: &str, port: u16) -> bool {
    port == 443
        && (host == "claude.ai"
            || host.ends_with(".claude.ai")
            || host == "claude.com"
            || host.ends_with(".claude.com"))
}

async fn tunnel<T>(mut client: T, authority: &str) -> Result<(), String>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut upstream = TcpStream::connect(authority)
        .await
        .map_err(|error| format!("could not connect to {authority}: {error}"))?;
    copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(|error| format!("tunnel copy failed for {authority}: {error}"))?;
    Ok(())
}

async fn serve_inspected<T>(stream: T, host: String, state: Arc<ProxyState>) -> Result<(), String>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let config = state.server_config(&host)?;
    let tls = TlsAcceptor::from(config)
        .accept(stream)
        .await
        .map_err(|error| format!("TLS handshake failed for {host}: {error}"))?;
    let service =
        service_fn(move |request| forward_inspected(request, host.clone(), Arc::clone(&state)));
    http1::Builder::new()
        .max_buf_size(64 * 1024)
        .max_headers(128)
        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
        .await
        .map_err(|error| format!("inspected HTTP connection failed: {error}"))
}

async fn forward_inspected(
    request: Request<Incoming>,
    host: String,
    state: Arc<ProxyState>,
) -> Result<Response<ProxyBody>, Infallible> {
    match forward_inspected_inner(request, &host, &state).await {
        Ok(response) => Ok(response),
        Err(error) => {
            eprintln!("[pentect] Claude App request failed: {error}");
            Ok(empty_response(StatusCode::BAD_GATEWAY))
        }
    }
}

async fn forward_inspected_inner(
    request: Request<Incoming>,
    host: &str,
    state: &ProxyState,
) -> Result<Response<ProxyBody>, String> {
    let method = request.method().clone();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let path = request.uri().path().to_string();
    let safe_path = metadata_path(&path);
    let content_type = request
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-");
    let protect_chat = is_chat_completion(host, &path, content_type);
    eprintln!("[pentect] claude-app > {method} {host}{safe_path} {content_type}");

    let url = format!("https://{host}{path_and_query}");
    let mut headers = request.headers().clone();
    remove_hop_by_hop_headers(&mut headers);
    headers.remove(hyper::header::HOST);
    let body = if protect_chat {
        let body = Limited::new(request.into_body(), MAX_CHAT_BODY_BYTES)
            .collect()
            .await
            .map_err(|error| format!("could not read Claude App Chat request: {error}"))?
            .to_bytes();
        let original = body.clone();
        let masker = Arc::clone(&state.masker);
        let protected =
            tokio::task::spawn_blocking(move || protect_chat_request(&original, &masker))
                .await
                .map_err(|_| "Claude App Chat protection task failed".to_string())??;
        reqwest::Body::from(protected)
    } else {
        let stream = request
            .into_body()
            .into_data_stream()
            .map(|result| result.map_err(io::Error::other));
        reqwest::Body::wrap_stream(stream)
    };
    let upstream = state
        .client
        .request(method.clone(), url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|error| format!("upstream request failed for {method} {host}{path}: {error}"))?;
    let status = upstream.status();
    let response_content_type = upstream
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or("-");
    eprintln!("[pentect] claude-app < {status} {method} {host}{safe_path} {response_content_type}");

    let mut builder = Response::builder().status(status);
    for (name, value) in upstream.headers() {
        if !is_hop_by_hop_header(name) {
            builder = builder.header(name, value);
        }
    }
    #[cfg(debug_assertions)]
    let schema_trace = (std::env::var_os("PENTECT_CLAUDE_APP_TRACE_SCHEMA").is_some()
        && path.ends_with("/completion")
        && response_content_type.eq_ignore_ascii_case("text/event-stream"))
    .then(|| Arc::new(Mutex::new(SseSchemaTracer::default())));
    let transform_chat = protect_chat
        && status.is_success()
        && response_content_type.eq_ignore_ascii_case("text/event-stream");
    let stream = upstream.bytes_stream().map(move |result| {
        #[cfg(debug_assertions)]
        if let (Ok(chunk), Some(trace)) = (&result, &schema_trace) {
            if let Ok(mut trace) = trace.lock() {
                trace.observe(chunk);
            }
        }
        result
            .map(Frame::data)
            .map_err(|error| Box::new(error) as ProxyBodyError)
    });
    let body = if transform_chat {
        chat_sse_body(Box::pin(stream))
    } else {
        BodyExt::boxed_unsync(StreamBody::new(stream))
    };
    builder
        .body(body)
        .map_err(|error| format!("could not build Claude App response: {error}"))
}

fn is_chat_completion(host: &str, path: &str, content_type: &str) -> bool {
    (host == "claude.ai" || host.ends_with(".claude.ai"))
        && path.ends_with("/completion")
        && content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn protect_chat_request(
    body: &Bytes,
    masker: &Mutex<pentect_agent::ActiveToolOutputMasker>,
) -> Result<Bytes, String> {
    let mut value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("[pentect] Claude App Chat protection skipped: invalid JSON: {error}");
            return Ok(body.clone());
        }
    };
    inject_chat_contract(&mut value);
    let mut masker = masker
        .lock()
        .map_err(|_| "Claude App Chat masker lock was poisoned".to_string())?;
    if let Err(error) = mask_chat_value(&mut value, false, &mut masker) {
        if error.starts_with("image blocked:") || error.starts_with("document blocked:") {
            return Err(error);
        }
        eprintln!("[pentect] Claude App Chat protection skipped: {error}");
        return Ok(body.clone());
    }
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|error| format!("could not encode protected Claude App Chat request: {error}"))
}

fn inject_chat_contract(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for key in ["system", "prompt"] {
        if let Some(serde_json::Value::String(text)) = object.get_mut(key) {
            if !text.contains(HANDLE_CONTRACT) {
                let existing = std::mem::take(text);
                *text = format!("{HANDLE_CONTRACT}\n\n{existing}");
            }
            return;
        }
    }
}

fn mask_chat_value(
    value: &mut serde_json::Value,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    match value {
        serde_json::Value::String(text) => {
            crate::claude_http_proxy::mask_string(text, tool_result, masker)
        }
        serde_json::Value::Array(values) => {
            for value in values {
                mask_chat_value(value, tool_result, masker)?;
            }
            Ok(())
        }
        serde_json::Value::Object(object) => {
            let kind = object
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            if kind.contains("image") {
                inspect_chat_image(object)?;
                return Ok(());
            }
            if kind.contains("file") || kind.contains("document") {
                inspect_chat_document(object, tool_result, masker)?;
                return Ok(());
            }
            let nested_tool_result = tool_result
                || kind.contains("tool_result")
                || kind.contains("tool_output")
                || kind.contains("function_output");
            for (key, nested) in object {
                if matches!(
                    key.as_str(),
                    "signature" | "thinking_signature" | "attestation" | "authorization" | "token"
                ) {
                    continue;
                }
                mask_chat_value(nested, nested_tool_result, masker)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn inspect_chat_image(
    object: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let key = ["image_url", "url", "data"]
        .into_iter()
        .find(|key| object.contains_key(*key));
    let Some(serde_json::Value::String(url)) = key.and_then(|key| object.get_mut(key)) else {
        return unscanned_chat_image();
    };
    let Some((metadata, encoded)) = url.split_once(',') else {
        return unscanned_chat_image();
    };
    if !metadata.starts_with("data:image/") || !metadata.ends_with(";base64") {
        return unscanned_chat_image();
    }
    if let Some(protected) = crate::claude_http_proxy::redact_inline_image_data(encoded)? {
        *url = format!("data:image/png;base64,{protected}");
    }
    Ok(())
}

fn inspect_chat_document(
    object: &mut serde_json::Map<String, serde_json::Value>,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    if object.get("file_id").is_some() || object.get("url").is_some() {
        return crate::claude_http_proxy::enforce_unscanned_document_policy();
    }
    let data = object
        .get("file_data")
        .or_else(|| object.get("data"))
        .and_then(serde_json::Value::as_str);
    let Some(data) = data else {
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
        .unwrap_or(("application/octet-stream", data));
    let source = serde_json::json!({
        "type": "base64",
        "media_type": media_type,
        "data": encoded,
    });
    crate::claude_http_proxy::inspect_base64_document(&source, tool_result, masker)
}

fn unscanned_chat_image() -> Result<(), String> {
    if pentect_agent::unscanned_images_should_block()? {
        Err("image blocked: image source could not be scanned".to_string())
    } else {
        Ok(())
    }
}

type ChatFrameStream =
    Pin<Box<dyn futures_util::Stream<Item = Result<Frame<Bytes>, ProxyBodyError>> + Send>>;

struct ChatStreamState {
    upstream: ChatFrameStream,
    pending: Vec<u8>,
    ready: VecDeque<Result<Frame<Bytes>, ProxyBodyError>>,
    passthrough: bool,
    finished: bool,
}

fn chat_sse_body<S>(stream: S) -> ProxyBody
where
    S: futures_util::Stream<Item = Result<Frame<Bytes>, ProxyBodyError>> + Send + 'static,
{
    let state = ChatStreamState {
        upstream: Box::pin(stream),
        pending: Vec::new(),
        ready: VecDeque::new(),
        passthrough: false,
        finished: false,
    };
    let stream = futures_util::stream::unfold(state, |mut state| async move {
        loop {
            if let Some(item) = state.ready.pop_front() {
                return Some((item, state));
            }
            if state.finished {
                return None;
            }
            match state.upstream.next().await {
                Some(Ok(frame)) if state.passthrough => {
                    return Some((Ok(frame), state));
                }
                Some(Ok(frame)) => {
                    let Ok(chunk) = frame.into_data() else {
                        continue;
                    };
                    if state.pending.len().saturating_add(chunk.len()) > MAX_CHAT_BODY_BYTES {
                        eprintln!(
                            "[pentect] Claude App Chat restoration disabled: event exceeded limit"
                        );
                        let mut bytes = std::mem::take(&mut state.pending);
                        bytes.extend_from_slice(&chunk);
                        state.ready.push_back(Ok(Frame::data(Bytes::from(bytes))));
                        state.passthrough = true;
                        continue;
                    }
                    state.pending.extend_from_slice(&chunk);
                    while let Some(end) = first_sse_block_end(&state.pending) {
                        let block = state.pending.drain(..end).collect::<Vec<_>>();
                        state
                            .ready
                            .push_back(Ok(Frame::data(rewrite_chat_sse_block(&block))));
                    }
                }
                Some(Err(error)) => {
                    state.finished = true;
                    state.ready.push_back(Err(error));
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

fn rewrite_chat_sse_block(block: &[u8]) -> Bytes {
    let Ok(text) = std::str::from_utf8(block) else {
        return Bytes::copy_from_slice(block);
    };
    let Some(data) = text.lines().find_map(|line| line.strip_prefix("data:")) else {
        return Bytes::copy_from_slice(block);
    };
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(data.trim_start()) else {
        return Bytes::copy_from_slice(block);
    };
    let mut resolve = crate::claude_http_proxy::request_scoped_resolver();
    if let Err(error) = resolve_chat_tool_calls(&mut value, &mut resolve) {
        eprintln!("[pentect] Claude App Chat tool restoration skipped: {error}");
        return Bytes::copy_from_slice(block);
    }
    let Ok(encoded) = serde_json::to_string(&value) else {
        return Bytes::copy_from_slice(block);
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
    Bytes::from(output)
}

fn resolve_chat_tool_calls<R>(value: &mut serde_json::Value, resolve: &mut R) -> Result<(), String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                resolve_chat_tool_calls(value, resolve)?;
            }
        }
        serde_json::Value::Object(object) => {
            let kind = object
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            let tool_call = kind.contains("tool_use")
                || kind.contains("tool_call")
                || kind.contains("function_call");
            if tool_call {
                let name = object
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                for key in ["arguments", "input"] {
                    if let Some(serde_json::Value::String(arguments)) = object.get_mut(key) {
                        *arguments = crate::claude_http_proxy::resolve_tool_input_json(
                            arguments,
                            name.as_deref(),
                            resolve,
                        )?;
                    }
                }
            }
            for nested in object.values_mut() {
                resolve_chat_tool_calls(nested, resolve)?;
            }
        }
        _ => {}
    }
    Ok(())
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

#[cfg(debug_assertions)]
#[derive(Default)]
struct SseSchemaTracer {
    pending: Vec<u8>,
    seen: HashSet<String>,
    event_name: Option<String>,
}

#[cfg(debug_assertions)]
impl SseSchemaTracer {
    fn observe(&mut self, chunk: &[u8]) {
        const MAX_PENDING: usize = 1024 * 1024;
        if self.pending.len().saturating_add(chunk.len()) > MAX_PENDING {
            self.pending.clear();
            return;
        }
        self.pending.extend_from_slice(chunk);
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line = self.pending.drain(..=end).collect::<Vec<_>>();
            self.observe_line(&line);
        }
    }

    fn observe_line(&mut self, bytes: &[u8]) {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return;
        };
        let line = text.trim_end_matches(['\r', '\n']);
        if let Some(event_name) = line
            .strip_prefix("event:")
            .map(str::trim)
            .filter(|value| protocol_name(value))
        {
            self.event_name = Some(event_name.to_string());
            return;
        }
        let Some(data) = line.strip_prefix("data:").map(str::trim) else {
            return;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(data) else {
            return;
        };
        let shape = safe_json_shape(&value, 0);
        let event_name = self.event_name.as_deref().unwrap_or("message");
        let summary = format!("{event_name} {shape}");
        if self.seen.insert(summary.clone()) {
            eprintln!("[pentect] claude-app SSE schema: {summary}");
        }
    }
}

#[cfg(debug_assertions)]
fn safe_json_shape(value: &serde_json::Value, depth: usize) -> String {
    use serde_json::Value;
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(_) => "bool".to_string(),
        Value::Number(_) => "number".to_string(),
        Value::String(_) => "string".to_string(),
        Value::Array(values) => {
            let nested = values
                .first()
                .map(|value| safe_json_shape(value, depth + 1))
                .unwrap_or_else(|| "empty".to_string());
            format!("array<{nested}>")
        }
        Value::Object(object) => {
            let mut fields = object
                .iter()
                .map(|(key, value)| {
                    let shape = if matches!(key.as_str(), "type" | "subtype" | "event" | "status")
                        && value.as_str().is_some_and(protocol_name)
                    {
                        format!("string({})", value.as_str().unwrap_or_default())
                    } else if depth >= 2
                        || matches!(
                            key.as_str(),
                            "input" | "arguments" | "content" | "text" | "prompt"
                        )
                    {
                        json_kind(value).to_string()
                    } else {
                        safe_json_shape(value, depth + 1)
                    };
                    format!("{key}:{shape}")
                })
                .collect::<Vec<_>>();
            fields.sort_unstable();
            format!("{{{}}}", fields.join(","))
        }
    }
}

#[cfg(debug_assertions)]
fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(debug_assertions)]
fn protocol_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn metadata_path(path: &str) -> String {
    let mut safe = String::with_capacity(path.len().min(256));
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        safe.push('/');
        if segment.len() > 36
            || segment.bytes().all(|byte| byte.is_ascii_digit())
            || looks_like_uuid(segment)
            || looks_like_opaque_id(segment)
        {
            safe.push_str(":id");
        } else {
            safe.push_str(segment);
        }
        if safe.len() >= 256 {
            safe.truncate(256);
            safe.push_str("...");
            break;
        }
    }
    if safe.len() > 1 && path.ends_with('/') {
        safe.push('/');
    }
    if safe.is_empty() {
        safe.push('/');
    }
    safe
}

fn looks_like_opaque_id(segment: &str) -> bool {
    segment.starts_with("cse_")
        || (segment.len() >= 24
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
}

fn looks_like_uuid(segment: &str) -> bool {
    segment.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| segment.as_bytes().get(index) == Some(&b'-'))
        && segment
            .bytes()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn remove_hop_by_hop_headers(headers: &mut hyper::HeaderMap) {
    for name in [
        hyper::header::CONNECTION,
        hyper::header::PROXY_AUTHENTICATE,
        hyper::header::PROXY_AUTHORIZATION,
        hyper::header::TE,
        hyper::header::TRAILER,
        hyper::header::TRANSFER_ENCODING,
        hyper::header::UPGRADE,
    ] {
        headers.remove(name);
    }
}

fn is_hop_by_hop_header(name: &hyper::header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn empty_response(status: StatusCode) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("static empty response")
}

fn default_claude_app_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(path) = find_windows_claude_app() {
            return path;
        }
    }
    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Applications/Claude.app/Contents/MacOS/Claude");
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for path in [
            "/usr/bin/claude-desktop",
            "/usr/local/bin/claude-desktop",
            "/opt/Claude/claude",
        ] {
            let path = PathBuf::from(path);
            if path.is_file() {
                return path;
            }
        }
    }
    PathBuf::from("claude-desktop")
}

fn claude_user_data_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("Claude"))
            .ok_or_else(|| "could not locate Claude Desktop user data".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|path| {
                path.join("Library")
                    .join("Application Support")
                    .join("Claude")
            })
            .ok_or_else(|| "could not locate Claude Desktop user data".to_string())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .map(|path| path.join("Claude"))
            .ok_or_else(|| "could not locate Claude Desktop user data".to_string())
    }
}

#[cfg(windows)]
fn find_windows_claude_app() -> Option<PathBuf> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const PACKAGES_KEY: &str = r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

    // WindowsApps intentionally denies ordinary directory enumeration. The
    // per-user AppModel repository is the supported local index for package
    // roots and does not require elevation.
    let output = Command::new("reg.exe")
        .args(["query", PACKAGES_KEY])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let keys = String::from_utf8_lossy(&output.stdout);
    let mut candidates = keys
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.rsplit('\\')
                .next()
                .is_some_and(|name| name.starts_with("Claude_") && name.contains("_x64__"))
        })
        .filter_map(|key| {
            let package_name = key.rsplit('\\').next()?.to_string();
            let output = Command::new("reg.exe")
                .args(["query", key, "/v", "PackageRootFolder"])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let root = String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(|line| {
                    let (_, value) = line.split_once("REG_SZ")?;
                    Some(value.trim())
                })?
                .to_string();
            let executable = PathBuf::from(root).join("app").join("Claude.exe");
            executable
                .is_file()
                .then(|| (windows_package_version(&package_name), executable))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    candidates.pop().map(|(_, path)| path)
}

#[cfg(windows)]
fn windows_package_version(name: &str) -> Vec<u64> {
    name.split('_')
        .nth(1)
        .unwrap_or_default()
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

fn claude_desktop_is_running(app: &Path) -> bool {
    let expected = app
        .canonicalize()
        .unwrap_or_else(|_| app.to_path_buf())
        .to_string_lossy()
        .to_ascii_lowercase();
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    system.processes().values().any(|process| {
        process
            .exe()
            .and_then(|path| path.canonicalize().ok())
            .is_some_and(|path| path.to_string_lossy().to_ascii_lowercase() == expected)
    })
}

#[cfg(windows)]
fn success_status() -> std::process::ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(0)
}

#[cfg(unix)]
fn success_status() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_accept_an_explicit_app_path() {
        let args = vec![
            "pentect".to_string(),
            "claude-app".to_string(),
            "--app".to_string(),
            "Claude.exe".to_string(),
        ];
        let options = ClaudeAppOptions::parse(&args).unwrap();
        assert_eq!(options.app, Some(PathBuf::from("Claude.exe")));
    }

    #[test]
    fn inspection_scope_is_exact_domain_suffix() {
        assert!(should_inspect("claude.ai", 443));
        assert!(should_inspect("assets.claude.ai", 443));
        assert!(!should_inspect("claude.ai.example.test", 443));
        assert!(!should_inspect("notclaude.ai", 443));
        assert!(!should_inspect("claude.ai", 8443));
    }

    #[test]
    fn chat_rewriting_requires_the_completion_json_endpoint() {
        assert!(is_chat_completion(
            "claude.ai",
            "/api/organizations/example/chat_conversations/example/completion",
            "application/json; charset=utf-8"
        ));
        assert!(!is_chat_completion(
            "claude.ai.example.test",
            "/completion",
            "application/json"
        ));
        assert!(!is_chat_completion(
            "claude.ai",
            "/completion",
            "multipart/form-data"
        ));
    }

    #[test]
    fn metadata_paths_hide_identifiers_and_long_segments() {
        assert_eq!(
            metadata_path(
                "/api/organizations/d65b35c5-7372-4d95-805b-6e59d6b07e24/chat_conversations"
            ),
            "/api/organizations/:id/chat_conversations"
        );
        assert_eq!(
            metadata_path("/cdn-cgi/challenge/abcdefghijklmnopqrstuvwxyz0123456789AB"),
            "/cdn-cgi/challenge/:id"
        );
        assert_eq!(
            metadata_path("/v1/code/sessions/cse_01Ni2WadyEAmYhNEa9JK4hLH/events"),
            "/v1/code/sessions/:id/events"
        );
    }

    #[test]
    fn ephemeral_ca_builds_host_certificate() {
        let authority = CertificateAuthority::new().unwrap();
        assert!(!authority.spki_hash.is_empty());
        authority.server_config("claude.ai").unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_package_versions_sort_numerically() {
        assert!(
            windows_package_version("Claude_1.10.0.0_x64__id")
                > windows_package_version("Claude_1.9.99.0_x64__id")
        );
    }
}
