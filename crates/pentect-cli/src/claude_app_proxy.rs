//! Explicit HTTPS gateway for the unmodified Claude Desktop application.
//!
//! The root CA and its signing key exist only in memory. Claude Desktop is
//! launched with Chromium's SPKI allow-list, so this does not modify the OS
//! certificate store. Chat completion bodies are protected in memory and are
//! never logged. Claude Code children inherit the Anthropic HTTP gateway.

use futures_util::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, PublicKeyData,
};
use sha2::{Digest, Sha256};
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
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroize;

use crate::handle_contract::HANDLE_CONTRACT;

type ProxyBodyError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, ProxyBodyError>;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 128;
const MAX_CERTIFICATE_CACHE_ENTRIES: usize = 64;
const MAX_CHAT_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_PENDING_UPLOADS: usize = 256;
const MAX_IDS_PER_UPLOAD: usize = 16;

pub(crate) fn cmd_claude_app(args: &[String]) -> i32 {
    match run_claude_app(args) {
        Ok(status) => status.code().unwrap_or(0),
        Err(error) => {
            eprintln!("[pentect] {error}");
            2
        }
    }
}

pub(crate) fn check_mode(args: &[String]) -> Result<bool, String> {
    ClaudeAppOptions::parse(args).map(|options| options.check)
}

fn run_claude_app(args: &[String]) -> Result<std::process::ExitStatus, String> {
    let options = ClaudeAppOptions::parse(args)?;
    let app = options.app.unwrap_or_else(default_claude_app_path);
    if options.check {
        let installed = app.is_file();
        println!("App: {}", app.display());
        println!("Installed: {}", if installed { "yes" } else { "no" });
        println!(
            "Running: {}",
            if claude_desktop_is_running(&app) {
                "yes"
            } else {
                "no"
            }
        );
        println!("Protection: Claude Chat, attachments, and Anthropic Messages APIs");
        let upstream = options
            .upstream
            .as_deref()
            .unwrap_or("https://api.anthropic.com");
        crate::upstream::parse_base(upstream, "Anthropic Messages")?;
        crate::upstream::header_overrides(&options.upstream_header_env)?;
        if !installed {
            return Err("Claude Desktop was not found; pass --app PATH".to_string());
        }
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
            "Claude Desktop is already running; quit it before `pentect claude app` so Chromium can apply the private proxy settings"
                .to_string(),
        );
    }

    let anthropic = crate::claude_http_proxy::ClaudeHttpProxyGuard::start_with_header_env(
        options
            .upstream
            .clone()
            .unwrap_or_else(|| "https://api.anthropic.com".to_string()),
        &options.upstream_header_env,
    )?;
    let proxy = ClaudeAppProxyGuard::start()?;
    let user_data_dir = claude_user_data_dir()?;
    eprintln!(
        "[pentect] Claude App gateway ready at {}",
        proxy.proxy_url()
    );
    eprintln!(
        "[pentect] Chat, supported attachments, and Claude Code model traffic are protected; bodies are not logged"
    );

    let mut command = Command::new(&app);
    crate::upstream::hide_header_source_env(&mut command, &options.upstream_header_env);
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
    configure_child_process(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start Claude Desktop: {error}"))?;
    let child_id = child.id();
    if let Err(error) = ctrlc::set_handler(move || {
        terminate_child_process(child_id);
        std::process::exit(130);
    }) {
        terminate_child_process(child_id);
        let _ = child.wait();
        return Err(format!(
            "could not install Claude Desktop shutdown handler: {error}"
        ));
    }
    let status = child
        .wait()
        .map_err(|error| format!("could not wait for Claude Desktop: {error}"))?;
    drop(proxy);
    drop(anthropic);
    Ok(status)
}

#[cfg(windows)]
fn configure_child_process(_command: &mut Command) {}

#[cfg(unix)]
fn configure_child_process(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(windows)]
fn terminate_child_process(pid: u32) {
    let _ = Command::new(crate::windows_system_executable("taskkill.exe"))
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(unix)]
fn terminate_child_process(pid: u32) {
    unsafe {
        libc::kill(-(pid as i32), libc::SIGTERM);
    }
}

#[derive(Debug)]
struct ClaudeAppOptions {
    app: Option<PathBuf>,
    upstream: Option<String>,
    upstream_header_env: Vec<String>,
    check: bool,
}

impl ClaudeAppOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut app = None;
        let mut upstream = None;
        let mut upstream_header_env = Vec::new();
        let mut check = false;
        let mut index = if args.get(1).is_some_and(|arg| arg == "claude")
            && args.get(2).is_some_and(|arg| arg == "app")
        {
            3
        } else {
            2
        };
        while index < args.len() {
            match args[index].as_str() {
                "--app" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--app requires a value".to_string())?;
                    app = Some(PathBuf::from(value));
                    index += 2;
                }
                "--check" | "--dry-run" => {
                    check = true;
                    index += 1;
                }
                "--upstream" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--upstream requires a value".to_string())?;
                    upstream = Some(value.clone());
                    index += 2;
                }
                "--upstream-header-env" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--upstream-header-env requires a value".to_string())?;
                    upstream_header_env.push(value.clone());
                    index += 2;
                }
                "--plugins" => {
                    if args
                        .get(index + 1)
                        .is_none_or(|value| value.starts_with("--"))
                    {
                        return Err("--plugins requires a value".to_string());
                    }
                    index += 2;
                }
                value => return Err(format!("unknown `pentect claude app` option: {value}")),
            }
        }
        Ok(Self {
            app,
            upstream,
            upstream_header_env,
            check,
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
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
    block_unknown_formats: bool,
    files: Mutex<HashMap<String, crate::http_files::Coverage>>,
    file_attestations: crate::http_files::FileAttestationStore,
    pending_files: Mutex<PendingFiles>,
}

#[derive(Default)]
struct PendingFiles {
    entries: HashMap<String, Vec<String>>,
    insertion_order: VecDeque<String>,
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
        if configs.len() >= MAX_CERTIFICATE_CACHE_ENTRIES {
            if let Some(expired) = configs.keys().next().cloned() {
                configs.remove(&expired);
            }
        }
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
        .read_timeout(Duration::from_secs(60))
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_nodelay(true)
        .build()
        .map_err(|error| format!("could not build Claude App upstream client: {error}"))?;
    let plugins = pentect_agent::PluginMiddleware::from_env()?;
    let state = Arc::new(ProxyState {
        authority,
        server_configs: Mutex::new(HashMap::new()),
        client,
        masker: Arc::new(Mutex::new(
            pentect_agent::ActiveToolOutputMasker::new_with_plugins(plugins.clone())?,
        )),
        plugins: Arc::new(Mutex::new(plugins)),
        block_unknown_formats: pentect_agent::unknown_formats_should_block()?,
        files: Mutex::new(HashMap::new()),
        file_attestations: crate::http_files::FileAttestationStore::open_default()?,
        pending_files: Mutex::new(PendingFiles::default()),
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
                    let permit = Arc::new(Mutex::new(Some(permit)));
                    let service = service_fn(move |request| {
                        connect_request(request, Arc::clone(&state), Arc::clone(&permit))
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
    connection_permit: Arc<Mutex<Option<tokio::sync::OwnedSemaphorePermit>>>,
) -> Result<Response<ProxyBody>, Infallible> {
    if request.method() != Method::CONNECT {
        return Ok(empty_response(StatusCode::METHOD_NOT_ALLOWED));
    }
    let Some(authority) = request.uri().authority().cloned() else {
        return Ok(empty_response(StatusCode::BAD_REQUEST));
    };
    let host = authority.host().to_ascii_lowercase();
    let port = authority.port_u16().unwrap_or(443);
    if port != 443 {
        return Ok(empty_response(StatusCode::FORBIDDEN));
    }
    let Some(permit) = connection_permit
        .lock()
        .ok()
        .and_then(|mut permit| permit.take())
    else {
        return Ok(empty_response(StatusCode::SERVICE_UNAVAILABLE));
    };
    let upgraded = hyper::upgrade::on(&mut request);
    if should_inspect(&host, port) {
        tokio::spawn(async move {
            let _permit = permit;
            let result = async {
                let upgraded = upgraded
                    .await
                    .map_err(|error| format!("CONNECT upgrade failed: {error}"))?;
                let stream = hyper_util::rt::TokioIo::new(upgraded);
                serve_inspected(stream, host, state).await
            }
            .await;
            if let Err(error) = result {
                eprintln!("[pentect] Claude App inspected tunnel failed: {error}");
            }
        });
    } else {
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = passthrough_tunnel(upgraded, &host, port).await {
                eprintln!("[pentect] Claude App network tunnel failed: {error}");
            }
        });
    }
    Ok(empty_response(StatusCode::OK))
}

async fn passthrough_tunnel(
    upgraded: hyper::upgrade::OnUpgrade,
    host: &str,
    port: u16,
) -> Result<(), String> {
    let upgraded = upgraded
        .await
        .map_err(|error| format!("CONNECT upgrade failed: {error}"))?;
    let mut client = hyper_util::rt::TokioIo::new(upgraded);
    let mut upstream = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    .map_err(|_| "could not reach required app service: connection timed out".to_string())?
    .map_err(|error| format!("could not reach required app service: {error}"))?;
    if let Err(error) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        if !matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof
        ) {
            return Err(format!("network tunnel failed: {error}"));
        }
    }
    Ok(())
}

fn should_inspect(host: &str, port: u16) -> bool {
    port == 443 && is_claude_host(host)
}

fn is_claude_host(host: &str) -> bool {
    host == "claude.ai"
        || host.ends_with(".claude.ai")
        || host == "claude.com"
        || host.ends_with(".claude.com")
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
            let category = error.split(':').next().unwrap_or("gateway request failed");
            eprintln!("[pentect] Claude App request failed: {category}");
            Ok(
                if error.starts_with("unknown format blocked:")
                    || error.starts_with("image blocked:")
                    || error.starts_with("document blocked:")
                    || error.starts_with("file upload blocked:")
                    || error.starts_with("Files API upload")
                    || error.starts_with("plugin blocked:")
                {
                    text_response(StatusCode::UNPROCESSABLE_ENTITY, &error)
                } else if error.starts_with("payload too large:") {
                    text_response(StatusCode::PAYLOAD_TOO_LARGE, &error)
                } else {
                    text_response(StatusCode::BAD_GATEWAY, "Pentect Claude App gateway failed")
                },
            )
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
        .unwrap_or("-")
        .to_string();
    let request_kind = classify_claude_app_request(&method, host, &path, &content_type);
    let protect_chat = request_kind == ClaudeAppRequest::ChatJson;
    let prepare_upload = request_kind == ClaudeAppRequest::PrepareUploadJson;
    if request_kind == ClaudeAppRequest::UnsupportedModel && state.block_unknown_formats {
        return Err(
            "unknown format blocked: Claude App selected a model transport Pentect cannot inspect; set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through"
                .to_string(),
        );
    }
    eprintln!("[pentect] claude-app > {method} {host}{safe_path} {content_type}");

    let url = format!("https://{host}{path_and_query}");
    let mut headers = request.headers().clone();
    let account_scope = state
        .file_attestations
        .account_scope_for_app_headers(&headers);
    remove_hop_by_hop_headers(&mut headers);
    headers.remove(hyper::header::HOST);
    let mut upload_coverage = None;
    let mut upload_key = None;
    let mut upload_filename = None;
    if protect_chat || prepare_upload || request_kind == ClaudeAppRequest::Upload {
        headers.insert(
            hyper::header::ACCEPT_ENCODING,
            hyper::header::HeaderValue::from_static("identity"),
        );
    }
    let body = if protect_chat {
        let body = read_request_capped(request.into_body(), "Chat").await?;
        hydrate_claude_app_attested_files(&body, &account_scope, state).await?;
        let original = body.clone();
        let masker = Arc::clone(&state.masker);
        let plugins = Arc::clone(&state.plugins);
        let files = {
            let registry = state
                .files
                .lock()
                .map_err(|_| "Claude App file registry lock was poisoned".to_string())?;
            crate::http_files::scoped_file_coverages(&registry, &account_scope)
        };
        let block_unknown_formats = state.block_unknown_formats;
        let protected = tokio::task::spawn_blocking(move || {
            protect_chat_request(&original, &masker, &plugins, &files, block_unknown_formats)
        })
        .await
        .map_err(|_| "Claude App Chat protection task failed".to_string())??;
        if let Some(response) = protected.local_response {
            return Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(
                    Full::new(response)
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .map_err(|error| format!("could not build Claude App plugin response: {error}"));
        }
        headers.remove(hyper::header::CONTENT_LENGTH);
        reqwest::Body::from(protected.body)
    } else if matches!(
        request_kind,
        ClaudeAppRequest::JsonScan | ClaudeAppRequest::PrepareUploadJson
    ) {
        let body = read_request_capped(request.into_body(), "JSON").await?;
        let masker = Arc::clone(&state.masker);
        let block_unknown_formats = state.block_unknown_formats;
        let protected = tokio::task::spawn_blocking(move || {
            protect_generic_json_request(&body, &masker, block_unknown_formats)
        })
        .await
        .map_err(|_| "Claude App JSON protection task failed".to_string())??;
        headers.remove(hyper::header::CONTENT_LENGTH);
        reqwest::Body::from(protected)
    } else if request_kind == ClaudeAppRequest::Upload {
        let body = read_request_capped(request.into_body(), "upload").await?;
        upload_key = claude_filestore_upload_key(&content_type, &body);
        upload_filename = crate::http_files::multipart_file_name(&content_type, &body);
        let masker = Arc::clone(&state.masker);
        let plugins = Arc::clone(&state.plugins);
        let protected = tokio::task::spawn_blocking(move || {
            let mut masker = masker
                .lock()
                .map_err(|_| "Claude App upload masker lock was poisoned".to_string())?;
            let plugins = plugins
                .lock()
                .map_err(|_| "Claude App plugin lock was poisoned".to_string())?;
            crate::http_files::protect_multipart_upload_with_plugins(
                &content_type,
                &body,
                &mut masker,
                &plugins,
            )
        })
        .await
        .map_err(|_| "Claude App upload protection task failed".to_string())??;
        upload_coverage = Some(protected.coverage);
        headers.remove(hyper::header::CONTENT_LENGTH);
        reqwest::Body::from(protected.body)
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
        .map_err(|error| {
            format!(
                "upstream request failed for {method} {host}{safe_path}: {}",
                reqwest_error_summary(&error)
            )
        })?;
    let status = upstream.status();
    let mut response_headers = upstream.headers().clone();
    remove_hop_by_hop_headers(&mut response_headers);
    let response_content_type = response_headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or("-");
    eprintln!("[pentect] claude-app < {status} {method} {host}{safe_path} {response_content_type}");

    let transform_chat = protect_chat
        && status.is_success()
        && response_content_type.eq_ignore_ascii_case("text/event-stream");
    if (transform_chat || upload_coverage.is_some() || prepare_upload)
        && response_headers
            .get(hyper::header::CONTENT_ENCODING)
            .is_some_and(|encoding| {
                !encoding
                    .to_str()
                    .is_ok_and(|value| value.eq_ignore_ascii_case("identity"))
            })
    {
        return Err(
            "Claude App upstream returned compressed protected content despite requesting identity encoding"
                .to_string(),
        );
    }

    let mut builder = Response::builder().status(status);
    for (name, value) in &response_headers {
        if !transform_chat || name != hyper::header::CONTENT_LENGTH {
            builder = builder.header(name, value);
        }
    }
    if let Some(coverage) = upload_coverage {
        let body = read_response_capped(upstream).await?;
        if status.is_success() {
            let attestation_upstream = "claude-app-service";
            if let Some(filename) = upload_filename.as_deref() {
                for id in uploaded_claude_file_ids(&body, filename) {
                    if state
                        .file_attestations
                        .remember_async(
                            "claude-app",
                            attestation_upstream,
                            &account_scope,
                            &id,
                            coverage,
                        )
                        .await
                        .is_err()
                    {
                        eprintln!("[pentect] file attestation unavailable; uploaded file remains untrusted");
                    } else if let Ok(mut files) = state.files.lock() {
                        crate::http_files::remember_scoped_file_coverage(
                            &mut files,
                            &account_scope,
                            id,
                            coverage,
                        );
                    } else {
                        eprintln!("[pentect] uploaded file registry unavailable; persistent attestation retained");
                    }
                }
            }
            if let Some(key) = upload_key.as_deref() {
                for id in promote_pending_claude_files(key, &account_scope, &state.pending_files)? {
                    if state
                        .file_attestations
                        .remember_async(
                            "claude-app",
                            attestation_upstream,
                            &account_scope,
                            &id,
                            coverage,
                        )
                        .await
                        .is_err()
                    {
                        eprintln!("[pentect] file attestation unavailable; uploaded file remains untrusted");
                    } else if let Ok(mut files) = state.files.lock() {
                        crate::http_files::remember_scoped_file_coverage(
                            &mut files,
                            &account_scope,
                            id,
                            coverage,
                        );
                    } else {
                        eprintln!("[pentect] uploaded file registry unavailable; persistent attestation retained");
                    }
                }
            }
        }
        let mut response = Response::builder().status(status);
        for (name, value) in &response_headers {
            if name != hyper::header::CONTENT_LENGTH {
                response = response.header(name, value);
            }
        }
        return response
            .header("x-pentect-coverage", coverage.as_header())
            .body(
                Full::new(body)
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .map_err(|error| format!("could not build Claude App upload response: {error}"));
    }
    if prepare_upload {
        let body = read_response_capped(upstream).await?;
        if status.is_success() {
            remember_pending_claude_files(&body, &account_scope, &state.pending_files)?;
        }
        let mut response = Response::builder().status(status);
        for (name, value) in &response_headers {
            if name != hyper::header::CONTENT_LENGTH {
                response = response.header(name, value);
            }
        }
        return response
            .body(
                Full::new(body)
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .map_err(|error| format!("could not build Claude App prepare response: {error}"));
    }

    let stream = upstream.bytes_stream().map(move |result| {
        result
            .map(Frame::data)
            .map_err(|error| Box::new(error) as ProxyBodyError)
    });
    let body = if transform_chat {
        chat_sse_body(Box::pin(stream), Arc::clone(&state.plugins))
    } else {
        BodyExt::boxed_unsync(StreamBody::new(stream))
    };
    builder
        .body(body)
        .map_err(|error| format!("could not build Claude App response: {error}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaudeAppRequest {
    Other,
    ChatJson,
    PrepareUploadJson,
    JsonScan,
    Upload,
    UnsupportedModel,
}

fn classify_claude_app_request(
    method: &Method,
    host: &str,
    path: &str,
    content_type: &str,
) -> ClaudeAppRequest {
    if !is_claude_host(host) {
        return ClaudeAppRequest::Other;
    }
    if is_claude_voice_path(path) {
        return ClaudeAppRequest::UnsupportedModel;
    }
    if *method != Method::POST {
        return ClaudeAppRequest::Other;
    }
    let media_type = content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default();
    if is_chat_completion_path(path) {
        return if media_type.eq_ignore_ascii_case("application/json") {
            ClaudeAppRequest::ChatJson
        } else {
            ClaudeAppRequest::UnsupportedModel
        };
    }
    if is_claude_binary_model_path(path) {
        return ClaudeAppRequest::UnsupportedModel;
    }
    if is_claude_prepare_upload_path(path)
        && (media_type.eq_ignore_ascii_case("application/json")
            || media_type.to_ascii_lowercase().ends_with("+json"))
    {
        return ClaudeAppRequest::PrepareUploadJson;
    }
    if media_type.eq_ignore_ascii_case("multipart/form-data") && is_claude_upload_path(path) {
        return ClaudeAppRequest::Upload;
    }
    if media_type.eq_ignore_ascii_case("application/json")
        || media_type.to_ascii_lowercase().ends_with("+json")
    {
        return ClaudeAppRequest::JsonScan;
    }
    ClaudeAppRequest::Other
}

#[cfg(test)]
fn is_chat_completion(host: &str, path: &str, content_type: &str) -> bool {
    classify_claude_app_request(&Method::POST, host, path, content_type)
        == ClaudeAppRequest::ChatJson
}

fn is_chat_completion_path(path: &str) -> bool {
    let Some(segment) = path.trim_end_matches('/').rsplit('/').next() else {
        return false;
    };
    let completion = segment.strip_prefix("retry_").unwrap_or(segment);
    completion == "completion"
        || completion.strip_prefix("completion").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn is_claude_binary_model_path(path: &str) -> bool {
    matches!(
        path.rsplit('/').next(),
        Some("appendMessage" | "retryMessage")
    ) && path.starts_with("/v1/mobile/")
}

fn is_claude_voice_path(path: &str) -> bool {
    path.starts_with("/api/ws/voice/") && path.contains("/chat_conversations/")
}

fn is_claude_upload_path(path: &str) -> bool {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    matches!(segments.as_slice(), ["api", _, "upload"])
        || matches!(
            segments.as_slice(),
            ["api", "organizations", _, "projects", _, "upload"]
        )
        || matches!(
            segments.as_slice(),
            ["api", "organizations", _, "cowork", "attachments"]
        )
        || matches!(segments.as_slice(), ["v1", "filestore", "fs", "createFile"])
}

fn is_claude_prepare_upload_path(path: &str) -> bool {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    matches!(
        segments.as_slice(),
        [
            "api",
            "organizations",
            _,
            "conversations",
            _,
            "files",
            "prepare-upload"
        ]
    )
}

fn uploaded_claude_file_ids(body: &[u8], uploaded_filename: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    uploaded_file_ids(&value, uploaded_filename)
}

async fn hydrate_claude_app_attested_files(
    body: &[u8],
    account_scope: &str,
    state: &ProxyState,
) -> Result<(), String> {
    let attestations = state.file_attestations.clone();
    let body = body.to_vec();
    let scope_for_task = account_scope.to_string();
    let coverages = tokio::task::spawn_blocking(move || {
        attestations.coverages_in_json(&body, "claude-app", "claude-app-service", &scope_for_task)
    })
    .await
    .map_err(|_| "Claude App file attestation task failed".to_string())??;
    for (id, coverage) in coverages {
        let registry = state
            .files
            .lock()
            .map_err(|_| "Claude App file registry lock was poisoned".to_string())?;
        let already_known =
            crate::http_files::scoped_file_coverage(&registry, account_scope, &id).is_some();
        drop(registry);
        if already_known {
            continue;
        }
        let mut files = state
            .files
            .lock()
            .map_err(|_| "Claude App file registry lock was poisoned".to_string())?;
        crate::http_files::remember_scoped_file_coverage(&mut files, account_scope, id, coverage);
    }
    Ok(())
}

fn uploaded_file_ids(value: &serde_json::Value, uploaded_filename: &str) -> Vec<String> {
    let Some(root) = value.as_object() else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    if file_object_matches_name(root, uploaded_filename) {
        candidates.push(root);
    }
    for key in ["file", "data"] {
        if let Some(object) = root.get(key).and_then(serde_json::Value::as_object) {
            if file_object_matches_name(object, uploaded_filename) {
                candidates.push(object);
            }
        }
    }
    for key in ["files", "uploads"] {
        if let Some(values) = root.get(key).and_then(serde_json::Value::as_array) {
            candidates.extend(
                values
                    .iter()
                    .filter_map(serde_json::Value::as_object)
                    .filter(|object| file_object_matches_name(object, uploaded_filename)),
            );
        }
    }
    candidates
        .into_iter()
        .flat_map(|object| ["file_id", "file_uuid", "id", "uuid"].map(move |key| (object, key)))
        .filter_map(|(object, key)| object.get(key).and_then(serde_json::Value::as_str))
        .filter(|id| !id.is_empty() && id.len() <= 200)
        .map(str::to_string)
        .collect()
}

fn file_object_matches_name(
    object: &serde_json::Map<String, serde_json::Value>,
    uploaded_filename: &str,
) -> bool {
    ["file_name", "filename", "name", "path"]
        .into_iter()
        .filter_map(|key| object.get(key).and_then(serde_json::Value::as_str))
        .any(|candidate| {
            candidate == uploaded_filename
                || Path::new(candidate)
                    .file_name()
                    .and_then(|name| name.to_str())
                    == Some(uploaded_filename)
        })
}

fn claude_filestore_upload_key(content_type: &str, body: &[u8]) -> Option<String> {
    let params = crate::http_files::multipart_text_field(content_type, body, "params")?;
    let value: serde_json::Value = serde_json::from_str(&params).ok()?;
    let filesystem = value.get("filesystem_id")?.as_str()?;
    let path = value.get("path")?.as_str()?;
    if filesystem.is_empty() || path.is_empty() || filesystem.len() > 500 || path.len() > 4096 {
        return None;
    }
    Some(format!("{filesystem}\0{path}"))
}

fn remember_pending_claude_files(
    body: &[u8],
    account_scope: &str,
    pending: &Mutex<PendingFiles>,
) -> Result<(), String> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Ok(());
    };
    let Some(uploads) = value.get("uploads").and_then(serde_json::Value::as_array) else {
        return Ok(());
    };
    let mut pending = pending
        .lock()
        .map_err(|_| "Claude App pending file registry lock was poisoned".to_string())?;
    for upload in uploads {
        let Some(filesystem) = upload
            .get("filesystem_id")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let Some(path) = upload.get("path").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(file_id) = upload
            .get("file_uuid")
            .or_else(|| upload.get("file_id"))
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        if filesystem.is_empty()
            || path.is_empty()
            || file_id.is_empty()
            || filesystem.len() > 500
            || path.len() > 4096
            || file_id.len() > 200
        {
            continue;
        }
        let key = scoped_pending_key(account_scope, &format!("{filesystem}\0{path}"));
        if !pending.entries.contains_key(&key) {
            pending.insertion_order.push_back(key.clone());
        }
        let ids = pending.entries.entry(key).or_default();
        if ids.len() < MAX_IDS_PER_UPLOAD && !ids.iter().any(|known| known == file_id) {
            ids.push(file_id.to_string());
        }
        while pending.entries.len() > MAX_PENDING_UPLOADS {
            let Some(expired) = pending.insertion_order.pop_front() else {
                break;
            };
            pending.entries.remove(&expired);
        }
    }
    Ok(())
}

fn promote_pending_claude_files(
    key: &str,
    account_scope: &str,
    pending: &Mutex<PendingFiles>,
) -> Result<Vec<String>, String> {
    let key = scoped_pending_key(account_scope, key);
    let ids = {
        let mut pending = pending
            .lock()
            .map_err(|_| "Claude App pending file registry lock was poisoned".to_string())?;
        pending.insertion_order.retain(|known| known != &key);
        pending.entries.remove(&key).unwrap_or_default()
    };
    Ok(ids)
}

fn scoped_pending_key(account_scope: &str, key: &str) -> String {
    format!("{account_scope}:{key}")
}

async fn read_response_capped(response: reqwest::Response) -> Result<Bytes, String> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            format!(
                "could not read Claude App upstream response: {}",
                reqwest_error_summary(&error)
            )
        })?;
        if body.len().saturating_add(chunk.len()) > MAX_CHAT_BODY_BYTES {
            return Err("Claude App upload response exceeded the size limit".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(body))
}

async fn read_request_capped(body: Incoming, label: &str) -> Result<Bytes, String> {
    match Limited::new(body, MAX_CHAT_BODY_BYTES).collect().await {
        Ok(body) => Ok(body.to_bytes()),
        Err(error) if error.is::<http_body_util::LengthLimitError>() => Err(format!(
            "payload too large: Claude App {label} request exceeds {MAX_CHAT_BODY_BYTES} bytes"
        )),
        Err(_) => Err(format!("could not read Claude App {label} request")),
    }
}

fn reqwest_error_summary(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_body() || error.is_decode() {
        "response body failed"
    } else {
        "request failed"
    }
}

struct ProtectedChatRequest {
    body: Bytes,
    local_response: Option<Bytes>,
}

fn protect_chat_request(
    body: &Bytes,
    masker: &Mutex<pentect_agent::ActiveToolOutputMasker>,
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    files: &HashMap<String, crate::http_files::Coverage>,
    block_unknown_formats: bool,
) -> Result<ProtectedChatRequest, String> {
    let mut value = match parse_chat_json(body, block_unknown_formats)? {
        Some(value) => value,
        None => {
            return Ok(ProtectedChatRequest {
                body: body.clone(),
                local_response: None,
            });
        }
    };
    let run = plugins
        .lock()
        .map_err(|_| "Claude App plugin lock was poisoned".to_string())?
        .run(
            pentect_agent::MiddlewareStage::Request,
            value,
            Some(serde_json::json!({"provider": "claude", "transport": "desktop-http"})),
        )?;
    if block_unknown_formats && run.coverage == pentect_agent::MiddlewareCoverage::Partial {
        return Err(
            "unknown format blocked: a Claude App plugin reported partial request coverage; set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to allow it"
                .to_string(),
        );
    }
    value = run.payload;
    if let Some(outcome) = run.stopped {
        if outcome == pentect_agent::StopOutcome::Block {
            return Err(format!(
                "plugin blocked: {}",
                run.message.unwrap_or_else(|| "request blocked".to_string())
            ));
        }
        let body = serde_json::to_vec(&value)
            .map(Bytes::from)
            .map_err(|error| format!("could not encode Claude App plugin response: {error}"))?;
        return Ok(ProtectedChatRequest {
            body: Bytes::new(),
            local_response: Some(body),
        });
    }
    let mut masker = masker
        .lock()
        .map_err(|_| "Claude App Chat masker lock was poisoned".to_string())?;
    if let Err(error) = mask_chat_value(&mut value, false, &mut masker, files) {
        if error.starts_with("image blocked:") || error.starts_with("document blocked:") {
            return Err(error);
        }
        if block_unknown_formats {
            return Err(format!(
                "Claude App Chat request blocked: content inspection is unavailable ({error})"
            ));
        }
        eprintln!("[pentect] Claude App Chat protection skipped: {error}");
        return Ok(ProtectedChatRequest {
            body: body.clone(),
            local_response: None,
        });
    }
    inject_chat_contract(&mut value);
    let protected = serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|error| format!("could not encode protected Claude App Chat request: {error}"))?;
    Ok(ProtectedChatRequest {
        body: protected,
        local_response: None,
    })
}

fn parse_chat_json(
    body: &Bytes,
    block_unknown_formats: bool,
) -> Result<Option<serde_json::Value>, String> {
    match serde_json::from_slice(body) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            if block_unknown_formats {
                return Err(format!(
                    "unknown format blocked: Claude App Chat request is not valid JSON ({error}); set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through"
                ));
            }
            eprintln!("[pentect] Claude App Chat protection skipped: invalid JSON: {error}");
            Ok(None)
        }
    }
}

fn protect_generic_json_request(
    body: &Bytes,
    masker: &Mutex<pentect_agent::ActiveToolOutputMasker>,
    block_unknown_formats: bool,
) -> Result<Bytes, String> {
    let mut value = match parse_chat_json(body, block_unknown_formats)? {
        Some(value) => value,
        None => return Ok(body.clone()),
    };
    let mut masker = masker
        .lock()
        .map_err(|_| "Claude App JSON masker lock was poisoned".to_string())?;
    if let Err(error) = mask_generic_json_value(&mut value, &mut masker) {
        if block_unknown_formats {
            return Err(format!(
                "Claude App JSON request blocked: content inspection is unavailable ({error})"
            ));
        }
        eprintln!("[pentect] Claude App JSON protection skipped: {error}");
        return Ok(body.clone());
    }
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|error| format!("could not encode protected Claude App JSON request: {error}"))
}

fn mask_generic_json_value(
    value: &mut serde_json::Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    match value {
        serde_json::Value::String(text) => {
            crate::claude_http_proxy::mask_string(text, false, masker)
        }
        serde_json::Value::Array(values) => {
            for value in values {
                mask_generic_json_value(value, masker)?;
            }
            Ok(())
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if matches!(
                    key.as_str(),
                    "signature" | "thinking_signature" | "attestation" | "authorization" | "token"
                ) {
                    continue;
                }
                mask_generic_json_value(value, masker)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn inject_chat_contract(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for key in ["system", "prompt", "custom_system_prompt"] {
        if let Some(serde_json::Value::String(text)) = object.get_mut(key) {
            if !text.contains(HANDLE_CONTRACT) {
                let existing = std::mem::take(text);
                *text = format!("{HANDLE_CONTRACT}\n\n{existing}");
            }
            return;
        }
    }
    object.insert(
        "system".to_string(),
        serde_json::Value::String(HANDLE_CONTRACT.to_string()),
    );
}

fn mask_chat_value(
    value: &mut serde_json::Value,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    match value {
        serde_json::Value::String(text) => {
            crate::claude_http_proxy::mask_string(text, tool_result, masker)
        }
        serde_json::Value::Array(values) => {
            for value in values {
                mask_chat_value(value, tool_result, masker, files)?;
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
                inspect_chat_image(object, files)?;
                return Ok(());
            }
            if kind.contains("file") || kind.contains("document") || looks_like_chat_file(object) {
                inspect_chat_document(object, tool_result, masker, files)?;
            }
            let nested_tool_result = tool_result
                || kind.contains("tool_result")
                || kind.contains("tool_output")
                || kind.contains("function_output");
            for (key, nested) in object {
                if matches!(
                    key.as_str(),
                    "signature" | "thinking_signature" | "attestation"
                ) || (!nested_tool_result && is_chat_protocol_metadata_field(key))
                {
                    continue;
                }
                mask_chat_value(nested, nested_tool_result, masker, files)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn inspect_chat_image(
    object: &mut serde_json::Map<String, serde_json::Value>,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    if chat_file_reference(object)
        .and_then(|id| files.get(id))
        .copied()
        == Some(crate::http_files::Coverage::Full)
    {
        return Ok(());
    }
    if let Some(source) = object
        .get_mut("source")
        .and_then(serde_json::Value::as_object_mut)
    {
        if source.get("type").and_then(serde_json::Value::as_str) == Some("base64")
            && source
                .get("media_type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|media_type| media_type.starts_with("image/"))
        {
            let Some(serde_json::Value::String(encoded)) = source.get_mut("data") else {
                return unscanned_chat_image();
            };
            if let Some(protected) = crate::claude_http_proxy::redact_inline_image_data(encoded)? {
                *encoded = protected;
                source.insert(
                    "media_type".to_string(),
                    serde_json::Value::String("image/png".to_string()),
                );
            }
            return Ok(());
        }
        return unscanned_chat_image();
    }
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
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    if chat_file_reference(object)
        .and_then(|id| files.get(id))
        .copied()
        == Some(crate::http_files::Coverage::Full)
    {
        return Ok(());
    }
    if let Some(source) = object.get_mut("source") {
        if let Some(id) = ["file_id", "id"]
            .into_iter()
            .find_map(|key| source.get(key).and_then(serde_json::Value::as_str))
        {
            if files.get(id) == Some(&crate::http_files::Coverage::Full) {
                return Ok(());
            }
        }
        if source.get("type").and_then(serde_json::Value::as_str) == Some("text") {
            if let Some(serde_json::Value::String(text)) = source.get_mut("data") {
                return crate::claude_http_proxy::mask_string(text, tool_result, masker);
            }
        }
        if source.get("type").and_then(serde_json::Value::as_str) == Some("base64") {
            return crate::claude_http_proxy::inspect_base64_document(source, tool_result, masker);
        }
        return crate::claude_http_proxy::enforce_unscanned_document_policy();
    }
    if object.get("file_id").is_some()
        || object.get("file_uuid").is_some()
        || object.get("url").is_some()
    {
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

fn is_chat_protocol_metadata_field(key: &str) -> bool {
    matches!(
        key,
        "type"
            | "id"
            | "uuid"
            | "tool_use_id"
            | "role"
            | "name"
            | "index"
            | "stop_reason"
            | "signature"
            | "thinking_signature"
            | "attestation"
            | "authorization"
            | "token"
    )
}

fn looks_like_chat_file(object: &serde_json::Map<String, serde_json::Value>) -> bool {
    (object.contains_key("file_id") || object.contains_key("file_uuid"))
        && (object.contains_key("file_name")
            || object.contains_key("filename")
            || object.contains_key("mime_type")
            || object.contains_key("content_type"))
}

fn chat_file_reference(object: &serde_json::Map<String, serde_json::Value>) -> Option<&str> {
    ["file_id", "file_uuid"]
        .into_iter()
        .find_map(|key| object.get(key).and_then(serde_json::Value::as_str))
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
type ChatResolver = Box<dyn FnMut(&str) -> Result<String, String> + Send>;

struct ChatStreamState {
    upstream: ChatFrameStream,
    pending: Vec<u8>,
    ready: VecDeque<Result<Frame<Bytes>, ProxyBodyError>>,
    passthrough: bool,
    finished: bool,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
    resolve: Option<ChatResolver>,
}

fn chat_sse_body<S>(stream: S, plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>) -> ProxyBody
where
    S: futures_util::Stream<Item = Result<Frame<Bytes>, ProxyBodyError>> + Send + 'static,
{
    let state = ChatStreamState {
        upstream: Box::pin(stream),
        pending: Vec::new(),
        ready: VecDeque::new(),
        passthrough: false,
        finished: false,
        plugins,
        resolve: Some(Box::new(crate::claude_http_proxy::request_scoped_resolver())),
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
                        if !chat_sse_block_contains_tool_call(&block) {
                            state.ready.push_back(Ok(Frame::data(Bytes::from(block))));
                            continue;
                        }
                        let Some(mut resolve) = state.resolve.take() else {
                            state.finished = true;
                            state.ready.push_back(Err(Box::new(io::Error::other(
                                "Claude App Chat resolver is unavailable",
                            ))));
                            break;
                        };
                        let plugins = Arc::clone(&state.plugins);
                        let rewritten = tokio::task::spawn_blocking(move || {
                            let result = rewrite_chat_sse_block(&block, &plugins, &mut resolve);
                            (result, resolve)
                        })
                        .await;
                        let (result, resolve) = match rewritten {
                            Ok(result) => result,
                            Err(_) => {
                                state.finished = true;
                                state.ready.push_back(Err(Box::new(io::Error::other(
                                    "Claude App Chat restoration task failed",
                                ))));
                                break;
                            }
                        };
                        state.resolve = Some(resolve);
                        match result {
                            Ok(block) => state.ready.push_back(Ok(Frame::data(block))),
                            Err(error) => {
                                state.finished = true;
                                state
                                    .ready
                                    .push_back(Err(Box::new(io::Error::other(error))));
                                break;
                            }
                        }
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

fn chat_sse_block_contains_tool_call(block: &[u8]) -> bool {
    std::str::from_utf8(block)
        .ok()
        .and_then(|text| text.lines().find_map(|line| line.strip_prefix("data:")))
        .and_then(|data| serde_json::from_str::<serde_json::Value>(data.trim_start()).ok())
        .is_some_and(|value| contains_chat_tool_call(&value))
}

fn rewrite_chat_sse_block<R>(
    block: &[u8],
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    resolve: &mut R,
) -> Result<Bytes, String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    let Ok(text) = std::str::from_utf8(block) else {
        return Ok(Bytes::copy_from_slice(block));
    };
    let Some(data) = text.lines().find_map(|line| line.strip_prefix("data:")) else {
        return Ok(Bytes::copy_from_slice(block));
    };
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(data.trim_start()) else {
        return Ok(Bytes::copy_from_slice(block));
    };
    if contains_chat_tool_call(&value) {
        let plugins = {
            plugins
                .lock()
                .map_err(|_| "Claude App plugin lock was poisoned".to_string())?
                .clone()
        };
        run_chat_tool_plugins(&mut value, &plugins)?;
    }
    if let Err(error) = resolve_chat_tool_calls(&mut value, resolve) {
        eprintln!("[pentect] Claude App Chat tool restoration skipped: {error}");
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

fn contains_chat_tool_call(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(values) => values.iter().any(contains_chat_tool_call),
        serde_json::Value::Object(object) => {
            let kind = object
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            ((kind.contains("tool_use")
                || kind.contains("tool_call")
                || kind.contains("function_call"))
                && ["arguments", "input"]
                    .into_iter()
                    .any(|key| object.contains_key(key)))
                || object.values().any(contains_chat_tool_call)
        }
        _ => false,
    }
}

fn run_chat_tool_plugins(
    value: &mut serde_json::Value,
    plugins: &pentect_agent::PluginMiddleware,
) -> Result<(), String> {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                run_chat_tool_plugins(value, plugins)?;
            }
        }
        serde_json::Value::Object(object) => {
            let kind = object
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            let is_call = (kind.contains("tool_use")
                || kind.contains("tool_call")
                || kind.contains("function_call"))
                && ["arguments", "input"]
                    .into_iter()
                    .any(|key| object.contains_key(key));
            if is_call {
                let run = plugins.run(
                    pentect_agent::MiddlewareStage::ToolCall,
                    serde_json::Value::Object(object.clone()),
                    Some(serde_json::json!({"provider": "claude", "transport": "desktop-http"})),
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
                run_chat_tool_plugins(child, plugins)?;
            }
        }
        _ => {}
    }
    Ok(())
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
                    if let Some(arguments) = object.get_mut(key) {
                        let (encoded, was_string) = match &*arguments {
                            serde_json::Value::String(text) => (text.clone(), true),
                            value => (
                                serde_json::to_string(value).map_err(|error| {
                                    format!("could not encode Claude App tool input: {error}")
                                })?,
                                false,
                            ),
                        };
                        let resolved = crate::claude_http_proxy::resolve_tool_input_json(
                            &encoded,
                            name.as_deref(),
                            resolve,
                        )?;
                        *arguments = if was_string {
                            serde_json::Value::String(resolved)
                        } else {
                            serde_json::from_str(&resolved).map_err(|error| {
                                format!("could not decode Claude App tool input: {error}")
                            })?
                        };
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
    let connection_headers = headers
        .get(hyper::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .filter_map(|name| name.trim().parse::<hyper::header::HeaderName>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for name in connection_headers {
        headers.remove(name);
    }
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
    headers.remove("proxy-connection");
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

fn text_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(
            Full::new(Bytes::copy_from_slice(message.as_bytes()))
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("static text response")
}

pub(crate) fn default_claude_app_path() -> PathBuf {
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
    let reg = crate::windows_system_executable("reg.exe");
    let output = Command::new(&reg)
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
            line.rsplit('\\').next().is_some_and(|name| {
                name.starts_with("Claude_") && windows_package_matches_arch(name)
            })
        })
        .filter_map(|key| {
            let package_name = key.rsplit('\\').next()?.to_string();
            let output = Command::new(&reg)
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

#[cfg(windows)]
fn windows_package_matches_arch(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if cfg!(target_arch = "aarch64") {
        name.contains("_arm64__")
    } else {
        name.contains("_x64__")
    }
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

    struct MaskingTestEnv {
        _guard: crate::EnvVarGuard,
        home: PathBuf,
        process_host_candidate: Option<PathBuf>,
    }

    impl MaskingTestEnv {
        fn install(store: &pentect_agent::InProcessMemoryStore) -> Self {
            let home = std::env::temp_dir().join(format!(
                "pentect-claude-app-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&home).unwrap();
            let guard = crate::EnvVarGuard::set_optional([
                (
                    "PENTECT_MEMORY_STORE_ADDR",
                    Some(store.addr().to_string().into()),
                ),
                (
                    "PENTECT_MEMORY_STORE_TOKEN",
                    Some(store.token().to_string().into()),
                ),
                (
                    "PENTECT_AGENT_LAUNCHED",
                    Some(store.token().to_string().into()),
                ),
                ("PENTECT_HOME", Some(home.as_os_str().to_owned())),
                (crate::plugins::CONFIGS_ENV, None),
                (crate::plugins::BINARIES_ENV, None),
                (crate::plugins::GLOBAL_BINARIES_ENV, None),
                (crate::plugins::GLOBAL_BINARY_IDS_ENV, None),
            ]);
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
                _guard: guard,
                home,
                process_host_candidate,
            }
        }
    }

    impl Drop for MaskingTestEnv {
        fn drop(&mut self) {
            if let Some(path) = self.process_host_candidate.take() {
                let _ = std::fs::remove_file(path);
            }
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }

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
    fn options_accept_the_nested_claude_app_command() {
        let args = vec![
            "pentect".to_string(),
            "claude".to_string(),
            "app".to_string(),
            "--plugins".to_string(),
            "company-policy".to_string(),
            "--app".to_string(),
            "Claude.exe".to_string(),
            "--dry-run".to_string(),
        ];
        let options = ClaudeAppOptions::parse(&args).unwrap();
        assert_eq!(options.app, Some(PathBuf::from("Claude.exe")));
        assert!(options.check);
    }

    #[test]
    fn options_reject_missing_plugin_value() {
        let args = vec![
            "pentect".to_string(),
            "claude".to_string(),
            "app".to_string(),
            "--plugins".to_string(),
            "--dry-run".to_string(),
        ];
        assert!(ClaudeAppOptions::parse(&args).is_err());
    }

    #[test]
    fn check_mode_does_not_treat_an_option_value_as_a_flag() {
        let args = vec![
            "pentect".to_string(),
            "claude".to_string(),
            "app".to_string(),
            "--app".to_string(),
            "--check".to_string(),
        ];
        assert!(!check_mode(&args).unwrap());
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
        assert!(is_chat_completion(
            "api.claude.com",
            "/api/chat_conversations/example/completion",
            "application/json"
        ));
        assert!(is_chat_completion(
            "claude.ai",
            "/api/organizations/example/chat_conversations/example/completion2",
            "application/json"
        ));
        assert!(is_chat_completion(
            "claude.ai",
            "/api/organizations/example/chat_conversations/example/retry_completion2",
            "application/json"
        ));
        assert!(is_chat_completion(
            "claude.ai",
            "/api/organizations/example/chat_conversations/example/completion/",
            "application/json"
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
        assert!(!is_chat_completion(
            "claude.ai",
            "/completion_status",
            "application/json"
        ));
    }

    #[test]
    fn unsupported_model_transports_are_classified_without_matching_unrelated_routes() {
        assert_eq!(
            classify_claude_app_request(
                &Method::POST,
                "claude.ai",
                "/v1/mobile/appendMessage",
                "application/proto"
            ),
            ClaudeAppRequest::UnsupportedModel
        );
        assert_eq!(
            classify_claude_app_request(
                &Method::GET,
                "claude.ai",
                "/api/ws/voice/organizations/o/chat_conversations/c",
                "-"
            ),
            ClaudeAppRequest::UnsupportedModel
        );
        assert_eq!(
            classify_claude_app_request(
                &Method::POST,
                "claude.ai",
                "/v1/mobile/unrelated",
                "application/proto"
            ),
            ClaudeAppRequest::Other
        );
        assert_eq!(
            classify_claude_app_request(
                &Method::POST,
                "claude.ai",
                "/api/event_logging/v2/batch",
                "application/json"
            ),
            ClaudeAppRequest::JsonScan
        );
    }

    #[test]
    fn only_known_claude_upload_routes_are_rewritten() {
        for path in [
            "/api/org/upload",
            "/api/organizations/org/projects/project/upload",
            "/api/organizations/org/cowork/attachments",
            "/v1/filestore/fs/createFile",
        ] {
            assert_eq!(
                classify_claude_app_request(
                    &Method::POST,
                    "claude.ai",
                    path,
                    "multipart/form-data; boundary=test"
                ),
                ClaudeAppRequest::Upload,
                "{path}"
            );
        }
        for path in ["/upload", "/api/organizations/org/dxt/upload"] {
            assert_eq!(
                classify_claude_app_request(
                    &Method::POST,
                    "claude.ai",
                    path,
                    "multipart/form-data; boundary=test"
                ),
                ClaudeAppRequest::Other,
                "{path}"
            );
        }
        assert_eq!(
            classify_claude_app_request(
                &Method::POST,
                "claude.ai",
                "/api/organizations/org/conversations/conversation/files/prepare-upload",
                "application/json"
            ),
            ClaudeAppRequest::PrepareUploadJson
        );
    }

    #[test]
    fn malformed_chat_json_obeys_the_unknown_format_policy() {
        let body = Bytes::from_static(b"{not-json");
        assert!(parse_chat_json(&body, true)
            .unwrap_err()
            .starts_with("unknown format blocked:"));
        assert!(parse_chat_json(&body, false).unwrap().is_none());
    }

    #[test]
    fn chat_request_masks_content_without_rewriting_protocol_metadata() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = MaskingTestEnv::install(&store);
        let secret = [
            "rpa_",
            "ZYXWVUTS",
            "RQPONMLK",
            "JIHGFEDC",
            "BA098765",
            "4321fedcba",
        ]
        .concat();
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "model": "claude-test-model",
                "organization_uuid": "11111111-2222-3333-4444-555555555555",
                "prompt": format!("Use this value:\nRUNPOD_API_KEY={secret}\n"),
                "future_instructions": format!("A future field contains {secret}"),
                "messages": [{"content": [{
                    "type": "tool_result",
                    "tool_use_id": "tool-stable-id",
                    "content": {"token": secret, "status": "ok"}
                }]}],
                "client_context": {"locale": "ja-JP", "revision": 7}
            }))
            .unwrap(),
        );
        let masker = Mutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let protected =
            protect_chat_request(&body, &masker, &plugins, &HashMap::new(), true).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&protected.body).unwrap();
        let prompt = value["prompt"].as_str().unwrap();
        assert!(!prompt.contains(&secret));
        assert!(prompt.contains("<<"));
        assert!(prompt.contains(HANDLE_CONTRACT));
        assert!(!value["future_instructions"]
            .as_str()
            .unwrap()
            .contains(&secret));
        assert_eq!(value["model"], "claude-test-model");
        assert_eq!(
            value["organization_uuid"],
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(value["client_context"]["revision"], 7);
        assert_eq!(
            value["messages"][0]["content"][0]["tool_use_id"],
            "tool-stable-id"
        );
        assert_ne!(
            value["messages"][0]["content"][0]["content"]["token"],
            secret
        );

        let telemetry = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "event": "client-error",
                "detail": format!("accidentally captured:\nRUNPOD_API_KEY={secret}\n")
            }))
            .unwrap(),
        );
        let protected = protect_generic_json_request(&telemetry, &masker, true).unwrap();
        assert!(!String::from_utf8_lossy(&protected).contains(&secret));
    }

    #[test]
    fn uploaded_file_ids_are_registered_without_trusting_unrelated_ids() {
        let ids = uploaded_claude_file_ids(
            br#"{"id":"organization-id","nested":{"file_uuid":"file-123","filename":"other.txt"},"file":{"id":"file-456","type":"file","filename":"a.txt"}}"#,
            "a.txt",
        );
        assert_eq!(ids, ["file-456"]);
    }

    #[test]
    fn direct_upload_preparation_is_promoted_only_after_the_file_is_protected() {
        let content_type = "multipart/form-data; boundary=pentect-test";
        let body = concat!(
            "--pentect-test\r\n",
            "Content-Disposition: form-data; name=\"params\"\r\n",
            "Content-Type: application/json\r\n\r\n",
            "{\"filesystem_id\":\"fs-1\",\"path\":\"/uploads/a.txt\"}\r\n",
            "--pentect-test\r\n",
            "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "hello\r\n",
            "--pentect-test--\r\n"
        );
        let key = claude_filestore_upload_key(content_type, body.as_bytes()).unwrap();
        let pending = Mutex::new(PendingFiles::default());
        remember_pending_claude_files(
            br#"{"uploads":[{"filesystem_id":"fs-1","path":"/uploads/a.txt","file_uuid":"file-1"}]}"#,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &pending,
        )
        .unwrap();
        let promoted = promote_pending_claude_files(
            &key,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &pending,
        )
        .unwrap();
        assert_eq!(promoted, ["file-1"]);
    }

    #[test]
    fn pending_upload_eviction_keeps_the_newest_correlations() {
        let pending = Mutex::new(PendingFiles::default());
        for index in 0..=MAX_PENDING_UPLOADS {
            let body = serde_json::to_vec(&serde_json::json!({
                "uploads": [{
                    "filesystem_id": "fs",
                    "path": format!("/{index}.txt"),
                    "file_uuid": format!("file-{index}")
                }]
            }))
            .unwrap();
            remember_pending_claude_files(
                &body,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &pending,
            )
            .unwrap();
        }
        let pending = pending.lock().unwrap();
        assert_eq!(pending.entries.len(), MAX_PENDING_UPLOADS);
        assert!(!pending.entries.contains_key(&scoped_pending_key(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "fs\0/0.txt",
        )));
        assert!(pending.entries.contains_key(&scoped_pending_key(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &format!("fs\0/{MAX_PENDING_UPLOADS}.txt"),
        )));
    }

    #[test]
    fn completed_tool_calls_restore_nested_inputs_but_normal_text_stays_opaque() {
        let handle = "<<SECRET_0011223344556677>>";
        let mut value = serde_json::json!({
            "content": [
                {"type": "text", "text": format!("show {handle}")},
                {"type": "tool_use", "name": "http", "input": {
                    "headers": {"x-token": handle},
                    "body": [handle]
                }}
            ]
        });
        let mut resolve = |text: &str| Ok(text.replace(handle, "local-value"));
        resolve_chat_tool_calls(&mut value, &mut resolve).unwrap();
        assert_eq!(value["content"][0]["text"], format!("show {handle}"));
        assert_eq!(
            value["content"][1]["input"]["headers"]["x-token"],
            "local-value"
        );
        assert_eq!(value["content"][1]["input"]["body"][0], "local-value");
    }

    #[test]
    fn chat_contract_is_added_when_request_has_no_prompt_field() {
        let mut value = serde_json::json!({"messages": []});
        inject_chat_contract(&mut value);
        assert_eq!(value["system"], HANDLE_CONTRACT);
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
    fn proxy_removes_standard_and_connection_named_hop_headers() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("keep-alive, x-private-hop"),
        );
        headers.insert(
            hyper::header::HeaderName::from_static("x-private-hop"),
            hyper::header::HeaderValue::from_static("remove"),
        );
        headers.insert(
            hyper::header::HeaderName::from_static("x-end-to-end"),
            hyper::header::HeaderValue::from_static("keep"),
        );
        remove_hop_by_hop_headers(&mut headers);
        assert!(!headers.contains_key(hyper::header::CONNECTION));
        assert!(!headers.contains_key("x-private-hop"));
        assert_eq!(headers["x-end-to-end"], "keep");
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
        assert!(windows_package_matches_arch(
            if cfg!(target_arch = "aarch64") {
                "Claude_1.10.0.0_arm64__id"
            } else {
                "Claude_1.10.0.0_x64__id"
            }
        ));
    }
}
