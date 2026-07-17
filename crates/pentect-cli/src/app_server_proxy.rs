use fastwebsockets::handshake;
use fastwebsockets::upgrade;
use fastwebsockets::{Frame, OpCode, Payload, WebSocketError};
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONNECTION, UPGRADE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;
use zeroize::Zeroize;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(8);
pub(crate) const PENTECT_CODEX_APP_SERVER_PROXY_ENV: &str = "PENTECT_CODEX_APP_SERVER_PROXY";

pub(crate) struct AppServerProxyGuard {
    url: String,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl AppServerProxyGuard {
    pub(crate) fn start(codex: &Path, app_server_args: Vec<String>) -> Result<Self, String> {
        let codex = codex.to_path_buf();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let thread = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!(
                        "could not start app-server proxy runtime: {e}"
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                let ready_err_tx = ready_tx.clone();
                if let Err(e) = run_proxy(codex, app_server_args, ready_tx, shutdown_rx).await {
                    let _ = ready_err_tx.send(Err(e.clone()));
                    eprintln!("[pentect] app-server proxy stopped: {e}");
                }
            });
        });
        let url = ready_rx
            .recv_timeout(STARTUP_TIMEOUT)
            .map_err(|_| "app-server proxy did not start within 8 seconds".to_string())??;
        Ok(Self {
            url,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }
}

impl Drop for AppServerProxyGuard {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn run_proxy(
    codex: PathBuf,
    app_server_args: Vec<String>,
    ready_tx: mpsc::Sender<Result<String, String>>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), String> {
    let backend_addr = reserve_loopback_addr()?;
    let backend_url = format!("ws://{backend_addr}");
    let mut backend = start_codex_app_server(&codex, &backend_url, app_server_args)?;
    let _backend_supervisor = AppServerProcessSupervisor::new(&backend);
    if let Err(e) = wait_for_ready(backend_addr, &mut backend).await {
        stop_child(&mut backend).await;
        return Err(e);
    }

    let listener = match TcpListener::bind(("127.0.0.1", 0)).await {
        Ok(listener) => listener,
        Err(e) => {
            stop_child(&mut backend).await;
            return Err(format!("could not bind app-server proxy: {e}"));
        }
    };
    let proxy_addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            stop_child(&mut backend).await;
            return Err(format!("could not read app-server proxy addr: {e}"));
        }
    };
    let _ = ready_tx.send(Ok(format!("ws://{proxy_addr}")));

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            status = backend.wait() => {
                return Err(match status {
                    Ok(status) => format!("codex app-server exited: {status}"),
                    Err(error) => format!("could not wait for codex app-server: {error}"),
                });
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        stop_child(&mut backend).await;
                        return Err(format!("app-server proxy accept failed: {e}"));
                    }
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req| proxy_upgrade(req, backend_addr));
                    let conn = http1::Builder::new().serve_connection(io, service).with_upgrades();
                    if let Err(e) = conn.await {
                        eprintln!("[pentect] app-server proxy connection failed: {e}");
                    }
                });
            }
        }
    }

    stop_child(&mut backend).await;
    Ok(())
}

fn reserve_loopback_addr() -> Result<SocketAddr, String> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("could not reserve app-server port: {e}"))?;
    listener
        .local_addr()
        .map_err(|e| format!("could not read reserved app-server port: {e}"))
}

fn start_codex_app_server(
    codex: &Path,
    backend_url: &str,
    app_server_args: Vec<String>,
) -> Result<Child, String> {
    let mut cmd = Command::new(codex);
    cmd.arg("app-server")
        .arg("--listen")
        .arg(backend_url)
        .args(app_server_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    cmd.spawn()
        .map_err(|e| format!("could not start codex app-server: {e}"))
}

#[cfg(windows)]
struct AppServerProcessSupervisor {
    job: windows_sys::Win32::Foundation::HANDLE,
    root: Option<SupervisedProcess>,
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct SupervisedProcess {
    pid: sysinfo::Pid,
    start_time: Option<u64>,
}

#[cfg(windows)]
impl AppServerProcessSupervisor {
    fn new(child: &Child) -> Self {
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let root = child.id().map(|pid| {
            let pid = sysinfo::Pid::from_u32(pid);
            let mut system = sysinfo::System::new();
            system.refresh_processes_specifics(
                sysinfo::ProcessesToUpdate::Some(&[pid]),
                true,
                sysinfo::ProcessRefreshKind::nothing(),
            );
            SupervisedProcess {
                pid,
                start_time: system.process(pid).map(sysinfo::Process::start_time),
            }
        });
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Self { job, root };
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } != 0;
        let assigned = configured
            && child.raw_handle().is_some_and(|process| unsafe {
                AssignProcessToJobObject(job, process.cast()) != 0
            });
        if assigned {
            Self { job, root }
        } else {
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(job);
            }
            Self {
                job: std::ptr::null_mut(),
                root,
            }
        }
    }
}

#[cfg(windows)]
impl Drop for AppServerProcessSupervisor {
    fn drop(&mut self) {
        if !self.job.is_null() {
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(self.job);
            }
            self.job = std::ptr::null_mut();
        }
        let Some(root) = self.root.take() else {
            return;
        };
        terminate_windows_process_tree(root);
    }
}

#[cfg(windows)]
fn terminate_windows_process_tree(root: SupervisedProcess) {
    use std::thread;

    for _ in 0..4 {
        let mut system = sysinfo::System::new();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            sysinfo::ProcessRefreshKind::nothing(),
        );
        let root_process = system.process(root.pid);
        let root_matches = root
            .start_time
            .zip(root_process)
            .is_some_and(|(start_time, process)| start_time == process.start_time());
        let root_reused = root.start_time.is_none() || (root_process.is_some() && !root_matches);
        let mut targets = system
            .processes()
            .iter()
            .filter_map(|(pid, _)| {
                ((root_matches && *pid == root.pid)
                    || (!root_reused
                        && windows_process_descends_from(*pid, root.pid, system.processes())))
                .then_some(*pid)
            })
            .filter(|pid| pid.as_u32() > 1 && pid.as_u32() != std::process::id())
            .collect::<Vec<_>>();
        if targets.is_empty() {
            break;
        }
        targets.sort_unstable_by_key(|pid| std::cmp::Reverse(pid.as_u32()));
        for pid in targets {
            if let Some(process) = system.process(pid) {
                let _ = process.kill();
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(windows)]
fn windows_process_descends_from(
    mut pid: sysinfo::Pid,
    root: sysinfo::Pid,
    processes: &std::collections::HashMap<sysinfo::Pid, sysinfo::Process>,
) -> bool {
    if pid == root {
        return false;
    }
    for _ in 0..64 {
        let Some(parent) = processes.get(&pid).and_then(sysinfo::Process::parent) else {
            return false;
        };
        if parent == root {
            return true;
        }
        if parent == pid {
            return false;
        }
        pid = parent;
    }
    false
}

#[cfg(unix)]
struct AppServerProcessSupervisor {
    process_group: Option<i32>,
}

#[cfg(unix)]
impl AppServerProcessSupervisor {
    fn new(child: &Child) -> Self {
        Self {
            process_group: child.id().and_then(|pid| i32::try_from(pid).ok()),
        }
    }
}

#[cfg(unix)]
impl Drop for AppServerProcessSupervisor {
    fn drop(&mut self) {
        if let Some(process_group) = self.process_group.take() {
            unsafe {
                let _ = libc::kill(-process_group, libc::SIGKILL);
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
struct AppServerProcessSupervisor;

#[cfg(not(any(unix, windows)))]
impl AppServerProcessSupervisor {
    fn new(_child: &Child) -> Self {
        Self
    }
}

async fn wait_for_ready(addr: SocketAddr, child: &mut Child) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < STARTUP_TIMEOUT {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("could not inspect codex app-server: {e}"))?
        {
            return Err(format!("codex app-server exited before ready: {status}"));
        }
        if let Ok(Ok(true)) =
            tokio::time::timeout(Duration::from_millis(500), ready_probe(addr)).await
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("codex app-server did not become ready within 8 seconds".to_string())
}

async fn stop_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

async fn ready_probe(addr: SocketAddr) -> Result<bool, String> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("ready connect failed: {e}"))?;
    let req = format!("GET /readyz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("ready write failed: {e}"))?;
    let mut buf = [0u8; 64];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| format!("ready read failed: {e}"))?;
    Ok(buf[..n].starts_with(b"HTTP/1.1 200") || buf[..n].starts_with(b"HTTP/1.0 200"))
}

async fn proxy_upgrade(
    mut req: Request<Incoming>,
    backend_addr: SocketAddr,
) -> Result<Response<Empty<Bytes>>, WebSocketError> {
    if req.uri().path() == "/readyz" || req.uri().path() == "/healthz" {
        let mut response = Response::new(Empty::new());
        *response.status_mut() = StatusCode::OK;
        return Ok(response);
    }
    let (response, fut) = upgrade::upgrade(&mut req)?;
    tokio::spawn(async move {
        if let Err(e) = handle_client(fut, backend_addr).await {
            eprintln!("[pentect] app-server proxy session failed: {e}");
        }
    });
    Ok(response)
}

async fn handle_client(fut: upgrade::UpgradeFut, backend_addr: SocketAddr) -> Result<(), String> {
    let mut client = fastwebsockets::FragmentCollector::new(
        fut.await
            .map_err(|e| format!("websocket upgrade failed: {e}"))?,
    );
    let mut backend = connect_backend(backend_addr).await?;
    let mut output_masker = pentect_agent::ActiveToolOutputMasker::new()?;

    loop {
        tokio::select! {
            frame = client.read_frame() => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(e) if is_clean_websocket_close(&e) => break,
                    Err(e) => return Err(format!("client websocket read failed: {e}")),
                };
                match frame.opcode {
                    OpCode::Close => break,
                    OpCode::Text | OpCode::Binary => {
                        debug_app_server_frame("client", &frame);
                        let frame = rewrite_app_server_frame(frame, false, &mut output_masker)?;
                        backend.write_frame(frame).await
                            .map_err(|e| format!("backend websocket write failed: {e}"))?;
                    }
                    _ => {}
                }
            }
            frame = backend.read_frame() => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(e) if is_clean_websocket_close(&e) => break,
                    Err(e) => return Err(format!("backend websocket read failed: {e}")),
                };
                match frame.opcode {
                    OpCode::Close => break,
                    OpCode::Text | OpCode::Binary => {
                        debug_app_server_frame("backend", &frame);
                        let frame = rewrite_app_server_frame(frame, true, &mut output_masker)?;
                        client.write_frame(frame).await
                            .map_err(|e| format!("client websocket write failed: {e}"))?;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn debug_app_server_frame(direction: &str, frame: &Frame<'_>) {
    if !app_server_debug() {
        return;
    }
    let payload: &[u8] = frame.payload.as_ref();
    let mut line = format!(
        "direction={direction} opcode={:?} bytes={}",
        frame.opcode,
        payload.len()
    );
    if let Ok(text) = std::str::from_utf8(payload) {
        match serde_json::from_str::<Value>(text) {
            Ok(value) => {
                let mut parts = Vec::new();
                debug_value_shape(&value, "$", 0, &mut parts);
                if !parts.is_empty() {
                    line.push(' ');
                    line.push_str(&parts.join(" "));
                }
            }
            Err(_) => {
                line.push_str(" text=plain");
            }
        }
    } else {
        line.push_str(" text=non-utf8");
    }
    let _ = append_app_server_debug_line(&line);
}

fn app_server_debug() -> bool {
    std::env::var("PENTECT_APP_PROXY_DEBUG").is_ok_and(|value| value == "1")
}

fn append_app_server_debug_line(line: &str) -> std::io::Result<()> {
    use std::io::Write as _;

    let path = Path::new("log").join("app-proxy-debug.log");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")
}

fn debug_value_shape(value: &Value, path: &str, depth: usize, out: &mut Vec<String>) {
    if depth > 5 || out.len() >= 80 {
        return;
    }
    match value {
        Value::Object(object) => {
            let keys = object.keys().cloned().collect::<Vec<_>>().join(",");
            out.push(format!("{path}=object[{keys}]"));
            for (key, value) in object {
                let child = format!("{path}.{key}");
                if debug_key_interesting(key) || matches!(value, Value::Object(_) | Value::Array(_))
                {
                    debug_value_shape(value, &child, depth + 1, out);
                }
            }
        }
        Value::Array(values) => {
            out.push(format!("{path}=array[{}]", values.len()));
            for (index, value) in values.iter().take(4).enumerate() {
                debug_value_shape(value, &format!("{path}[{index}]"), depth + 1, out);
            }
        }
        Value::String(text) => {
            out.push(format!("{path}=string[{}]", text.len()));
        }
        Value::Bool(_) => out.push(format!("{path}=bool")),
        Value::Number(_) => out.push(format!("{path}=number")),
        Value::Null => out.push(format!("{path}=null")),
    }
}

fn debug_key_interesting(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [
        "type", "method", "tool", "toolname", "name", "command", "cmd", "argv", "args", "env",
        "input", "output", "stdout", "stderr", "params", "request", "response", "process",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn rewrite_app_server_frame(
    frame: Frame<'static>,
    clean_command_display: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<Frame<'static>, String> {
    rewrite_app_server_frame_with_mask(frame, clean_command_display, &mut |text| {
        mask_output_text(masker, text)
    })
}

fn rewrite_app_server_frame_with_mask<F>(
    frame: Frame<'static>,
    clean_command_display: bool,
    mask: &mut F,
) -> Result<Frame<'static>, String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    match frame.opcode {
        OpCode::Text => {
            let payload = Vec::<u8>::from(frame.payload);
            let text = std::str::from_utf8(&payload)
                .map_err(|e| format!("codex app-server sent non-utf8 text frame: {e}"))?;
            let text = rewrite_server_text_frame_for_display(text, clean_command_display, mask)?;
            Ok(Frame::text(Payload::Owned(text.into_bytes())))
        }
        OpCode::Binary => {
            let payload = Vec::<u8>::from(frame.payload);
            let payload = rewrite_server_binary_payload(&payload, clean_command_display, mask)?;
            Ok(Frame::binary(Payload::Owned(payload)))
        }
        _ => Ok(frame),
    }
}

struct SpawnExecutor;

impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::task::spawn(fut);
    }
}

async fn connect_backend(
    addr: SocketAddr,
) -> Result<fastwebsockets::FragmentCollector<TokioIo<hyper::upgrade::Upgraded>>, String> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("could not connect to codex app-server: {e}"))?;
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{addr}/"))
        .header("Host", addr.to_string())
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header(
            "Sec-WebSocket-Key",
            fastwebsockets::handshake::generate_key(),
        )
        .header("Sec-WebSocket-Version", "13")
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("could not build websocket request: {e}"))?;
    let (ws, _) = handshake::client(&SpawnExecutor, req, stream)
        .await
        .map_err(|e| format!("codex app-server websocket handshake failed: {e}"))?;
    Ok(fastwebsockets::FragmentCollector::new(ws))
}

#[cfg(test)]
fn rewrite_server_text_frame<F>(text: &str, mask: &mut F) -> Result<String, String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    rewrite_server_text_frame_for_display(text, true, mask)
}

fn rewrite_server_text_frame_for_display<F>(
    text: &str,
    clean_command_display: bool,
    mask: &mut F,
) -> Result<String, String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    rewrite_server_text_frame_with_image_redactor(
        text,
        clean_command_display,
        mask,
        &mut redact_app_server_images,
    )
}

fn rewrite_server_text_frame_with_image_redactor<F, G>(
    text: &str,
    clean_command_display: bool,
    mask: &mut F,
    redact_images: &mut G,
) -> Result<String, String>
where
    F: FnMut(&str) -> Result<String, String>,
    G: FnMut(&mut Value) -> Result<(), String>,
{
    let mut value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => return mask(text),
    };
    redact_images(&mut value)?;
    if clean_command_display {
        suppress_partial_json_deltas(&mut value);
    }
    mask_app_server_display_strings(&mut value, None, clean_command_display, mask)?;
    if clean_command_display {
        prefer_command_action_display(&mut value);
    }
    serde_json::to_string(&value).map_err(|e| e.to_string())
}

fn rewrite_server_binary_payload<F>(
    payload: &[u8],
    clean_command_display: bool,
    mask: &mut F,
) -> Result<Vec<u8>, String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    if image_payload(payload) {
        return pentect_agent::redact_image_bytes_into_active_memory_store(payload)
            .map(|redacted| redacted.unwrap_or_else(|| payload.to_vec()));
    }
    if let Ok(text) = std::str::from_utf8(payload) {
        return rewrite_server_text_frame_for_display(text, clean_command_display, mask)
            .map(String::into_bytes);
    }
    Err("app-server binary output cannot be protected".to_string())
}

fn image_payload(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || bytes.starts_with(&[0xff, 0xd8, 0xff])
        || bytes.starts_with(b"GIF87a")
        || bytes.starts_with(b"GIF89a")
        || bytes.starts_with(b"BM")
        || (bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"))
}

fn redact_app_server_images(value: &mut Value) -> Result<(), String> {
    if let Some(updated) = pentect_agent::redact_tool_images_into_active_memory_store(value)? {
        *value = updated;
    }
    Ok(())
}

fn mask_app_server_display_strings<F>(
    value: &mut Value,
    key: Option<&str>,
    clean_command_display: bool,
    mask: &mut F,
) -> Result<(), String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    match value {
        Value::String(text) => {
            if clean_command_display && key.is_some_and(maskable_app_server_text_key) {
                let before_len = text.len();
                if let Some(clean) = clean_pentect_exec_display_text(text) {
                    *text = clean;
                    debug_app_server_display_clean(key, before_len, text.len(), true);
                } else if text.to_ascii_lowercase().contains("pentect exec") {
                    debug_app_server_display_clean(key, before_len, before_len, false);
                }
            }
            if !looks_like_image_payload_string(text)
                && !key.is_some_and(|key| safe_protocol_path(key, text))
            {
                let masked = mask(text)?;
                if masked != *text {
                    *text = masked;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                mask_app_server_display_strings(value, key, clean_command_display, mask)?;
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                mask_app_server_display_strings(value, Some(key), clean_command_display, mask)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn prefer_command_action_display(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                prefer_command_action_display(value);
            }
        }
        Value::Object(object) => {
            let action_command = object
                .get("commandActions")
                .and_then(Value::as_array)
                .and_then(|actions| actions.first())
                .and_then(|action| action.get("command"))
                .and_then(Value::as_str)
                .filter(|command| !command.trim().is_empty())
                .map(|command| normalize_pentect_display_payload(command.to_string()));
            if let Some(action_command) = action_command {
                if object.get("command").and_then(Value::as_str).is_some() {
                    object.insert("command".to_string(), Value::String(action_command));
                }
            }
            for value in object.values_mut() {
                prefer_command_action_display(value);
            }
        }
        _ => {}
    }
}

fn debug_app_server_display_clean(
    key: Option<&str>,
    before_len: usize,
    after_len: usize,
    cleaned: bool,
) {
    if !app_server_debug() {
        return;
    }
    let key = key.unwrap_or("<none>");
    let _ = append_app_server_debug_line(&format!(
        "display-clean key={key} before_len={before_len} after_len={after_len} cleaned={cleaned}"
    ));
}

fn clean_pentect_exec_display_text(text: &str) -> Option<String> {
    if let Some(clean) = pentect_agent::display_command_without_pentect_exec_wrapper(text) {
        return Some(normalize_pentect_display_payload(clean));
    }
    let lower = text.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(relative) = lower[search_from..].find("pentect") {
        let start = search_from + relative;
        let before = &text[..start];
        let Some(clean) =
            pentect_agent::display_command_without_pentect_exec_wrapper(&text[start..])
        else {
            search_from = start + "pentect".len();
            continue;
        };
        if display_prefix_keeps_before_pentect(before) {
            return Some(format!(
                "{before}{}",
                normalize_pentect_display_payload(clean)
            ));
        }
        if let Some(prefix) = display_prefix_replaces_path_before_pentect(before) {
            return Some(format!(
                "{prefix}{}",
                normalize_pentect_display_payload(clean)
            ));
        }
        if display_prefix_drops_before_pentect(before) {
            return Some(normalize_pentect_display_payload(clean));
        }
        return Some(normalize_pentect_display_payload(clean));
    }
    None
}

fn normalize_pentect_display_payload(command: String) -> String {
    if quoted_word_count(&command) < 3 {
        return command;
    }
    dequote_display_words(&command).unwrap_or(command)
}

fn quoted_word_count(text: &str) -> usize {
    let mut count = 0usize;
    let mut at_word_start = true;
    for ch in text.chars() {
        if ch.is_whitespace() {
            at_word_start = true;
            continue;
        }
        if at_word_start && matches!(ch, '\'' | '"') {
            count += 1;
        }
        at_word_start = false;
    }
    count
}

fn dequote_display_words(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.char_indices().peekable();
    let mut at_word_start = true;
    while let Some((_, ch)) = chars.next() {
        if at_word_start && matches!(ch, '\'' | '"') {
            let quote = ch;
            let mut closed = false;
            while let Some((_, inner)) = chars.next() {
                if inner == quote {
                    if quote == '\'' && chars.peek().is_some_and(|(_, next)| *next == '\'') {
                        out.push('\'');
                        let _ = chars.next();
                        continue;
                    }
                    closed = true;
                    break;
                }
                out.push(inner);
            }
            if !closed {
                return None;
            }
            at_word_start = false;
            continue;
        }
        out.push(ch);
        at_word_start = ch.is_whitespace();
    }
    Some(out)
}

fn display_prefix_keeps_before_pentect(before: &str) -> bool {
    let before = before.trim_end();
    before.is_empty() || before.ends_with("Ran")
}

fn display_prefix_replaces_path_before_pentect(before: &str) -> Option<String> {
    let trimmed_len = before.trim_end().len();
    let trimmed = before.get(..trimmed_len)?;
    let lower = trimmed.to_ascii_lowercase();
    let ran_pos = lower.rfind("ran ")?;
    if !trimmed[..ran_pos].trim().is_empty() {
        return None;
    }
    Some(format!("{}Ran ", &trimmed[..ran_pos]))
}

fn display_prefix_drops_before_pentect(before: &str) -> bool {
    let before = before.trim_end().to_ascii_lowercase();
    before == "cmd /d /s /c"
        || before.ends_with(" cmd /d /s /c")
        || before == "powershell -command"
        || before.ends_with(" powershell -command")
        || before == "pwsh -command"
        || before.ends_with(" pwsh -command")
}

fn maskable_app_server_text_key(key: &str) -> bool {
    matches!(
        key,
        "text"
            | "delta"
            | "message"
            | "preview"
            | "summary"
            | "content"
            | "contentItems"
            | "output"
            | "stdout"
            | "stderr"
            | "stdin"
            | "command"
            | "reason"
            | "detail"
            | "details"
            | "error"
            | "aggregatedOutput"
            | "aggregated_output"
            | "formattedOutput"
            | "formatted_output"
    )
}

fn safe_protocol_path(key: &str, text: &str) -> bool {
    use pentect_core::OverMaskGuard;

    if !matches!(key, "path" | "cwd") {
        return false;
    }
    let candidate = text
        .strip_prefix("file:///")
        .or_else(|| text.strip_prefix("file://"))
        .unwrap_or(text);
    !text.contains(['?', '#', '\r', '\n']) && pentect_core::ShapeGuard::builtin().benign(candidate)
}

fn looks_like_image_payload_string(text: &str) -> bool {
    text.trim_start()
        .get(..11)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("data:image/"))
}

fn suppress_partial_json_deltas(value: &mut Value) -> bool {
    if !json_has_partial_event_marker(value) {
        return false;
    }
    clear_partial_json_payload(value, None)
}

fn json_has_partial_event_marker(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.iter().any(|(key, value)| {
                matches!(key.as_str(), "type" | "event" | "method")
                    && value.as_str().is_some_and(|text| {
                        let lower = text.to_ascii_lowercase();
                        lower == "stream_event"
                            || lower
                                .rsplit(['/', '_'])
                                .next()
                                .is_some_and(|part| part.ends_with("delta"))
                    })
            }) || object.values().any(json_has_partial_event_marker)
        }
        Value::Array(values) => values.iter().any(json_has_partial_event_marker),
        _ => false,
    }
}

fn clear_partial_json_payload(value: &mut Value, key: Option<&str>) -> bool {
    match value {
        Value::Object(object) => {
            let mut changed = false;
            for (key, value) in object {
                changed |= clear_partial_json_payload(value, Some(key));
            }
            changed
        }
        Value::Array(values) => {
            let mut changed = false;
            for value in values {
                changed |= clear_partial_json_payload(value, key);
            }
            changed
        }
        Value::String(text) if !key.is_some_and(partial_json_metadata_key) => {
            text.zeroize();
            text.clear();
            true
        }
        _ => false,
    }
}

fn partial_json_metadata_key(key: &str) -> bool {
    matches!(
        key,
        "type"
            | "event"
            | "method"
            | "jsonrpc"
            | "id"
            | "requestId"
            | "request_id"
            | "responseId"
            | "response_id"
            | "sessionId"
            | "session_id"
            | "threadId"
            | "thread_id"
            | "turnId"
            | "turn_id"
            | "itemId"
            | "item_id"
            | "messageId"
            | "message_id"
            | "toolUseId"
            | "tool_use_id"
            | "callId"
            | "call_id"
            | "parentId"
            | "parent_id"
            | "uuid"
            | "status"
            | "phase"
            | "timestamp"
            | "createdAt"
            | "created_at"
            | "updatedAt"
            | "updated_at"
            | "version"
    )
}

fn mask_output_text(
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    text: &str,
) -> Result<String, String> {
    Ok(masker
        .mask_tool_output(text)?
        .unwrap_or_else(|| text.to_string()))
}

fn is_clean_websocket_close(error: &WebSocketError) -> bool {
    match error {
        WebSocketError::ConnectionClosed | WebSocketError::UnexpectedEOF => true,
        WebSocketError::IoError(error) => matches!(
            error.kind(),
            ErrorKind::ConnectionAborted
                | ErrorKind::ConnectionReset
                | ErrorKind::BrokenPipe
                | ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_frame_masks_nested_strings() {
        let raw = serde_json::json!({
            "method": "item/completed",
            "session_id": "sk-abcdefghijklmnopqrstuvwx",
            "params": {
                "item": {
                    "content": [
                        {"text": "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx"}
                    ],
                    "output": {"value": "sk-abcdefghijklmnopqrstuvwx"}
                }
            }
        })
        .to_string();
        let masked = rewrite_server_text_frame(&raw, &mut |text| {
            Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        })
        .unwrap();
        assert!(masked.contains("<<OPENAI_API_KEY_x>>"), "{masked}");
        let value: Value = serde_json::from_str(&masked).unwrap();
        assert_eq!(value["session_id"], "<<OPENAI_API_KEY_x>>");
        assert_eq!(
            value["params"]["item"]["content"][0]["text"],
            "OPENAI_API_KEY=<<OPENAI_API_KEY_x>>"
        );
        assert_eq!(
            value["params"]["item"]["output"]["value"],
            "<<OPENAI_API_KEY_x>>"
        );
    }

    #[test]
    fn server_frame_masks_plain_text_when_not_json() {
        let masked = rewrite_server_text_frame("token sk-abcdefghijklmnopqrstuvwx", &mut |text| {
            Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        })
        .unwrap();
        assert_eq!(masked, "token <<OPENAI_API_KEY_x>>");
    }

    #[test]
    fn server_binary_frame_masks_utf8_json_payload() {
        let raw = serde_json::json!({
            "method": "item/completed",
            "params": {
                "item": {
                    "content": [
                        {"text": "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx"}
                    ]
                }
            }
        })
        .to_string();
        let masked = rewrite_server_binary_payload(raw.as_bytes(), true, &mut |text| {
            Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        })
        .unwrap();
        let masked = String::from_utf8(masked).unwrap();
        assert!(!masked.contains("sk-abcdefghijklmnopqrstuvwx"), "{masked}");
        assert!(masked.contains("<<OPENAI_API_KEY_x>>"), "{masked}");
    }

    #[test]
    fn server_frame_suppresses_partial_command_output() {
        let raw = serde_json::json!({
            "method": "item/commandExecution/outputDelta",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "itemId": "item-1",
                "delta": {
                    "type": "text_delta",
                    "text": "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx"
                }
            }
        })
        .to_string();
        let masked = rewrite_server_text_frame(&raw, &mut |text| {
            Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        })
        .unwrap();
        assert!(!masked.contains("sk-abcdefghijklmnopqrstuvwx"), "{masked}");
        let value: Value = serde_json::from_str(&masked).unwrap();
        assert_eq!(value["params"]["delta"]["type"], "text_delta");
        assert_eq!(value["params"]["delta"]["text"], "");
    }

    #[test]
    fn server_frame_masks_completed_command_outputs() {
        let raw = serde_json::json!({
            "method": "item/completed",
            "params": {
                "item": {
                    "type": "commandExecution",
                    "id": "item-1",
                    "command": "Get-Content sandbox\\tmp\\pentect-e2e.env",
                    "aggregatedOutput": "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx",
                    "formattedOutput": "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx"
                }
            }
        })
        .to_string();
        let masked = rewrite_server_text_frame(&raw, &mut |text| {
            Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        })
        .unwrap();
        assert!(!masked.contains("sk-abcdefghijklmnopqrstuvwx"), "{masked}");
        assert_eq!(
            masked.matches("<<OPENAI_API_KEY_x>>").count(),
            2,
            "{masked}"
        );
        assert!(
            masked.contains("Get-Content sandbox\\\\tmp\\\\pentect-e2e.env"),
            "{masked}"
        );
    }

    #[test]
    fn server_frame_hides_pentect_exec_wrapper_in_command_display() {
        let raw = serde_json::json!({
            "method": "item/completed",
            "params": {
                "item": {
                    "type": "commandExecution",
                    "id": "item-1",
                    "command": "pentect exec 'Get-Content .env'",
                    "aggregatedOutput": "done"
                }
            }
        })
        .to_string();
        let rewritten = rewrite_server_text_frame(&raw, &mut |text| Ok(text.to_string())).unwrap();
        assert!(!rewritten.contains("pentect exec"), "{rewritten}");
        assert!(rewritten.contains("Get-Content .env"), "{rewritten}");
    }

    #[test]
    fn server_frame_prefers_clean_command_action_display() {
        let raw = serde_json::json!({
            "method": "item/completed",
            "params": {
                "item": {
                    "type": "commandExecution",
                    "id": "item-1",
                    "command": "internal setup; pentect exec 'Get-Content .env'",
                    "commandActions": [{
                        "type": "copy",
                        "command": "pentect exec 'Get-Content .env'"
                    }]
                }
            }
        })
        .to_string();
        let rewritten = rewrite_server_text_frame(&raw, &mut |text| Ok(text.to_string())).unwrap();
        let value: Value = serde_json::from_str(&rewritten).unwrap();
        assert_eq!(
            value["params"]["item"]["command"].as_str(),
            Some("Get-Content .env")
        );
        assert!(!rewritten.contains("pentect exec"), "{rewritten}");
    }

    #[test]
    fn display_text_hides_ran_pentect_exec_wrapper() {
        let text = "Ran pentect exec '$has = if ($true) { ''HAS_ENV=YES'' }'";
        let cleaned = clean_pentect_exec_display_text(text).unwrap();
        assert!(!cleaned.contains("pentect exec"), "{cleaned}");
        assert!(cleaned.contains("Ran $has = if"), "{cleaned}");
        assert!(cleaned.contains("'HAS_ENV=YES'"), "{cleaned}");
    }

    #[test]
    fn display_text_hides_real_powershell_pentect_exec_wrapper() {
        let text = concat!(
            "Ran pentect exec '$out = if ($env:OPENAI_API_KEY) { ''HAS_ENV=YES'' } else ",
            "{ ''HAS_ENV=NO_ENV'' }; New-Item -ItemType Directory -Path ''log'' -Force | ",
            "Out-Null; Set-Content -Path ''log\\prompt-appserver-final.txt'' -Value $out'"
        );
        let cleaned = clean_pentect_exec_display_text(text).unwrap();
        assert!(!cleaned.contains("pentect exec"), "{cleaned}");
        assert!(cleaned.contains("Ran $out = if"), "{cleaned}");
        assert!(cleaned.contains("$env:OPENAI_API_KEY"), "{cleaned}");
    }

    #[test]
    fn display_text_hides_shell_prefixed_pentect_exec_wrapper() {
        let text = "cmd /D /S /C pentect exec 'Get-Content .env'";
        let cleaned = clean_pentect_exec_display_text(text).unwrap();
        assert_eq!(cleaned, "Get-Content .env");
    }

    #[test]
    fn display_text_drops_unknown_prefix_before_pentect_exec_wrapper() {
        let text = "internal setup; pentect exec 'Get-Content .env'";
        let cleaned = clean_pentect_exec_display_text(text).unwrap();
        assert_eq!(cleaned, "Get-Content .env");
    }

    #[test]
    fn display_text_dequotes_shell_word_list_payload() {
        let text = "'$target' '=' \"log\\\\out.txt;\" '$dir' '=' Split-Path '$target'";
        let cleaned = normalize_pentect_display_payload(text.to_string());
        assert!(!cleaned.contains("'$target'"), "{cleaned}");
        assert!(cleaned.contains("$target ="), "{cleaned}");
        assert!(cleaned.contains("$dir = Split-Path $target"), "{cleaned}");
    }

    #[test]
    fn display_text_dequotes_real_codex_word_list_payload() {
        let text = "'$value' '=' '$env:OPENAI_API_KEY;' '$status' '=' if '([string]::IsNullOrWhiteSpace($value))' '{' 'HAS_ENV=NO_ENV' '}' else '{' 'HAS_ENV=YES' '};' New-Item -ItemType Directory -Path log -Force '|' 'Out-Null;' Set-Content -Path log\\out.txt -Value '$status'";
        let cleaned = normalize_pentect_display_payload(text.to_string());
        assert!(!cleaned.contains("'$value'"), "{cleaned}");
        assert!(
            cleaned.contains("$value = $env:OPENAI_API_KEY;"),
            "{cleaned}"
        );
        assert!(cleaned.contains("| Out-Null;"), "{cleaned}");
    }

    #[test]
    fn display_text_hides_uppercase_pentect_exe_wrapper() {
        let text = "Ran C:\\Tools\\PENTECT.EXE exec 'Get-Content .env'";
        let cleaned = clean_pentect_exec_display_text(text).unwrap();
        assert!(!cleaned.contains("PENTECT.EXE"), "{cleaned}");
        assert!(cleaned.contains("Ran Get-Content .env"), "{cleaned}");
    }

    #[test]
    fn server_binary_frame_rejects_unknown_non_utf8_payload() {
        let raw = [0xff, 0x00, 0x80];
        let error =
            rewrite_server_binary_payload(
                &raw,
                true,
                &mut |_| Ok("<<SHOULD_NOT_RUN>>".to_string()),
            )
            .unwrap_err();
        assert_eq!(error, "app-server binary output cannot be protected");
    }

    #[test]
    fn server_frame_does_not_mask_protocol_paths() {
        let raw = serde_json::json!({
            "id": 1,
            "result": {
                "thread": {
                    "cwd": "C:\\Users\\yun40\\Desktop\\pentect",
                    "path": "file:///C:/Users/yun40/Desktop/pentect"
                },
                "preview": "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx"
            }
        })
        .to_string();
        let masked = rewrite_server_text_frame(&raw, &mut |text| {
            Ok(text
                .replace("C:\\Users\\yun40\\Desktop\\pentect", "<<LOCAL_PATH_x>>")
                .replace("file:///C:/Users/yun40/Desktop/pentect", "<<LOCAL_URI_x>>")
                .replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        })
        .unwrap();
        assert!(
            masked.contains("C:\\\\Users\\\\yun40\\\\Desktop\\\\pentect"),
            "{masked}"
        );
        assert!(
            masked.contains("file:///C:/Users/yun40/Desktop/pentect"),
            "{masked}"
        );
        assert!(!masked.contains("sk-abcdefghijklmnopqrstuvwx"), "{masked}");
        assert!(masked.contains("<<OPENAI_API_KEY_x>>"), "{masked}");
        assert!(!masked.contains("<<LOCAL_PATH_x>>"), "{masked}");
        assert!(!masked.contains("<<LOCAL_URI_x>>"), "{masked}");
    }

    #[test]
    fn server_frame_scans_metadata_keys_that_do_not_contain_real_paths() {
        let raw = serde_json::json!({
            "id": "sk-abcdefghijklmnopqrstuvwx",
            "path": "Authorization: Bearer sk-abcdefghijklmnopqrstuvwx"
        })
        .to_string();
        let masked = rewrite_server_text_frame(&raw, &mut |text| {
            Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        })
        .unwrap();
        assert!(!masked.contains("sk-abcdefghijklmnopqrstuvwx"), "{masked}");
        assert_eq!(masked.matches("<<OPENAI_API_KEY_x>>").count(), 2);
    }

    #[test]
    fn server_frame_redacts_image_payloads_before_display_masking() {
        let raw = serde_json::json!({
            "method": "item/completed",
            "params": {
                "item": {
                    "content": [{
                        "type": "image",
                        "mimeType": "image/png",
                        "data": "RAW_IMAGE_BYTES"
                    }]
                }
            }
        })
        .to_string();
        let masked = rewrite_server_text_frame_with_image_redactor(
            &raw,
            true,
            &mut |text| Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>")),
            &mut |value| {
                value["params"]["item"]["content"][0]["data"] =
                    Value::String("REDACTED_IMAGE_BYTES".to_string());
                value["params"]["item"]["content"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({
                        "type": "text",
                        "text": "Pentect image masks\n[1] OPENAI_API_KEY"
                    }));
                Ok(())
            },
        )
        .unwrap();
        assert!(!masked.contains("RAW_IMAGE_BYTES"), "{masked}");
        assert!(masked.contains("REDACTED_IMAGE_BYTES"), "{masked}");
        assert!(masked.contains("Pentect image masks"), "{masked}");
        assert!(masked.contains("[1] OPENAI_API_KEY"), "{masked}");
    }

    #[test]
    fn app_server_frame_masks_client_to_backend_payloads() {
        let raw = serde_json::json!({
            "method": "tool/result",
            "params": {
                "content": "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx"
            }
        })
        .to_string();
        let frame = Frame::text(Payload::Owned(raw.into_bytes()));
        let masked = rewrite_app_server_frame_with_mask(frame, false, &mut |text| {
            Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        })
        .unwrap();
        let payload = String::from_utf8(Vec::<u8>::from(masked.payload)).unwrap();
        assert!(
            !payload.contains("sk-abcdefghijklmnopqrstuvwx"),
            "{payload}"
        );
        assert!(payload.contains("<<OPENAI_API_KEY_x>>"), "{payload}");
    }

    #[test]
    fn app_server_client_frame_keeps_pentect_exec_command_for_execution() {
        let raw = serde_json::json!({
            "method": "tool/request",
            "params": {
                "command": "pentect exec 'Get-Content .env'"
            }
        })
        .to_string();
        let frame = Frame::text(Payload::Owned(raw.into_bytes()));
        let rewritten =
            rewrite_app_server_frame_with_mask(frame, false, &mut |text| Ok(text.to_string()))
                .unwrap();
        let payload = String::from_utf8(Vec::<u8>::from(rewritten.payload)).unwrap();
        assert!(payload.contains("pentect exec"), "{payload}");
        assert!(payload.contains("Get-Content .env"), "{payload}");
    }
}
