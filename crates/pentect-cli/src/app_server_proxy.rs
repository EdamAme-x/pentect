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

const STARTUP_TIMEOUT: Duration = Duration::from_secs(8);

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
    cmd.spawn()
        .map_err(|e| format!("could not start codex app-server: {e}"))
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
                    OpCode::Text => {
                        let payload = Vec::<u8>::from(frame.payload);
                        let text = std::str::from_utf8(&payload)
                            .map_err(|e| format!("codex app-server sent non-utf8 text frame: {e}"))?;
                        let text = rewrite_server_text_frame(text, &mut |text| mask_output_text(&mut output_masker, text))?;
                        client.write_frame(Frame::text(Payload::Owned(text.into_bytes()))).await
                            .map_err(|e| format!("client websocket write failed: {e}"))?;
                    }
                    OpCode::Binary => {
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

fn rewrite_server_text_frame<F>(text: &str, mask: &mut F) -> Result<String, String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    let mut value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => return mask(text),
    };
    mask_app_server_display_strings(&mut value, None, mask)?;
    serde_json::to_string(&value).map_err(|e| e.to_string())
}

fn mask_app_server_display_strings<F>(
    value: &mut Value,
    key: Option<&str>,
    mask: &mut F,
) -> Result<(), String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    match value {
        Value::String(text) => {
            if key.is_some_and(maskable_app_server_text_key) {
                let masked = mask(text)?;
                if masked != *text {
                    *text = masked;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                mask_app_server_display_strings(value, key, mask)?;
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                mask_app_server_display_strings(value, Some(key), mask)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn maskable_app_server_text_key(key: &str) -> bool {
    matches!(
        key,
        "text"
            | "message"
            | "preview"
            | "summary"
            | "content"
            | "output"
            | "stdout"
            | "stderr"
            | "command"
            | "reason"
            | "detail"
            | "details"
            | "error"
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
            "params": {
                "item": {
                    "content": [
                        {"text": "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx"}
                    ]
                }
            }
        })
        .to_string();
        let masked = rewrite_server_text_frame(&raw, &mut |text| {
            Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        })
        .unwrap();
        assert!(!masked.contains("sk-abcdefghijklmnopqrstuvwx"), "{masked}");
        assert!(masked.contains("<<OPENAI_API_KEY_x>>"), "{masked}");
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
}
