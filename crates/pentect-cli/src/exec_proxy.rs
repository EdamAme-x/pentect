use fastwebsockets::upgrade;
use fastwebsockets::{Frame, OpCode, Payload, WebSocketError};
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::oneshot;

const PROCESS_OUTPUT_METHOD: &str = "process/output";
const PROCESS_START_METHOD: &str = "process/start";
const OUTPUT_HOLDBACK_BYTES: usize = 8192;

pub(crate) const PENTECT_CODEX_EXEC_PROXY_ENV: &str = "PENTECT_CODEX_EXEC_PROXY";

pub(crate) struct ExecProxyGuard {
    url: String,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ExecProxyGuard {
    pub(crate) fn start(codex: &Path) -> Result<Self, String> {
        let codex = codex.to_path_buf();
        let auth = random_auth_token()?;
        let (ready_tx, ready_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let thread = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("could not start exec proxy runtime: {e}")));
                    return;
                }
            };
            runtime.block_on(async move {
                if let Err(e) = run_proxy(codex, auth, ready_tx, shutdown_rx).await {
                    eprintln!("[pentect] exec proxy stopped: {e}");
                }
            });
        });
        let url = ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| "exec proxy did not start within 5 seconds".to_string())??;
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

impl Drop for ExecProxyGuard {
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
    auth: String,
    ready_tx: mpsc::Sender<Result<String, String>>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| format!("could not bind exec proxy: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("could not read exec proxy addr: {e}"))?;
    let _ = ready_tx.send(Ok(format!("ws://{addr}/?token={auth}")));

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|e| format!("exec proxy accept failed: {e}"))?;
                let codex = codex.clone();
                let auth = auth.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let service = service_fn(move |req| server_upgrade(req, codex.clone(), auth.clone()));
                    let conn = http1::Builder::new().serve_connection(io, service).with_upgrades();
                    if let Err(e) = conn.await {
                        eprintln!("[pentect] exec proxy connection failed: {e}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn server_upgrade(
    mut req: Request<Incoming>,
    codex: PathBuf,
    auth: String,
) -> Result<Response<Empty<Bytes>>, WebSocketError> {
    if !request_has_auth(&req, &auth) {
        let mut response = Response::new(Empty::new());
        *response.status_mut() = StatusCode::FORBIDDEN;
        return Ok(response);
    }
    let (response, fut) = upgrade::upgrade(&mut req)?;
    tokio::spawn(async move {
        if let Err(e) = handle_client(fut, codex).await {
            eprintln!("[pentect] exec proxy session failed: {e}");
        }
    });
    Ok(response)
}

async fn handle_client(fut: upgrade::UpgradeFut, codex: PathBuf) -> Result<(), String> {
    let mut ws = fastwebsockets::FragmentCollector::new(
        fut.await
            .map_err(|e| format!("websocket upgrade failed: {e}"))?,
    );
    let mut output_masker = pentect_agent::ActiveToolOutputMasker::new()?;
    let mut backend = Command::new(codex);
    backend
        .arg("exec-server")
        .arg("--listen")
        .arg("stdio")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env_remove("PENTECT_IN_MEMORY_MANAGER_ADDR")
        .env_remove("PENTECT_IN_MEMORY_MANAGER_TOKEN")
        .env_remove("PENTECT_AGENT_LAUNCHED");
    let mut backend = backend
        .spawn()
        .map_err(|e| format!("could not start codex exec-server stdio: {e}"))?;
    let mut backend_stdin = backend
        .stdin
        .take()
        .ok_or_else(|| "codex exec-server stdin unavailable".to_string())?;
    let backend_stdout = backend
        .stdout
        .take()
        .ok_or_else(|| "codex exec-server stdout unavailable".to_string())?;
    if let Some(stderr) = backend.stderr.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = line;
                if exec_proxy_debug() {
                    eprintln!("[pentect] codex exec-server stderr");
                }
            }
        });
    }
    let mut backend_lines = BufReader::new(backend_stdout).lines();
    let mut backend_rewriter =
        BackendRewriter::new(move |text: &str| mask_exec_output_text(&mut output_masker, text));

    loop {
        tokio::select! {
            frame = ws.read_frame() => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(e) if is_clean_websocket_close(&e) => break,
                    Err(e) => return Err(format!("websocket read failed: {e}")),
                };
                match frame.opcode {
                    OpCode::Close => break,
                    OpCode::Text | OpCode::Binary => {
                        let payload = Vec::<u8>::from(frame.payload);
                        let text = std::str::from_utf8(&payload)
                            .map_err(|e| format!("codex sent non-utf8 exec-server frame: {e}"))?;
                        let line = rewrite_client_json_line(text)?;
                        backend_stdin.write_all(line.as_bytes()).await
                            .map_err(|e| format!("could not write exec-server request: {e}"))?;
                        backend_stdin.write_all(b"\n").await
                            .map_err(|e| format!("could not terminate exec-server request: {e}"))?;
                        backend_stdin.flush().await
                            .map_err(|e| format!("could not flush exec-server request: {e}"))?;
                    }
                    _ => {}
                }
            }
            line = backend_lines.next_line() => {
                let Some(line) = line.map_err(|e| format!("could not read exec-server response: {e}"))? else {
                    break;
                };
                if line.trim().is_empty() {
                    continue;
                }
                let line = backend_rewriter.rewrite_line(&line)?;
                if let Err(e) = ws.write_frame(Frame::text(Payload::Owned(line.into_bytes()))).await {
                    if is_clean_websocket_close(&e) {
                        break;
                    }
                    return Err(format!("websocket write failed: {e}"));
                }
            }
        }
    }

    let _ = backend.kill().await;
    let _ = backend.wait().await;
    Ok(())
}

fn request_has_auth<B>(req: &Request<B>, auth: &str) -> bool {
    req.uri()
        .query()
        .is_some_and(|query| query.split('&').any(|part| part == format!("token={auth}")))
}

fn random_auth_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| format!("could not create exec proxy token: {e}"))?;
    Ok(data_encoding::HEXLOWER.encode(&bytes))
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

fn rewrite_client_json_line(line: &str) -> Result<String, String> {
    rewrite_client_json_line_with(
        line,
        &mut |argv, env| {
            Ok(
                pentect_agent::preflight_exec_server_process_start_from_active_in_memory_manager(
                    argv, env,
                )?
                .unwrap_or_default(),
            )
        },
        &mut |text| {
            Ok(
                pentect_agent::resolve_text_from_active_in_memory_manager(text)?
                    .unwrap_or_else(|| text.to_string()),
            )
        },
    )
}

fn rewrite_client_json_line_with<P, R>(
    line: &str,
    preflight: &mut P,
    resolve: &mut R,
) -> Result<String, String>
where
    P: FnMut(&[String], &[(String, String)]) -> Result<Vec<(String, String)>, String>,
    R: FnMut(&str) -> Result<String, String>,
{
    let mut value: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(_) => return Ok(line.to_string()),
    };
    if value.get("method").and_then(Value::as_str) != Some(PROCESS_START_METHOD) {
        return serde_json::to_string(&value).map_err(|e| e.to_string());
    }
    let Some(params) = value.get_mut("params").and_then(Value::as_object_mut) else {
        return serde_json::to_string(&value).map_err(|e| e.to_string());
    };
    let argv_before = params
        .get("argv")
        .and_then(Value::as_array)
        .map(|values| json_array_strings(values))
        .unwrap_or_default();
    let env_before = params
        .get("env")
        .and_then(Value::as_object)
        .map(|env| {
            env.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_string()))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let env_overlays = preflight(&argv_before, &env_before)?;
    if let Some(argv) = params.get_mut("argv").and_then(Value::as_array_mut) {
        for arg in argv {
            resolve_json_string(arg, resolve)?;
        }
    }
    let env = params
        .entry("env")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Some(env) = env.as_object_mut() {
        strip_private_env(env);
        for (name, value) in env_overlays {
            env.insert(name, Value::String(value));
        }
        for value in env.values_mut() {
            resolve_json_string(value, resolve)?;
        }
    }
    serde_json::to_string(&value).map_err(|e| e.to_string())
}

fn strip_private_env(env: &mut serde_json::Map<String, Value>) {
    env.remove("PENTECT_IN_MEMORY_MANAGER_ADDR");
    env.remove("PENTECT_IN_MEMORY_MANAGER_TOKEN");
    env.remove("PENTECT_AGENT_LAUNCHED");
}

fn json_array_strings(values: &[Value]) -> Vec<String> {
    values
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn resolve_json_string<F>(value: &mut Value, resolve: &mut F) -> Result<(), String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    let Some(text) = value.as_str() else {
        return Ok(());
    };
    let resolved = resolve(text)?;
    if resolved != text {
        *value = Value::String(resolved);
    }
    Ok(())
}

struct BackendRewriter<F> {
    mask: F,
    pending_output: BTreeMap<String, String>,
}

impl<F> BackendRewriter<F>
where
    F: FnMut(&str) -> Result<String, String>,
{
    fn new(mask: F) -> Self {
        Self {
            mask,
            pending_output: BTreeMap::new(),
        }
    }

    fn rewrite_line(&mut self, line: &str) -> Result<String, String> {
        let mut value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => return Ok(line.to_string()),
        };
        let method = value
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_string);
        if exec_proxy_debug() {
            let shape = if method.is_some() {
                "notification"
            } else if value.get("result").is_some() {
                "response"
            } else if value.get("error").is_some() {
                "error"
            } else {
                "other"
            };
            eprintln!(
                "[pentect] exec proxy backend {shape} method={} result_keys={}",
                method.as_deref().unwrap_or("-"),
                value
                    .get("result")
                    .and_then(Value::as_object)
                    .map(|object| object.keys().cloned().collect::<Vec<_>>().join(","))
                    .unwrap_or_default()
            );
        }
        if method.as_deref() == Some(PROCESS_OUTPUT_METHOD) {
            if let Some(params) = value.get_mut("params") {
                self.mask_process_output(params)?;
            }
        } else if is_process_read_response(&value) {
            if let Some(chunks) = value
                .get_mut("result")
                .and_then(|result| result.get_mut("chunks"))
                .and_then(Value::as_array_mut)
            {
                mask_read_chunks(chunks, &mut self.mask)?;
            }
        }
        if matches!(method.as_deref(), Some("process/exited" | "process/closed")) {
            clear_process_pending(&mut self.pending_output, &value);
        }
        if let Some(error) = value.get_mut("error") {
            mask_json_strings(error, &mut self.mask)?;
        }
        serde_json::to_string(&value).map_err(|e| e.to_string())
    }

    fn mask_process_output(&mut self, value: &mut Value) -> Result<(), String> {
        let Some(text) = decoded_chunk_text(value)? else {
            return Ok(());
        };
        let key = output_buffer_key(value);
        let pending = self.pending_output.remove(&key).unwrap_or_default();
        let combined = format!("{pending}{text}");
        if should_flush_output(&combined) {
            let masked = (self.mask)(&combined)?;
            set_chunk_text(value, &masked);
        } else {
            self.pending_output.insert(key, combined);
            set_chunk_text(value, "");
        }
        Ok(())
    }
}

fn is_process_read_response(value: &Value) -> bool {
    let Some(result) = value.get("result") else {
        return false;
    };
    result.get("chunks").is_some()
        && result.get("nextSeq").is_some()
        && result.get("closed").is_some()
}

fn mask_read_chunks<F>(chunks: &mut [Value], mask: &mut F) -> Result<(), String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    let mut groups: BTreeMap<String, Vec<(usize, String)>> = BTreeMap::new();
    for (index, chunk) in chunks.iter().enumerate() {
        let Some(text) = decoded_chunk_text(chunk)? else {
            continue;
        };
        groups
            .entry(output_buffer_key(chunk))
            .or_default()
            .push((index, text));
    }
    for entries in groups.into_values() {
        let combined = entries
            .iter()
            .map(|(_, text)| text.as_str())
            .collect::<String>();
        let masked = mask(&combined)?;
        let mut iter = entries.into_iter();
        if let Some((first, _)) = iter.next() {
            set_chunk_text(&mut chunks[first], &masked);
        }
        for (index, _) in iter {
            set_chunk_text(&mut chunks[index], "");
        }
    }
    Ok(())
}

fn decoded_chunk_text(value: &Value) -> Result<Option<String>, String> {
    let Some(chunk) = value.get("chunk") else {
        return Ok(None);
    };
    let Some(encoded) = chunk.as_str() else {
        return Ok(None);
    };
    let Ok(bytes) = data_encoding::BASE64.decode(encoded.as_bytes()) else {
        return Ok(None);
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Ok(None);
    };
    Ok(Some(text.to_string()))
}

fn set_chunk_text(value: &mut Value, text: &str) {
    if let Some(chunk) = value.get_mut("chunk") {
        *chunk = Value::String(data_encoding::BASE64.encode(text.as_bytes()));
    }
}

fn output_buffer_key(value: &Value) -> String {
    let process = value
        .get("processId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let stream = value
        .get("stream")
        .and_then(Value::as_str)
        .unwrap_or_default();
    format!("{process}\0{stream}")
}

fn should_flush_output(text: &str) -> bool {
    text.contains('\n') || text.len() >= OUTPUT_HOLDBACK_BYTES
}

fn clear_process_pending(pending: &mut BTreeMap<String, String>, value: &Value) {
    let Some(process) = value
        .get("params")
        .and_then(|params| params.get("processId"))
        .and_then(Value::as_str)
    else {
        return;
    };
    let prefix = format!("{process}\0");
    pending.retain(|key, _| !key.starts_with(&prefix));
}

fn mask_json_strings<F>(value: &mut Value, mask: &mut F) -> Result<(), String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    match value {
        Value::String(text) => {
            let masked = mask(text)?;
            if masked != *text {
                *text = masked;
            }
        }
        Value::Array(values) => {
            for value in values {
                mask_json_strings(value, mask)?;
            }
        }
        Value::Object(object) => {
            for value in object.values_mut() {
                mask_json_strings(value, mask)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn mask_exec_output_text(
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    text: &str,
) -> Result<String, String> {
    let masked = masker.mask_tool_output(text)?;
    if exec_proxy_debug() {
        eprintln!(
            "[pentect] exec proxy mask memory={} changed={}",
            masked.is_some(),
            masked.as_ref().is_some_and(|value| value != text)
        );
    }
    Ok(masked.unwrap_or_else(|| text.to_string()))
}

fn exec_proxy_debug() -> bool {
    std::env::var("PENTECT_EXEC_PROXY_DEBUG").is_ok_and(|value| value == "1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_notification_masks_output_chunk() {
        let raw = data_encoding::BASE64.encode(b"OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx\n");
        let line = serde_json::json!({
            "method": PROCESS_OUTPUT_METHOD,
            "params": {"processId": "proc-1", "seq": 1, "stream": "stdout", "chunk": raw}
        })
        .to_string();
        let mut rewriter = BackendRewriter::new(|text: &str| {
            Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        });
        let rewritten = rewriter.rewrite_line(&line).unwrap();
        let value: Value = serde_json::from_str(&rewritten).unwrap();
        let text = decoded_chunk_text(value.get("params").unwrap())
            .unwrap()
            .unwrap();
        assert!(text.contains("<<OPENAI_API_KEY_x>>"), "{text}");
    }

    #[test]
    fn client_process_start_resolves_argv_and_drops_manager_env() {
        let line = serde_json::json!({
            "id": 1,
            "method": PROCESS_START_METHOD,
            "params": {
                "processId": "proc-1",
                "argv": ["powershell", "-Command", "echo <<SECRET_x>>"],
                "cwd": "file:///tmp",
                "env": {
                    "PENTECT_IN_MEMORY_MANAGER_TOKEN": "token",
                    "SAFE": "<<SECRET_x>>"
                },
                "tty": false,
                "pipeStdin": false,
                "arg0": null
            }
        })
        .to_string();
        let rewritten = rewrite_client_json_line_with(
            &line,
            &mut |argv, env| {
                assert_eq!(
                    argv,
                    &[
                        "powershell".to_string(),
                        "-Command".to_string(),
                        "echo <<SECRET_x>>".to_string()
                    ]
                );
                assert!(env.iter().any(|(key, _)| key == "SAFE"));
                Ok(vec![(
                    "RUNPOD_API_KEY".to_string(),
                    "runpod-raw".to_string(),
                )])
            },
            &mut |text| Ok(text.replace("<<SECRET_x>>", "raw")),
        )
        .unwrap();
        assert!(rewritten.contains("echo raw"), "{rewritten}");
        assert!(rewritten.contains("\"SAFE\":\"raw\""), "{rewritten}");
        assert!(rewritten.contains("\"RUNPOD_API_KEY\":\"runpod-raw\""));
        assert!(
            !rewritten.contains("PENTECT_IN_MEMORY_MANAGER_TOKEN"),
            "{rewritten}"
        );
    }

    #[test]
    fn backend_read_response_masks_across_split_chunks() {
        let line = serde_json::json!({
            "id": 7,
            "result": {
                "chunks": [
                    {"processId": "proc-1", "seq": 1, "stream": "stdout", "chunk": data_encoding::BASE64.encode(b"OPENAI_API_KEY=sk-abcdef")},
                    {"processId": "proc-1", "seq": 2, "stream": "stdout", "chunk": data_encoding::BASE64.encode(b"ghijklmnopqrstuvwx\n")}
                ],
                "closed": true,
                "exitCode": 0,
                "exited": true,
                "failure": null,
                "nextSeq": 3,
                "sandboxDenied": false
            }
        })
        .to_string();
        let mut rewriter = BackendRewriter::new(|text: &str| {
            Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        });
        let rewritten = rewriter.rewrite_line(&line).unwrap();
        assert!(!rewritten.contains("sk-abcdef"), "{rewritten}");
        let value: Value = serde_json::from_str(&rewritten).unwrap();
        let chunks = value
            .get("result")
            .and_then(|result| result.get("chunks"))
            .and_then(Value::as_array)
            .unwrap();
        let first = decoded_chunk_text(&chunks[0]).unwrap().unwrap();
        let second = decoded_chunk_text(&chunks[1]).unwrap().unwrap();
        assert!(first.contains("<<OPENAI_API_KEY_x>>"), "{first}");
        assert_eq!(second, "");
    }

    #[test]
    fn backend_output_notification_holds_partial_secret_until_newline() {
        let first = serde_json::json!({
            "method": PROCESS_OUTPUT_METHOD,
            "params": {"processId": "proc-1", "seq": 1, "stream": "stdout", "chunk": data_encoding::BASE64.encode(b"OPENAI_API_KEY=sk-abcdef")}
        })
        .to_string();
        let second = serde_json::json!({
            "method": PROCESS_OUTPUT_METHOD,
            "params": {"processId": "proc-1", "seq": 2, "stream": "stdout", "chunk": data_encoding::BASE64.encode(b"ghijklmnopqrstuvwx\n")}
        })
        .to_string();
        let mut rewriter = BackendRewriter::new(|text: &str| {
            Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        });
        let first = rewriter.rewrite_line(&first).unwrap();
        let first_value: Value = serde_json::from_str(&first).unwrap();
        assert_eq!(
            decoded_chunk_text(first_value.get("params").unwrap())
                .unwrap()
                .unwrap(),
            ""
        );
        let second = rewriter.rewrite_line(&second).unwrap();
        let second_value: Value = serde_json::from_str(&second).unwrap();
        let text = decoded_chunk_text(second_value.get("params").unwrap())
            .unwrap()
            .unwrap();
        assert!(text.contains("<<OPENAI_API_KEY_x>>"), "{text}");
    }

    #[test]
    fn backend_error_strings_are_masked() {
        let line = serde_json::json!({
            "id": 1,
            "error": {"message": "failed with sk-abcdefghijklmnopqrstuvwx"}
        })
        .to_string();
        let mut rewriter = BackendRewriter::new(|text: &str| {
            Ok(text.replace("sk-abcdefghijklmnopqrstuvwx", "<<OPENAI_API_KEY_x>>"))
        });
        let rewritten = rewriter.rewrite_line(&line).unwrap();
        assert!(
            !rewritten.contains("sk-abcdefghijklmnopqrstuvwx"),
            "{rewritten}"
        );
        assert!(rewritten.contains("<<OPENAI_API_KEY_x>>"), "{rewritten}");
    }

    #[test]
    fn proxy_auth_requires_token_query() {
        let request = Request::builder()
            .uri("ws://127.0.0.1:1234/?token=abc")
            .body(())
            .unwrap();
        assert!(request_has_auth(&request, "abc"));
        assert!(!request_has_auth(&request, "def"));
    }
}
