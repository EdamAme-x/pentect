use crate::masking::{decode_env_alias_record, is_env_alias_placeholder};
use crate::session::Session;
use crate::Result;
use anyhow::{anyhow, bail, Context};
use pentect_core::{Config, Recovery};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const ENV_ADDR: &str = "PENTECT_MEMORY_STORE_ADDR";
pub(crate) const ENV_TOKEN: &str = "PENTECT_MEMORY_STORE_TOKEN";

const TOKEN_BYTES: usize = 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CLIENT_CONNECTIONS: usize = 32;
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ACTIVITY_EVENTS: usize = 4_096;
const MAX_ACTIVITY_EVENT_BYTES: usize = 16 * 1024;
const MAX_ACTIVITY_POLL_EVENTS: usize = 256;
const MAX_AGENT_SCRIPTS: usize = 128;
const MAX_AGENT_SCRIPT_BYTES: usize = 4 * 1024 * 1024;
const AGENT_SCRIPT_TTL: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct MemoryStore {
    pub(crate) session: Session,
}

impl MemoryStore {
    pub(crate) fn for_session(session: &Session) -> Self {
        Self {
            session: session.clone(),
        }
    }

    pub(crate) fn resolve_all(&self, text: &str) -> Result<String> {
        let recoveries = self.lock()?;
        let mut out = text.to_string();
        for recovery in recoveries.iter() {
            out = recovery.resolve(&out);
        }
        drop(recoveries);
        if let Some(recovery) = crate::file_pointer_manager::recover_text(&out, &self.session.key) {
            self.add_recovery(recovery.clone())?;
            out = recovery.resolve(&out);
        }
        Ok(out)
    }

    pub(crate) fn remask_all(&self, text: &str) -> Result<String> {
        let recoveries = self.lock()?;
        let mut out = text.to_string();
        for recovery in recoveries.iter() {
            out = recovery.remask(&out);
        }
        Ok(out)
    }

    pub(crate) fn snapshot(&self) -> Result<Vec<Recovery>> {
        Ok(self.lock()?.clone())
    }

    pub(crate) fn auto_env_bindings(&self) -> Result<Vec<(String, String)>> {
        let recoveries = self.snapshot()?;
        let mut bindings: BTreeMap<String, (String, String)> = BTreeMap::new();
        for recovery in &recoveries {
            for placeholder in recovery.placeholders() {
                if !is_env_alias_placeholder(&placeholder) {
                    continue;
                }
                let record = recovery.resolve(&placeholder);
                let Some((name, handle)) = decode_env_alias_record(&record) else {
                    continue;
                };
                if is_reserved_child_env_name(name) {
                    continue;
                }
                let value = resolve_with_recoveries(&recoveries, handle);
                if value == handle {
                    continue;
                }
                bindings.insert(name.to_ascii_lowercase(), (name.to_string(), value));
            }
        }
        Ok(bindings.into_values().collect())
    }

    pub(crate) fn add_recovery(&self, recovery: Recovery) -> Result<()> {
        if recovery.is_empty() {
            return Ok(());
        }
        self.session.sync_recovery(&recovery)?;
        self.lock()?.push(recovery);
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Vec<Recovery>>> {
        self.session
            .recoveries
            .lock()
            .map_err(|_| anyhow!("recovery cache lock poisoned"))
    }
}

fn resolve_with_recoveries(recoveries: &[Recovery], text: &str) -> String {
    let mut out = text.to_string();
    for recovery in recoveries {
        out = recovery.resolve(&out);
    }
    out
}

fn is_reserved_child_env_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_pentect_control_env_name(&lower)
        || matches!(
            lower.as_str(),
            "path"
                | "pathext"
                | "systemroot"
                | "windir"
                | "comspec"
                | "temp"
                | "tmp"
                | "userprofile"
                | "home"
                | "shell"
                | "term"
                | "lang"
                | "lc_all"
                | "tmpdir"
        )
}

/// These names control Pentect itself. Secret aliases may use the `PENTECT_`
/// prefix, so the boundary is an explicit case-insensitive list rather than a
/// blanket prefix ban.
const PENTECT_CONTROL_ENV_NAMES: &[&str] = &[
    "PENTECT_BIN",
    "PENTECT_AGENT_LAUNCHED",
    "PENTECT_MEMORY_STORE_ADDR",
    "PENTECT_MEMORY_STORE_TOKEN",
    "PENTECT_PROCESS_HOST_ROOT",
    "PENTECT_PROCESS_HOST_READ_TOKEN",
    "PENTECT_PROCESS_HOST_WRITE_TOKEN",
    "PENTECT_PLUGIN_CONFIGS",
    "PENTECT_PLUGIN_BINARIES",
    "PENTECT_PLUGIN_NAME",
    "PENTECT_PLUGIN_DATA_DIR",
    "PENTECT_PLUGIN_CACHE_DIR",
    "PENTECT_PLUGIN_CONFIG",
    "PENTECT_AGENT_CONTRACT",
    "PENTECT_STATUS_LINE",
    "PENTECT_HOME",
    "PENTECT_SESSION",
    "PENTECT_FILE_POINTER_MANAGER_DIR",
    "PENTECT_CODEX",
    "PENTECT_CLAUDE",
];

pub fn pentect_control_env_names() -> &'static [&'static str] {
    PENTECT_CONTROL_ENV_NAMES
}

pub fn is_pentect_control_env_name(name: &str) -> bool {
    PENTECT_CONTROL_ENV_NAMES
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

#[derive(Clone, Debug)]
pub(crate) struct MemoryStoreClient {
    addr: String,
    token: String,
    connection: Arc<Mutex<Option<BufReader<TcpStream>>>>,
}

pub(crate) struct MemoryStoreSnapshot {
    pub(crate) key: [u8; 32],
    pub(crate) identity_key: [u8; 32],
    pub(crate) recovery: Recovery,
}

pub struct MemoryStoreLease {
    _stream: TcpStream,
}

pub struct InProcessMemoryStore {
    addr: String,
    token: Zeroizing<String>,
    process_host_read_token: Zeroizing<String>,
    process_host_write_token: Zeroizing<String>,
    shutdown: Option<mpsc::Sender<()>>,
    server_thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for InProcessMemoryStore {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
            let _ = TcpStream::connect(&self.addr);
        }
        if let Some(thread) = self.server_thread.take() {
            let _ = thread.join();
        }
    }
}

impl InProcessMemoryStore {
    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn token(&self) -> &str {
        self.token.as_str()
    }

    pub fn process_host_read_token(&self) -> &str {
        self.process_host_read_token.as_str()
    }

    pub fn process_host_write_token(&self) -> &str {
        self.process_host_write_token.as_str()
    }
}

struct MemoryStoreState {
    key: [u8; 32],
    identity_key: [u8; 32],
    recovery: Recovery,
    masked_count: u64,
    activity: VecDeque<(u64, String)>,
    next_activity_id: u64,
    agent_scripts: HashMap<String, AgentScript>,
}

struct AgentScript {
    shell: String,
    script: Zeroizing<String>,
    expires_at: Instant,
}

struct ConnectionPermit(Arc<AtomicUsize>);

impl ConnectionPermit {
    fn acquire(active: &Arc<AtomicUsize>) -> Option<Self> {
        let previous = active.fetch_add(1, Ordering::AcqRel);
        if previous >= MAX_CLIENT_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            None
        } else {
            Some(Self(Arc::clone(active)))
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for MemoryStoreState {
    fn drop(&mut self) {
        self.key.zeroize();
        self.identity_key.zeroize();
    }
}

impl MemoryStoreClient {
    pub(crate) fn from_env() -> Option<Self> {
        let addr = std::env::var(ENV_ADDR).ok()?;
        let token = std::env::var(ENV_TOKEN).ok()?;
        let launch_proof = std::env::var("PENTECT_AGENT_LAUNCHED").ok()?;
        let root = crate::delegated_process_host::process_host_root().ok()?;
        if !valid_runtime_token(&token)
            || launch_proof != token
            || !addr
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|addr| addr.ip().is_loopback())
            || !crate::delegated_process_host::contains_host(&root, &addr, &token)
        {
            return None;
        }
        Some(Self::new(addr, token))
    }

    pub(crate) fn new(addr: String, token: String) -> Self {
        Self {
            addr,
            token,
            connection: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) fn for_activity(addr: String, token: String) -> Self {
        Self::new(addr, token)
    }

    pub(crate) fn snapshot(&self) -> Result<MemoryStoreSnapshot> {
        let line = self.request("SNAPSHOT", "")?;
        decode_snapshot_response(&line)
    }

    pub(crate) fn snapshot_once(&self, timeout: Duration) -> Result<MemoryStoreSnapshot> {
        let line = self.request_once_with_timeout("SNAPSHOT", "", timeout)?;
        decode_snapshot_response(&line)
    }

    pub(crate) fn masked_count_once(&self, timeout: Duration) -> Result<u64> {
        let line = self.request_once_with_timeout("COUNT", "", timeout)?;
        decode_masked_count_response(&line)
    }

    pub(crate) fn key(&self) -> Result<[u8; 32]> {
        let line = self.request("KEY", "")?;
        let fields = response_fields(&line)?;
        if fields.len() != 2 || fields[0] != "OK" {
            bail!("memory store key response is malformed");
        }
        decode_key_hex(fields[1])
    }

    pub(crate) fn keys(&self) -> Result<([u8; 32], [u8; 32])> {
        let line = self.request("KEYS", "")?;
        let fields = response_fields(&line)?;
        if fields.len() != 3 || fields[0] != "OK" {
            bail!("memory store keys response is malformed");
        }
        Ok((decode_key_hex(fields[1])?, decode_key_hex(fields[2])?))
    }

    pub(crate) fn add_recovery(&self, key: &[u8; 32], recovery: &Recovery) -> Result<()> {
        let payload = data_encoding::BASE64.encode(&recovery.serialize(key));
        let line = self.request("ADD", &payload)?;
        let fields = response_fields(&line)?;
        if fields.as_slice() == ["OK"] {
            Ok(())
        } else {
            bail!("memory store add response is malformed")
        }
    }

    pub(crate) fn put_agent_script(&self, shell: &str, script: &str) -> Result<String> {
        if script.len() > MAX_AGENT_SCRIPT_BYTES {
            bail!("agent script exceeds {MAX_AGENT_SCRIPT_BYTES} bytes");
        }
        let mut bytes = Vec::with_capacity(shell.len() + script.len() + 1);
        bytes.extend_from_slice(shell.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(script.as_bytes());
        let payload = data_encoding::BASE64.encode(&bytes);
        bytes.zeroize();
        // Script IDs are single-use capabilities. Retrying a put after the
        // server committed it can create an unreachable duplicate.
        let line = self.request_once("SCRIPT_PUT", &payload)?;
        let fields = response_fields(&line)?;
        if fields.len() != 2 || fields[0] != "OK" || !valid_runtime_token(fields[1]) {
            bail!("memory store script response is malformed");
        }
        Ok(fields[1].to_string())
    }

    pub(crate) fn take_agent_script(&self, id: &str) -> Result<(String, Zeroizing<String>)> {
        self.take_agent_script_with("SCRIPT_TAKE", id, false)
    }

    #[cfg(test)]
    pub(crate) fn take_rendered_agent_script(
        &self,
        id: &str,
    ) -> Result<(String, Zeroizing<String>)> {
        self.take_agent_script_with("SCRIPT_RENDER", id, true)
    }

    fn take_agent_script_with(
        &self,
        operation: &str,
        id: &str,
        retry: bool,
    ) -> Result<(String, Zeroizing<String>)> {
        // Taking consumes the capability, while test-only rendering is an
        // idempotent read and may safely use the generic reconnect path.
        let line = Zeroizing::new(if retry {
            self.request(operation, id)?
        } else {
            self.request_once(operation, id)?
        });
        let fields = response_fields(&line)?;
        if fields.len() != 2 || fields[0] != "OK" {
            bail!("memory store script response is malformed");
        }
        let bytes = Zeroizing::new(
            data_encoding::BASE64
                .decode(fields[1].as_bytes())
                .context("memory store script response is not valid base64")?,
        );
        let separator = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| anyhow!("memory store script response is malformed"))?;
        let shell = String::from_utf8(bytes[..separator].to_vec())
            .context("memory store script shell is not UTF-8")?;
        let script = String::from_utf8(bytes[separator + 1..].to_vec())
            .context("memory store script is not UTF-8")?;
        Ok((shell, Zeroizing::new(script)))
    }

    pub(crate) fn masked_count(&self) -> Result<u64> {
        let line = self.request("COUNT", "")?;
        decode_masked_count_response(&line)
    }

    pub(crate) fn add_masked_count(&self, count: u64) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let line = self.request("ADD_COUNT", &count.to_string())?;
        let fields = response_fields(&line)?;
        if fields.as_slice() == ["OK"] {
            Ok(())
        } else {
            bail!("memory store add count response is malformed")
        }
    }

    pub(crate) fn add_activity(&self, event_json: &str) -> Result<()> {
        if event_json.len() > MAX_ACTIVITY_EVENT_BYTES {
            bail!("activity event is too large");
        }
        let payload = data_encoding::BASE64.encode(event_json.as_bytes());
        let line = self.request("LOG_ADD", &payload)?;
        let fields = response_fields(&line)?;
        if fields.as_slice() == ["OK"] {
            Ok(())
        } else {
            bail!("memory store activity response is malformed")
        }
    }

    pub(crate) fn poll_activity(&self, after: u64) -> Result<Vec<(u64, String)>> {
        let line = self.request("LOGS", &after.to_string())?;
        let fields = response_fields(&line)?;
        if fields.len() != 2 || fields[0] != "OK" {
            bail!("memory store activity response is malformed");
        }
        let payload = data_encoding::BASE64
            .decode(fields[1].as_bytes())
            .context("memory store activity response is not valid base64")?;
        serde_json::from_slice(&payload).context("memory store activity response is not valid JSON")
    }

    fn request(&self, command: &str, payload: &str) -> Result<String> {
        let mut first_error = None;
        for _ in 0..2 {
            match self.request_once(command, payload) {
                Ok(line) => return Ok(line),
                Err(error) => {
                    if let Ok(mut connection) = self.connection.lock() {
                        *connection = None;
                    }
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        Err(first_error.unwrap_or_else(|| anyhow!("memory store request failed")))
    }

    fn request_once(&self, command: &str, payload: &str) -> Result<String> {
        self.request_once_with_timeout(command, payload, REQUEST_TIMEOUT)
    }

    fn request_once_with_timeout(
        &self,
        command: &str,
        payload: &str,
        timeout: Duration,
    ) -> Result<String> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow!("memory store connection lock poisoned"))?;
        if connection.is_none() {
            let addr = self
                .addr
                .parse::<std::net::SocketAddr>()
                .with_context(|| format!("invalid memory store address: {}", self.addr))?;
            let stream = TcpStream::connect_timeout(&addr, timeout)
                .with_context(|| format!("could not connect to memory store at {}", self.addr))?;
            *connection = Some(BufReader::new(stream));
        }
        let reader = connection
            .as_mut()
            .ok_or_else(|| anyhow!("memory store connection unavailable"))?;
        let _ = reader.get_mut().set_read_timeout(Some(timeout));
        let _ = reader.get_mut().set_write_timeout(Some(timeout));
        writeln!(reader.get_mut(), "{}\t{}\t{}", self.token, command, payload)
            .and_then(|_| reader.get_mut().flush())
            .context("could not send memory store request")?;
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .context("could not read memory store response")?;
        if line.is_empty() {
            bail!("memory store closed the connection");
        }
        if let Some(reason) = line.strip_prefix("ERR\t") {
            bail!("memory store rejected request: {}", reason.trim());
        }
        Ok(line)
    }
}

fn decode_snapshot_response(line: &str) -> Result<MemoryStoreSnapshot> {
    let fields = response_fields(line)?;
    if fields.len() != 4 || fields[0] != "OK" {
        bail!("memory store snapshot response is malformed");
    }
    let key = decode_key_hex(fields[1])?;
    let identity_key = decode_key_hex(fields[2])?;
    let recovery_blob = data_encoding::BASE64
        .decode(fields[3].as_bytes())
        .context("memory store snapshot is not valid base64")?;
    let recovery = Recovery::load(&recovery_blob, &key)
        .map_err(|e| anyhow!("memory store snapshot is invalid: {e}"))?;
    Ok(MemoryStoreSnapshot {
        key,
        identity_key,
        recovery,
    })
}

fn decode_masked_count_response(line: &str) -> Result<u64> {
    let fields = response_fields(line)?;
    if fields.len() != 2 || fields[0] != "OK" {
        bail!("memory store count response is malformed");
    }
    fields[1]
        .parse::<u64>()
        .context("memory store masked count is not a number")
}

fn valid_runtime_token(token: &str) -> bool {
    token.len() == TOKEN_BYTES * 2 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl Drop for MemoryStoreClient {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

pub fn open_memory_store_lease(addr: &str, token: &str) -> Result<MemoryStoreLease> {
    let mut stream = TcpStream::connect(addr)
        .with_context(|| format!("could not connect to memory store at {addr}"))?;
    let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
    writeln!(stream, "{token}\tLEASE\t")
        .and_then(|_| stream.flush())
        .context("could not open memory store lease")?;
    let reader_stream = stream
        .try_clone()
        .context("could not clone memory store lease")?;
    let mut reader = BufReader::new(reader_stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("could not read memory store lease response")?;
    if response_fields(&line)?.as_slice() != ["OK"] {
        bail!("memory store lease response is malformed");
    }
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
    Ok(MemoryStoreLease { _stream: stream })
}

pub fn memory_store_ready(addr: &str, token: &str) -> bool {
    let client = MemoryStoreClient::new(addr.to_string(), token.to_string());
    client.masked_count().is_ok()
}

pub fn active_memory_store_ready() -> bool {
    MemoryStoreClient::from_env().is_some_and(|client| client.masked_count().is_ok())
}

pub(crate) fn serve_memory_store() -> i32 {
    match serve_memory_store_inner() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("[pentect] {e}");
            2
        }
    }
}

fn serve_memory_store_inner() -> Result<()> {
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).context("could not bind memory store listener")?;
    let addr = listener
        .local_addr()
        .context("could not read memory store address")?;
    let token = Arc::new(Zeroizing::new(random_token_hex()?));
    let process_host_read_token = Arc::new(Zeroizing::new(random_token_hex()?));
    let process_host_write_token = Arc::new(Zeroizing::new(random_token_hex()?));
    let key = Config::generate().key;
    let identity_key = runtime_identity_key()?;
    let state = Arc::new(Mutex::new(MemoryStoreState {
        key,
        identity_key,
        recovery: Recovery::empty_for_key(&key),
        masked_count: 0,
        activity: VecDeque::with_capacity(MAX_ACTIVITY_EVENTS),
        next_activity_id: 1,
        agent_scripts: HashMap::new(),
    }));
    println!(
        "{}",
        serde_json::json!({
            "addr": addr.to_string(),
            "token": token.as_str(),
            "process_host_read_token": process_host_read_token.as_str(),
            "process_host_write_token": process_host_write_token.as_str(),
        })
    );
    let _ = std::io::stdout().flush();
    let active_connections = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let Some(permit) = ConnectionPermit::acquire(&active_connections) else {
            continue;
        };
        let state = state.clone();
        let token = Arc::clone(&token);
        let process_host_read_token = Arc::clone(&process_host_read_token);
        let process_host_write_token = Arc::clone(&process_host_write_token);
        std::thread::spawn(move || {
            let _permit = permit;
            let _ = handle_client(
                stream,
                token.as_str(),
                process_host_read_token.as_str(),
                process_host_write_token.as_str(),
                &state,
            );
        });
    }
    Ok(())
}

pub fn start_in_process_memory_store() -> Result<InProcessMemoryStore> {
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).context("could not bind memory store listener")?;
    let addr = listener
        .local_addr()
        .context("could not read memory store address")?
        .to_string();
    let token = Zeroizing::new(random_token_hex()?);
    let process_host_read_token = Zeroizing::new(random_token_hex()?);
    let process_host_write_token = Zeroizing::new(random_token_hex()?);
    let key = Config::generate().key;
    let identity_key = runtime_identity_key()?;
    let state = Arc::new(Mutex::new(MemoryStoreState {
        key,
        identity_key,
        recovery: Recovery::empty_for_key(&key),
        masked_count: 0,
        activity: VecDeque::with_capacity(MAX_ACTIVITY_EVENTS),
        next_activity_id: 1,
        agent_scripts: HashMap::new(),
    }));
    let server_token = Arc::new(Zeroizing::new(token.to_string()));
    let server_read_token = Arc::new(Zeroizing::new(process_host_read_token.to_string()));
    let server_write_token = Arc::new(Zeroizing::new(process_host_write_token.to_string()));
    let active_connections = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let server_thread = std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            if shutdown_rx.try_recv().is_ok() {
                break;
            }
            let Some(permit) = ConnectionPermit::acquire(&active_connections) else {
                continue;
            };
            let state = Arc::clone(&state);
            let token = Arc::clone(&server_token);
            let read_token = Arc::clone(&server_read_token);
            let write_token = Arc::clone(&server_write_token);
            std::thread::spawn(move || {
                let _permit = permit;
                let _ = handle_client(
                    stream,
                    token.as_str(),
                    read_token.as_str(),
                    write_token.as_str(),
                    &state,
                );
            });
        }
    });
    Ok(InProcessMemoryStore {
        addr,
        token,
        process_host_read_token,
        process_host_write_token,
        shutdown: Some(shutdown_tx),
        server_thread: Some(server_thread),
    })
}

#[cfg(not(test))]
fn runtime_identity_key() -> Result<[u8; 32]> {
    crate::config::handle_identity_key().map_err(anyhow::Error::msg)
}

#[cfg(test)]
fn runtime_identity_key() -> Result<[u8; 32]> {
    Ok(Config::generate().identity_key)
}

#[cfg(test)]
pub(crate) fn spawn_test_memory_store(token: String) -> String {
    let read_token = format!("{token}-activity-read");
    let write_token = format!("{token}-activity-write");
    spawn_test_memory_store_with_activity(token, read_token, write_token)
}

#[cfg(test)]
pub(crate) fn spawn_test_memory_store_with_activity(
    token: String,
    read_token: String,
    write_token: String,
) -> String {
    let token = Arc::new(Zeroizing::new(token));
    let read_token = Arc::new(Zeroizing::new(read_token));
    let write_token = Arc::new(Zeroizing::new(write_token));
    let key = Config::generate().key;
    let identity_key = Config::generate().identity_key;
    let state = Arc::new(Mutex::new(MemoryStoreState {
        key,
        identity_key,
        recovery: Recovery::empty_for_key(&key),
        masked_count: 0,
        activity: VecDeque::with_capacity(MAX_ACTIVITY_EVENTS),
        next_activity_id: 1,
        agent_scripts: HashMap::new(),
    }));
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let active_connections = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let Some(permit) = ConnectionPermit::acquire(&active_connections) else {
                continue;
            };
            let token = Arc::clone(&token);
            let read_token = Arc::clone(&read_token);
            let write_token = Arc::clone(&write_token);
            let state = state.clone();
            std::thread::spawn(move || {
                let _permit = permit;
                handle_client(
                    stream,
                    token.as_str(),
                    read_token.as_str(),
                    write_token.as_str(),
                    &state,
                )
                .unwrap();
            });
        }
    });
    addr
}

fn handle_client(
    stream: TcpStream,
    token: &str,
    process_host_read_token: &str,
    process_host_write_token: &str,
    state: &Arc<Mutex<MemoryStoreState>>,
) -> Result<()> {
    let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let mut exit_on_disconnect = false;
    let mut authenticated = false;
    loop {
        line.clear();
        let read = match Read::take(reader.by_ref(), MAX_REQUEST_LINE_BYTES as u64 + 1)
            .read_line(&mut line)
        {
            Ok(read) => read,
            Err(_) if exit_on_disconnect => std::process::exit(0),
            Err(error) => return Err(error).context("could not read memory store request"),
        };
        if read == 0 {
            if exit_on_disconnect {
                std::process::exit(0);
            }
            return Ok(());
        }
        if read > MAX_REQUEST_LINE_BYTES {
            bail!("memory store request is too large");
        }
        let fields = request_fields(&line);
        let provided_token = fields.first().copied().unwrap_or_default();
        let access = if constant_time_token_eq(provided_token, token) {
            Some(RequestAccess::Primary)
        } else if constant_time_token_eq(provided_token, process_host_read_token) {
            Some(RequestAccess::ProcessRead)
        } else if constant_time_token_eq(provided_token, process_host_write_token) {
            Some(RequestAccess::ProcessWrite)
        } else {
            None
        };
        let Some(access) = access else {
            let stream = reader.get_mut();
            writeln!(stream, "ERR\tbad token")
                .and_then(|_| stream.flush())
                .context("could not write memory store error")?;
            return Ok(());
        };
        if !authenticated {
            authenticated = true;
            let _ = reader.get_mut().set_read_timeout(None);
        }
        let response = match fields.as_slice() {
            [_, "KEY", ""] if access == RequestAccess::Primary => key_response(state),
            [_, "KEYS", ""] if access == RequestAccess::Primary => keys_response(state),
            [_, "COUNT", ""] if access == RequestAccess::Primary => count_response(state),
            [_, "SNAPSHOT", ""] if access == RequestAccess::Primary => snapshot_response(state),
            [_, "ADD", payload] if access == RequestAccess::Primary => {
                add_recovery_request(state, payload)
            }
            [_, "ADD_COUNT", payload] if access == RequestAccess::Primary => {
                add_masked_count_request(state, payload)
            }
            [_, "SCRIPT_PUT", payload] if access == RequestAccess::Primary => {
                put_agent_script_request(state, payload)
            }
            [_, "SCRIPT_TAKE", id] if access == RequestAccess::Primary => {
                take_agent_script_request(state, id)
            }
            [_, "SCRIPT_RENDER", id] if access == RequestAccess::Primary => {
                render_agent_script_request(state, id)
            }
            [_, "LEASE", ""] if access == RequestAccess::Primary => {
                exit_on_disconnect = true;
                Ok("OK".to_string())
            }
            [_, "LOG_ADD", payload] if access == RequestAccess::ProcessWrite => {
                add_activity_request(state, payload)
            }
            [_, "LOGS", payload] if access == RequestAccess::ProcessRead => {
                activity_response(state, payload)
            }
            _ => Err(anyhow!("malformed request")),
        };
        let stream = reader.get_mut();
        match response {
            Ok(mut line) => {
                let result = writeln!(stream, "{line}").and_then(|_| stream.flush());
                line.zeroize();
                result.context("could not write memory store response")?;
            }
            Err(error) => writeln!(stream, "ERR\t{}", sanitize_field(&error.to_string()))
                .and_then(|_| stream.flush())
                .context("could not write memory store error")?,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RequestAccess {
    Primary,
    ProcessRead,
    ProcessWrite,
}

fn constant_time_token_eq(provided: &str, expected: &str) -> bool {
    if provided.len() != expected.len() {
        return false;
    }
    provided
        .as_bytes()
        .iter()
        .zip(expected.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn key_response(state: &Arc<Mutex<MemoryStoreState>>) -> Result<String> {
    let guard = state
        .lock()
        .map_err(|_| anyhow!("memory store lock poisoned"))?;
    Ok(format!(
        "OK\t{}",
        data_encoding::HEXLOWER.encode(&guard.key)
    ))
}

fn keys_response(state: &Arc<Mutex<MemoryStoreState>>) -> Result<String> {
    let guard = state
        .lock()
        .map_err(|_| anyhow!("memory store lock poisoned"))?;
    Ok(format!(
        "OK\t{}\t{}",
        data_encoding::HEXLOWER.encode(&guard.key),
        data_encoding::HEXLOWER.encode(&guard.identity_key)
    ))
}

fn snapshot_response(state: &Arc<Mutex<MemoryStoreState>>) -> Result<String> {
    let guard = state
        .lock()
        .map_err(|_| anyhow!("memory store lock poisoned"))?;
    Ok(format!(
        "OK\t{}\t{}\t{}",
        data_encoding::HEXLOWER.encode(&guard.key),
        data_encoding::HEXLOWER.encode(&guard.identity_key),
        data_encoding::BASE64.encode(&guard.recovery.serialize(&guard.key))
    ))
}

fn count_response(state: &Arc<Mutex<MemoryStoreState>>) -> Result<String> {
    let guard = state
        .lock()
        .map_err(|_| anyhow!("memory store lock poisoned"))?;
    Ok(format!("OK\t{}", guard.masked_count))
}

fn add_recovery_request(state: &Arc<Mutex<MemoryStoreState>>, payload: &str) -> Result<String> {
    let bytes = data_encoding::BASE64
        .decode(payload.as_bytes())
        .context("recovery payload is not valid base64")?;
    let mut guard = state
        .lock()
        .map_err(|_| anyhow!("memory store lock poisoned"))?;
    let recovery = Recovery::load(&bytes, &guard.key)
        .map_err(|e| anyhow!("recovery payload is invalid: {e}"))?;
    if !recovery.is_empty() {
        guard.recovery.extend_same_key(recovery);
    }
    Ok("OK".to_string())
}

fn add_masked_count_request(state: &Arc<Mutex<MemoryStoreState>>, payload: &str) -> Result<String> {
    let count = payload
        .parse::<u64>()
        .context("masked count payload is not a number")?;
    let mut guard = state
        .lock()
        .map_err(|_| anyhow!("memory store lock poisoned"))?;
    guard.masked_count = guard.masked_count.saturating_add(count);
    Ok("OK".to_string())
}

fn put_agent_script_request(state: &Arc<Mutex<MemoryStoreState>>, payload: &str) -> Result<String> {
    let mut bytes = data_encoding::BASE64
        .decode(payload.as_bytes())
        .context("agent script payload is not valid base64")?;
    let separator = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| anyhow!("agent script payload is malformed"))?;
    if bytes.len().saturating_sub(separator + 1) > MAX_AGENT_SCRIPT_BYTES {
        bytes.zeroize();
        bail!("agent script exceeds {MAX_AGENT_SCRIPT_BYTES} bytes");
    }
    let shell = String::from_utf8(bytes[..separator].to_vec())
        .context("agent script shell is not UTF-8")?;
    if !matches!(shell.as_str(), "bash" | "powershell" | "native") {
        bytes.zeroize();
        bail!("agent script shell is invalid");
    }
    let script =
        String::from_utf8(bytes[separator + 1..].to_vec()).context("agent script is not UTF-8")?;
    bytes.zeroize();

    let mut guard = state
        .lock()
        .map_err(|_| anyhow!("memory store lock poisoned"))?;
    let now = Instant::now();
    guard
        .agent_scripts
        .retain(|_, pending| pending.expires_at > now);
    if guard.agent_scripts.len() >= MAX_AGENT_SCRIPTS {
        bail!("too many pending agent scripts");
    }
    let id = random_token_hex()?;
    guard.agent_scripts.insert(
        id.clone(),
        AgentScript {
            shell,
            script: Zeroizing::new(script),
            expires_at: now + AGENT_SCRIPT_TTL,
        },
    );
    Ok(format!("OK\t{id}"))
}

fn take_agent_script_request(state: &Arc<Mutex<MemoryStoreState>>, id: &str) -> Result<String> {
    let pending = take_pending_agent_script(state, id)?;
    encode_agent_script_response(&pending.shell, pending.script.as_str())
}

fn render_agent_script_request(state: &Arc<Mutex<MemoryStoreState>>, id: &str) -> Result<String> {
    let pending = take_pending_agent_script(state, id)?;
    let guard = state
        .lock()
        .map_err(|_| anyhow!("memory store lock poisoned"))?;
    let recovery = &guard.recovery;
    let mode = crate::ExecMode::Shell(pending.script.to_string());
    let resolved = Zeroizing::new(recovery.resolve(pending.script.as_str()));
    if crate::contains_unresolved_masked_handle(resolved.as_str()) {
        bail!("unknown masked handle");
    }
    let names = crate::referenced_env_names(&mode);
    let mut bindings = BTreeMap::new();
    for placeholder in recovery.placeholders() {
        if !is_env_alias_placeholder(&placeholder) {
            continue;
        }
        let record = recovery.resolve(&placeholder);
        let Some((name, handle)) = decode_env_alias_record(&record) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if !names.contains(&lower) || is_reserved_child_env_name(name) {
            continue;
        }
        let value = recovery.resolve(handle);
        if value != handle {
            bindings.insert(lower, (name.to_string(), value));
        }
    }
    let rendered = Zeroizing::new(
        crate::render_agent_script(
            &pending.shell,
            &bindings.into_values().collect::<Vec<_>>(),
            resolved.as_str(),
        )
        .map_err(anyhow::Error::msg)?,
    );
    encode_agent_script_response(&pending.shell, rendered.as_str())
}

fn take_pending_agent_script(
    state: &Arc<Mutex<MemoryStoreState>>,
    id: &str,
) -> Result<AgentScript> {
    if !valid_runtime_token(id) {
        bail!("agent script id is invalid");
    }
    let mut guard = state
        .lock()
        .map_err(|_| anyhow!("memory store lock poisoned"))?;
    let pending = guard
        .agent_scripts
        .remove(id)
        .ok_or_else(|| anyhow!("agent script is unavailable"))?;
    if pending.expires_at <= Instant::now() {
        bail!("agent script expired");
    }
    Ok(pending)
}

fn encode_agent_script_response(shell: &str, script: &str) -> Result<String> {
    let mut bytes = Vec::with_capacity(shell.len() + script.len() + 1);
    bytes.extend_from_slice(shell.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(script.as_bytes());
    let payload = data_encoding::BASE64.encode(&bytes);
    bytes.zeroize();
    Ok(format!("OK\t{payload}"))
}

fn add_activity_request(state: &Arc<Mutex<MemoryStoreState>>, payload: &str) -> Result<String> {
    let bytes = data_encoding::BASE64
        .decode(payload.as_bytes())
        .context("activity payload is not valid base64")?;
    if bytes.len() > MAX_ACTIVITY_EVENT_BYTES {
        bail!("activity payload is too large");
    }
    let event = String::from_utf8(bytes).context("activity payload is not UTF-8")?;
    serde_json::from_str::<serde_json::Value>(&event)
        .context("activity payload is not valid JSON")?;
    let mut guard = state
        .lock()
        .map_err(|_| anyhow!("memory store lock poisoned"))?;
    let id = guard.next_activity_id;
    guard.next_activity_id = guard.next_activity_id.saturating_add(1);
    guard.activity.push_back((id, event));
    while guard.activity.len() > MAX_ACTIVITY_EVENTS {
        guard.activity.pop_front();
    }
    Ok("OK".to_string())
}

fn activity_response(state: &Arc<Mutex<MemoryStoreState>>, payload: &str) -> Result<String> {
    let after = payload
        .parse::<u64>()
        .context("activity cursor is not a number")?;
    let guard = state
        .lock()
        .map_err(|_| anyhow!("memory store lock poisoned"))?;
    let events = guard
        .activity
        .iter()
        .filter(|(id, _)| *id > after)
        .take(MAX_ACTIVITY_POLL_EVENTS)
        .cloned()
        .collect::<Vec<_>>();
    let json = serde_json::to_vec(&events).context("could not serialize activity events")?;
    Ok(format!("OK\t{}", data_encoding::BASE64.encode(&json)))
}

fn request_fields(line: &str) -> Vec<&str> {
    line.trim_end_matches(['\r', '\n']).split('\t').collect()
}

fn response_fields(line: &str) -> Result<Vec<&str>> {
    let fields = request_fields(line);
    if fields.first() == Some(&"ERR") {
        let reason = fields.get(1).copied().unwrap_or("unknown error");
        bail!("{reason}");
    }
    Ok(fields)
}

fn random_token_hex() -> Result<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| anyhow!("could not generate memory store token: {e}"))?;
    Ok(data_encoding::HEXLOWER.encode(&bytes))
}

fn decode_key_hex(value: &str) -> Result<[u8; 32]> {
    let bytes = data_encoding::HEXLOWER
        .decode(value.as_bytes())
        .context("memory store key is not valid hex")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("memory store key has wrong length"))?;
    Ok(key)
}

fn sanitize_field(value: &str) -> String {
    value.replace(['\r', '\n', '\t'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentect_core::{Engine, Input, Kind, Profile};

    #[test]
    fn connection_limit_is_enforced_and_released() {
        let active = Arc::new(AtomicUsize::new(0));
        let permits = (0..MAX_CLIENT_CONNECTIONS)
            .map(|_| ConnectionPermit::acquire(&active).expect("within connection limit"))
            .collect::<Vec<_>>();
        assert!(ConnectionPermit::acquire(&active).is_none());
        drop(permits);
        assert!(ConnectionPermit::acquire(&active).is_some());
    }

    #[test]
    fn bad_token_connection_is_closed_after_one_error() {
        let token = "good-token-close".to_string();
        let addr = spawn_test_memory_store(token);
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        writeln!(stream, "bad-token\tCOUNT\t").unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        assert_eq!(line.trim(), "ERR\tbad token");
        line.clear();
        assert_eq!(reader.read_line(&mut line).unwrap(), 0);
    }

    #[test]
    fn client_round_trips_recovery_through_memory_store_state() {
        let token = "test-token".to_string();
        let client = MemoryStoreClient::new(spawn_test_memory_store(token.clone()), token);
        let snapshot = client.snapshot().unwrap();
        assert_eq!(client.key().unwrap(), snapshot.key);
        assert_eq!(
            client.keys().unwrap(),
            (snapshot.key, snapshot.identity_key)
        );
        let result = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Env,
                data: "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n".to_string(),
            },
            &Config::new(snapshot.key).with_identity_key(snapshot.identity_key),
        );
        let masked = result.masked.clone();
        client
            .add_recovery(&snapshot.key, &result.recovery)
            .unwrap();

        let snapshot = client.snapshot().unwrap();
        assert_eq!(
            snapshot.recovery.resolve(&masked),
            "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n"
        );
    }

    #[test]
    fn in_process_memory_store_starts_without_a_child_process() {
        let server = start_in_process_memory_store().unwrap();
        assert!(memory_store_ready(server.addr(), server.token()));
        assert_eq!(server.token().len(), 64);
        drop(server);
    }

    #[test]
    fn read_style_masking_registers_recovery_and_env_aliases_in_memory_store() {
        let token = "test-token-read".to_string();
        let client = MemoryStoreClient::new(spawn_test_memory_store(token.clone()), token);
        let raw = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n";
        let result = crate::mask_input_into_memory_store_client(
            &client,
            Input {
                kind: Kind::Env,
                data: raw.to_string(),
            },
            Profile::Strict,
            Vec::new(),
        )
        .unwrap();
        assert!(result.masked.contains("OPENAI_API_KEY=<<OPENAI_API_KEY_"));
        assert!(!result.masked.contains("_length_"), "{}", result.masked);
        assert_eq!(client.masked_count().unwrap(), 1);

        let snapshot = client.snapshot().unwrap();
        assert_eq!(snapshot.recovery.resolve(&result.masked), raw);
        let alias_records: Vec<_> = snapshot
            .recovery
            .placeholders()
            .into_iter()
            .filter(|placeholder| crate::masking::is_env_alias_placeholder(placeholder))
            .filter_map(|placeholder| {
                let record = snapshot.recovery.resolve(&placeholder);
                crate::masking::decode_env_alias_record(&record)
                    .map(|(name, handle)| (name.to_string(), handle.to_string()))
            })
            .collect();
        assert!(alias_records.iter().any(|(name, handle)| {
            name.starts_with("PENTECT_OPENAI_API_KEY_")
                && snapshot.recovery.resolve(handle) == "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
        }));
        assert!(!alias_records
            .iter()
            .any(|(name, _)| name == "OPENAI_API_KEY"));
    }

    #[test]
    fn client_tracks_masked_count_in_memory() {
        let token = "test-token-count".to_string();
        let client = MemoryStoreClient::new(spawn_test_memory_store(token.clone()), token);
        assert_eq!(client.masked_count().unwrap(), 0);
        client.add_masked_count(2).unwrap();
        client.add_masked_count(3).unwrap();
        assert_eq!(client.masked_count().unwrap(), 5);
    }

    #[test]
    fn agent_scripts_are_memory_only_and_single_use() {
        let token = "test-token-script".to_string();
        let client = MemoryStoreClient::new(spawn_test_memory_store(token.clone()), token);
        let id = client
            .put_agent_script("bash", "printf '%s' \"$PENTECT_SECRET_deadbeef\"")
            .unwrap();
        let (shell, script) = client.take_agent_script(&id).unwrap();
        assert_eq!(shell, "bash");
        assert_eq!(script.as_str(), "printf '%s' \"$PENTECT_SECRET_deadbeef\"");
        assert!(client.take_agent_script(&id).is_err());
    }

    #[test]
    fn client_reuses_one_connection_for_repeated_output_checks() {
        let token = "test-token-persistent".to_string();
        let client = MemoryStoreClient::new(spawn_test_memory_store(token.clone()), token);
        for _ in 0..1_000 {
            assert_eq!(client.masked_count().unwrap(), 0);
        }
    }

    #[test]
    fn readiness_rejects_stale_or_incorrect_store_details() {
        let token = "test-token-ready".to_string();
        let addr = spawn_test_memory_store(token.clone());
        assert!(memory_store_ready(&addr, &token));
        assert!(!memory_store_ready(&addr, "wrong-token"));
        assert!(!memory_store_ready("127.0.0.1:9", &token));
    }

    #[test]
    fn activity_stream_uses_read_only_token_and_cursor() {
        let token = "test-token-activity".to_string();
        let read_token = "test-token-activity-read".to_string();
        let write_token = "test-token-activity-write".to_string();
        let addr =
            spawn_test_memory_store_with_activity(token, read_token.clone(), write_token.clone());
        let writer = MemoryStoreClient::for_activity(addr.clone(), write_token);
        let reader = MemoryStoreClient::for_activity(addr, read_token);

        writer
            .add_activity(r#"{"action":"mask","count":1}"#)
            .unwrap();
        let first = reader.poll_activity(0).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, 1);
        assert!(first[0].1.contains("\"action\":\"mask\""));
        assert!(
            reader.key().is_err(),
            "activity token exposed the store key"
        );
        assert!(
            reader.keys().is_err(),
            "activity token exposed the store keys"
        );

        writer
            .add_activity(r#"{"action":"resolve","count":1}"#)
            .unwrap();
        let second = reader.poll_activity(first[0].0).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].0, 2);
        assert!(second[0].1.contains("\"action\":\"resolve\""));
    }

    #[test]
    fn activity_ring_discards_oldest_events() {
        let key = Config::generate().key;
        let state = Arc::new(Mutex::new(MemoryStoreState {
            key,
            identity_key: key,
            recovery: Recovery::empty_for_key(&key),
            masked_count: 0,
            activity: VecDeque::with_capacity(MAX_ACTIVITY_EVENTS),
            next_activity_id: 1,
            agent_scripts: HashMap::new(),
        }));
        let payload = data_encoding::BASE64.encode(br#"{"action":"mask"}"#);
        for _ in 0..=MAX_ACTIVITY_EVENTS {
            add_activity_request(&state, &payload).unwrap();
        }
        let guard = state.lock().unwrap();
        assert_eq!(guard.activity.len(), MAX_ACTIVITY_EVENTS);
        assert_eq!(guard.activity.front().map(|(id, _)| *id), Some(2));
    }
}
