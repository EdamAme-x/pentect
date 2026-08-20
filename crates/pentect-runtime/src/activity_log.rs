use crate::delegated_process_host::{self, ProcessHostEndpoint};
use crate::memory_store::MemoryStoreClient;
use pentect_core::MaskResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

const MAX_LABELS_PER_EVENT: usize = 64;
const MAX_SEEN_EVENTS: usize = 4_096;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const LOG_BATCH_EVENTS: usize = 64;
const LOG_BATCH_BYTES: usize = 64 * 1024;
const LOG_FLUSH_INTERVAL: Duration = Duration::from_millis(250);
const LOG_CHANNEL_CAPACITY: usize = 1_024;
const LOG_MAX_BYTES: u64 = 32 * 1024 * 1024;
const LOG_ROTATIONS: usize = 8;
static LOG_SHARE: OnceLock<bool> = OnceLock::new();
static PERSISTENT_LOG: OnceLock<Option<PersistentLogWriter>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ActivityEvent {
    time: String,
    action: String,
    surface: String,
    count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    labels: Vec<LabelCount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    panic_location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backtrace: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LabelCount {
    name: String,
    count: u64,
}

struct ActivitySource {
    client: MemoryStoreClient,
    cursor: u64,
    endpoint: ProcessHostEndpoint,
}

struct LifecycleSource {
    path: PathBuf,
    file: Option<std::fs::File>,
    offset: u64,
    pending: Vec<u8>,
}

struct PersistentLogWriter {
    sender: SyncSender<LogMessage>,
    dropped: Arc<AtomicU64>,
}

enum LogMessage {
    Entry(String),
    Flush(mpsc::Sender<()>),
}

#[derive(Default)]
struct SeenActivity {
    order: VecDeque<[u8; 32]>,
    values: HashSet<[u8; 32]>,
}

impl SeenActivity {
    fn insert(&mut self, payload: &str) -> bool {
        let digest: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
        if !self.values.insert(digest) {
            return false;
        }
        self.order.push_back(digest);
        if self.order.len() > MAX_SEEN_EVENTS {
            if let Some(oldest) = self.order.pop_front() {
                self.values.remove(&oldest);
            }
        }
        true
    }
}

impl ActivityEvent {
    fn new(
        action: &str,
        surface: &str,
        count: u64,
        labels: BTreeMap<String, u64>,
        target: Option<String>,
    ) -> Self {
        Self {
            time: jiff::Timestamp::now().to_string(),
            action: action.to_string(),
            surface: surface.to_string(),
            count,
            labels: labels
                .into_iter()
                .take(MAX_LABELS_PER_EVENT)
                .map(|(name, count)| LabelCount { name, count })
                .collect(),
            target,
            event: None,
            pid: None,
            version: None,
            os: None,
            arch: None,
            exit_code: None,
            panic_location: None,
            backtrace: None,
        }
    }

    fn process(
        event: &str,
        surface: &str,
        version: &str,
        exit_code: Option<i32>,
        panic_location: Option<&str>,
        backtrace: Option<&str>,
    ) -> Self {
        Self {
            time: jiff::Timestamp::now().to_string(),
            action: "process".to_string(),
            surface: safe_identifier(surface),
            count: 1,
            labels: Vec::new(),
            target: None,
            event: Some(safe_identifier(event)),
            pid: Some(std::process::id()),
            version: Some(version.chars().take(64).collect()),
            os: Some(std::env::consts::OS.to_string()),
            arch: Some(std::env::consts::ARCH.to_string()),
            exit_code,
            panic_location: panic_location.map(safe_panic_location),
            backtrace: backtrace.map(safe_backtrace),
        }
    }
}

pub(crate) fn record_process(
    event: &str,
    surface: &str,
    version: &str,
    exit_code: Option<i32>,
    panic_location: Option<&str>,
    backtrace: Option<&str>,
) {
    record(ActivityEvent::process(
        event,
        surface,
        version,
        exit_code,
        panic_location,
        backtrace,
    ));
}

pub(crate) fn flush_persistent() {
    if let Some(writer) = persistent_log() {
        writer.flush();
    }
}

pub(crate) fn persistent_log_path() -> PathBuf {
    if let Some(directory) = std::env::var_os("PENTECT_LOG_DIR") {
        return PathBuf::from(directory).join("pentect.log");
    }
    user_home()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".pentect")
        .join("logs")
        .join("pentect.log")
}

pub(crate) fn record_mask_result(surface: &str, result: &MaskResult, target: Option<&Path>) {
    if result.summary.masked_count == 0 {
        return;
    }
    let mut labels = BTreeMap::new();
    for item in &result.items {
        *labels.entry(item.label.clone()).or_insert(0) += 1;
    }
    record(ActivityEvent::new(
        "mask",
        surface,
        result.summary.masked_count as u64,
        labels,
        target.map(safe_target),
    ));
}

pub(crate) fn record_resolve(surface: &str, target: Option<&Path>) {
    record(ActivityEvent::new(
        "resolve",
        surface,
        1,
        BTreeMap::new(),
        target.map(safe_target),
    ));
}

pub(crate) fn record_summary(
    action: &str,
    surface: &str,
    count: u64,
    labels: BTreeMap<String, u64>,
    target: Option<&Path>,
) {
    if count == 0 {
        return;
    }
    record(ActivityEvent::new(
        action,
        surface,
        count,
        labels,
        target.map(safe_target),
    ));
}

pub(crate) fn record_image(secret_images: usize, notes: &[String]) {
    if secret_images == 0 {
        return;
    }
    let mut labels = BTreeMap::new();
    for note in notes {
        let Some((_, list)) = note.split_once(']') else {
            continue;
        };
        for label in list
            .split(',')
            .map(str::trim)
            .filter(|label| !label.is_empty())
        {
            *labels.entry(label.to_string()).or_insert(0) += 1;
        }
    }
    record(ActivityEvent::new(
        "redact",
        "image",
        secret_images as u64,
        labels,
        None,
    ));
}

pub(crate) fn follow(json: bool) -> Result<(), String> {
    let mut source = activity_source()?;
    let mut lifecycle = LifecycleSource::open();
    let mut persistent = LifecycleSource::open_at(persistent_log_path());
    let mut seen = SeenActivity::default();

    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    loop {
        let mut wrote = false;
        for payload in persistent.read_new()? {
            if !seen.insert(&payload) {
                continue;
            }
            let event: ActivityEvent = serde_json::from_str(&payload)
                .map_err(|error| format!("invalid persistent log event: {error}"))?;
            if json {
                writeln!(output, "{payload}")
                    .map_err(|error| format!("could not write persistent log: {error}"))?;
            } else {
                writeln!(output, "{}", format_event(&event))
                    .map_err(|error| format!("could not write persistent log: {error}"))?;
            }
            wrote = true;
        }
        for payload in lifecycle.read_new()? {
            if json {
                writeln!(output, "{payload}")
                    .map_err(|error| format!("could not write lifecycle log: {error}"))?;
            } else if let Ok(entry) = serde_json::from_str::<serde_json::Value>(&payload) {
                writeln!(
                    output,
                    "{}  lifecycle/codex-app  {}  {}",
                    entry["time"].as_str().unwrap_or("unknown"),
                    entry["event"].as_str().unwrap_or("event"),
                    entry["detail"].as_str().unwrap_or_default(),
                )
                .map_err(|error| format!("could not write lifecycle log: {error}"))?;
            }
            wrote = true;
        }
        match source.client.poll_activity(source.cursor) {
            Ok(records) => {
                for (id, payload) in records {
                    source.cursor = source.cursor.max(id);
                    if !seen.insert(&payload) {
                        continue;
                    }
                    let event: ActivityEvent = serde_json::from_str(&payload)
                        .map_err(|error| format!("invalid activity event: {error}"))?;
                    if json {
                        writeln!(output, "{payload}")
                            .map_err(|error| format!("could not write activity log: {error}"))?;
                    } else {
                        writeln!(output, "{}", format_event(&event))
                            .map_err(|error| format!("could not write activity log: {error}"))?;
                    }
                    wrote = true;
                }
            }
            Err(_) => {
                delegated_process_host::invalidate_host(&source.endpoint);
                source = activity_source()?;
                continue;
            }
        }
        if wrote {
            output
                .flush()
                .map_err(|error| format!("could not flush activity log: {error}"))?;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

impl LifecycleSource {
    fn open() -> Self {
        Self::open_at(codex_lifecycle_log_path())
    }

    fn open_at(path: PathBuf) -> Self {
        let file = std::fs::OpenOptions::new().read(true).open(&path).ok();
        Self {
            path,
            file,
            offset: 0,
            pending: Vec::new(),
        }
    }

    fn read_new(&mut self) -> Result<Vec<String>, String> {
        if self.file.is_none() {
            self.file = std::fs::OpenOptions::new().read(true).open(&self.path).ok();
        }
        let path_replaced = self
            .file
            .as_ref()
            .and_then(|file| file.metadata().ok())
            .zip(std::fs::metadata(&self.path).ok())
            .is_some_and(|(open, current)| !same_file_identity(&open, &current));
        if path_replaced {
            self.file = std::fs::OpenOptions::new().read(true).open(&self.path).ok();
            self.offset = 0;
            self.pending.clear();
        }
        let Some(file) = self.file.as_mut() else {
            return Ok(Vec::new());
        };
        let length = file
            .metadata()
            .map_err(|error| format!("could not inspect Codex App lifecycle log: {error}"))?
            .len();
        if length < self.offset {
            self.offset = 0;
            self.pending.clear();
        }
        file.seek(SeekFrom::Start(self.offset))
            .map_err(|error| format!("could not seek Codex App lifecycle log: {error}"))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| format!("could not read Codex App lifecycle log: {error}"))?;
        self.offset += bytes.len() as u64;
        self.pending.extend_from_slice(&bytes);

        let complete = self
            .pending
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map(|index| self.pending.drain(..=index).collect::<Vec<_>>())
            .unwrap_or_default();
        Ok(String::from_utf8_lossy(&complete)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_string)
            .collect())
    }
}

#[cfg(unix)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    // Stable Rust does not expose the Windows file index. Pentect creates the
    // replacement log itself, so its creation timestamp changes on rotation.
    left.creation_time() == right.creation_time()
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    true
}

fn codex_lifecycle_log_path() -> PathBuf {
    let home = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .or_else(|| std::env::var_os("HOME"))
                .map(PathBuf::from)
                .map(|home| home.join(".codex"))
        })
        .unwrap_or_else(|| PathBuf::from(".codex"));
    home.join(".pentect").join("logs").join("codex-app.log")
}

fn record(event: ActivityEvent) {
    let Ok(json) = serde_json::to_string(&event) else {
        return;
    };
    if let Some(writer) = persistent_log() {
        writer.enqueue(json.clone());
    }
    let share = *LOG_SHARE.get_or_init(|| crate::config::activity_share_enabled().unwrap_or(true));
    let _ = delegated_process_host::send_activity(&json, share);
}

fn persistent_log() -> Option<&'static PersistentLogWriter> {
    PERSISTENT_LOG
        .get_or_init(|| PersistentLogWriter::spawn(persistent_log_path()).ok())
        .as_ref()
}

impl PersistentLogWriter {
    fn spawn(path: PathBuf) -> Result<Self, String> {
        prepare_log_path(&path)?;
        let (sender, receiver) = mpsc::sync_channel(LOG_CHANNEL_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let worker_dropped = Arc::clone(&dropped);
        std::thread::Builder::new()
            .name("pentect-log-writer".to_string())
            .spawn(move || log_writer_loop(path, receiver, worker_dropped))
            .map_err(|error| format!("could not start persistent log writer: {error}"))?;
        Ok(Self { sender, dropped })
    }

    fn enqueue(&self, entry: String) {
        match self.sender.try_send(LogMessage::Entry(entry)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    fn flush(&self) {
        let (sender, receiver) = mpsc::channel();
        if self.sender.send(LogMessage::Flush(sender)).is_ok() {
            let _ = receiver.recv_timeout(Duration::from_secs(5));
        }
    }
}

fn log_writer_loop(path: PathBuf, receiver: Receiver<LogMessage>, dropped: Arc<AtomicU64>) {
    let mut batch = Vec::with_capacity(LOG_BATCH_EVENTS);
    let mut bytes = 0usize;
    loop {
        let message = if batch.is_empty() {
            match receiver.recv() {
                Ok(message) => message,
                Err(_) => break,
            }
        } else {
            match receiver.recv_timeout(LOG_FLUSH_INTERVAL) {
                Ok(message) => message,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    flush_batch(&path, &mut batch, &dropped);
                    bytes = 0;
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        };
        match message {
            LogMessage::Entry(entry) => {
                bytes = bytes.saturating_add(entry.len() + 1);
                batch.push(entry);
                if batch.len() >= LOG_BATCH_EVENTS || bytes >= LOG_BATCH_BYTES {
                    flush_batch(&path, &mut batch, &dropped);
                    bytes = 0;
                }
            }
            LogMessage::Flush(acknowledge) => {
                flush_batch(&path, &mut batch, &dropped);
                bytes = 0;
                let _ = acknowledge.send(());
            }
        }
    }
    flush_batch(&path, &mut batch, &dropped);
}

fn flush_batch(path: &Path, batch: &mut Vec<String>, dropped: &AtomicU64) {
    let lost = dropped.swap(0, Ordering::Relaxed);
    if lost > 0 {
        batch.push(
            serde_json::json!({
                "time": jiff::Timestamp::now().to_string(),
                "action": "process",
                "surface": "logger",
                "count": lost,
                "event": "queue-overflow",
                "pid": std::process::id(),
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            })
            .to_string(),
        );
    }
    if batch.is_empty() {
        return;
    }
    if write_batch(path, batch).is_err() {
        dropped.fetch_add(batch.len() as u64, Ordering::Relaxed);
    }
    batch.clear();
}

fn write_batch(path: &Path, batch: &[String]) -> Result<(), String> {
    prepare_log_path(path)?;
    let payload = batch.join("\n") + "\n";
    rotate_log_if_needed(path, payload.len() as u64);
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("could not open persistent log: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    file.write_all(payload.as_bytes())
        .and_then(|()| file.flush())
        .map_err(|error| format!("could not write persistent log: {error}"))
}

fn prepare_log_path(path: &Path) -> Result<(), String> {
    let directory = path
        .parent()
        .ok_or_else(|| "persistent log path has no parent directory".to_string())?;
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("could not create persistent log directory: {error}"))?;
    if std::fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err("persistent log directory must not be a symbolic link".to_string());
    }
    if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("persistent log must not be a symbolic link".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn rotate_log_if_needed(path: &Path, incoming: u64) {
    let current = std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if current.saturating_add(incoming) <= LOG_MAX_BYTES {
        return;
    }
    for generation in (1..=LOG_ROTATIONS).rev() {
        let source = if generation == 1 {
            path.to_path_buf()
        } else {
            rotated_log_path(path, generation - 1)
        };
        let destination = rotated_log_path(path, generation);
        if generation == LOG_ROTATIONS {
            let _ = std::fs::remove_file(&destination);
        }
        if source.exists() {
            let _ = std::fs::rename(source, destination);
        }
    }
}

fn rotated_log_path(path: &Path, generation: usize) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{generation}"));
    PathBuf::from(name)
}

fn activity_source() -> Result<ActivitySource, String> {
    let endpoint = delegated_process_host::reader_endpoint()?;
    Ok(ActivitySource {
        client: MemoryStoreClient::for_activity(endpoint.addr.clone(), endpoint.read_token.clone()),
        cursor: 0,
        endpoint,
    })
}

fn format_event(event: &ActivityEvent) -> String {
    if event.action == "process" {
        let event_name = event.event.as_deref().unwrap_or("event");
        let exit = event
            .exit_code
            .map(|code| format!("  exit={code}"))
            .unwrap_or_default();
        let location = event
            .panic_location
            .as_deref()
            .map(|location| format!("  at={location}"))
            .unwrap_or_default();
        return format!(
            "{}  process/{}  {}  pid={}  version={}  {}/{}{}{}",
            event.time,
            event.surface,
            event_name,
            event.pid.unwrap_or_default(),
            event.version.as_deref().unwrap_or("unknown"),
            event.os.as_deref().unwrap_or("unknown"),
            event.arch.as_deref().unwrap_or("unknown"),
            exit,
            location,
        );
    }
    let labels = event
        .labels
        .iter()
        .map(|label| {
            if label.count == 1 {
                label.name.clone()
            } else {
                format!("{} x{}", label.name, label.count)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let target = event
        .target
        .as_deref()
        .map(|target| format!("  {target}"))
        .unwrap_or_default();
    let labels = if labels.is_empty() {
        String::new()
    } else {
        format!("  {labels}")
    };
    format!(
        "{}  {}/{}  {}{}{}",
        event.time, event.action, event.surface, event.count, labels, target
    )
}

fn user_home() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}

fn safe_identifier(value: &str) -> String {
    let value = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(64)
        .collect::<String>();
    if value.is_empty() {
        "unknown".to_string()
    } else {
        value
    }
}

fn safe_panic_location(value: &str) -> String {
    value
        .chars()
        .filter(|character| !matches!(character, '\r' | '\n' | '\0'))
        .take(512)
        .collect()
}

fn safe_backtrace(value: &str) -> String {
    value
        .chars()
        .filter(|character| *character != '\0')
        .take(16 * 1024)
        .collect()
}

fn safe_target(path: &Path) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(relative) = path.strip_prefix(&cwd) {
            return display_path(relative);
        }
    }
    if path.is_relative() {
        return display_path(path);
    }
    path.file_name()
        .map(PathBuf::from)
        .as_deref()
        .map(display_path)
        .unwrap_or_else(|| "external".to_string())
}

fn display_path(path: &Path) -> String {
    let displayed = path.to_string_lossy().replace('\\', "/");
    if displayed.is_empty() {
        ".".to_string()
    } else {
        displayed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_event_contains_metadata_only() {
        let event = ActivityEvent::new(
            "mask",
            "tool",
            2,
            BTreeMap::from([("OPENAI_API_KEY".to_string(), 2)]),
            Some(".env".to_string()),
        );
        let raw = serde_json::to_string(&event).unwrap();
        assert!(raw.contains("OPENAI_API_KEY"));
        assert!(!raw.contains("sk-"));
        assert!(format_event(&event).contains("OPENAI_API_KEY x2"));
    }

    #[test]
    fn safe_target_hides_external_parent_directories() {
        let path = if cfg!(windows) {
            Path::new(r"C:\Users\name\secret\.env")
        } else {
            Path::new("/home/name/secret/.env")
        };
        assert_eq!(safe_target(path), ".env");
    }

    #[test]
    fn shared_events_are_printed_once_after_handoff() {
        let mut seen = SeenActivity::default();
        let event = r#"{"action":"mask","count":1}"#;
        assert!(seen.insert(event));
        assert!(!seen.insert(event));
        assert!(seen.insert(r#"{"action":"resolve","count":1}"#));
    }

    #[test]
    fn lifecycle_source_reads_only_appended_records_after_the_first_poll() {
        let root = std::env::temp_dir().join(format!(
            "pentect-lifecycle-source-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("codex-app.log");
        std::fs::write(&path, "{\"event\":\"gateway-started\"}\n").unwrap();
        let mut source = LifecycleSource::open_at(path.clone());
        assert_eq!(source.read_new().unwrap().len(), 1);
        assert!(source.read_new().unwrap().is_empty());
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{{\"event\":\"session-finished\"}}").unwrap();
        assert_eq!(source.read_new().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lifecycle_source_waits_for_complete_lines_and_recovers_after_truncation() {
        let root = std::env::temp_dir().join(format!(
            "pentect-lifecycle-partial-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("codex-app.log");
        std::fs::write(&path, "{\"event\":\"gateway").unwrap();
        let mut source = LifecycleSource::open_at(path.clone());
        assert!(source.read_new().unwrap().is_empty());

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "-started\"}}").unwrap();
        assert_eq!(
            source.read_new().unwrap(),
            ["{\"event\":\"gateway-started\"}"]
        );

        drop(file);
        std::fs::write(&path, "{\"event\":\"rotated\"}\n").unwrap();
        assert_eq!(source.read_new().unwrap(), ["{\"event\":\"rotated\"}"]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lifecycle_source_follows_path_replacement_rotation() {
        let root = std::env::temp_dir().join(format!(
            "pentect-lifecycle-rotation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("codex-app.log");
        let rotated = root.join("codex-app.log.1");
        std::fs::write(&path, "{\"event\":\"before-rotation\"}\n").unwrap();
        let mut source = LifecycleSource::open_at(path.clone());
        assert_eq!(
            source.read_new().unwrap(),
            ["{\"event\":\"before-rotation\"}"]
        );

        std::fs::rename(&path, &rotated).unwrap();
        std::fs::write(&path, "{\"event\":\"after-rotation\"}\n").unwrap();
        assert_eq!(
            source.read_new().unwrap(),
            ["{\"event\":\"after-rotation\"}"]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn persistent_writer_flushes_a_batch_on_the_interval() {
        let root = std::env::temp_dir().join(format!(
            "pentect-persistent-batch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = root.join("pentect.log");
        let writer = PersistentLogWriter::spawn(path.clone()).unwrap();
        writer.enqueue("{\"event\":\"one\"}".to_string());
        writer.enqueue("{\"event\":\"two\"}".to_string());
        std::thread::sleep(LOG_FLUSH_INTERVAL + Duration::from_millis(100));
        let payload = std::fs::read_to_string(&path).unwrap();
        assert_eq!(payload.lines().count(), 2);
        drop(writer);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn persistent_log_rotates_and_keeps_the_current_file_bounded() {
        let root = std::env::temp_dir().join(format!(
            "pentect-persistent-rotation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("pentect.log");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(LOG_MAX_BYTES + 1).unwrap();
        write_batch(&path, &["{\"event\":\"after-rotation\"}".to_string()]).unwrap();
        assert!(rotated_log_path(&path, 1).exists());
        assert!(std::fs::metadata(&path).unwrap().len() < LOG_MAX_BYTES);
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("after-rotation"));
        let _ = std::fs::remove_dir_all(root);
    }
}
