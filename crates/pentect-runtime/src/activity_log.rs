use crate::delegated_process_host::{self, ProcessHostEndpoint};
use crate::memory_store::MemoryStoreClient;
use pentect_core::MaskResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

const MAX_LABELS_PER_EVENT: usize = 64;
const MAX_SEEN_EVENTS: usize = 4_096;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
static LOG_SHARE: OnceLock<bool> = OnceLock::new();

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
    file: Option<std::fs::File>,
    offset: u64,
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
        }
    }
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
    let mut seen = SeenActivity::default();

    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    loop {
        let mut wrote = false;
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
        let file = std::fs::OpenOptions::new().read(true).open(path).ok();
        Self { file, offset: 0 }
    }

    fn read_new(&mut self) -> Result<Vec<String>, String> {
        if self.file.is_none() {
            self.file = std::fs::OpenOptions::new()
                .read(true)
                .open(codex_lifecycle_log_path())
                .ok();
        }
        let Some(file) = self.file.as_mut() else {
            return Ok(Vec::new());
        };
        file.seek(SeekFrom::Start(self.offset))
            .map_err(|error| format!("could not seek Codex App lifecycle log: {error}"))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| format!("could not read Codex App lifecycle log: {error}"))?;
        self.offset += bytes.len() as u64;
        Ok(String::from_utf8_lossy(&bytes)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_string)
            .collect())
    }
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
    let share = *LOG_SHARE.get_or_init(|| crate::config::activity_share_enabled().unwrap_or(true));
    let _ = delegated_process_host::send_activity(&json, share);
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
}
