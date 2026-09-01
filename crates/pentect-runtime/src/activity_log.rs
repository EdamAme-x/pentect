use crate::delegated_process_host::{self, ProcessHostEndpoint};
use crate::memory_store::MemoryStoreClient;
use pentect_core::{model::labels, MaskResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

const MAX_LABELS_PER_EVENT: usize = 64;
const MAX_SEEN_EVENTS: usize = 4_096;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const LOG_BATCH_EVENTS: usize = 64;
const LOG_BATCH_BYTES: usize = 64 * 1024;
const LOG_FLUSH_INTERVAL: Duration = Duration::from_millis(250);
const LOG_CHANNEL_CAPACITY: usize = 1_024;
const LOG_MAX_BYTES: u64 = 128 * 1024 * 1024;
const LOG_ROTATIONS: usize = 31;
const DIAGNOSTIC_BATCH_WINDOW: Duration = Duration::from_secs(5);
const DIAGNOSTIC_POLL_INTERVAL: Duration = Duration::from_millis(250);
const DIAGNOSTIC_CHANNEL_CAPACITY: usize = 1_024;
static LOG_SHARE: OnceLock<bool> = OnceLock::new();
static PERSISTENT_LOG: OnceLock<Option<PersistentLogWriter>> = OnceLock::new();
static DIAGNOSTIC_WRITER: OnceLock<Option<DiagnosticWriter>> = OnceLock::new();

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
    kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retryable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
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

#[derive(Debug, Default, Serialize)]
struct PrivacyMetrics {
    enabled: bool,
    scope: &'static str,
    masked_text_occurrences: u64,
    redacted_image_occurrences: u64,
    blocked_image_occurrences: u64,
    restoration_operations: u64,
    blocked_restoration_occurrences: u64,
    blocked_occurrences: u64,
    warning_occurrences: u64,
    plugin_failure_occurrences: u64,
    plugin_timeout_occurrences: u64,
    by_secret_type: BTreeMap<String, u64>,
    by_surface: BTreeMap<String, u64>,
    by_warning_reason: BTreeMap<String, u64>,
    records_read: u64,
    records_skipped: u64,
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

struct DiagnosticWriter {
    sender: SyncSender<DiagnosticMessage>,
    dropped: Arc<AtomicU64>,
}

enum DiagnosticMessage {
    Entry(Box<ActivityEvent>),
    Flush(mpsc::Sender<()>),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DiagnosticKey {
    action: String,
    surface: String,
    event: Option<String>,
    kind: Option<String>,
    endpoint: Option<String>,
    method: Option<String>,
    status: Option<u16>,
    retryable: Option<bool>,
    pid: Option<u32>,
}

struct PendingDiagnostic {
    event: ActivityEvent,
    first_seen: Instant,
}

#[derive(Default)]
struct DiagnosticBatch {
    pending: HashMap<DiagnosticKey, PendingDiagnostic>,
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
            kind: None,
            endpoint: None,
            method: None,
            status: None,
            retryable: None,
            last_time: None,
            duration_ms: None,
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
            kind: None,
            endpoint: None,
            method: None,
            status: None,
            retryable: None,
            last_time: None,
            duration_ms: None,
            pid: Some(std::process::id()),
            version: Some(version.chars().take(64).collect()),
            os: Some(std::env::consts::OS.to_string()),
            arch: Some(std::env::consts::ARCH.to_string()),
            exit_code,
            panic_location: panic_location.map(safe_panic_location),
            backtrace: backtrace.map(safe_backtrace),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn diagnostic(
        surface: &str,
        event: &str,
        kind: Option<&str>,
        endpoint: Option<&str>,
        method: Option<&str>,
        status: Option<u16>,
        retryable: Option<bool>,
        version: Option<&str>,
    ) -> Self {
        Self {
            time: jiff::Timestamp::now().to_string(),
            action: "warning".to_string(),
            surface: diagnostic_surface(surface),
            count: 1,
            labels: Vec::new(),
            target: None,
            event: Some(diagnostic_event(event)),
            kind: kind.map(diagnostic_kind),
            endpoint: endpoint.map(diagnostic_endpoint),
            method: method.map(diagnostic_method),
            status,
            retryable,
            last_time: None,
            duration_ms: None,
            pid: Some(std::process::id()),
            version: version.and_then(diagnostic_version),
            os: Some(std::env::consts::OS.to_string()),
            arch: Some(std::env::consts::ARCH.to_string()),
            exit_code: None,
            panic_location: None,
            backtrace: None,
        }
    }
}

impl ActivityEvent {
    #[allow(clippy::too_many_arguments)]
    fn diagnostic_counted(
        action: &str,
        surface: &str,
        event: &str,
        kind: Option<&str>,
        endpoint: Option<&str>,
        method: Option<&str>,
        status: Option<u16>,
        retryable: Option<bool>,
        version: Option<&str>,
        count: u64,
    ) -> Self {
        let mut out = Self::diagnostic(
            surface, event, kind, endpoint, method, status, retryable, version,
        );
        out.action = match action {
            "warning" => "warning",
            _ => "diagnostic",
        }
        .to_string();
        out.count = count.max(1);
        out
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
    if let Some(writer) = diagnostic_writer() {
        writer.flush();
    }
    if let Some(writer) = persistent_log() {
        writer.flush();
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_diagnostic(
    surface: &str,
    event: &str,
    kind: Option<&str>,
    endpoint: Option<&str>,
    method: Option<&str>,
    status: Option<u16>,
    retryable: Option<bool>,
    version: Option<&str>,
) {
    record(ActivityEvent::diagnostic(
        surface, event, kind, endpoint, method, status, retryable, version,
    ));
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_structured(
    action: &str,
    surface: &str,
    event: &str,
    kind: Option<&str>,
    endpoint: Option<&str>,
    method: Option<&str>,
    status: Option<u16>,
    retryable: Option<bool>,
    version: Option<&str>,
    count: u64,
) {
    record(ActivityEvent::diagnostic_counted(
        action, surface, event, kind, endpoint, method, status, retryable, version, count,
    ));
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

pub(crate) fn print_metrics(json: bool) -> Result<(), String> {
    let metrics = read_metrics(&persistent_log_path())?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&metrics)
                .map_err(|error| format!("could not encode privacy metrics: {error}"))?
        );
        return Ok(());
    }

    println!("Pentect privacy metrics (retained local logs)");
    println!("Masked occurrences: {}", metrics.masked_text_occurrences);
    println!("Redacted images: {}", metrics.redacted_image_occurrences);
    println!("Blocked images: {}", metrics.blocked_image_occurrences);
    println!(
        "Local restoration operations: {}",
        metrics.restoration_operations
    );
    println!(
        "Blocked restoration attempts: {}",
        metrics.blocked_restoration_occurrences
    );
    println!("Blocked operations: {}", metrics.blocked_occurrences);
    println!("Warnings: {}", metrics.warning_occurrences);
    println!(
        "Plugin failures (including timeouts): {}",
        metrics.plugin_failure_occurrences
    );
    println!("Plugin timeouts: {}", metrics.plugin_timeout_occurrences);
    print_metric_group(
        "Secret types (text masks and image redactions)",
        &metrics.by_secret_type,
    );
    print_metric_group("Protection surfaces", &metrics.by_surface);
    print_metric_group("Warning reasons", &metrics.by_warning_reason);
    if metrics.records_skipped > 0 {
        println!(
            "Skipped unreadable records: {} (counts may be incomplete)",
            metrics.records_skipped
        );
    }
    println!("No secret values, handles, paths, URLs, or account identifiers are included.");
    Ok(())
}

fn print_metric_group(title: &str, values: &BTreeMap<String, u64>) {
    println!("{title}:");
    if values.is_empty() {
        println!("  (none)");
        return;
    }
    let mut values = values.iter().collect::<Vec<_>>();
    values.sort_by(|(left_name, left_count), (right_name, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_name.cmp(right_name))
    });
    for (name, count) in values {
        let readable = labels::description(name)
            .map(str::to_string)
            .unwrap_or_else(|| readable_metric_name(name));
        if readable == *name {
            println!("  {name}: {count}");
        } else {
            println!("  {name} ({readable}): {count}");
        }
    }
}

fn readable_metric_name(name: &str) -> String {
    let mut output = String::new();
    for (index, word) in name
        .split(['_', '-'])
        .filter(|word| !word.is_empty())
        .enumerate()
    {
        if index > 0 {
            output.push(' ');
        }
        if is_metric_acronym(word) {
            output.push_str(&word.to_ascii_uppercase());
            continue;
        }
        let normalized = word.to_ascii_lowercase();
        if index == 0 {
            let mut chars = normalized.chars();
            if let Some(first) = chars.next() {
                output.extend(first.to_uppercase());
                output.push_str(chars.as_str());
            }
        } else {
            output.push_str(&normalized);
        }
    }
    if output.is_empty() {
        "Unknown".to_string()
    } else {
        output
    }
}

fn is_metric_acronym(word: &str) -> bool {
    matches!(
        word.to_ascii_uppercase().as_str(),
        "API"
            | "AWS"
            | "CLI"
            | "CMD"
            | "GPS"
            | "HTTP"
            | "IBAN"
            | "JSON"
            | "JWT"
            | "MCP"
            | "NINO"
            | "OCR"
            | "OPENAI"
            | "OTP"
            | "PII"
            | "S3"
            | "SSE"
            | "UK"
            | "URL"
            | "UUID"
    )
}

fn read_metrics(path: &Path) -> Result<PrivacyMetrics, String> {
    let mut metrics = PrivacyMetrics {
        enabled: true,
        scope: "retained_local_logs",
        ..PrivacyMetrics::default()
    };
    for generation in (1..=LOG_ROTATIONS).rev() {
        aggregate_metrics_file(&rotated_log_path(path, generation), &mut metrics)?;
    }
    aggregate_metrics_file(path, &mut metrics)?;
    Ok(metrics)
}

fn aggregate_metrics_file(path: &Path, metrics: &mut PrivacyMetrics) -> Result<(), String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("could not read persistent activity log: {error}")),
    };
    for line in BufReader::new(file).lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => {
                metrics.records_skipped = metrics.records_skipped.saturating_add(1);
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let event = match serde_json::from_str::<ActivityEvent>(&line) {
            Ok(event) => event,
            Err(_) => {
                metrics.records_skipped = metrics.records_skipped.saturating_add(1);
                continue;
            }
        };
        metrics.records_read = metrics.records_read.saturating_add(1);
        aggregate_metric_event(&event, metrics);
    }
    Ok(())
}

fn aggregate_metric_event(event: &ActivityEvent, metrics: &mut PrivacyMetrics) {
    match event.action.as_str() {
        "mask" | "redact" => {
            if event.action == "mask" {
                metrics.masked_text_occurrences =
                    metrics.masked_text_occurrences.saturating_add(event.count);
            } else {
                metrics.redacted_image_occurrences = metrics
                    .redacted_image_occurrences
                    .saturating_add(event.count);
            }
            increment_metric(
                &mut metrics.by_surface,
                safe_metric_surface(&event.surface).to_string(),
                event.count,
            );
            for label in &event.labels {
                increment_metric(
                    &mut metrics.by_secret_type,
                    safe_metric_secret_type(&label.name).to_string(),
                    label.count,
                );
            }
        }
        "resolve" => {
            metrics.restoration_operations =
                metrics.restoration_operations.saturating_add(event.count);
        }
        "restoration-blocked" => {
            metrics.blocked_restoration_occurrences = metrics
                .blocked_restoration_occurrences
                .saturating_add(event.count);
        }
        "block" => {
            metrics.blocked_occurrences = metrics.blocked_occurrences.saturating_add(event.count);
        }
        "block-image" => {
            metrics.blocked_image_occurrences = metrics
                .blocked_image_occurrences
                .saturating_add(event.count);
        }
        "warning" => {
            metrics.warning_occurrences = metrics.warning_occurrences.saturating_add(event.count);
            increment_metric(
                &mut metrics.by_warning_reason,
                diagnostic_event(event.event.as_deref().unwrap_or("unknown")),
                event.count,
            );
            if is_block_event(event.event.as_deref()) {
                metrics.blocked_occurrences =
                    metrics.blocked_occurrences.saturating_add(event.count);
            }
        }
        "diagnostic" if is_block_event(event.event.as_deref()) => {
            metrics.blocked_occurrences = metrics.blocked_occurrences.saturating_add(event.count);
        }
        "plugin-failure" => {
            metrics.plugin_failure_occurrences = metrics
                .plugin_failure_occurrences
                .saturating_add(event.count);
            if event.labels.iter().any(|label| label.name == "timeout") {
                metrics.plugin_timeout_occurrences = metrics
                    .plugin_timeout_occurrences
                    .saturating_add(event.count);
            }
        }
        _ => {}
    }
}

fn is_block_event(event: Option<&str>) -> bool {
    matches!(
        event,
        Some(
            "request-rejected"
                | "scan-failure-blocked"
                | "scan-unavailable-blocked"
                | "unknown-content-block"
        )
    )
}

fn increment_metric(values: &mut BTreeMap<String, u64>, name: String, count: u64) {
    let value = values.entry(name).or_default();
    *value = value.saturating_add(count);
}

fn safe_metric_surface(value: &str) -> &str {
    match value {
        "prompt" | "output" | "tool" | "read" | "image" => value,
        _ => "OTHER",
    }
}

fn safe_metric_secret_type(value: &str) -> &str {
    if labels::is_canonical(value) {
        return value;
    }
    match value {
        "ACCESS_TOKEN" | "ANTHROPIC_API_KEY" | "API_KEY" | "AWS_AKID" | "AWS_MULTI"
        | "BASE64_PRIVATE_KEY" | "BASIC_AUTH" | "BEARER_TOKEN" | "CREDENTIAL" | "CREDENTIALS"
        | "CREDIT_CARD" | "EMAIL_ADDRESS" | "GITHUB_PAT" | "GITHUB_TOKEN" | "GOOGLE_API_KEY"
        | "HUGGINGFACE_TOKEN" | "IBAN_CODE" | "OPENAI_API_KEY" | "PASSWORD" | "PEM_PRIVATE_KEY"
        | "PHONE_NUMBER" | "SESSION_TOKEN" | "SLACK_TOKEN" | "SLACK_WEBHOOK"
        | "STRIPE_SECRET_KEY" | "TELEGRAM_BOT_TOKEN" | "TOKEN" | "UK_NINO" => value,
        _ => "OTHER",
    }
}

fn safe_metric_labels(values: &BTreeMap<String, u64>) -> BTreeMap<String, u64> {
    let mut labels = BTreeMap::new();
    for (label, count) in values {
        increment_metric(
            &mut labels,
            safe_metric_secret_type(label).to_string(),
            *count,
        );
    }
    labels
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

pub(crate) fn record_restoration_blocked(surface: &str) {
    record_summary(
        "restoration-blocked",
        restoration_block_surface(surface),
        1,
        BTreeMap::new(),
        None,
    );
}

fn restoration_block_surface(surface: &str) -> &str {
    match surface {
        "argv" | "command" | "exec-server" | "file-repair" => surface,
        _ => "other",
    }
}

pub(crate) fn record_image(secret_images: usize, detected_labels: &BTreeMap<String, u64>) {
    if secret_images == 0 {
        return;
    }
    let labels = safe_metric_labels(detected_labels);
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
    if matches!(event.action.as_str(), "warning" | "diagnostic") {
        if let Some(writer) = diagnostic_writer() {
            writer.enqueue(event);
            return;
        }
    }
    record_immediate(event);
}

fn record_immediate(event: ActivityEvent) {
    let Ok(json) = serde_json::to_string(&event) else {
        return;
    };
    if let Some(writer) = persistent_log() {
        writer.enqueue(json.clone());
    }
    let share = *LOG_SHARE.get_or_init(|| crate::config::activity_share_enabled().unwrap_or(true));
    let _ = delegated_process_host::send_activity(&json, share);
}

fn diagnostic_writer() -> Option<&'static DiagnosticWriter> {
    DIAGNOSTIC_WRITER
        .get_or_init(|| DiagnosticWriter::spawn().ok())
        .as_ref()
}

impl DiagnosticWriter {
    fn spawn() -> Result<Self, String> {
        let (sender, receiver) = mpsc::sync_channel(DIAGNOSTIC_CHANNEL_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let worker_dropped = Arc::clone(&dropped);
        std::thread::Builder::new()
            .name("pentect-diagnostic-writer".to_string())
            .spawn(move || diagnostic_writer_loop(receiver, worker_dropped))
            .map_err(|error| format!("could not start diagnostic writer: {error}"))?;
        Ok(Self { sender, dropped })
    }

    fn enqueue(&self, event: ActivityEvent) {
        match self
            .sender
            .try_send(DiagnosticMessage::Entry(Box::new(event)))
        {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    fn flush(&self) {
        let (sender, receiver) = mpsc::channel();
        if self.sender.send(DiagnosticMessage::Flush(sender)).is_ok() {
            let _ = receiver.recv_timeout(Duration::from_secs(5));
        }
    }
}

impl DiagnosticBatch {
    fn push(&mut self, event: ActivityEvent, now: Instant) {
        let key = DiagnosticKey {
            action: event.action.clone(),
            surface: event.surface.clone(),
            event: event.event.clone(),
            kind: event.kind.clone(),
            endpoint: event.endpoint.clone(),
            method: event.method.clone(),
            status: event.status,
            retryable: event.retryable,
            pid: event.pid,
        };
        match self.pending.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let pending = entry.get_mut();
                pending.event.count = pending.event.count.saturating_add(event.count);
                pending.event.last_time = Some(event.time);
                pending.event.duration_ms = Some(
                    now.saturating_duration_since(pending.first_seen)
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX),
                );
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(PendingDiagnostic {
                    event,
                    first_seen: now,
                });
            }
        }
    }

    fn drain_expired(&mut self, now: Instant, force: bool) -> Vec<ActivityEvent> {
        let keys = self
            .pending
            .iter()
            .filter(|(_, pending)| {
                force
                    || now.saturating_duration_since(pending.first_seen) >= DIAGNOSTIC_BATCH_WINDOW
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        keys.into_iter()
            .filter_map(|key| self.pending.remove(&key).map(|pending| pending.event))
            .collect()
    }
}

fn diagnostic_writer_loop(receiver: Receiver<DiagnosticMessage>, dropped: Arc<AtomicU64>) {
    let mut batch = DiagnosticBatch::default();
    loop {
        match receiver.recv_timeout(DIAGNOSTIC_POLL_INTERVAL) {
            Ok(DiagnosticMessage::Entry(event)) => batch.push(*event, Instant::now()),
            Ok(DiagnosticMessage::Flush(acknowledge)) => {
                flush_diagnostic_batch(&mut batch, &dropped, true);
                let _ = acknowledge.send(());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                flush_diagnostic_batch(&mut batch, &dropped, false);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    flush_diagnostic_batch(&mut batch, &dropped, true);
}

fn flush_diagnostic_batch(batch: &mut DiagnosticBatch, dropped: &AtomicU64, force: bool) {
    for event in batch.drain_expired(Instant::now(), force) {
        record_immediate(event);
    }
    let lost = dropped.swap(0, Ordering::Relaxed);
    if lost > 0 {
        let mut event = ActivityEvent::diagnostic(
            "logger",
            "diagnostic-queue-overflow",
            Some("capacity"),
            None,
            None,
            None,
            Some(true),
            None,
        );
        event.count = lost;
        record_immediate(event);
    }
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
    if matches!(event.action.as_str(), "warning" | "diagnostic") && event.event.is_some() {
        let mut details = Vec::new();
        if let Some(kind) = &event.kind {
            details.push(format!("kind={kind}"));
        }
        if let Some(endpoint) = &event.endpoint {
            details.push(format!("endpoint={endpoint}"));
        }
        if let Some(method) = &event.method {
            details.push(format!("method={method}"));
        }
        if let Some(status) = event.status {
            details.push(format!("status={status}"));
        }
        if let Some(retryable) = event.retryable {
            details.push(format!("retryable={retryable}"));
        }
        if let Some(duration_ms) = event.duration_ms {
            details.push(format!("span_ms={duration_ms}"));
        }
        if let Some(pid) = event.pid {
            details.push(format!("pid={pid}"));
        }
        let count = if event.count == 1 {
            String::new()
        } else {
            format!(" x{}", event.count)
        };
        let details = if details.is_empty() {
            String::new()
        } else {
            format!("  {}", details.join("  "))
        };
        return format!(
            "{}  {}/{}  {}{}{}",
            event.time,
            event.action,
            event.surface,
            event.event.as_deref().unwrap_or("event"),
            count,
            details,
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

fn allowed_diagnostic_identifier(value: &str, allowed: &[&str]) -> String {
    if allowed.contains(&value) {
        value.to_string()
    } else {
        "unknown".to_string()
    }
}

fn diagnostic_surface(value: &str) -> String {
    allowed_diagnostic_identifier(
        value,
        &[
            "claude",
            "claude-app",
            "cloud-code",
            "decode",
            "gemini",
            "logger",
            "ocr",
            "openai",
        ],
    )
}

fn diagnostic_event(value: &str) -> String {
    allowed_diagnostic_identifier(
        value,
        &[
            "cmd-binding-skipped",
            "connection-failed",
            "candidate-limit",
            "decoded-byte-limit",
            "diagnostic-queue-overflow",
            "elapsed-limit",
            "expansion-limit",
            "file-attestation-unavailable",
            "file-registry-unavailable",
            "gateway-busy",
            "gateway-stopped",
            "no-protected-connection",
            "provider-mcp-credential-forwarded",
            "request-content-encoding-skipped",
            "request-encode-skipped",
            "request-failed",
            "request-invalid-json",
            "request-protection-skipped",
            "request-rejected",
            "response-protection-skipped",
            "response-restore-skipped",
            "scan-complete",
            "scan-failed",
            "scan-failure-allowed",
            "scan-failure-blocked",
            "scan-unavailable-allowed",
            "scan-unavailable-blocked",
            "shell-secret-unresolved",
            "sse-event-limit",
            "sse-restore-skipped",
            "sse-tool-limit",
            "stream-event-protection-skipped",
            "tool-input-restore-skipped",
            "unknown-content-block",
            "unknown-endpoint",
            "upstream-response",
        ],
    )
}

fn diagnostic_kind(value: &str) -> String {
    allowed_diagnostic_identifier(
        value,
        &[
            "authentication",
            "bundled",
            "capacity",
            "client-connection",
            "conflict",
            "connect",
            "credential-forwarding",
            "decode",
            "disabled",
            "initialize",
            "internal",
            "limit",
            "model-load",
            "plugin",
            "policy",
            "preprocess",
            "protection",
            "protocol",
            "rate-limit",
            "recognition",
            "redirect",
            "resolution",
            "response-body",
            "runtime",
            "source-or-limit",
            "storage",
            "stream",
            "timeout",
            "unclassified",
            "unexpected-status",
            "unsupported",
            "upstream-client",
            "upstream-server",
            "windows",
            "macos",
        ],
    )
}

fn diagnostic_endpoint(value: &str) -> String {
    allowed_diagnostic_identifier(
        value,
        &[
            "audio-speech",
            "audio-transcription",
            "audio-translation",
            "batch-embed-contents",
            "bundled",
            "chat-completions",
            "complete",
            "completions",
            "control",
            "count-tokens",
            "disabled",
            "embed-content",
            "embeddings",
            "files",
            "files-collection",
            "gateway",
            "generate-content",
            "health",
            "image",
            "image-generation",
            "input-tokens",
            "macos",
            "messages",
            "message-batches",
            "models",
            "responses",
            "responses-resource",
            "standalone-search",
            "stream-generate-content",
            "telemetry",
            "tool-input",
            "unknown",
            "unsupported",
            "windows",
        ],
    )
}

fn diagnostic_method(value: &str) -> String {
    allowed_diagnostic_identifier(
        value,
        &[
            "DELETE", "GET", "HEAD", "HTTP", "OPTIONS", "OTHER", "PATCH", "POST", "PUT", "SCAN",
        ],
    )
}

fn diagnostic_version(value: &str) -> Option<String> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let mut parts = value.split('.');
    let valid = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
    }) && parts.next().is_none();
    valid.then(|| value.to_string())
}

fn safe_panic_location(value: &str) -> String {
    let filtered = value
        .chars()
        .filter(|character| !matches!(character, '\r' | '\n' | '\0'))
        .take(512)
        .collect::<String>();
    basename_source_location(&filtered)
}

fn safe_backtrace(value: &str) -> String {
    let filtered = value
        .chars()
        .filter(|character| *character != '\0')
        .take(16 * 1024)
        .collect::<String>();
    filtered
        .split_inclusive('\n')
        .map(|line| {
            let (content, newline) = line
                .strip_suffix('\n')
                .map_or((line, ""), |content| (content, "\n"));
            let indent_len = content.len() - content.trim_start().len();
            let (indent, trimmed) = content.split_at(indent_len);
            if let Some(location) = trimmed.strip_prefix("at ") {
                format!("{indent}at {}{newline}", basename_source_location(location))
            } else {
                line.to_string()
            }
        })
        .collect()
}

fn basename_source_location(value: &str) -> String {
    let mut path_end = value.len();
    for _ in 0..2 {
        let Some((prefix, field)) = value[..path_end].rsplit_once(':') else {
            break;
        };
        if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
            break;
        }
        path_end = prefix.len();
    }
    let (path, suffix) = value.split_at(path_end);
    let basename = path
        .rsplit(['/', '\\'])
        .find(|component| !component.is_empty())
        .unwrap_or("external");
    format!("{basename}{suffix}")
}

fn safe_target(path: &Path) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        let cwd = normalize_path_lexically(&cwd);
        let absolute = if path.is_absolute() {
            normalize_path_lexically(path)
        } else {
            normalize_path_lexically(&cwd.join(path))
        };
        if let Ok(relative) = absolute.strip_prefix(&cwd) {
            return display_path(relative);
        }
        return absolute
            .file_name()
            .map(PathBuf::from)
            .as_deref()
            .map(display_path)
            .unwrap_or_else(|| "external".to_string());
    }
    if path.is_relative()
        && !path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return display_path(path);
    }
    path.file_name()
        .map(PathBuf::from)
        .as_deref()
        .map(display_path)
        .unwrap_or_else(|| "external".to_string())
}

fn normalize_path_lexically(path: &Path) -> PathBuf {
    let anchored = path.is_absolute();
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(
                    normalized.components().next_back(),
                    Some(Component::Normal(_))
                ) {
                    normalized.pop();
                } else if !anchored {
                    normalized.push(component.as_os_str());
                }
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
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
    fn privacy_metrics_count_occurrences_without_retaining_sensitive_fields() {
        let root = std::env::temp_dir().join(format!(
            "pentect-metrics-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("pentect.log");

        let masked = ActivityEvent::new(
            "mask",
            "prompt",
            3,
            BTreeMap::from([
                ("AWS_AKID".to_string(), 2),
                ("EMAIL_ADDRESS".to_string(), 1),
            ]),
            Some("private-project/.env".to_string()),
        );
        let redacted = ActivityEvent::new(
            "redact",
            "image",
            1,
            BTreeMap::from([("AWS_AKID".to_string(), 1)]),
            None,
        );
        let restored = ActivityEvent::new("resolve", "tool", 2, BTreeMap::new(), None);
        let restoration_blocked = ActivityEvent::new(
            "restoration-blocked",
            "command",
            4,
            BTreeMap::new(),
            Some("private-restoration-target".to_string()),
        );
        let warning = ActivityEvent::diagnostic(
            "openai",
            "request-failed",
            Some("connect"),
            None,
            None,
            None,
            Some(true),
            None,
        );
        let mut untrusted_warning = warning.clone();
        untrusted_warning.event = Some("private-account-warning".to_string());
        let plugin_failure = ActivityEvent::new(
            "plugin-failure",
            "plugin",
            2,
            BTreeMap::from([("failure".to_string(), 2)]),
            Some("private-plugin-name".to_string()),
        );
        let plugin_timeout = ActivityEvent::new(
            "plugin-failure",
            "plugin",
            3,
            BTreeMap::from([("timeout".to_string(), 3)]),
            None,
        );
        std::fs::write(
            rotated_log_path(&path, 1),
            format!("{}\n", serde_json::to_string(&masked).unwrap()),
        )
        .unwrap();
        std::fs::write(
            &path,
            [
                redacted,
                restored,
                restoration_blocked,
                warning,
                untrusted_warning,
                plugin_failure,
                plugin_timeout,
            ]
            .iter()
            .map(|event| serde_json::to_string(event).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
                + "\nnot-json\n",
        )
        .unwrap();

        let metrics = read_metrics(&path).unwrap();
        assert!(metrics.enabled);
        assert_eq!(metrics.masked_text_occurrences, 3);
        assert_eq!(metrics.redacted_image_occurrences, 1);
        assert_eq!(metrics.restoration_operations, 2);
        assert_eq!(metrics.blocked_restoration_occurrences, 4);
        assert_eq!(metrics.warning_occurrences, 2);
        assert_eq!(metrics.plugin_failure_occurrences, 5);
        assert_eq!(metrics.plugin_timeout_occurrences, 3);
        assert_eq!(metrics.by_secret_type["AWS_AKID"], 3);
        assert_eq!(metrics.by_secret_type["EMAIL_ADDRESS"], 1);
        assert_eq!(metrics.by_surface["prompt"], 3);
        assert_eq!(metrics.by_surface["image"], 1);
        assert_eq!(metrics.by_warning_reason["request-failed"], 1);
        assert_eq!(metrics.by_warning_reason["unknown"], 1);
        assert_eq!(metrics.records_skipped, 1);

        let output = serde_json::to_string(&metrics).unwrap();
        assert!(!output.contains("private-project"));
        assert!(!output.contains("private-account"));
        assert!(!output.contains("private-plugin"));
        assert!(!output.contains("private-restoration"));
        assert!(!output.contains(".env"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restoration_block_surfaces_are_bounded() {
        assert_eq!(restoration_block_surface("argv"), "argv");
        assert_eq!(restoration_block_surface("private-project-name"), "other");
    }

    #[test]
    fn metric_names_are_readable_without_changing_the_stable_key() {
        assert_eq!(readable_metric_name("AWS_S3_BUCKET"), "AWS S3 bucket");
        assert_eq!(readable_metric_name("OPENAI_API_KEY"), "OPENAI API key");
        assert_eq!(readable_metric_name("request-failed"), "Request failed");
        assert_eq!(readable_metric_name("PII"), "PII");
        assert_eq!(readable_metric_name(""), "Unknown");
    }

    #[test]
    fn privacy_metric_dimensions_collapse_untrusted_values() {
        assert_eq!(safe_metric_secret_type("AWS_AKID"), "AWS_AKID");
        for label in labels::ALL {
            assert_eq!(safe_metric_secret_type(label), *label);
        }
        let image_labels = safe_metric_labels(&BTreeMap::from([
            (labels::KEYED_SECRET.to_string(), 2),
            ("<<KEYED_SECRET_deadbeefdeadbeef>>".to_string(), 1),
        ]));
        assert_eq!(image_labels.get(labels::KEYED_SECRET), Some(&2));
        assert_eq!(image_labels.get("OTHER"), Some(&1));
        assert!(image_labels.keys().all(|label| !label.contains("<<")));
        assert_eq!(safe_metric_secret_type("accountIdentifier456"), "OTHER");
        assert_eq!(safe_metric_secret_type("secret\u{1b}[31m"), "OTHER");
        assert_eq!(safe_metric_surface("prompt"), "prompt");
        assert_eq!(safe_metric_surface("private-plugin"), "OTHER");
    }

    #[test]
    fn image_detection_count_does_not_inflate_blocked_operations() {
        let mut metrics = PrivacyMetrics::default();
        aggregate_metric_event(
            &ActivityEvent::new("detect", "image", 3, BTreeMap::new(), None),
            &mut metrics,
        );
        aggregate_metric_event(
            &ActivityEvent::new("block", "image", 1, BTreeMap::new(), None),
            &mut metrics,
        );
        aggregate_metric_event(
            &ActivityEvent::new("block-image", "image", 3, BTreeMap::new(), None),
            &mut metrics,
        );
        assert_eq!(metrics.blocked_occurrences, 1);
        assert_eq!(metrics.blocked_image_occurrences, 3);
    }

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
        assert_eq!(
            safe_target(Path::new("../../outside/secret.env")),
            "secret.env"
        );
    }

    #[test]
    fn safe_target_preserves_only_normalized_project_relative_paths() {
        assert_eq!(
            safe_target(Path::new("config/../secrets.env")),
            "secrets.env"
        );
        assert_eq!(
            safe_target(Path::new("config/nested.env")),
            "config/nested.env"
        );
    }

    #[test]
    fn lexical_normalization_preserves_consecutive_leading_parent_components() {
        assert_eq!(
            normalize_path_lexically(Path::new("../../secret.env")),
            PathBuf::from("../../secret.env")
        );
    }

    #[test]
    fn panic_diagnostics_hide_source_parent_directories() {
        assert_eq!(
            safe_panic_location("/home/builder/pentect/src/main.rs:305:9"),
            "main.rs:305:9"
        );
        assert_eq!(
            safe_panic_location(r"C:\Users\builder\pentect\src\main.rs:305:9"),
            "main.rs:305:9"
        );

        let backtrace = "  0: pentect::run\n             at /home/builder/pentect/src/main.rs:305:9\n             at C:\\Users\\builder\\.cargo\\registry\\src\\lib.rs:42:7\n";
        let sanitized = safe_backtrace(backtrace);
        assert_eq!(
            sanitized,
            "  0: pentect::run\n             at main.rs:305:9\n             at lib.rs:42:7\n"
        );
        assert!(!sanitized.contains("builder"));
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
        for generation in 1..=LOG_ROTATIONS {
            std::fs::write(
                rotated_log_path(&path, generation),
                format!("generation-{generation}"),
            )
            .unwrap();
        }
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"current-generation").unwrap();
        file.set_len(LOG_MAX_BYTES + 1).unwrap();
        write_batch(&path, &["{\"event\":\"after-rotation\"}".to_string()]).unwrap();
        assert!(rotated_log_path(&path, 1).exists());
        let mut previous = std::fs::File::open(rotated_log_path(&path, 1)).unwrap();
        let mut prefix = [0_u8; 18];
        previous.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"current-generation");
        for generation in 2..=LOG_ROTATIONS {
            assert_eq!(
                std::fs::read_to_string(rotated_log_path(&path, generation)).unwrap(),
                format!("generation-{}", generation - 1)
            );
        }
        assert!(std::fs::metadata(&path).unwrap().len() < LOG_MAX_BYTES);
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("after-rotation"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn diagnostic_batch_aggregates_repeats_and_flushes_from_first_seen() {
        let start = Instant::now();
        let mut batch = DiagnosticBatch::default();
        let event = ActivityEvent::diagnostic_counted(
            "warning",
            "openai",
            "request-failed",
            Some("connect"),
            Some("responses"),
            Some("POST"),
            Some(502),
            Some(true),
            Some("test"),
            1,
        );
        batch.push(event.clone(), start);
        batch.push(event, start + Duration::from_secs(4));

        let drained = batch.drain_expired(start + DIAGNOSTIC_BATCH_WINDOW, false);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].count, 2);
        assert_eq!(drained[0].duration_ms, Some(4_000));
        assert!(batch.pending.is_empty());
    }

    #[test]
    fn structured_diagnostics_keep_action_and_classifier_boundaries() {
        let start = Instant::now();
        let mut batch = DiagnosticBatch::default();
        for action in ["diagnostic", "warning"] {
            batch.push(
                ActivityEvent::diagnostic_counted(
                    action,
                    "ocr",
                    "scan-complete",
                    Some("bundled"),
                    Some("image"),
                    Some("SCAN"),
                    None,
                    Some(false),
                    None,
                    3,
                ),
                start,
            );
        }
        let drained = batch.drain_expired(start, true);
        assert_eq!(drained.len(), 2);
        assert!(drained.iter().any(|event| event.action == "diagnostic"));
        assert!(drained.iter().any(|event| event.action == "warning"));
        assert!(drained.iter().all(|event| !serde_json::to_string(event)
            .unwrap()
            .contains("image bytes")));
    }

    #[test]
    fn decode_limit_diagnostic_keeps_only_fixed_classifiers() {
        let event = ActivityEvent::diagnostic(
            "decode",
            "candidate-limit",
            Some("limit"),
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(event.surface, "decode");
        assert_eq!(event.event.as_deref(), Some("candidate-limit"));
        assert_eq!(event.kind.as_deref(), Some("limit"));
        let rendered = serde_json::to_string(&event).unwrap();
        assert!(!rendered.contains("candidate text"));
    }

    #[test]
    fn structured_diagnostics_reject_unlisted_identifier_shaped_input() {
        let event = ActivityEvent::diagnostic(
            "tenantCredential123",
            "httpsApiExampleComPrivateRoute",
            Some("apiKeyMaterial123"),
            Some("accountIdentifier456"),
            Some("SECRETVERB"),
            Some(502),
            Some(false),
            Some("12345678901234567890"),
        );
        let json = serde_json::to_string(&event).unwrap();

        for rejected in [
            "tenantCredential123",
            "httpsApiExampleComPrivateRoute",
            "apiKeyMaterial123",
            "accountIdentifier456",
            "SECRETVERB",
            "12345678901234567890",
        ] {
            assert!(!json.contains(rejected), "persisted rejected field: {json}");
        }
        assert_eq!(event.surface, "unknown");
        assert_eq!(event.event.as_deref(), Some("unknown"));
        assert_eq!(event.kind.as_deref(), Some("unknown"));
        assert_eq!(event.endpoint.as_deref(), Some("unknown"));
        assert_eq!(event.method.as_deref(), Some("unknown"));
        assert_eq!(event.version, None);
    }

    #[test]
    fn emitted_http_diagnostic_identifiers_are_preserved() {
        assert_eq!(diagnostic_surface("claude-app"), "claude-app");
        assert_eq!(
            diagnostic_event("no-protected-connection"),
            "no-protected-connection"
        );
        assert_eq!(diagnostic_kind("plugin"), "plugin");
        for endpoint in [
            "audio-speech",
            "audio-transcription",
            "audio-translation",
            "batch-embed-contents",
            "complete",
            "completions",
            "embed-content",
            "embeddings",
            "image-generation",
            "message-batches",
            "standalone-search",
        ] {
            assert_eq!(diagnostic_endpoint(endpoint), endpoint);
        }
        assert_eq!(diagnostic_kind("response"), "unknown");
    }
}
