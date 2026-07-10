use crate::approve_ui::ApprovalDecision;
use crate::session::session_root;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::Digest;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const PENTECT_DIR: &str = ".pentect";
const APPROVALS_DIR: &str = "approvals";
const APPROVAL_SIGNATURE_SCHEME: &str = "ed25519-v1";
const HEARTBEAT_TRUST_MAX_AGE: Duration = Duration::from_secs(3);
const DECISION_TTL_MS: u128 = 5 * 60 * 1000;

#[derive(Clone, Debug)]
pub(crate) struct ApprovalTicket {
    pub(crate) id: String,
    pub(crate) nonce: String,
    pub(crate) fingerprint: String,
    pub(crate) command: String,
    pub(crate) env_names: Vec<String>,
    pub(crate) secret_files: Vec<String>,
    pub(crate) direct_handles: usize,
    pub(crate) destinations: Vec<String>,
    pub(crate) may_send_network: bool,
    pub(crate) may_write_local_file: bool,
    pub(crate) path: Option<PathBuf>,
}

pub(crate) struct ApprovalTicketDraft {
    pub(crate) fingerprint: String,
    pub(crate) command: String,
    pub(crate) env_names: Vec<String>,
    pub(crate) secret_files: Vec<String>,
    pub(crate) direct_handles: usize,
    pub(crate) destinations: Vec<String>,
    pub(crate) may_send_network: bool,
    pub(crate) may_write_local_file: bool,
}

#[derive(Clone)]
pub(crate) struct ApprovalQueue {
    dirs: ApprovalDirs,
    signer: Option<Arc<SigningKey>>,
}

#[derive(Clone)]
struct ApprovalDirs {
    pending: PathBuf,
    decisions: PathBuf,
    always: PathBuf,
    heartbeat: PathBuf,
    dashboard_key: PathBuf,
    history: PathBuf,
}

struct DashboardHeartbeat {
    key: VerifyingKey,
}

impl ApprovalQueue {
    pub(crate) fn open(session: &str) -> Result<Self, String> {
        let root = session_root(session)
            .map_err(|e| e.to_string())?
            .join("approvals");
        let dirs = ApprovalDirs {
            pending: root.join("pending"),
            decisions: root.join("decisions"),
            always: root.join("always"),
            heartbeat: root.join("dashboard.heartbeat"),
            dashboard_key: root.join("dashboard.pub"),
            history: root.join("history.log"),
        };
        fs::create_dir_all(&dirs.pending)
            .map_err(|e| format!("could not create '{}': {e}", dirs.pending.display()))?;
        fs::create_dir_all(&dirs.decisions)
            .map_err(|e| format!("could not create '{}': {e}", dirs.decisions.display()))?;
        fs::create_dir_all(&dirs.always)
            .map_err(|e| format!("could not create '{}': {e}", dirs.always.display()))?;
        Ok(Self { dirs, signer: None })
    }

    pub(crate) fn open_dashboard(session: &str) -> Result<Self, String> {
        let mut queue = Self::open(session)?;
        let signer = Arc::new(new_dashboard_signer()?);
        let public_key = public_key_hex(&signer.verifying_key());
        fs::write(&queue.dirs.dashboard_key, format!("{public_key}\n")).map_err(|e| {
            format!(
                "could not write '{}': {e}",
                queue.dirs.dashboard_key.display()
            )
        })?;
        queue.signer = Some(signer);
        Ok(queue)
    }

    pub(crate) fn heartbeat(&self) -> Result<(), String> {
        let time_ms = unix_millis();
        let Some(signer) = &self.signer else {
            return Ok(());
        };
        let key = public_key_hex(&signer.verifying_key());
        let payload = heartbeat_payload(time_ms, &key);
        let mut body = format!("time={time_ms}\nkey={key}\n");
        body.push_str(&format!("signature={}\n", sign_hex(signer, &payload)));
        fs::write(&self.dirs.heartbeat, body)
            .map_err(|e| format!("could not write '{}': {e}", self.dirs.heartbeat.display()))
    }

    pub(crate) fn dashboard_alive(&self, max_age: Duration) -> bool {
        self.dashboard_heartbeat(max_age).is_some()
    }

    pub(crate) fn always_granted(&self, fingerprint: &str) -> bool {
        let Some(heartbeat) = self.dashboard_heartbeat(HEARTBEAT_TRUST_MAX_AGE) else {
            return false;
        };
        let path = self.dirs.always.join(fingerprint);
        let Ok(text) = fs::read_to_string(&path) else {
            return false;
        };
        self.verify_always_grant(fingerprint, &text, &heartbeat.key)
            .unwrap_or(false)
    }

    pub(crate) fn remember_always(&self, fingerprint: &str) -> Result<(), String> {
        let Some(signer) = &self.signer else {
            return Ok(());
        };
        let created_at_ms = unix_millis();
        let payload = always_payload(fingerprint, created_at_ms);
        let signature = sign_hex(signer, &payload);
        let body = json!({
            "scheme": APPROVAL_SIGNATURE_SCHEME,
            "kind": "always",
            "fingerprint": fingerprint,
            "created_at_ms": created_at_ms.to_string(),
            "signer": public_key_hex(&signer.verifying_key()),
            "signature": signature,
        });
        fs::write(self.dirs.always.join(fingerprint), body.to_string())
            .map_err(|e| format!("could not write approval: {e}"))
    }

    pub(crate) fn submit(&self, ticket: &ApprovalTicket) -> Result<(), String> {
        let final_path = self.pending_path(&ticket.id);
        let tmp_path = self.dirs.pending.join(format!("{}.json.tmp", ticket.id));
        fs::write(&tmp_path, ticket_json(ticket).to_string())
            .map_err(|e| format!("could not write approval request: {e}"))?;
        fs::rename(&tmp_path, &final_path).map_err(|e| {
            let _ = remove_file_if_exists(&tmp_path);
            format!("could not publish approval request: {e}")
        })
    }

    pub(crate) fn wait_for_decision(
        &self,
        ticket: &ApprovalTicket,
        heartbeat_max_age: Duration,
    ) -> Result<ApprovalDecision, String> {
        loop {
            if let Some(decision) = self.read_decision(ticket, heartbeat_max_age)? {
                if decision == ApprovalDecision::Always {
                    self.remember_always(&ticket.fingerprint)?;
                    self.remember_project_always(ticket)?;
                }
                remove_file_if_exists(&self.pending_path(&ticket.id))?;
                remove_file_if_exists(&self.decision_path(&ticket.id))?;
                return Ok(decision);
            }
            if !self.dashboard_alive(heartbeat_max_age) {
                self.finish(ticket, ApprovalDecision::Decline, "auto")?;
                return Ok(ApprovalDecision::Decline);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    pub(crate) fn next_pending(&self) -> Result<Option<ApprovalTicket>, String> {
        let mut entries = fs::read_dir(&self.dirs.pending)
            .map_err(|e| format!("could not read '{}': {e}", self.dirs.pending.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("could not read approval queue: {e}"))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let text = match fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("could not read '{}': {e}", path.display())),
            };
            let mut ticket = match ticket_from_json(&text) {
                Ok(ticket) => ticket,
                Err(_) => {
                    let _ = remove_file_if_exists(&path);
                    continue;
                }
            };
            ticket.path = Some(path);
            return Ok(Some(ticket));
        }
        Ok(None)
    }

    pub(crate) fn decide(
        &self,
        ticket: &ApprovalTicket,
        decision: ApprovalDecision,
        actor: &str,
    ) -> Result<(), String> {
        self.write_decision(ticket, decision)?;
        if decision == ApprovalDecision::Always {
            self.remember_always(&ticket.fingerprint)?;
            self.remember_project_always(ticket)?;
        }
        self.append_history(ticket, decision, actor)?;
        remove_file_if_exists(&self.pending_path(&ticket.id))?;
        if let Some(path) = &ticket.path {
            remove_file_if_exists(path)?;
        }
        Ok(())
    }

    pub(crate) fn record(
        &self,
        ticket: &ApprovalTicket,
        decision: ApprovalDecision,
        actor: &str,
    ) -> Result<(), String> {
        self.finish(ticket, decision, actor)
    }

    pub(crate) fn recent_history(&self, limit: usize) -> Result<Vec<String>, String> {
        let Ok(mut file) = fs::File::open(&self.dirs.history) else {
            return Ok(Vec::new());
        };
        let len = file
            .metadata()
            .map_err(|e| format!("could not stat '{}': {e}", self.dirs.history.display()))?
            .len();
        let window = len.min(16 * 1024);
        file.seek(SeekFrom::Start(len - window))
            .map_err(|e| format!("could not seek '{}': {e}", self.dirs.history.display()))?;
        let mut bytes = Vec::with_capacity(window as usize);
        file.read_to_end(&mut bytes)
            .map_err(|e| format!("could not read '{}': {e}", self.dirs.history.display()))?;
        let mut text = String::from_utf8_lossy(&bytes).into_owned();
        if window < len {
            if let Some(index) = text.find('\n') {
                text.drain(..=index);
            }
        }
        let mut lines = text
            .lines()
            .rev()
            .take(limit)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        lines.reverse();
        Ok(lines)
    }

    fn finish(
        &self,
        ticket: &ApprovalTicket,
        decision: ApprovalDecision,
        actor: &str,
    ) -> Result<(), String> {
        if decision == ApprovalDecision::Always {
            self.remember_always(&ticket.fingerprint)?;
            self.remember_project_always(ticket)?;
        }
        self.append_history(ticket, decision, actor)?;
        remove_file_if_exists(&self.pending_path(&ticket.id))?;
        remove_file_if_exists(&self.decision_path(&ticket.id))?;
        if let Some(path) = &ticket.path {
            remove_file_if_exists(path)?;
        }
        Ok(())
    }

    fn append_history(
        &self,
        ticket: &ApprovalTicket,
        decision: ApprovalDecision,
        actor: &str,
    ) -> Result<(), String> {
        let line = format!(
            "{} {} {} {}\n",
            unix_millis(),
            actor,
            decision.as_str(),
            ticket.short()
        );
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.dirs.history)
            .map_err(|e| format!("could not open '{}': {e}", self.dirs.history.display()))?;
        file.write_all(line.as_bytes())
            .map_err(|e| format!("could not write approval history: {e}"))?;
        self.append_project_history(ticket, decision, actor)
    }

    fn append_project_history(
        &self,
        ticket: &ApprovalTicket,
        decision: ApprovalDecision,
        actor: &str,
    ) -> Result<(), String> {
        let dir = project_approvals_dir()?;
        let line = format!(
            "{} actor={} decision={} {}\n  command={}\n",
            unix_millis(),
            actor,
            decision.as_str(),
            ticket.short(),
            single_line(&ticket.command)
        );
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("history.log"))
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .map_err(|e| format!("could not write project approval history: {e}"))
    }

    fn remember_project_always(&self, ticket: &ApprovalTicket) -> Result<(), String> {
        let dir = project_approvals_dir()?;
        let path = dir.join("always.toml");
        let existing = fs::read_to_string(&path).unwrap_or_default();
        if existing.contains(&format!(
            "fingerprint = {}",
            toml_string(&ticket.fingerprint)
        )) {
            return Ok(());
        }
        let entry = format!(
            "\n[[always]]\nfingerprint = {}\ncommand = {}\nsummary = {}\ncreated_at_ms = {}\n",
            toml_string(&ticket.fingerprint),
            toml_string(&ticket.command),
            toml_string(&ticket.short()),
            unix_millis()
        );
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| file.write_all(entry.as_bytes()))
            .map_err(|e| format!("could not write project always approvals: {e}"))
    }

    fn write_decision(
        &self,
        ticket: &ApprovalTicket,
        decision: ApprovalDecision,
    ) -> Result<(), String> {
        let Some(signer) = &self.signer else {
            return Err("approval decisions require a dashboard signing key".to_string());
        };
        let created_at_ms = unix_millis();
        let expires_at_ms = created_at_ms + DECISION_TTL_MS;
        let payload = decision_payload(ticket, decision, created_at_ms, expires_at_ms);
        let body = json!({
            "scheme": APPROVAL_SIGNATURE_SCHEME,
            "kind": "decision",
            "ticket_id": ticket.id,
            "ticket_nonce": ticket.nonce,
            "fingerprint": ticket.fingerprint,
            "decision": decision.as_str(),
            "created_at_ms": created_at_ms.to_string(),
            "expires_at_ms": expires_at_ms.to_string(),
            "signer": public_key_hex(&signer.verifying_key()),
            "signature": sign_hex(signer, &payload),
        });
        fs::write(self.decision_path(&ticket.id), body.to_string())
            .map_err(|e| format!("could not write approval decision: {e}"))
    }

    fn read_decision(
        &self,
        ticket: &ApprovalTicket,
        heartbeat_max_age: Duration,
    ) -> Result<Option<ApprovalDecision>, String> {
        let path = self.decision_path(&ticket.id);
        if !path.exists() {
            return Ok(None);
        }
        let text = fs::read_to_string(&path)
            .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
        let Some(heartbeat) = self.dashboard_heartbeat(heartbeat_max_age) else {
            return Err(
                "approval decision exists but no trusted dashboard heartbeat is alive".to_string(),
            );
        };
        self.verify_decision(ticket, &text, &heartbeat.key)
            .map(Some)
    }

    fn dashboard_heartbeat(&self, max_age: Duration) -> Option<DashboardHeartbeat> {
        let text = fs::read_to_string(&self.dirs.heartbeat).ok()?;
        let mut key = None;
        let mut key_hex = None;
        let mut time_ms = None;
        let mut signature = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("time=") {
                time_ms = value.trim().parse::<u128>().ok();
            } else if let Some(value) = line.strip_prefix("key=") {
                let value = value.trim();
                key = verifying_key_from_hex(value).ok();
                key_hex = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("signature=") {
                signature = Some(value.trim().to_string());
            }
        }
        let key = key?;
        let key_hex = key_hex?;
        let pinned = self.pinned_dashboard_key()?;
        if pinned.to_bytes() != key.to_bytes() {
            return None;
        }
        let time_ms = time_ms?;
        let signature = signature?;
        let now = unix_millis();
        let max_age_ms = max_age.as_millis();
        if time_ms > now.saturating_add(max_age_ms) {
            return None;
        }
        if now.saturating_sub(time_ms) > max_age_ms {
            return None;
        }
        let payload = heartbeat_payload(time_ms, &key_hex);
        verify_signature(&key, &payload, &signature).ok()?;
        Some(DashboardHeartbeat { key })
    }

    fn pinned_dashboard_key(&self) -> Option<VerifyingKey> {
        let text = fs::read_to_string(&self.dirs.dashboard_key).ok()?;
        verifying_key_from_hex(text.trim()).ok()
    }

    fn verify_decision(
        &self,
        ticket: &ApprovalTicket,
        text: &str,
        heartbeat_key: &VerifyingKey,
    ) -> Result<ApprovalDecision, String> {
        let value: Value = serde_json::from_str(text)
            .map_err(|e| format!("approval decision is unsigned or malformed: {e}"))?;
        require_json_string(&value, "scheme", APPROVAL_SIGNATURE_SCHEME)?;
        require_json_string(&value, "kind", "decision")?;
        require_json_string(&value, "ticket_id", &ticket.id)?;
        require_json_string(&value, "ticket_nonce", &ticket.nonce)?;
        require_json_string(&value, "fingerprint", &ticket.fingerprint)?;
        let decision = decision_from_str(&string_json(&value, "decision")?)
            .ok_or_else(|| "approval decision is unknown".to_string())?;
        let created_at_ms = u128_json(&value, "created_at_ms")?;
        let expires_at_ms = u128_json(&value, "expires_at_ms")?;
        if unix_millis() > expires_at_ms {
            return Err("approval decision expired".to_string());
        }
        let signer = verifying_key_from_hex(&string_json(&value, "signer")?)?;
        if signer.to_bytes() != heartbeat_key.to_bytes() {
            return Err("approval decision was not signed by the active dashboard".to_string());
        }
        let payload = decision_payload(ticket, decision, created_at_ms, expires_at_ms);
        verify_signature(&signer, &payload, &string_json(&value, "signature")?)?;
        Ok(decision)
    }

    fn verify_always_grant(
        &self,
        fingerprint: &str,
        text: &str,
        heartbeat_key: &VerifyingKey,
    ) -> Result<bool, String> {
        let value: Value = serde_json::from_str(text)
            .map_err(|e| format!("approval grant is unsigned or malformed: {e}"))?;
        require_json_string(&value, "scheme", APPROVAL_SIGNATURE_SCHEME)?;
        require_json_string(&value, "kind", "always")?;
        require_json_string(&value, "fingerprint", fingerprint)?;
        let created_at_ms = u128_json(&value, "created_at_ms")?;
        let signer = verifying_key_from_hex(&string_json(&value, "signer")?)?;
        if signer.to_bytes() != heartbeat_key.to_bytes() {
            return Ok(false);
        }
        let payload = always_payload(fingerprint, created_at_ms);
        verify_signature(&signer, &payload, &string_json(&value, "signature")?)?;
        Ok(true)
    }

    fn pending_path(&self, id: &str) -> PathBuf {
        self.dirs.pending.join(format!("{id}.json"))
    }

    fn decision_path(&self, id: &str) -> PathBuf {
        self.dirs.decisions.join(format!("{id}.txt"))
    }
}

impl ApprovalTicket {
    pub(crate) fn new(draft: ApprovalTicketDraft) -> Self {
        let nonce = random_hex_or_fallback("approval-ticket");
        let mut ticket = Self {
            id: String::new(),
            nonce,
            fingerprint: draft.fingerprint,
            command: draft.command,
            env_names: draft.env_names,
            secret_files: draft.secret_files,
            direct_handles: draft.direct_handles,
            destinations: draft.destinations,
            may_send_network: draft.may_send_network,
            may_write_local_file: draft.may_write_local_file,
            path: None,
        };
        ticket.id = ticket_id(&ticket);
        ticket
    }

    pub(crate) fn short(&self) -> String {
        let mut bits = Vec::new();
        if !self.env_names.is_empty() {
            bits.push(self.env_names.join(","));
        }
        if !self.secret_files.is_empty() {
            bits.push(format!("{} file(s)", self.secret_files.len()));
        }
        if self.direct_handles > 0 {
            bits.push(format!("{} handle(s)", self.direct_handles));
        }
        if self.may_write_local_file {
            bits.push("write".to_string());
        }
        if bits.is_empty() {
            "no-secret".to_string()
        } else {
            bits.join("+")
        }
    }
}

impl ApprovalDecision {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ApprovalDecision::Once => "once",
            ApprovalDecision::Always => "always",
            ApprovalDecision::Decline => "decline",
        }
    }
}

pub(crate) fn ticket_summary(ticket: &ApprovalTicket) -> String {
    let mut lines = vec!["command".to_string(), ticket.command.clone()];
    if !ticket.env_names.is_empty() {
        lines.push(String::new());
        lines.push(format!("secret {}", ticket.env_names.join(", ")));
    }
    if !ticket.secret_files.is_empty() {
        lines.push(String::new());
        lines.push(format!("file {}", ticket.secret_files.join(", ")));
    }
    if ticket.direct_handles > 0 {
        lines.push(format!("handles {}", ticket.direct_handles));
    }
    if !ticket.destinations.is_empty() {
        lines.push(format!("send {}", ticket.destinations.join(", ")));
    } else if ticket.may_send_network {
        lines.push("send possible".to_string());
    }
    if ticket.may_write_local_file {
        lines.push("write local file".to_string());
    }
    lines.join("\n")
}

fn ticket_json(ticket: &ApprovalTicket) -> Value {
    json!({
        "id": ticket.id,
        "nonce": ticket.nonce,
        "fingerprint": ticket.fingerprint,
        "command": ticket.command,
        "env": ticket.env_names,
        "files": ticket.secret_files,
        "handles": ticket.direct_handles,
        "destinations": ticket.destinations,
        "network": ticket.may_send_network,
        "local_write": ticket.may_write_local_file,
    })
}

fn ticket_from_json(text: &str) -> Result<ApprovalTicket, String> {
    let value: Value =
        serde_json::from_str(text).map_err(|e| format!("approval request is malformed: {e}"))?;
    let ticket = ApprovalTicket {
        id: string_json(&value, "id")?,
        nonce: string_json(&value, "nonce")?,
        fingerprint: string_json(&value, "fingerprint")?,
        command: string_json(&value, "command")?,
        env_names: string_array_json(&value, "env")?,
        secret_files: string_array_json(&value, "files")?,
        direct_handles: value
            .get("handles")
            .and_then(Value::as_u64)
            .unwrap_or_default() as usize,
        destinations: string_array_json(&value, "destinations")?,
        may_send_network: value
            .get("network")
            .and_then(Value::as_bool)
            .unwrap_or_default(),
        may_write_local_file: value
            .get("local_write")
            .and_then(Value::as_bool)
            .unwrap_or_default(),
        path: None,
    };
    let expected = ticket_id(&ticket);
    if ticket.id != expected {
        return Err("approval request id does not match its signed content".to_string());
    }
    Ok(ticket)
}

fn ticket_id(ticket: &ApprovalTicket) -> String {
    let digest = sha2::Sha256::digest(canonical_ticket_payload(ticket).as_bytes());
    data_encoding::HEXLOWER.encode(&digest[..16])
}

fn canonical_ticket_payload(ticket: &ApprovalTicket) -> String {
    let mut out = String::new();
    canonical_field(&mut out, "kind", "approval-ticket-v1");
    canonical_field(&mut out, "nonce", &ticket.nonce);
    canonical_field(&mut out, "fingerprint", &ticket.fingerprint);
    canonical_field(&mut out, "command", &ticket.command);
    canonical_list(&mut out, "env", &ticket.env_names);
    canonical_list(&mut out, "files", &ticket.secret_files);
    canonical_field(&mut out, "handles", &ticket.direct_handles.to_string());
    canonical_list(&mut out, "destinations", &ticket.destinations);
    canonical_field(&mut out, "network", bool_str(ticket.may_send_network));
    canonical_field(
        &mut out,
        "local_write",
        bool_str(ticket.may_write_local_file),
    );
    out
}

fn decision_payload(
    ticket: &ApprovalTicket,
    decision: ApprovalDecision,
    created_at_ms: u128,
    expires_at_ms: u128,
) -> String {
    let mut out = String::new();
    canonical_field(&mut out, "kind", "approval-decision-v1");
    canonical_field(&mut out, "ticket_id", &ticket.id);
    canonical_field(&mut out, "ticket_nonce", &ticket.nonce);
    canonical_field(&mut out, "fingerprint", &ticket.fingerprint);
    canonical_field(&mut out, "decision", decision.as_str());
    canonical_field(&mut out, "created_at_ms", &created_at_ms.to_string());
    canonical_field(&mut out, "expires_at_ms", &expires_at_ms.to_string());
    out
}

fn always_payload(fingerprint: &str, created_at_ms: u128) -> String {
    let mut out = String::new();
    canonical_field(&mut out, "kind", "approval-always-v1");
    canonical_field(&mut out, "fingerprint", fingerprint);
    canonical_field(&mut out, "created_at_ms", &created_at_ms.to_string());
    out
}

fn heartbeat_payload(time_ms: u128, key_hex: &str) -> String {
    let mut out = String::new();
    canonical_field(&mut out, "kind", "approval-heartbeat-v1");
    canonical_field(&mut out, "time_ms", &time_ms.to_string());
    canonical_field(&mut out, "key", key_hex);
    out
}

fn canonical_list(out: &mut String, key: &str, values: &[String]) {
    canonical_field(out, key, &values.join("\u{1f}"));
}

fn canonical_field(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push(':');
    out.push_str(&value.len().to_string());
    out.push(':');
    out.push_str(value);
    out.push('\n');
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn new_dashboard_signer() -> Result<SigningKey, String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| format!("could not generate approval signing key: {e}"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn random_hex_or_fallback(label: &str) -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_ok() {
        return data_encoding::HEXLOWER.encode(&bytes);
    }
    let fallback = format!("{label}:{}:{}", unix_millis(), std::process::id());
    let digest = sha2::Sha256::digest(fallback.as_bytes());
    data_encoding::HEXLOWER.encode(&digest[..16])
}

fn public_key_hex(key: &VerifyingKey) -> String {
    data_encoding::HEXLOWER.encode(&key.to_bytes())
}

fn sign_hex(signer: &SigningKey, payload: &str) -> String {
    let signature: Signature = signer.sign(payload.as_bytes());
    data_encoding::HEXLOWER.encode(&signature.to_bytes())
}

fn verify_signature(key: &VerifyingKey, payload: &str, signature_hex: &str) -> Result<(), String> {
    let signature_bytes = decode_hex_array::<64>(signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify(payload.as_bytes(), &signature)
        .map_err(|_| "approval signature is invalid".to_string())
}

fn verifying_key_from_hex(value: &str) -> Result<VerifyingKey, String> {
    let bytes = decode_hex_array::<32>(value)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "approval public key is invalid".to_string())
}

fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let bytes = data_encoding::HEXLOWER
        .decode(value.as_bytes())
        .map_err(|_| "approval signature material is not valid lowercase hex".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "approval signature material has the wrong length".to_string())
}

fn require_json_string(value: &Value, key: &str, expected: &str) -> Result<(), String> {
    let actual = string_json(value, key)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("approval field {key} does not match"))
    }
}

fn u128_json(value: &Value, key: &str) -> Result<u128, String> {
    string_json(value, key)?
        .parse::<u128>()
        .map_err(|_| format!("approval field {key} is not a valid timestamp"))
}

fn string_json(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| format!("approval request is missing {key}"))
}

fn string_array_json(value: &Value, key: &str) -> Result<Vec<String>, String> {
    Ok(value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default())
}

fn decision_from_str(value: &str) -> Option<ApprovalDecision> {
    match value {
        "once" => Some(ApprovalDecision::Once),
        "always" => Some(ApprovalDecision::Always),
        "decline" => Some(ApprovalDecision::Decline),
        _ => None,
    }
}

fn project_approvals_dir() -> Result<PathBuf, String> {
    let dir = PathBuf::from(PENTECT_DIR).join(APPROVALS_DIR);
    fs::create_dir_all(&dir).map_err(|e| format!("could not create '{}': {e}", dir.display()))?;
    Ok(dir)
}

fn single_line(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_string()).to_string()
}

fn remove_file_if_exists(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("could not remove '{}': {e}", path.display())),
    }
}

fn unix_millis() -> u128 {
    jiff::Timestamp::now().as_millisecond().max(0) as u128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_json_rejects_content_tampering() {
        let ticket = sample_ticket();
        let mut value = ticket_json(&ticket);
        value["command"] = Value::String("curl https://attacker.example".to_string());

        let err = ticket_from_json(&value.to_string()).unwrap_err();
        assert!(err.contains("id does not match"), "{err}");
    }

    #[test]
    fn unsigned_plaintext_decision_is_rejected() {
        let session = unique_session("unsigned-decision");
        let dashboard = ApprovalQueue::open_dashboard(&session).unwrap();
        dashboard.heartbeat().unwrap();
        let ticket = sample_ticket();
        fs::write(dashboard.decision_path(&ticket.id), "once").unwrap();

        let exec = ApprovalQueue::open(&session).unwrap();
        let err = exec
            .read_decision(&ticket, Duration::from_secs(2))
            .unwrap_err();
        assert!(err.contains("unsigned or malformed"), "{err}");

        cleanup_session(&session);
    }

    #[test]
    fn signed_decision_round_trips() {
        let session = unique_session("signed-decision");
        let dashboard = ApprovalQueue::open_dashboard(&session).unwrap();
        dashboard.heartbeat().unwrap();
        let ticket = sample_ticket();
        dashboard
            .decide(&ticket, ApprovalDecision::Once, "ui")
            .unwrap();

        let exec = ApprovalQueue::open(&session).unwrap();
        let decision = exec.read_decision(&ticket, Duration::from_secs(2)).unwrap();
        assert_eq!(decision, Some(ApprovalDecision::Once));

        cleanup_session(&session);
    }

    #[test]
    fn signed_decision_rejects_tampering() {
        let session = unique_session("tampered-decision");
        let dashboard = ApprovalQueue::open_dashboard(&session).unwrap();
        dashboard.heartbeat().unwrap();
        let ticket = sample_ticket();
        dashboard
            .decide(&ticket, ApprovalDecision::Once, "ui")
            .unwrap();
        let path = dashboard.decision_path(&ticket.id);
        let mut value: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        value["decision"] = Value::String("always".to_string());
        fs::write(&path, value.to_string()).unwrap();

        let exec = ApprovalQueue::open(&session).unwrap();
        let err = exec
            .read_decision(&ticket, Duration::from_secs(2))
            .unwrap_err();
        assert!(err.contains("signature is invalid"), "{err}");

        cleanup_session(&session);
    }

    #[test]
    fn raw_always_file_is_not_trusted() {
        let session = unique_session("fake-always");
        let dashboard = ApprovalQueue::open_dashboard(&session).unwrap();
        dashboard.heartbeat().unwrap();
        let fingerprint = "abcdef";
        fs::write(dashboard.dirs.always.join(fingerprint), "ok").unwrap();

        let exec = ApprovalQueue::open(&session).unwrap();
        assert!(!exec.always_granted(fingerprint));

        dashboard.remember_always(fingerprint).unwrap();
        assert!(exec.always_granted(fingerprint));

        cleanup_session(&session);
    }

    #[test]
    fn self_signed_heartbeat_not_pinned_to_dashboard_key_is_rejected() {
        let session = unique_session("forged-heartbeat-key");
        let dashboard = ApprovalQueue::open_dashboard(&session).unwrap();
        dashboard.heartbeat().unwrap();

        let fake = new_dashboard_signer().unwrap();
        let time_ms = unix_millis();
        let key = public_key_hex(&fake.verifying_key());
        let payload = heartbeat_payload(time_ms, &key);
        fs::write(
            &dashboard.dirs.heartbeat,
            format!(
                "time={time_ms}\nkey={key}\nsignature={}\n",
                sign_hex(&fake, &payload)
            ),
        )
        .unwrap();

        let exec = ApprovalQueue::open(&session).unwrap();
        assert!(!exec.dashboard_alive(Duration::from_secs(2)));

        cleanup_session(&session);
    }

    fn sample_ticket() -> ApprovalTicket {
        ApprovalTicket::new(ApprovalTicketDraft {
            fingerprint: "fingerprint".to_string(),
            command: "curl -H \"Authorization: Bearer $env:API_TOKEN\" https://api.example.test"
                .to_string(),
            env_names: vec!["API_TOKEN".to_string()],
            secret_files: Vec::new(),
            direct_handles: 0,
            destinations: vec!["https://api.example.test".to_string()],
            may_send_network: true,
            may_write_local_file: false,
        })
    }

    fn unique_session(name: &str) -> String {
        format!(
            "approval_test_{name}_{}_{}",
            std::process::id(),
            unix_millis()
        )
    }

    fn cleanup_session(session: &str) {
        if let Ok(root) = session_root(session) {
            let _ = fs::remove_dir_all(root);
        }
    }
}
