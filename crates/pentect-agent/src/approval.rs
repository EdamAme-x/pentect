use crate::approve_ui::ApprovalDecision;
use crate::project_config::{load_project_config, set_approval_required};
use crate::session::session_root;
use anyhow::Context;
use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::Digest;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
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
    pub(crate) direct_handles: usize,
    pub(crate) destinations: Vec<String>,
    pub(crate) network_like: bool,
    pub(crate) materialize_like: bool,
    pub(crate) path: Option<PathBuf>,
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
    bypass_all: bool,
}

#[derive(Clone)]
struct WebState {
    queue: ApprovalQueue,
    session: Arc<str>,
    port: u16,
    bypass_all: Arc<AtomicBool>,
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

    pub(crate) fn heartbeat(&self, port: Option<u16>, bypass_all: bool) -> Result<(), String> {
        let mut body = format!("time={}\n", unix_millis());
        if let Some(signer) = &self.signer {
            body.push_str(&format!(
                "key={}\n",
                public_key_hex(&signer.verifying_key())
            ));
        }
        if let Some(port) = port {
            body.push_str(&format!("port={port}\n"));
        }
        body.push_str(if bypass_all {
            "bypass=true\n"
        } else {
            "bypass=false\n"
        });
        fs::write(&self.dirs.heartbeat, body)
            .map_err(|e| format!("could not write '{}': {e}", self.dirs.heartbeat.display()))
    }

    pub(crate) fn dashboard_alive(&self, max_age: Duration) -> bool {
        let Ok(meta) = fs::metadata(&self.dirs.heartbeat) else {
            return false;
        };
        let Ok(modified) = meta.modified() else {
            return false;
        };
        modified.elapsed().is_ok_and(|age| age <= max_age)
    }

    pub(crate) fn dashboard_bypass_alive(&self, max_age: Duration) -> bool {
        self.dashboard_heartbeat(max_age)
            .is_some_and(|heartbeat| heartbeat.bypass_all)
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
            if self.dashboard_bypass_alive(heartbeat_max_age) {
                self.finish(ticket, ApprovalDecision::Once, "bypass")?;
                return Ok(ApprovalDecision::Once);
            }
            if !load_project_config()
                .map_err(|e| e.to_string())?
                .approval_required
            {
                self.finish(ticket, ApprovalDecision::Once, "config")?;
                return Ok(ApprovalDecision::Once);
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
        let Ok(text) = fs::read_to_string(&self.dirs.history) else {
            return Ok(Vec::new());
        };
        let mut lines = text
            .lines()
            .rev()
            .take(limit)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        lines.reverse();
        Ok(lines)
    }

    pub(crate) fn serve_web(
        &self,
        session: &str,
        port: u16,
        _heartbeat_max_age: Duration,
    ) -> crate::Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("could not start web dashboard runtime")?;
        runtime.block_on(self.serve_web_async(session.to_string(), port))
    }

    async fn serve_web_async(&self, session: String, port: u16) -> crate::Result<()> {
        let bypass_all = Arc::new(AtomicBool::new(false));
        let state = WebState {
            queue: self.clone(),
            session: Arc::from(session),
            port,
            bypass_all,
        };
        let heartbeat_state = state.clone();
        tokio::spawn(async move {
            loop {
                let _ = heartbeat_state.queue.heartbeat(
                    Some(heartbeat_state.port),
                    heartbeat_state.bypass_all.load(Ordering::Relaxed),
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
        let app = Router::new()
            .route("/", get(web_index))
            .route("/decide", get(web_decide))
            .route("/bypass", get(web_bypass))
            .route("/config", get(web_config))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .with_context(|| format!("could not bind 127.0.0.1:{port}"))?;
        println!("pentect web dashboard: http://127.0.0.1:{port}");
        axum::serve(listener, app)
            .await
            .context("web dashboard failed")
    }

    fn render_html(&self, session: &str, bypass_all: bool) -> Result<String, String> {
        let pending = self.next_pending()?;
        let history = self.recent_history(8)?;
        let config = load_project_config().map_err(|e| e.to_string())?;
        let mut html = String::from(
            "<!doctype html><meta name=viewport content=\"width=device-width,initial-scale=1\"><meta http-equiv=refresh content=1><title>pentect</title>\
             <style>body{font:15px system-ui;margin:32px;max-width:880px;background:#0b0d10;color:#f4f7fb}pre{white-space:pre-wrap;background:#151922;padding:16px;border:1px solid #2b3340;border-radius:8px}button{min-height:40px;padding:0 16px;margin:4px 8px 4px 0;border-radius:8px;border:1px solid #394452;background:#1b2230;color:#f4f7fb}.good{color:#75e0a7}.bad{color:#ff9d9d}.muted{color:#9ca7b4}</style>",
        );
        html.push_str(&format!(
            "<h1>pentect</h1><p class=muted>session {}</p><p>approval: <b>{}</b> · bypass: <b>{}</b></p>",
            esc(session),
            if config.approval_required { "required" } else { "optional" },
            if bypass_all { "on" } else { "off" }
        ));
        html.push_str("<p>");
        html.push_str(&format!(
            "<a href=\"/bypass?enabled={}\"><button>{}</button></a>",
            if bypass_all { "false" } else { "true" },
            if bypass_all {
                "disable bypass"
            } else {
                "bypass all"
            }
        ));
        html.push_str(&format!(
            "<a href=\"/config?approval_required={}\"><button>{}</button></a>",
            if config.approval_required {
                "false"
            } else {
                "true"
            },
            if config.approval_required {
                "make optional"
            } else {
                "require approval"
            }
        ));
        html.push_str("</p>");
        if let Some(ticket) = pending {
            html.push_str("<h2>approval</h2><pre>");
            html.push_str(&esc(&ticket_summary(&ticket)));
            html.push_str("</pre>");
            for (label, decision) in [
                ("once", "once"),
                ("always", "always"),
                ("decline", "decline"),
            ] {
                html.push_str(&format!(
                    "<a href=\"/decide?id={}&decision={}\"><button>{}</button></a>",
                    esc_attr(&ticket.id),
                    decision,
                    label
                ));
            }
        } else {
            html.push_str("<h2>waiting</h2><p>No pending approvals.</p>");
        }
        if !history.is_empty() {
            html.push_str("<h2>history</h2><pre>");
            html.push_str(&esc(&history.join("\n")));
            html.push_str("</pre>");
        }
        Ok(html)
    }

    fn pending_by_id(&self, id: &str) -> Result<Option<ApprovalTicket>, String> {
        let path = self.pending_path(id);
        if !path.exists() {
            return Ok(None);
        }
        let text = fs::read_to_string(&path)
            .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
        let mut ticket = ticket_from_json(&text)?;
        ticket.path = Some(path);
        Ok(Some(ticket))
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
        if !self.dashboard_alive(max_age) {
            return None;
        }
        let text = fs::read_to_string(&self.dirs.heartbeat).ok()?;
        let mut key = None;
        let mut bypass_all = false;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("key=") {
                key = verifying_key_from_hex(value.trim()).ok();
            } else if line.trim() == "bypass=true" {
                bypass_all = true;
            }
        }
        let key = key.or_else(|| {
            fs::read_to_string(&self.dirs.dashboard_key)
                .ok()
                .and_then(|text| verifying_key_from_hex(text.trim()).ok())
        })?;
        Some(DashboardHeartbeat { key, bypass_all })
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

async fn web_index(State(state): State<WebState>) -> Response {
    match state.queue.render_html(
        state.session.as_ref(),
        state.bypass_all.load(Ordering::Relaxed),
    ) {
        Ok(html) => Html(html).into_response(),
        Err(e) => web_error(e),
    }
}

async fn web_decide(State(state): State<WebState>, RawQuery(query): RawQuery) -> Response {
    let result = (|| {
        let query = query.unwrap_or_default();
        let id = query_param(&query, "id").unwrap_or_default();
        let decision = query_param(&query, "decision")
            .and_then(|value| decision_from_str(&value))
            .unwrap_or(ApprovalDecision::Decline);
        if let Some(ticket) = state.queue.pending_by_id(&id)? {
            state.queue.decide(&ticket, decision, "web")?;
        }
        Ok(())
    })();
    redirect_or_error(result)
}

async fn web_bypass(State(state): State<WebState>, RawQuery(query): RawQuery) -> Response {
    let query = query.unwrap_or_default();
    let enabled = query_param(&query, "enabled").is_some_and(|value| value == "true");
    state.bypass_all.store(enabled, Ordering::Relaxed);
    let result = state.queue.heartbeat(Some(state.port), enabled);
    redirect_or_error(result)
}

async fn web_config(State(_state): State<WebState>, RawQuery(query): RawQuery) -> Response {
    let query = query.unwrap_or_default();
    let required = query_param(&query, "approval_required").is_none_or(|value| value != "false");
    redirect_or_error(
        set_approval_required(required)
            .map(|_| ())
            .map_err(|e| e.to_string()),
    )
}

fn redirect_or_error(result: Result<(), String>) -> Response {
    match result {
        Ok(()) => Redirect::to("/").into_response(),
        Err(e) => web_error(e),
    }
}

fn web_error(message: String) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
}

impl ApprovalTicket {
    pub(crate) fn new(
        fingerprint: String,
        command: String,
        env_names: Vec<String>,
        direct_handles: usize,
        destinations: Vec<String>,
        network_like: bool,
        materialize_like: bool,
    ) -> Self {
        let nonce = random_hex_or_fallback("approval-ticket");
        let mut ticket = Self {
            id: String::new(),
            nonce,
            fingerprint,
            command,
            env_names,
            direct_handles,
            destinations,
            network_like,
            materialize_like,
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
        if self.direct_handles > 0 {
            bits.push(format!("{} handle(s)", self.direct_handles));
        }
        if self.materialize_like {
            bits.push("materialize".to_string());
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
    if ticket.direct_handles > 0 {
        lines.push(format!("handles {}", ticket.direct_handles));
    }
    if !ticket.destinations.is_empty() {
        lines.push(format!("send {}", ticket.destinations.join(", ")));
    } else if ticket.network_like {
        lines.push("send possible".to_string());
    }
    if ticket.materialize_like {
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
        "handles": ticket.direct_handles,
        "destinations": ticket.destinations,
        "network": ticket.network_like,
        "materialize": ticket.materialize_like,
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
        direct_handles: value
            .get("handles")
            .and_then(Value::as_u64)
            .unwrap_or_default() as usize,
        destinations: string_array_json(&value, "destinations")?,
        network_like: value
            .get("network")
            .and_then(Value::as_bool)
            .unwrap_or_default(),
        materialize_like: value
            .get("materialize")
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
    canonical_field(&mut out, "handles", &ticket.direct_handles.to_string());
    canonical_list(&mut out, "destinations", &ticket.destinations);
    canonical_field(&mut out, "network", bool_str(ticket.network_like));
    canonical_field(&mut out, "materialize", bool_str(ticket.materialize_like));
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

fn query_param(query: &str, name: &str) -> Option<String> {
    for part in query.split('&') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn esc(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn esc_attr(value: &str) -> String {
    esc(value).replace('"', "&quot;")
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
        dashboard.heartbeat(None, false).unwrap();
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
        dashboard.heartbeat(None, false).unwrap();
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
        dashboard.heartbeat(None, false).unwrap();
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
        dashboard.heartbeat(None, false).unwrap();
        let fingerprint = "abcdef";
        fs::write(dashboard.dirs.always.join(fingerprint), "ok").unwrap();

        let exec = ApprovalQueue::open(&session).unwrap();
        assert!(!exec.always_granted(fingerprint));

        dashboard.remember_always(fingerprint).unwrap();
        assert!(exec.always_granted(fingerprint));

        cleanup_session(&session);
    }

    fn sample_ticket() -> ApprovalTicket {
        ApprovalTicket::new(
            "fingerprint".to_string(),
            "curl -H \"Authorization: Bearer $env:API_TOKEN\" https://api.example.test".to_string(),
            vec!["API_TOKEN".to_string()],
            0,
            vec!["https://api.example.test".to_string()],
            true,
            false,
        )
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
