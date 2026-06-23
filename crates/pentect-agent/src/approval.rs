use crate::approve_ui::ApprovalDecision;
use crate::session::session_root;
use serde_json::{json, Value};
use sha2::Digest;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub(crate) struct ApprovalTicket {
    pub(crate) id: String,
    pub(crate) fingerprint: String,
    pub(crate) command: String,
    pub(crate) env_names: Vec<String>,
    pub(crate) direct_handles: usize,
    pub(crate) destinations: Vec<String>,
    pub(crate) network_like: bool,
    pub(crate) path: Option<PathBuf>,
}

#[derive(Clone)]
pub(crate) struct ApprovalQueue {
    dirs: ApprovalDirs,
}

#[derive(Clone)]
struct ApprovalDirs {
    pending: PathBuf,
    decisions: PathBuf,
    always: PathBuf,
    heartbeat: PathBuf,
    history: PathBuf,
}

impl ApprovalQueue {
    pub(crate) fn open(session: &str) -> Result<Self, String> {
        let root = session_root(session)?.join("approvals");
        let dirs = ApprovalDirs {
            pending: root.join("pending"),
            decisions: root.join("decisions"),
            always: root.join("always"),
            heartbeat: root.join("dashboard.heartbeat"),
            history: root.join("history.log"),
        };
        fs::create_dir_all(&dirs.pending)
            .map_err(|e| format!("could not create '{}': {e}", dirs.pending.display()))?;
        fs::create_dir_all(&dirs.decisions)
            .map_err(|e| format!("could not create '{}': {e}", dirs.decisions.display()))?;
        fs::create_dir_all(&dirs.always)
            .map_err(|e| format!("could not create '{}': {e}", dirs.always.display()))?;
        Ok(Self { dirs })
    }

    pub(crate) fn heartbeat(&self, port: Option<u16>) -> Result<(), String> {
        let mut body = format!("time={}\n", unix_millis());
        if let Some(port) = port {
            body.push_str(&format!("port={port}\n"));
        }
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

    pub(crate) fn always_granted(&self, fingerprint: &str) -> bool {
        self.dirs.always.join(fingerprint).exists()
    }

    pub(crate) fn remember_always(&self, fingerprint: &str) -> Result<(), String> {
        fs::write(self.dirs.always.join(fingerprint), b"ok")
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
            if let Some(decision) = self.read_decision(&ticket.id)? {
                if decision == ApprovalDecision::Always {
                    self.remember_always(&ticket.fingerprint)?;
                }
                remove_file_if_exists(&self.pending_path(&ticket.id))?;
                remove_file_if_exists(&self.decision_path(&ticket.id))?;
                return Ok(decision);
            }
            if !self.dashboard_alive(heartbeat_max_age) {
                self.finish(ticket, ApprovalDecision::Once, "auto")?;
                return Ok(ApprovalDecision::Once);
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
        self.write_decision(&ticket.id, decision)?;
        if decision == ApprovalDecision::Always {
            self.remember_always(&ticket.fingerprint)?;
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
    ) -> Result<(), String> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .map_err(|e| format!("could not bind 127.0.0.1:{port}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("could not configure web dashboard: {e}"))?;
        let heartbeat_queue = self.clone();
        let _heartbeat_thread = std::thread::spawn(move || loop {
            let _ = heartbeat_queue.heartbeat(Some(port));
            std::thread::sleep(Duration::from_millis(500));
        });
        println!("pentect web dashboard: http://127.0.0.1:{port}");
        loop {
            match listener.accept() {
                Ok((stream, _)) => self.handle_http(stream, session)?,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => return Err(format!("web dashboard failed: {e}")),
            }
        }
    }

    fn handle_http(&self, mut stream: TcpStream, session: &str) -> Result<(), String> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| format!("could not configure web request timeout: {e}"))?;
        let mut buf = [0u8; 4096];
        let n = match stream.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(());
            }
            Err(e) => return Err(format!("could not read web request: {e}")),
        };
        let request = String::from_utf8_lossy(&buf[..n]);
        let first = request.lines().next().unwrap_or_default();
        let path = first.split_whitespace().nth(1).unwrap_or("/").to_string();
        if let Some(query) = path.strip_prefix("/decide?") {
            let id = query_param(query, "id").unwrap_or_default();
            let decision = query_param(query, "decision")
                .and_then(|value| decision_from_str(&value))
                .unwrap_or(ApprovalDecision::Decline);
            if let Some(ticket) = self.pending_by_id(&id)? {
                self.decide(&ticket, decision, "web")?;
            }
            return write_http(&mut stream, "303 See Other", "text/plain", "ok", Some("/"));
        }
        let html = self.render_html(session)?;
        write_http(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            &html,
            None,
        )
    }

    fn render_html(&self, session: &str) -> Result<String, String> {
        let pending = self.next_pending()?;
        let history = self.recent_history(8)?;
        let mut html = String::from(
            "<!doctype html><meta name=viewport content=\"width=device-width,initial-scale=1\"><meta http-equiv=refresh content=1><title>pentect</title>\
             <style>body{font:15px system-ui;margin:32px;max-width:760px}pre{white-space:pre-wrap;background:#f6f6f6;padding:16px;border:1px solid #ddd}button{min-height:44px;padding:0 18px;margin-right:8px} .muted{color:#666}</style>",
        );
        html.push_str(&format!(
            "<h1>pentect</h1><p class=muted>session {}</p>",
            esc(session)
        ));
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
            .map_err(|e| format!("could not write approval history: {e}"))
    }

    fn write_decision(&self, id: &str, decision: ApprovalDecision) -> Result<(), String> {
        fs::write(self.decision_path(id), decision.as_str())
            .map_err(|e| format!("could not write approval decision: {e}"))
    }

    fn read_decision(&self, id: &str) -> Result<Option<ApprovalDecision>, String> {
        let path = self.decision_path(id);
        if !path.exists() {
            return Ok(None);
        }
        let text = fs::read_to_string(&path)
            .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
        Ok(decision_from_str(text.trim()))
    }

    fn pending_path(&self, id: &str) -> PathBuf {
        self.dirs.pending.join(format!("{id}.json"))
    }

    fn decision_path(&self, id: &str) -> PathBuf {
        self.dirs.decisions.join(format!("{id}.txt"))
    }
}

impl ApprovalTicket {
    pub(crate) fn new(
        fingerprint: String,
        command: String,
        env_names: Vec<String>,
        direct_handles: usize,
        destinations: Vec<String>,
        network_like: bool,
    ) -> Self {
        let id_material = format!("{fingerprint}:{}:{}", unix_millis(), std::process::id());
        let digest = sha2::Sha256::digest(id_material.as_bytes());
        let id = data_encoding::HEXLOWER.encode(&digest[..8]);
        Self {
            id,
            fingerprint,
            command,
            env_names,
            direct_handles,
            destinations,
            network_like,
            path: None,
        }
    }

    pub(crate) fn short(&self) -> String {
        let mut bits = Vec::new();
        if !self.env_names.is_empty() {
            bits.push(self.env_names.join(","));
        }
        if self.direct_handles > 0 {
            bits.push(format!("{} handle(s)", self.direct_handles));
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
    lines.join("\n")
}

fn ticket_json(ticket: &ApprovalTicket) -> Value {
    json!({
        "id": ticket.id,
        "fingerprint": ticket.fingerprint,
        "command": ticket.command,
        "env": ticket.env_names,
        "handles": ticket.direct_handles,
        "destinations": ticket.destinations,
        "network": ticket.network_like,
    })
}

fn ticket_from_json(text: &str) -> Result<ApprovalTicket, String> {
    let value: Value =
        serde_json::from_str(text).map_err(|e| format!("approval request is malformed: {e}"))?;
    Ok(ApprovalTicket {
        id: string_json(&value, "id")?,
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
        path: None,
    })
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

fn write_http(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
    location: Option<&str>,
) -> Result<(), String> {
    let mut head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(location) = location {
        head.push_str(&format!("Location: {location}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body.as_bytes()))
        .map_err(|e| format!("could not write web response: {e}"))
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
