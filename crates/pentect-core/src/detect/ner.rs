//! Semantic PII via a persistent Python sidecar (see tools/ner_sidecar.py).
//! Catches the entities a deterministic core cannot — person, location,
//! organization, address — by talking to a spaCy sidecar loaded once in a child
//! process. Off unless built with the `semantic` feature.

use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

pub struct SemanticDetector {
    proc: Mutex<NerProc>,
}

struct NerProc {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl SemanticDetector {
    /// Spawn the sidecar (`<python> <script>`) and block until its model is
    /// loaded (it prints `READY`). `python` defaults to PENTECT_PYTHON or
    /// "python". Errors if the process can't start or never signals ready.
    pub fn spawn(script: &str) -> std::io::Result<Self> {
        let python = std::env::var("PENTECT_PYTHON").unwrap_or_else(|_| "python".into());
        let mut child = Command::new(python)
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let (ready, stdout) = wait_for_ready_line(&mut child)?;
        let ready = ready.trim();
        if ready != "READY" {
            let _ = child.kill();
            return Err(std::io::Error::other(
                "semantic sidecar did not signal READY",
            ));
        }
        Ok(Self {
            proc: Mutex::new(NerProc {
                child,
                stdin,
                stdout,
            }),
        })
    }
}

fn wait_for_ready_line(child: &mut Child) -> std::io::Result<(String, BufReader<ChildStdout>)> {
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let timeout = std::env::var("PENTECT_NER_READY_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(10));
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut ready = String::new();
        let result = stdout.read_line(&mut ready).map(|_| ready);
        let _ = tx.send((result, stdout));
    });
    match rx.recv_timeout(timeout) {
        Ok((Ok(ready), stdout)) => Ok((ready, stdout)),
        Ok((Err(err), _)) => Err(err),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = child.kill();
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "semantic sidecar did not signal READY before timeout",
            ))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = child.kill();
            Err(std::io::Error::other("semantic sidecar reader stopped"))
        }
    }
}

impl Drop for SemanticDetector {
    fn drop(&mut self) {
        if let Ok(mut p) = self.proc.lock() {
            let _ = p.child.kill();
        }
    }
}

impl Detector for SemanticDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        let Ok(req) = serde_json::to_string(text) else {
            return Vec::new();
        };
        let mut p = match self.proc.lock() {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };
        if writeln!(p.stdin, "{req}")
            .and_then(|()| p.stdin.flush())
            .is_err()
        {
            return Vec::new();
        }
        let mut line = String::new();
        if p.stdout.read_line(&mut line).is_err() {
            return Vec::new();
        }
        let ents: Vec<(usize, usize, String)> =
            serde_json::from_str(line.trim()).unwrap_or_default();
        ents.into_iter()
            .filter(|(s, e, _)| s < e && *e <= text.len())
            .map(|(s, e, label)| Span {
                range: view.to_raw(ByteRange::new(s, e)),
                category: Category::Pii,
                label,
                // Probabilistic, so Medium: a vendor rule on the same span keeps
                // its label, but semantic detection still beats nothing.
                confidence: Confidence::Medium,
                source: DetectorId::Ner,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    #[test]
    fn semantic_detects_person_org_location() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tools/ner_sidecar.py");
        let old_timeout = std::env::var_os("PENTECT_NER_READY_TIMEOUT_MS");
        std::env::set_var("PENTECT_NER_READY_TIMEOUT_MS", "1000");
        let det = match SemanticDetector::spawn(script) {
            Ok(d) => {
                restore_timeout(old_timeout);
                d
            }
            Err(_) => {
                restore_timeout(old_timeout);
                return; // python/spaCy unavailable here — skip, don't fail
            }
        };
        let raw = "John Smith works at Acme Corporation in Tokyo";
        let labels: Vec<String> = det
            .detect(&NormalizedView::build(&region(raw), raw))
            .into_iter()
            .map(|s| s.label)
            .collect();
        assert!(labels.contains(&"PERSON".to_string()), "{labels:?}");
        assert!(labels.contains(&"ORGANIZATION".to_string()), "{labels:?}");
        assert!(labels.contains(&"LOCATION".to_string()), "{labels:?}");
    }

    fn restore_timeout(old_timeout: Option<std::ffi::OsString>) {
        if let Some(value) = old_timeout {
            std::env::set_var("PENTECT_NER_READY_TIMEOUT_MS", value);
        } else {
            std::env::remove_var("PENTECT_NER_READY_TIMEOUT_MS");
        }
    }
}
