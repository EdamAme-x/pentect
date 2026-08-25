use pentect_core::normalize::NormalizedView;
use pentect_core::{ByteRange, Category, Confidence, Detector, DetectorId, Span};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};

const VERSION: &str = "0.20.2";
// A JSON string can expand one input byte to six bytes (for example `\u0000`).
// Four MiB therefore stays below the helper's 32 MiB Scanner limit even in the
// worst case. The overlap preserves recognizers spanning a chunk boundary.
const REQUEST_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const REQUEST_OVERLAP_BYTES: usize = 4 * 1024;
const EXPECTED_SHA256: &str = env!("PENTECT_ALCATRAZ_SHA256");
const UNCOMPRESSED_SIZE: usize = parse_size(env!("PENTECT_ALCATRAZ_SIZE"));
static COMPRESSED: &[u8] = include_bytes!(env!("PENTECT_ALCATRAZ_ZST"));
static PROCESS: OnceLock<Mutex<Option<Helper>>> = OnceLock::new();

pub(crate) struct AlcatrazDetector;

pub(crate) fn detect_text(text: &str) -> Vec<Span> {
    if UNCOMPRESSED_SIZE == 0 || text.is_empty() {
        return Vec::new();
    }
    match detect(text) {
        Ok(findings) => findings
            .into_iter()
            .filter_map(|finding| finding.into_direct_span(text))
            .collect(),
        Err(error) => {
            eprintln!("[pentect] warning/alcatraz detector-unavailable: {error}");
            Vec::new()
        }
    }
}

impl Detector for AlcatrazDetector {
    fn detect(&self, view: &NormalizedView<'_>) -> Vec<Span> {
        if UNCOMPRESSED_SIZE == 0 || view.text().is_empty() {
            return Vec::new();
        }
        match detect(view.text()) {
            Ok(findings) => findings
                .into_iter()
                .filter_map(|finding| finding.into_span(view))
                .collect(),
            Err(error) => {
                eprintln!("[pentect] warning/alcatraz detector-unavailable: {error}");
                Vec::new()
            }
        }
    }
}

#[derive(Deserialize)]
struct Response {
    id: u64,
    findings: Vec<Finding>,
}

#[derive(Deserialize)]
struct Finding {
    entity: String,
    start: usize,
    end: usize,
    score: f64,
}

impl Finding {
    fn confidence(&self) -> Confidence {
        if self.score >= 0.8 {
            Confidence::High
        } else if self.score >= 0.4 {
            Confidence::Medium
        } else {
            Confidence::Low
        }
    }

    fn into_direct_span(self, text: &str) -> Option<Span> {
        if self.start >= self.end
            || self.end > text.len()
            || !text.is_char_boundary(self.start)
            || !text.is_char_boundary(self.end)
        {
            return None;
        }
        let confidence = self.confidence();
        Some(Span {
            range: ByteRange::new(self.start, self.end),
            category: Category::Pii,
            label: self.entity,
            confidence,
            source: DetectorId::Alcatraz,
        })
    }

    fn into_span(self, view: &NormalizedView<'_>) -> Option<Span> {
        if self.start >= self.end
            || self.end > view.text().len()
            || !view.text().is_char_boundary(self.start)
            || !view.text().is_char_boundary(self.end)
        {
            return None;
        }
        let confidence = self.confidence();
        Some(Span {
            range: view.to_raw(ByteRange::new(self.start, self.end)),
            category: Category::Pii,
            label: self.entity,
            confidence,
            source: DetectorId::Alcatraz,
        })
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Helper {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Helper {
    fn start() -> Result<Self, String> {
        let executable = ensure_extracted()?;
        let mut child = Command::new(&executable)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("could not start '{}': {e}", executable.display()))?;
        let stdin = child.stdin.take().ok_or("Alcatraz stdin unavailable")?;
        let stdout = child.stdout.take().ok_or("Alcatraz stdout unavailable")?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        })
    }

    fn request(&mut self, text: &str) -> Result<Vec<Finding>, String> {
        if self.child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Err("Alcatraz helper exited".to_string());
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        serde_json::to_writer(
            &mut self.stdin,
            &serde_json::json!({"id": id, "text": text}),
        )
        .map_err(|e| format!("could not encode Alcatraz request: {e}"))?;
        self.stdin
            .write_all(b"\n")
            .and_then(|_| self.stdin.flush())
            .map_err(|e| format!("could not send Alcatraz request: {e}"))?;
        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .map_err(|e| format!("could not read Alcatraz response: {e}"))?;
        if line.is_empty() {
            return Err("Alcatraz helper closed stdout".to_string());
        }
        let response: Response =
            serde_json::from_str(&line).map_err(|e| format!("invalid Alcatraz response: {e}"))?;
        if response.id != id {
            return Err("Alcatraz response ID mismatch".to_string());
        }
        Ok(response.findings)
    }
}

fn detect(text: &str) -> Result<Vec<Finding>, String> {
    let mut findings = Vec::new();
    for (start, end) in chunk_ranges(text) {
        for mut finding in request(&text[start..end])? {
            finding.start += start;
            finding.end += start;
            findings.push(finding);
        }
    }
    findings.sort_by(|left, right| {
        (&left.entity, left.start, left.end)
            .cmp(&(&right.entity, right.start, right.end))
            .then_with(|| right.score.total_cmp(&left.score))
    });
    findings.dedup_by(|right, left| {
        right.entity == left.entity && right.start == left.start && right.end == left.end
    });
    Ok(findings)
}

fn request(text: &str) -> Result<Vec<Finding>, String> {
    let process = PROCESS.get_or_init(|| Mutex::new(None));
    let mut process = process.lock().map_err(|_| "Alcatraz lock poisoned")?;
    if process.is_none() {
        *process = Some(Helper::start()?);
    }
    match process.as_mut().expect("initialized").request(text) {
        Ok(findings) => Ok(findings),
        Err(first) => {
            *process = Some(Helper::start()?);
            process
                .as_mut()
                .expect("restarted")
                .request(text)
                .map_err(|second| format!("{first}; restart failed: {second}"))
        }
    }
}

fn chunk_ranges(text: &str) -> Vec<(usize, usize)> {
    if text.len() <= REQUEST_CHUNK_BYTES {
        return vec![(0, text.len())];
    }
    let mut ranges = Vec::with_capacity(text.len().div_ceil(REQUEST_CHUNK_BYTES));
    let mut start = 0usize;
    while start < text.len() {
        let mut end = (start + REQUEST_CHUNK_BYTES).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        ranges.push((start, end));
        if end == text.len() {
            break;
        }
        let mut next = end.saturating_sub(REQUEST_OVERLAP_BYTES);
        while !text.is_char_boundary(next) {
            next += 1;
        }
        start = next.max(start + 1);
        while !text.is_char_boundary(start) {
            start += 1;
        }
    }
    ranges
}

fn ensure_extracted() -> Result<PathBuf, String> {
    let root = cache_root()?
        .join("runtime")
        .join("alcatraz")
        .join(VERSION)
        .join(EXPECTED_SHA256);
    fs::create_dir_all(&root).map_err(|e| format!("could not create '{}': {e}", root.display()))?;
    restrict_directory(&root)?;
    let destination = root.join(if cfg!(windows) {
        "alcatraz.exe"
    } else {
        "alcatraz"
    });
    if valid_file(&destination)? {
        return Ok(destination);
    }
    let bytes = zstd::stream::decode_all(COMPRESSED)
        .map_err(|e| format!("could not decompress embedded Alcatraz: {e}"))?;
    if bytes.len() != UNCOMPRESSED_SIZE || sha256_hex(&bytes) != EXPECTED_SHA256 {
        return Err("embedded Alcatraz integrity check failed".to_string());
    }
    let temporary = root.join(format!(".alcatraz-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| format!("could not stage '{}': {e}", temporary.display()))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("could not write '{}': {e}", temporary.display()))?;
    make_executable(&temporary)?;
    match fs::rename(&temporary, &destination) {
        Ok(()) => {}
        Err(_) if valid_file(&destination)? => {
            let _ = fs::remove_file(&temporary);
        }
        Err(error) => {
            return Err(format!(
                "could not install '{}': {error}",
                destination.display()
            ))
        }
    }
    Ok(destination)
}

fn valid_file(path: &Path) -> Result<bool, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("could not verify '{}': {error}", path.display())),
    };
    Ok(bytes.len() == UNCOMPRESSED_SIZE && sha256_hex(&bytes) == EXPECTED_SHA256)
}

fn cache_root() -> Result<PathBuf, String> {
    #[cfg(windows)]
    let root = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let root = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join("Library").join("Caches"));
    #[cfg(not(any(windows, target_os = "macos")))]
    let root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".cache"))
        });
    root.map(|root| root.join("pentect"))
        .ok_or_else(|| "could not determine Pentect cache directory".to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

const fn parse_size(value: &str) -> usize {
    let bytes = value.as_bytes();
    let mut result = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        result = result * 10 + (bytes[index] - b'0') as usize;
        index += 1;
    }
    result
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("could not restrict '{}': {e}", path.display()))
}

#[cfg(not(unix))]
fn restrict_directory(_: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("could not make '{}': {e}", path.display()))
}

#[cfg(not(unix))]
fn make_executable(_: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_ranges_are_bounded_overlapping_and_utf8_aligned() {
        let text = format!(
            "{}é{}",
            "a".repeat(REQUEST_CHUNK_BYTES - 1),
            "b".repeat(9000)
        );
        let ranges = chunk_ranges(&text);
        assert!(ranges.len() >= 2);
        assert_eq!(ranges.first().copied().unwrap().0, 0);
        assert_eq!(ranges.last().copied().unwrap().1, text.len());
        for &(start, end) in &ranges {
            assert!(end - start <= REQUEST_CHUNK_BYTES);
            assert!(text.is_char_boundary(start));
            assert!(text.is_char_boundary(end));
        }
        for pair in ranges.windows(2) {
            assert!(pair[1].0 < pair[0].1);
        }
    }

    #[test]
    fn detects_pii_after_the_helper_line_limit() {
        let mut text = "a".repeat(33 * 1024 * 1024);
        text.push_str("\nemail: alice@example.com\n");
        let spans = detect_text(&text);
        assert!(spans.iter().any(|span| {
            span.label == "EMAIL_ADDRESS"
                && text.get(span.range.start..span.range.end) == Some("alice@example.com")
        }));
    }
}
