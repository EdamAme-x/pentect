use crate::memory_store::MemoryStoreClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

const RUNTIME_DIR: &str = "runtime";
const HOST_FILE: &str = "delegated-process-host.json";
const CANDIDATE_PREFIX: &str = "process-host-candidate-";
const CANDIDATE_SUFFIX: &str = ".json";
const ELECTION_ATTEMPTS: usize = 8;
const ELECTION_RETRY: Duration = Duration::from_millis(10);
const HOST_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ProcessHostEndpoint {
    pub(crate) addr: String,
    pub(crate) store_token_hash: String,
    pub(crate) read_token: String,
    pub(crate) write_token: String,
    pub(crate) pid: u32,
}

pub fn register_candidate(
    root: &Path,
    addr: &str,
    store_token: &str,
    read_token: &str,
    write_token: &str,
    pid: u32,
) -> Result<PathBuf, String> {
    let dir = runtime_dir(root);
    std::fs::create_dir_all(&dir)
        .map_err(|error| format!("could not create Pentect runtime directory: {error}"))?;
    restrict_dir(&dir);
    let path = dir.join(format!("{CANDIDATE_PREFIX}{pid}{CANDIDATE_SUFFIX}"));
    let endpoint = ProcessHostEndpoint {
        addr: addr.to_string(),
        store_token_hash: store_token_hash(store_token),
        read_token: read_token.to_string(),
        write_token: write_token.to_string(),
        pid,
    };
    write_endpoint(&path, &endpoint)?;
    if let Err(error) = ensure_host_at(root) {
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }
    Ok(path)
}

pub fn unregister_candidate(path: &Path) {
    let endpoint = read_endpoint(path).ok();
    let _ = std::fs::remove_file(path);
    let Some(dir) = path.parent() else {
        return;
    };
    if let Some(endpoint) = endpoint {
        let host_path = dir.join(HOST_FILE);
        if read_endpoint(&host_path).ok().as_ref() == Some(&endpoint) {
            let _ = std::fs::remove_file(host_path);
        }
    }
    let _ = std::fs::remove_dir(dir);
}

pub(crate) fn send_activity(event_json: &str, share: bool) -> Result<(), String> {
    send_activity_at(&process_host_root()?, event_json, share)
}

fn send_activity_at(root: &Path, event_json: &str, share: bool) -> Result<(), String> {
    if share {
        return broadcast_activity_at(root, event_json);
    }
    for _ in 0..2 {
        let endpoint = match current_host_at(root) {
            Ok(Some(endpoint)) => endpoint,
            Ok(None) => ensure_host_at(root)?,
            Err(_) => {
                invalidate_host_at(root, None);
                ensure_host_at(root)?
            }
        };
        let client =
            MemoryStoreClient::for_activity(endpoint.addr.clone(), endpoint.write_token.clone());
        if client.add_activity(event_json).is_ok() {
            return Ok(());
        }
        invalidate_host_at(root, Some(&endpoint));
    }
    Err("no running Delegated Process Host".to_string())
}

fn broadcast_activity_at(root: &Path, event_json: &str) -> Result<(), String> {
    let host = ensure_host_at(root)?;
    let mut targets = candidates_at(root)?;
    if !targets.iter().any(|(endpoint, _)| endpoint == &host) {
        targets.push((host.clone(), runtime_dir(root).join(HOST_FILE)));
    }

    let mut delivered = false;
    for (endpoint, path) in targets {
        let client =
            MemoryStoreClient::for_activity(endpoint.addr.clone(), endpoint.write_token.clone());
        if client.add_activity(event_json).is_ok() {
            delivered = true;
            continue;
        }
        if path.file_name().is_some_and(|name| name != HOST_FILE) {
            let _ = std::fs::remove_file(path);
        }
        invalidate_host_at(root, Some(&endpoint));
    }
    if delivered {
        Ok(())
    } else {
        Err("no running Delegated Process Host".to_string())
    }
}

pub(crate) fn reader_endpoint() -> Result<ProcessHostEndpoint, String> {
    ensure_host_at(&process_host_root()?)
}

pub(crate) fn invalidate_host(endpoint: &ProcessHostEndpoint) {
    if let Ok(root) = process_host_root() {
        invalidate_host_at(&root, Some(endpoint));
    }
}

pub fn is_running(root: &Path) -> bool {
    ensure_host_at(root).is_ok()
}

pub fn is_host(root: &Path, addr: &str) -> bool {
    current_host_at(root)
        .ok()
        .flatten()
        .is_some_and(|endpoint| endpoint.addr == addr && endpoint_is_alive(&endpoint))
}

/// Environment values are only transport for an already-registered host. Requiring
/// the complete endpoint prevents one overwritten control variable from redirecting
/// a child process to an arbitrary listener.
pub fn matches_host(root: &Path, addr: &str, read_token: &str, write_token: &str) -> bool {
    let matches = |endpoint: &ProcessHostEndpoint| {
        endpoint.addr == addr
            && endpoint.read_token == read_token
            && endpoint.write_token == write_token
            && endpoint_is_alive(endpoint)
    };
    current_host_at(root)
        .ok()
        .flatten()
        .as_ref()
        .is_some_and(&matches)
        || candidates_at(root)
            .is_ok_and(|candidates| candidates.iter().any(|(endpoint, _)| matches(endpoint)))
}

pub fn contains_host(root: &Path, addr: &str, store_token: &str) -> bool {
    let expected_hash = store_token_hash(store_token);
    let matches = |endpoint: &ProcessHostEndpoint| {
        endpoint.addr == addr
            && endpoint.store_token_hash == expected_hash
            && endpoint_is_alive(endpoint)
    };
    current_host_at(root)
        .ok()
        .flatten()
        .as_ref()
        .is_some_and(&matches)
        || candidates_at(root)
            .is_ok_and(|candidates| candidates.iter().any(|(endpoint, _)| matches(endpoint)))
}

fn store_token_hash(token: &str) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(token.as_bytes()))
}

/// Derive the host registry independently in every process. A bearer value in
/// `PENTECT_PROCESS_HOST_ROOT` must not be able to redirect authentication.
pub fn process_host_root() -> Result<PathBuf, String> {
    platform_process_host_root()
}

#[cfg(windows)]
fn platform_process_host_root() -> Result<PathBuf, String> {
    std::env::var_os("LOCALAPPDATA")
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|home| {
                PathBuf::from(home)
                    .join("AppData")
                    .join("Local")
                    .into_os_string()
            })
        })
        .map(PathBuf::from)
        .map(|root| root.join("pentect"))
        .ok_or_else(|| "could not locate local application data".to_string())
}

#[cfg(target_os = "macos")]
fn platform_process_host_root() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join("Library").join("Caches").join("pentect"))
        .ok_or_else(|| "could not locate the user cache directory".to_string())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_process_host_root() -> Result<PathBuf, String> {
    if let Some(root) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(root).join("pentect"));
    }
    if let Some(root) = std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(root).join("pentect"));
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".cache").join("pentect"))
        .ok_or_else(|| "could not locate the user cache directory".to_string())
}

fn ensure_host_at(root: &Path) -> Result<ProcessHostEndpoint, String> {
    for _ in 0..ELECTION_ATTEMPTS {
        if let Some(endpoint) = current_host_at(root)? {
            if endpoint_is_alive(&endpoint) {
                return Ok(endpoint);
            }
            invalidate_host_at(root, Some(&endpoint));
        }

        for (candidate, path) in candidates_at(root)? {
            if !endpoint_is_alive(&candidate) {
                let _ = std::fs::remove_file(path);
                continue;
            }
            match publish_host(root, &candidate) {
                Ok(true) => return Ok(candidate),
                Ok(false) => break,
                Err(error) => return Err(error),
            }
        }
        std::thread::sleep(ELECTION_RETRY);
    }
    Err("no running Delegated Process Host".to_string())
}

fn current_host_at(root: &Path) -> Result<Option<ProcessHostEndpoint>, String> {
    let path = runtime_dir(root).join(HOST_FILE);
    match read_endpoint(&path) {
        Ok(endpoint) => Ok(Some(endpoint)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => {
            std::thread::sleep(ELECTION_RETRY);
            match read_endpoint(&path) {
                Ok(endpoint) => Ok(Some(endpoint)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                    let _ = std::fs::remove_file(path);
                    Ok(None)
                }
                Err(error) => Err(format!("could not read Delegated Process Host: {error}")),
            }
        }
    }
}

fn candidates_at(root: &Path) -> Result<Vec<(ProcessHostEndpoint, PathBuf)>, String> {
    let dir = runtime_dir(root);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(format!(
                "could not read Pentect runtime directory '{}': {error}",
                dir.display()
            ));
        }
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(CANDIDATE_PREFIX) && name.ends_with(CANDIDATE_SUFFIX)
                })
        })
        .collect::<Vec<_>>();
    paths.sort_by_key(|path| {
        std::cmp::Reverse(
            path.metadata()
                .and_then(|metadata| metadata.modified())
                .ok(),
        )
    });

    let mut candidates = Vec::new();
    for path in paths {
        match read_endpoint(&path) {
            Ok(endpoint) => candidates.push((endpoint, path)),
            Err(_) => {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    Ok(candidates)
}

fn publish_host(root: &Path, endpoint: &ProcessHostEndpoint) -> Result<bool, String> {
    let path = runtime_dir(root).join(HOST_FILE);
    let bytes = serde_json::to_vec(endpoint)
        .map_err(|error| format!("could not serialize Delegated Process Host: {error}"))?;
    let mut file = match OpenOptions::new().create_new(true).write(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(format!("could not elect Delegated Process Host: {error}")),
    };
    restrict_file(&file);
    if let Err(error) = file.write_all(&bytes).and_then(|_| file.flush()) {
        let _ = std::fs::remove_file(path);
        return Err(format!("could not elect Delegated Process Host: {error}"));
    }
    Ok(true)
}

fn invalidate_host_at(root: &Path, expected: Option<&ProcessHostEndpoint>) {
    let path = runtime_dir(root).join(HOST_FILE);
    if let Some(expected) = expected {
        if read_endpoint(&path).ok().as_ref() != Some(expected) {
            return;
        }
    }
    let _ = std::fs::remove_file(path);
}

fn endpoint_is_alive(endpoint: &ProcessHostEndpoint) -> bool {
    if !is_loopback_addr(&endpoint.addr)
        || endpoint.read_token.is_empty()
        || endpoint.write_token.is_empty()
    {
        return false;
    }
    MemoryStoreClient::for_activity(endpoint.addr.clone(), endpoint.read_token.clone())
        .poll_activity_once(u64::MAX, HOST_PROBE_TIMEOUT)
        .is_ok()
}

fn write_endpoint(path: &Path, endpoint: &ProcessHostEndpoint) -> Result<(), String> {
    let bytes = serde_json::to_vec(endpoint)
        .map_err(|error| format!("could not serialize process host candidate: {error}"))?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("could not write process host candidate: {error}"))?;
    restrict_file(&file);
    file.write_all(&bytes)
        .and_then(|_| file.flush())
        .map_err(|error| format!("could not write process host candidate: {error}"))
}

fn read_endpoint(path: &Path) -> std::io::Result<ProcessHostEndpoint> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn runtime_dir(root: &Path) -> PathBuf {
    root.join(RUNTIME_DIR)
}

fn is_loopback_addr(addr: &str) -> bool {
    addr.parse::<SocketAddr>()
        .is_ok_and(|addr| addr.ip().is_loopback())
}

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_: &Path) {}

#[cfg(unix)]
fn restrict_file(file: &File) {
    use std::os::unix::fs::PermissionsExt;
    let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_file(_: &File) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_store::spawn_test_memory_store_with_activity;
    use std::net::TcpListener;
    use std::time::Instant;

    #[test]
    fn host_probe_times_out_once_without_general_request_retries() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(2));
        });
        let endpoint = ProcessHostEndpoint {
            addr: addr.to_string(),
            store_token_hash: String::new(),
            read_token: "read-token".to_string(),
            write_token: "write-token".to_string(),
            pid: 1,
        };

        let started = Instant::now();
        assert!(!endpoint_is_alive(&endpoint));
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "host probe exceeded its single short timeout: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn remaining_candidate_takes_over_when_host_unregisters() {
        let root = test_root("handoff");
        let first_addr = spawn_test_memory_store_with_activity(
            "memory-1".to_string(),
            "read-1".to_string(),
            "write-1".to_string(),
        );
        let first =
            register_candidate(&root, &first_addr, "memory-1", "read-1", "write-1", 101).unwrap();
        assert_eq!(ensure_host_at(&root).unwrap().addr, first_addr);

        let second_addr = spawn_test_memory_store_with_activity(
            "memory-2".to_string(),
            "read-2".to_string(),
            "write-2".to_string(),
        );
        let second =
            register_candidate(&root, &second_addr, "memory-2", "read-2", "write-2", 202).unwrap();
        assert_eq!(ensure_host_at(&root).unwrap().addr, first_addr);
        assert!(matches_host(&root, &second_addr, "read-2", "write-2"));
        assert!(contains_host(&root, &second_addr, "memory-2"));
        assert!(!contains_host(&root, &second_addr, "replaced-memory"));

        unregister_candidate(&first);
        assert_eq!(ensure_host_at(&root).unwrap().addr, second_addr);

        unregister_candidate(&second);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn process_host_files_contain_no_activity_events() {
        let root = test_root("metadata");
        let addr = spawn_test_memory_store_with_activity(
            "memory".to_string(),
            "read".to_string(),
            "write".to_string(),
        );
        let candidate = register_candidate(&root, &addr, "memory", "read", "write", 303).unwrap();
        let candidate_json = std::fs::read_to_string(&candidate).unwrap();
        let host_json = std::fs::read_to_string(runtime_dir(&root).join(HOST_FILE)).unwrap();
        for json in [candidate_json, host_json] {
            assert!(!json.contains("events"));
            assert!(!json.contains("labels"));
            assert!(!json.contains("OPENAI_API_KEY"));
        }
        unregister_candidate(&candidate);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn shared_activity_is_replicated_to_handoff_candidates() {
        let root = test_root("shared-activity");
        let first_addr = spawn_test_memory_store_with_activity(
            "memory-1".to_string(),
            "read-1".to_string(),
            "write-1".to_string(),
        );
        let first =
            register_candidate(&root, &first_addr, "memory-1", "read-1", "write-1", 501).unwrap();
        let second_addr = spawn_test_memory_store_with_activity(
            "memory-2".to_string(),
            "read-2".to_string(),
            "write-2".to_string(),
        );
        let second =
            register_candidate(&root, &second_addr, "memory-2", "read-2", "write-2", 502).unwrap();
        let first_reader = MemoryStoreClient::for_activity(first_addr, "read-1".to_string());
        let second_reader = MemoryStoreClient::for_activity(second_addr, "read-2".to_string());

        send_activity_at(&root, r#"{"action":"mask"}"#, true).unwrap();
        assert_eq!(first_reader.poll_activity(0).unwrap().len(), 1);
        assert_eq!(second_reader.poll_activity(0).unwrap().len(), 1);

        send_activity_at(&root, r#"{"action":"resolve"}"#, false).unwrap();
        assert_eq!(first_reader.poll_activity(1).unwrap().len(), 1);
        assert!(second_reader.poll_activity(1).unwrap().is_empty());

        unregister_candidate(&first);
        unregister_candidate(&second);
        let _ = std::fs::remove_dir_all(root);
    }

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pentect-process-host-{name}-{}-{}",
            std::process::id(),
            jiff::Timestamp::now().as_nanosecond()
        ))
    }
}
