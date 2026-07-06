//! Persistent recovery hints for file-backed masked handles.
//!
//! This deliberately stores file pointers, not secret values. A pointer is only
//! usable while the original file still has the exact same size and SHA-256, so
//! stale handles fail closed instead of expanding to the wrong bytes.

use chacha20::cipher::StreamCipher;
use chacha20::{ChaCha20, Key, KeyIvInit, Nonce};
use hmac::{Hmac, Mac};
use pentect_core::{parse_placeholder, MaskResult, Recovery, RenderSegment};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const MANAGER_DIR: &str = "file-pointer-manager";
const INDEX_FILE: &str = "index.bin";
const KEY_FILE: &str = "key.bin";
const ENVELOPE_MAGIC: &[u8] = b"PNFPM1";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 32;
const INDEX_VERSION: u32 = 1;
const MAX_RECORDS: usize = 4096;
const MAX_INDEX_BYTES: u64 = 4 * 1024 * 1024;
const ENV_MANAGER_DIR: &str = "PENTECT_FILE_POINTER_MANAGER_DIR";
const ENV_ALIAS_LABEL: &str = "PENTECT_ENV_ALIAS";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FilePointerIndex {
    version: u32,
    records: Vec<FilePointerRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FilePointerRecord {
    handle: String,
    path: String,
    file_size: u64,
    file_hash: String,
    offset: u64,
    length: u64,
    label: String,
    created_at: u64,
}

/// Register only file-backed handles. Shell/MCP/browser handles do not have a
/// stable local source file, so they remain in-memory-only.
pub(crate) fn register_file_pointers(path: &Path, source: &str, result: &MaskResult) {
    if !save_enabled() {
        return;
    }
    if result.summary.masked_count == 0 {
        return;
    }
    let records = records_for_result(path, source, result);
    if records.is_empty() {
        return;
    }
    let mut index = load_index();
    let mut changed = false;
    for record in records {
        changed |= upsert_record(&mut index.records, record);
    }
    if changed {
        trim_index(&mut index.records);
        let _ = save_index(&index);
    }
}

/// Rebuild a temporary recovery map from unchanged files. No value is recovered
/// from the index itself; the index only tells us where to read after verifying
/// the full file hash.
pub(crate) fn recover_text(text: &str, key: &[u8; 32]) -> Option<Recovery> {
    if !save_enabled() {
        return None;
    }
    let handles = handles_in_text(text);
    if handles.is_empty() {
        return None;
    }
    let index = load_index();
    if index.records.is_empty() {
        return None;
    }
    let by_handle: HashMap<&str, &FilePointerRecord> = index
        .records
        .iter()
        .map(|record| (record.handle.as_str(), record))
        .collect();
    let mut by_path: BTreeMap<&str, Vec<&FilePointerRecord>> = BTreeMap::new();
    for handle in handles {
        let Some(record) = by_handle.get(handle.as_str()).copied() else {
            continue;
        };
        by_path
            .entry(record.path.as_str())
            .or_default()
            .push(record);
    }
    let mut recovered = HashMap::new();
    for (path, records) in by_path {
        recover_from_file(path, &records, &mut recovered);
    }
    if recovered.is_empty() {
        None
    } else {
        Some(Recovery::seal(recovered, key))
    }
}

/// `pentect view` can show length for a persisted file-backed handle without
/// exposing the value. It reads the original file only after the hash matches.
pub(crate) fn handle_length(handle: &str) -> Option<usize> {
    if !save_enabled() {
        return None;
    }
    let index = load_index();
    let record = index
        .records
        .iter()
        .find(|record| record.handle == handle)?;
    let bytes = read_verified_file(record)?;
    let value = slice_record_value(&bytes, record)?;
    Some(value.chars().count())
}

fn records_for_result(path: &Path, source: &str, result: &MaskResult) -> Vec<FilePointerRecord> {
    let file_size = source.len() as u64;
    let file_hash = sha256_hex(source.as_bytes());
    let path = stored_path(path);
    let created_at = unix_seconds();
    let mut records = Vec::new();
    let mut offset = 0usize;
    for segment in &result.segments {
        match segment {
            RenderSegment::Literal { text } => {
                offset = offset.saturating_add(text.len());
            }
            RenderSegment::Masked { text, label, .. } => {
                let mut value = result.recovery.resolve(text);
                if value == *text
                    || value.is_empty()
                    || label == ENV_ALIAS_LABEL
                    || result
                        .summary
                        .collisions
                        .iter()
                        .any(|handle| handle == text)
                {
                    offset = offset.saturating_add(value.len());
                    value.zeroize();
                    continue;
                }
                records.push(FilePointerRecord {
                    handle: text.clone(),
                    path: path.clone(),
                    file_size,
                    file_hash: file_hash.clone(),
                    offset: offset as u64,
                    length: value.len() as u64,
                    label: label.clone(),
                    created_at,
                });
                offset = offset.saturating_add(value.len());
                value.zeroize();
            }
        }
    }
    records
}

fn recover_from_file(
    path: &str,
    records: &[&FilePointerRecord],
    recovered: &mut HashMap<String, String>,
) {
    let Some(first) = records.first() else {
        return;
    };
    let Some(bytes) = read_verified_file(first) else {
        return;
    };
    if records.iter().any(|record| {
        record.file_size != first.file_size
            || record.file_hash != first.file_hash
            || record.path != path
    }) {
        return;
    }
    for record in records {
        let Some(value) = slice_record_value(&bytes, record) else {
            continue;
        };
        recovered.insert(record.handle.clone(), value);
    }
}

fn read_verified_file(record: &FilePointerRecord) -> Option<Vec<u8>> {
    let path = Path::new(&record.path);
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() != record.file_size {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() as u64 != record.file_size {
        return None;
    }
    if sha256_hex(&bytes) != record.file_hash {
        return None;
    }
    Some(bytes)
}

fn slice_record_value(bytes: &[u8], record: &FilePointerRecord) -> Option<String> {
    let start = usize::try_from(record.offset).ok()?;
    let len = usize::try_from(record.length).ok()?;
    let end = start.checked_add(len)?;
    let slice = bytes.get(start..end)?;
    std::str::from_utf8(slice).ok().map(str::to_string)
}

fn handles_in_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'<' && bytes[i + 1] == b'<' {
            if let Some(close) = find_from(bytes, i + 2, b">>") {
                let handle = &text[i..close + 2];
                if parse_placeholder(handle).is_ok() && !out.iter().any(|v| v == handle) {
                    out.push(handle.to_string());
                }
                i = close + 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn find_from(hay: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start >= hay.len() {
        return None;
    }
    let mut i = start;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn upsert_record(records: &mut Vec<FilePointerRecord>, record: FilePointerRecord) -> bool {
    if records.iter().any(|existing| existing == &record) {
        return false;
    }
    records.retain(|existing| existing.handle != record.handle);
    records.push(record);
    true
}

fn trim_index(records: &mut Vec<FilePointerRecord>) {
    records.sort_by_key(|record| record.created_at);
    if records.len() > MAX_RECORDS {
        let drop_count = records.len() - MAX_RECORDS;
        records.drain(0..drop_count);
    }
}

fn load_index() -> FilePointerIndex {
    let path = index_path();
    let Ok(meta) = std::fs::metadata(&path) else {
        return empty_index();
    };
    if meta.len() > MAX_INDEX_BYTES {
        return empty_index();
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return empty_index();
    };
    let Some(key) = manager_key(false).ok().flatten() else {
        return empty_index();
    };
    let Some(plaintext) = decrypt_payload(&bytes, &key) else {
        return empty_index();
    };
    let Ok(index) = serde_json::from_slice::<FilePointerIndex>(&plaintext) else {
        return empty_index();
    };
    if index.version == INDEX_VERSION {
        index
    } else {
        empty_index()
    }
}

fn save_index(index: &FilePointerIndex) -> Result<(), String> {
    let path = index_path();
    let parent = path
        .parent()
        .ok_or_else(|| "file pointer manager path has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("could not create '{}': {e}", parent.display()))?;
    let mut index = index.clone();
    trim_index(&mut index.records);
    let mut bytes = serde_json::to_vec(&index).map_err(|e| e.to_string())?;
    let max_plaintext = MAX_INDEX_BYTES.saturating_sub(envelope_overhead() as u64);
    while bytes.len() as u64 > max_plaintext && !index.records.is_empty() {
        index.records.remove(0);
        bytes = serde_json::to_vec(&index).map_err(|e| e.to_string())?;
    }
    let key =
        manager_key(true)?.ok_or_else(|| "file pointer manager key unavailable".to_string())?;
    let encrypted = encrypt_payload(&bytes, &key)?;
    let tmp = temp_index_path(&path);
    std::fs::write(&tmp, encrypted)
        .map_err(|e| format!("could not write '{}': {e}", tmp.display()))?;
    replace_file(&tmp, &path)
}

fn index_path() -> PathBuf {
    manager_dir().join(INDEX_FILE)
}

fn key_path() -> PathBuf {
    manager_dir().join(KEY_FILE)
}

fn temp_index_path(path: &Path) -> PathBuf {
    let nonce = random_hex_8();
    path.with_extension(format!("bin.{nonce}.tmp"))
}

fn replace_file(tmp: &Path, path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        std::fs::copy(tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(tmp);
            format!("could not replace '{}': {e}", path.display())
        })?;
        std::fs::remove_file(tmp)
            .map_err(|e| format!("could not remove '{}': {e}", tmp.display()))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(tmp);
            format!("could not replace '{}': {e}", path.display())
        })
    }
}

fn manager_dir() -> PathBuf {
    std::env::var_os(ENV_MANAGER_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".pentect").join(MANAGER_DIR))
}

fn empty_index() -> FilePointerIndex {
    FilePointerIndex {
        version: INDEX_VERSION,
        records: Vec::new(),
    }
}

fn envelope_overhead() -> usize {
    ENVELOPE_MAGIC.len() + NONCE_BYTES + TAG_BYTES
}

fn stored_path(path: &Path) -> String {
    if path.is_absolute() {
        if let Ok(cwd) = std::env::current_dir() {
            if let Ok(relative) = path.strip_prefix(cwd) {
                return relative.to_string_lossy().into_owned();
            }
        }
    }
    path.to_string_lossy().into_owned()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    data_encoding::HEXLOWER.encode(&digest)
}

fn save_enabled() -> bool {
    #[cfg(not(test))]
    {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| crate::config::file_pointer_manager_save_enabled().unwrap_or(false))
    }
    #[cfg(test)]
    {
        crate::config::file_pointer_manager_save_enabled().unwrap_or(false)
    }
}

fn manager_key(create: bool) -> Result<Option<[u8; 32]>, String> {
    let path = key_path();
    match std::fs::read(&path) {
        Ok(bytes) => {
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "file pointer manager key has wrong length".to_string())?;
            Ok(Some(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !create => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key)
                .map_err(|e| format!("could not create file pointer manager key: {e}"))?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("could not create '{}': {e}", parent.display()))?;
            }
            std::fs::write(&path, key)
                .map_err(|e| format!("could not write '{}': {e}", path.display()))?;
            harden_key_permissions(&path);
            Ok(Some(key))
        }
        Err(e) => Err(format!("could not read '{}': {e}", path.display())),
    }
}

fn random_hex_8() -> String {
    let mut bytes = [0u8; 8];
    if getrandom::getrandom(&mut bytes).is_ok() {
        return data_encoding::HEXLOWER.encode(&bytes);
    }
    let fallback = format!(
        "{}-{:?}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).ok()
    );
    let digest = Sha256::digest(fallback.as_bytes());
    data_encoding::HEXLOWER.encode(&digest[..8])
}

fn harden_key_permissions(path: &Path) {
    #[cfg(unix)]
    {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn encrypt_payload(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| format!("could not create file pointer manager nonce: {e}"))?;
    let mut ciphertext = plaintext.to_vec();
    apply_keystream(&mut ciphertext, key, &nonce);
    let tag = auth_tag(key, &nonce, &ciphertext)?;
    let mut out =
        Vec::with_capacity(ENVELOPE_MAGIC.len() + NONCE_BYTES + TAG_BYTES + ciphertext.len());
    out.extend_from_slice(ENVELOPE_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_payload(bytes: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    let header_len = ENVELOPE_MAGIC.len() + NONCE_BYTES + TAG_BYTES;
    if bytes.len() < header_len || !bytes.starts_with(ENVELOPE_MAGIC) {
        return None;
    }
    let nonce_start = ENVELOPE_MAGIC.len();
    let tag_start = nonce_start + NONCE_BYTES;
    let ciphertext_start = tag_start + TAG_BYTES;
    let nonce: [u8; NONCE_BYTES] = bytes.get(nonce_start..tag_start)?.try_into().ok()?;
    let tag = bytes.get(tag_start..ciphertext_start)?;
    let ciphertext = bytes.get(ciphertext_start..)?;
    let expected = auth_tag(key, &nonce, ciphertext).ok()?;
    if !constant_time_eq(tag, &expected) {
        return None;
    }
    let mut plaintext = ciphertext.to_vec();
    apply_keystream(&mut plaintext, key, &nonce);
    Some(plaintext)
}

fn apply_keystream(buf: &mut [u8], key: &[u8; 32], nonce: &[u8; NONCE_BYTES]) {
    let stream_key = derived_key(key, b"pentect-file-pointer-manager-stream-v1");
    let key = Key::from(stream_key);
    let nonce = Nonce::from(*nonce);
    let mut cipher = ChaCha20::new(&key, &nonce);
    cipher.apply_keystream(buf);
}

fn auth_tag(
    key: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<[u8; TAG_BYTES], String> {
    let mac_key = derived_key(key, b"pentect-file-pointer-manager-mac-v1");
    let mut mac = HmacSha256::new_from_slice(&mac_key).map_err(|e| e.to_string())?;
    mac.update(ENVELOPE_MAGIC);
    mac.update(nonce);
    mac.update(ciphertext);
    let bytes = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_BYTES];
    tag.copy_from_slice(&bytes);
    Ok(tag)
}

fn derived_key(key: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(key);
    hasher.finalize().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in a.iter().zip(b) {
        diff |= a ^ b;
    }
    diff == 0
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
