use aho_corasick::{AhoCorasickBuilder, MatchKind};
use chacha20::cipher::StreamCipher;
use chacha20::{ChaCha20, Key, KeyIvInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zeroize::Zeroize;

const MEMORY_KEY_DOMAIN: &[u8] = b"pentect-recovery-memory-key-v1";
const MEMORY_NONCE_DOMAIN: &[u8] = b"pentect-recovery-memory-nonce-v1";
const MAC_DOMAIN: &[u8] = b"pentect-recovery-mac-v1";
const MAX_PLACEHOLDER_BYTES: usize = 512;
/// Serialized recovery blob: `MAGIC | VERSION | HMAC(32) | body`. The body is
/// the already-encrypted map (no plaintext), the HMAC is keyed by a
/// key-derived MAC key over `MAGIC | VERSION | body`, so a wrong key, a version
/// bump, or any tampering fails closed on load.
const MAGIC: &[u8; 4] = b"PNR1";
const FORMAT_VERSION: u8 = 1;

/// Local-only placeholder -> original mapping. Values are encrypted with a
/// process-local ChaCha20 key so secrets do not remain as plaintext between
/// operations. This does not protect against an attacker that can read the key
/// and ciphertext from the same live process.
/// Deliberately not serializable — persisting it to disk is a separate, gated
/// decision (a versioned, integrity-checked header), not a casual derive.
#[derive(Clone, Debug, Default)]
pub struct Recovery {
    memory_key: [u8; 32],
    map: HashMap<String, Vec<u8>>,
}

impl Recovery {
    /// Create an empty recovery map using the same in-memory encryption key as
    /// maps sealed with `key`. This is useful for adapters that batch multiple
    /// mask results into one persisted recovery file.
    pub fn empty_for_key(key: &[u8; 32]) -> Self {
        Self {
            memory_key: derive_memory_key(key),
            map: HashMap::new(),
        }
    }

    /// Encrypt a plaintext placeholder->value map for in-memory storage.
    pub fn seal(plaintext: HashMap<String, String>, key: &[u8; 32]) -> Self {
        let memory_key = derive_memory_key(key);
        let map = plaintext
            .into_iter()
            .map(|(ph, val)| {
                let ciphertext = crypt_memory_value(&memory_key, ph.as_bytes(), val.as_bytes());
                (ph, ciphertext)
            })
            .collect();
        Self { memory_key, map }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Public placeholder tokens known to this recovery map.
    ///
    /// This does not reveal plaintext values. Adapters use it for local metadata
    /// records that are themselves stored under synthetic placeholders.
    pub fn placeholders(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    /// Merge another recovery produced with the same key into this one.
    ///
    /// Placeholders are deterministic for a given key/value/label pair, so
    /// duplicate entries are harmless and overwrite with the same original.
    pub fn extend_same_key(&mut self, mut other: Self) {
        self.map.extend(std::mem::take(&mut other.map));
    }

    /// Decrypt the original value for `placeholder`, if present.
    fn reveal(&self, placeholder: &str) -> Option<String> {
        let ciphertext = self.map.get(placeholder)?;
        let bytes = crypt_memory_value(&self.memory_key, placeholder.as_bytes(), ciphertext);
        // Always valid UTF-8: we only ever sealed &str bytes and encryption is exact.
        String::from_utf8(bytes).ok()
    }

    /// Resolve known placeholders into their original values.
    ///
    /// This is the local-only half of the agent boundary loop: an adapter can
    /// let the model work with masked commands, then call `resolve` immediately
    /// before executing them. Unknown placeholders pass through unchanged, so a
    /// hallucinated token never invents a value.
    pub fn resolve(&self, text: &str) -> String {
        resolve_text(text, self)
    }

    /// Re-mask: replace any sealed original value that reappears in `text` (e.g.
    /// a tool echoed it after a resolve) with its placeholder. The other half of
    /// `resolve`, for the resolve-at-exec loop: resolve placeholders just before
    /// running a command, then re-mask the command's output so a revealed secret
    /// does not leak back to the model. Longest value first, so a value that
    /// contains a shorter one is replaced as a whole.
    pub fn remask(&self, text: &str) -> String {
        let mut pairs: Vec<(String, &str)> = self
            .map
            .keys()
            .filter_map(|ph| self.reveal(ph).map(|v| (v, ph.as_str())))
            .filter(|(v, _)| is_remaskable_echo(v))
            .collect();
        if pairs.is_empty() {
            return text.to_string();
        }
        if pairs.len() == 1 {
            let (mut value, ph) = pairs.pop().expect("checked len");
            let out = text.replace(&value, ph);
            value.zeroize();
            return out;
        }
        let patterns: Vec<&str> = pairs.iter().map(|(value, _)| value.as_str()).collect();
        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(patterns)
            .expect("non-empty remask patterns");
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        for m in ac.find_iter(text) {
            out.push_str(&text[cursor..m.start()]);
            out.push_str(pairs[m.pattern().as_usize()].1);
            cursor = m.end();
        }
        out.push_str(&text[cursor..]);
        for (value, _) in &mut pairs {
            value.zeroize(); // don't leave the revealed plaintext on the heap
        }
        out
    }

    /// Serialize for persistence: `MAGIC | VERSION | HMAC | body`. The body is
    /// the encrypted map (no plaintext); the HMAC binds it to `key`. This is a
    /// FORMAT, not storage — an adapter writes the bytes to disk, and should
    /// wrap them in an AEAD at rest. The memory key is re-derived from `key`.
    pub fn serialize(&self, key: &[u8; 32]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(self.map.len() as u32).to_le_bytes());
        for (ph, val) in &self.map {
            body.extend_from_slice(&(ph.len() as u32).to_le_bytes());
            body.extend_from_slice(ph.as_bytes());
            body.extend_from_slice(&(val.len() as u32).to_le_bytes());
            body.extend_from_slice(val);
        }
        let mut out = Vec::with_capacity(4 + 1 + 32 + body.len());
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&mac(key, &out, &body));
        out.extend_from_slice(&body);
        out
    }

    /// Load a serialized blob, failing closed on a bad magic, an unsupported
    /// version, a wrong key / tampering (HMAC mismatch), or a malformed body.
    /// A corrupt or foreign blob never yields a partial or wrong mapping.
    pub fn load(bytes: &[u8], key: &[u8; 32]) -> Result<Self, RecoveryError> {
        if bytes.len() < 4 + 1 + 32 {
            return Err(RecoveryError::Malformed);
        }
        if &bytes[..4] != MAGIC {
            return Err(RecoveryError::BadMagic);
        }
        let version = bytes[4];
        if version != FORMAT_VERSION {
            return Err(RecoveryError::UnsupportedVersion(version));
        }
        let tag = &bytes[5..37];
        let body = &bytes[37..];
        // Constant-time HMAC verify over MAGIC | VERSION | body.
        let mut m = Hmac::<Sha256>::new_from_slice(&derive_mac_key(key)).expect("hmac key");
        m.update(&bytes[..5]);
        m.update(body);
        m.verify_slice(tag)
            .map_err(|_| RecoveryError::IntegrityFailure)?;

        let mut map = HashMap::new();
        let mut r = Reader { buf: body, pos: 0 };
        let count = r.u32()?;
        for _ in 0..count {
            let ph_len = r.u32()? as usize;
            let ph = String::from_utf8(r.take(ph_len)?.to_vec())
                .map_err(|_| RecoveryError::Malformed)?;
            let val_len = r.u32()? as usize;
            let val = r.take(val_len)?.to_vec();
            map.insert(ph, val);
        }
        if r.pos != body.len() {
            return Err(RecoveryError::Malformed); // trailing garbage
        }
        Ok(Self {
            memory_key: derive_memory_key(key),
            map,
        })
    }
}

#[derive(Default)]
pub struct RecoveryStreamRemasker {
    patterns: Vec<StreamPattern>,
    pending_raw: Vec<u8>,
    pending_visible: Vec<u8>,
    visible_raw_starts: Vec<usize>,
    visible_raw_ends: Vec<usize>,
}

struct StreamPattern {
    value: Vec<u8>,
    placeholder: Vec<u8>,
}

impl Recovery {
    pub fn stream_remasker(&self) -> RecoveryStreamRemasker {
        let mut remasker = RecoveryStreamRemasker::default();
        remasker.merge_recovery(self);
        remasker
    }
}

impl RecoveryStreamRemasker {
    pub fn merge_recovery(&mut self, recovery: &Recovery) {
        let mut incoming = recovery
            .map
            .keys()
            .filter_map(|placeholder| {
                recovery
                    .reveal(placeholder)
                    .filter(|value| is_remaskable_echo(value))
                    .map(|value| StreamPattern {
                        value: value.into_bytes(),
                        placeholder: placeholder.as_bytes().to_vec(),
                    })
            })
            .collect::<Vec<_>>();
        self.patterns.append(&mut incoming);
        self.patterns.sort_by(|left, right| {
            left.value
                .cmp(&right.value)
                .then_with(|| left.placeholder.cmp(&right.placeholder))
        });
        let mut deduplicated = Vec::with_capacity(self.patterns.len());
        for mut pattern in self.patterns.drain(..) {
            if deduplicated
                .last()
                .is_some_and(|previous: &StreamPattern| previous.value == pattern.value)
            {
                pattern.value.zeroize();
                pattern.placeholder.zeroize();
            } else {
                deduplicated.push(pattern);
            }
        }
        self.patterns = deduplicated;
    }

    pub fn push_text(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.pending_raw.reserve(bytes.len());
        self.pending_visible.reserve(bytes.len());
        self.visible_raw_starts.reserve(bytes.len());
        self.visible_raw_ends.reserve(bytes.len());
        for byte in bytes {
            let start = self.pending_raw.len();
            self.pending_raw.push(*byte);
            self.pending_visible.push(*byte);
            self.visible_raw_starts.push(start);
            self.visible_raw_ends.push(start + 1);
        }
        self.drain_ready(false)
    }

    pub fn push_control(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.pending_raw.extend_from_slice(bytes);
        self.drain_ready(false)
    }

    pub fn finish(&mut self) -> Vec<u8> {
        self.drain_ready(true)
    }

    fn drain_ready(&mut self, force: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if self.patterns.is_empty() {
            out.extend(std::mem::take(&mut self.pending_raw));
            self.clear_visible();
            return out;
        }
        loop {
            let candidate = self.first_candidate(force);
            match candidate {
                Some(StreamCandidate::Partial { start }) => {
                    if start > 0 {
                        self.emit_visible_prefix(start, &mut out);
                    }
                    break;
                }
                Some(StreamCandidate::Full {
                    start,
                    end,
                    pattern,
                }) => {
                    if start > 0 {
                        self.emit_visible_prefix(start, &mut out);
                        continue;
                    }
                    let raw_end = self.visible_raw_ends[end - 1];
                    out.extend_from_slice(&self.patterns[pattern].placeholder);
                    self.discard_prefix(end, raw_end);
                }
                None => {
                    out.extend(std::mem::take(&mut self.pending_raw));
                    self.clear_visible();
                    break;
                }
            }
        }
        out
    }

    fn first_candidate(&self, force: bool) -> Option<StreamCandidate> {
        for start in 0..self.pending_visible.len() {
            let remaining = &self.pending_visible[start..];
            let mut longest_full = None;
            let mut has_partial = false;
            for (index, pattern) in self.patterns.iter().enumerate() {
                if remaining.len() >= pattern.value.len() && remaining.starts_with(&pattern.value) {
                    if longest_full.is_none_or(|(_, len)| pattern.value.len() > len) {
                        longest_full = Some((index, pattern.value.len()));
                    }
                } else if !force
                    && remaining.len() < pattern.value.len()
                    && pattern.value.starts_with(remaining)
                {
                    has_partial = true;
                }
            }
            if has_partial {
                return Some(StreamCandidate::Partial { start });
            }
            if let Some((pattern, len)) = longest_full {
                return Some(StreamCandidate::Full {
                    start,
                    end: start + len,
                    pattern,
                });
            }
        }
        None
    }

    fn emit_visible_prefix(&mut self, visible: usize, out: &mut Vec<u8>) {
        let raw = self.visible_raw_starts[visible];
        out.extend(self.pending_raw.drain(..raw));
        self.remove_visible_prefix(visible, raw);
    }

    fn discard_prefix(&mut self, visible: usize, raw: usize) {
        let mut discarded = self.pending_raw.drain(..raw).collect::<Vec<_>>();
        discarded.zeroize();
        self.remove_visible_prefix(visible, raw);
    }

    fn remove_visible_prefix(&mut self, visible: usize, raw: usize) {
        let mut discarded = self.pending_visible.drain(..visible).collect::<Vec<_>>();
        discarded.zeroize();
        self.visible_raw_starts.drain(..visible);
        self.visible_raw_ends.drain(..visible);
        for offset in &mut self.visible_raw_starts {
            *offset -= raw;
        }
        for offset in &mut self.visible_raw_ends {
            *offset -= raw;
        }
    }

    fn clear_visible(&mut self) {
        self.pending_visible.zeroize();
        self.pending_visible.clear();
        self.visible_raw_starts.zeroize();
        self.visible_raw_starts.clear();
        self.visible_raw_ends.zeroize();
        self.visible_raw_ends.clear();
    }
}

enum StreamCandidate {
    Partial {
        start: usize,
    },
    Full {
        start: usize,
        end: usize,
        pattern: usize,
    },
}

impl Drop for RecoveryStreamRemasker {
    fn drop(&mut self) {
        for pattern in &mut self.patterns {
            pattern.value.zeroize();
            pattern.placeholder.zeroize();
        }
        self.pending_raw.zeroize();
        self.clear_visible();
    }
}

fn is_remaskable_echo(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() >= 6 && !matches!(trimmed, "true" | "false" | "null")
}

impl Drop for Recovery {
    fn drop(&mut self) {
        // Wipe the memory key and ciphertext so a dropped map
        // leaves no recovery material in freed memory. Placeholders are public.
        self.memory_key.zeroize();
        for v in self.map.values_mut() {
            v.zeroize();
        }
    }
}

/// HMAC-SHA256 over `header || body`, keyed by a key-derived MAC key.
fn mac(key: &[u8; 32], header: &[u8], body: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(&derive_mac_key(key)).expect("hmac key");
    m.update(header);
    m.update(body);
    m.finalize().into_bytes().into()
}

fn derive_mac_key(key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MAC_DOMAIN);
    h.update(key);
    h.finalize().into()
}

/// Length-prefix reader that fails closed (no panic) on truncation.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn u32(&mut self) -> Result<u32, RecoveryError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn take(&mut self, n: usize) -> Result<&[u8], RecoveryError> {
        let end = self.pos.checked_add(n).ok_or(RecoveryError::Malformed)?;
        if end > self.buf.len() {
            return Err(RecoveryError::Malformed);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
}

/// Uninhabited: resolving from a valid in-memory map cannot fail — it reveals
/// known tokens and passes unknown ones through. The fail-closed path is `load`
/// (validating an untrusted/persisted blob), which returns `RecoveryError`.
#[derive(Clone, Debug)]
pub enum RestoreError {}

/// Why loading a serialized recovery blob failed. Every variant means the blob
/// is rejected whole — `load` never returns a partial or wrong mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    /// Not a pentect recovery blob (magic mismatch).
    BadMagic,
    /// A newer/older format this build does not understand.
    UnsupportedVersion(u8),
    /// HMAC mismatch: wrong key, or the bytes were tampered/corrupted.
    IntegrityFailure,
    /// Truncated or structurally invalid body.
    Malformed,
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryError::BadMagic => write!(f, "not a pentect recovery blob"),
            RecoveryError::UnsupportedVersion(v) => write!(f, "unsupported recovery version {v}"),
            RecoveryError::IntegrityFailure => write!(f, "recovery integrity check failed"),
            RecoveryError::Malformed => write!(f, "malformed recovery blob"),
        }
    }
}

impl std::error::Error for RecoveryError {}

/// Compatibility wrapper for resolving known placeholders into originals.
/// Prefer `Recovery::resolve` in agent-boundary code.
pub fn restore(text: &str, rec: &Recovery) -> Result<String, RestoreError> {
    Ok(rec.resolve(text))
}

/// Replace known `<<...>>` tokens with their originals; leave unknown tokens
/// unchanged (a hallucinated placeholder has no mapping, so nothing can leak).
fn resolve_text(text: &str, rec: &Recovery) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'<' && i + 1 < bytes.len() && bytes[i + 1] == b'<' {
            if let Some(close) = find_from_limited(bytes, i + 2, b">>", MAX_PLACEHOLDER_BYTES) {
                let token = &text[i..close + 2];
                if let Some(mut v) = rec.reveal(token) {
                    out.push_str(&v);
                    v.zeroize();
                    i = close + 2;
                    continue;
                }
                // Unknown token: don't consume it whole. A stray '<' before a
                // real placeholder (masked output "<" + "<<X>>" = "<<<X>>") must
                // still resolve the inner one — fall through and copy one char.
            }
        }
        let len = utf8_len(bytes[i]);
        out.push_str(&text[i..i + len]);
        i += len;
    }
    out
}

/// Domain-separated encryption key derived from the masking key.
fn derive_memory_key(key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MEMORY_KEY_DOMAIN);
    h.update(key);
    h.finalize().into()
}

/// Encrypt or decrypt one value. A placeholder identifies one immutable value,
/// so its domain-separated hash is a stable nonce for that entry.
fn crypt_memory_value(key: &[u8; 32], placeholder: &[u8], data: &[u8]) -> Vec<u8> {
    let mut nonce_hash = Sha256::new();
    nonce_hash.update(MEMORY_NONCE_DOMAIN);
    nonce_hash.update(placeholder);
    let nonce_hash = nonce_hash.finalize();
    let key = Key::from(*key);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce_hash[..12]);
    let nonce = Nonce::from(nonce_bytes);
    let mut cipher = ChaCha20::new(&key, &nonce);
    let mut out = data.to_vec();
    cipher.apply_keystream(&mut out);
    out
}

fn find_from_limited(hay: &[u8], start: usize, needle: &[u8], max_len: usize) -> Option<usize> {
    if needle.is_empty() || start >= hay.len() {
        return None;
    }
    let limit = hay.len().min(start.saturating_add(max_len));
    let mut i = start;
    while i + needle.len() <= limit {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_placeholders_pass_through() {
        let rec = Recovery::default();
        let out = restore("a <<X_unknown>> b", &rec).unwrap();
        assert_eq!(out, "a <<X_unknown>> b");
    }

    #[test]
    fn seal_reveal_round_trips_without_storing_cleartext() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let rec = Recovery::seal(
            HashMap::from([(
                "<<AWS_AKID_0011223344556677>>".to_string(),
                secret.to_string(),
            )]),
            &[7u8; 32],
        );
        // restore decrypts exactly,
        assert_eq!(
            restore("use <<AWS_AKID_0011223344556677>>", &rec).unwrap(),
            format!("use {secret}")
        );
        // but the stored bytes are not the plaintext secret.
        let stored = rec.map.get("<<AWS_AKID_0011223344556677>>").unwrap();
        assert_ne!(stored.as_slice(), secret.as_bytes());
    }

    #[test]
    fn resolve_method_restores_known_placeholders() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let ph = "<<AWS_AKID_0011223344556677>>";
        let rec = Recovery::seal(
            HashMap::from([(ph.to_string(), secret.to_string())]),
            &[7u8; 32],
        );
        assert_eq!(rec.resolve(&format!("use {ph}")), format!("use {secret}"));
        assert_eq!(
            restore(&format!("use {ph}"), &rec).unwrap(),
            rec.resolve(&format!("use {ph}"))
        );
    }

    #[test]
    fn resolve_leaves_unknown_placeholders_byte_identical() {
        let rec = Recovery::default();
        let text = "run <<UNKNOWN_0011223344556677>> now";
        assert_eq!(rec.resolve(text), text);
    }

    #[test]
    fn remask_rehides_echoed_values_and_pairs_with_restore() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let ph = "<<AWS_AKID_0011223344556677>>";
        let rec = Recovery::seal(
            HashMap::from([(ph.to_string(), secret.to_string())]),
            &[5u8; 32],
        );
        // A tool echoed the resolved secret; remask hides it again.
        assert_eq!(
            rec.remask(&format!("ran with {secret} ok")),
            format!("ran with {ph} ok")
        );
        // restore then remask is the identity on masked text.
        let masked = format!("use {ph}");
        assert_eq!(rec.remask(&restore(&masked, &rec).unwrap()), masked);
    }

    #[test]
    fn remask_ignores_short_metadata_values() {
        let rec = Recovery::seal(
            HashMap::from([("<<COUNT_0011223344556677>>".to_string(), "3".to_string())]),
            &[5u8; 32],
        );
        assert_eq!(rec.resolve("n=<<COUNT_0011223344556677>>"), "n=3");
        assert_eq!(
            rec.remask("AKIA3EXAMPLE has a digit"),
            "AKIA3EXAMPLE has a digit"
        );
    }

    #[test]
    fn stream_remasker_masks_values_split_across_chunks_and_controls() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let placeholder = "<<AWS_AKID_0011223344556677>>";
        let recovery = Recovery::seal(
            HashMap::from([(placeholder.to_string(), secret.to_string())]),
            &[5u8; 32],
        );
        let mut remasker = recovery.stream_remasker();
        let mut out = remasker.push_text(b"answer AKIAIOS");
        out.extend(remasker.push_control(b"\x1b[31m"));
        out.extend(remasker.push_text(b"FODNN7EXAMPLE done"));
        out.extend(remasker.finish());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("answer {placeholder} done")
        );
    }

    #[test]
    fn stream_remasker_keeps_existing_placeholders_byte_identical() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let placeholder = "<<AWS_AKID_0011223344556677>>";
        let recovery = Recovery::seal(
            HashMap::from([(placeholder.to_string(), secret.to_string())]),
            &[5u8; 32],
        );
        let mut remasker = recovery.stream_remasker();
        let mut out = remasker.push_text(format!("answer {placeholder}").as_bytes());
        out.extend(remasker.finish());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("answer {placeholder}")
        );
    }

    #[test]
    fn stream_remasker_waits_for_the_longest_known_value() {
        let recovery = Recovery::seal(
            HashMap::from([
                (
                    "<<SHORT_0011223344556677>>".to_string(),
                    "secret".to_string(),
                ),
                (
                    "<<LONG_0011223344556677>>".to_string(),
                    "secret-value".to_string(),
                ),
            ]),
            &[5u8; 32],
        );
        let mut remasker = recovery.stream_remasker();
        assert!(remasker.push_text(b"secret").is_empty());
        let mut out = remasker.push_text(b"-value");
        out.extend(remasker.finish());
        assert_eq!(out, b"<<LONG_0011223344556677>>");
    }

    #[test]
    fn empty_for_key_extends_and_persists_batch() {
        let key = [8u8; 32];
        let mut batch = Recovery::empty_for_key(&key);
        batch.extend_same_key(Recovery::seal(
            HashMap::from([("<<A_0011223344556677>>".into(), "alpha".into())]),
            &key,
        ));
        batch.extend_same_key(Recovery::seal(
            HashMap::from([("<<B_0011223344556677>>".into(), "bravo".into())]),
            &key,
        ));

        let loaded = Recovery::load(&batch.serialize(&key), &key).unwrap();
        assert_eq!(
            loaded.resolve("x=<<A_0011223344556677>> y=<<B_0011223344556677>>"),
            "x=alpha y=bravo"
        );
    }

    fn sample_recovery(key: &[u8; 32]) -> Recovery {
        Recovery::seal(
            HashMap::from([
                (
                    "<<AWS_AKID_0011223344556677>>".into(),
                    "AKIAIOSFODNN7EXAMPLE".into(),
                ),
                (
                    "<<IDENTITY_8899aabbccddeeff>>".into(),
                    "alice@example.com".into(),
                ),
            ]),
            key,
        )
    }

    #[test]
    fn stray_angle_before_placeholder_still_restores() {
        let ph = "<<X_aabbccdd00112233>>";
        let rec = Recovery::seal(
            HashMap::from([(ph.to_string(), "secret".to_string())]),
            &[1u8; 32],
        );
        // Masked output where a literal '<' precedes the placeholder ("<<<X_..>>").
        assert_eq!(restore(&format!("<{ph}"), &rec).unwrap(), "<secret");
        assert_eq!(rec.resolve(&format!("<{ph}")), "<secret");
        // An unknown "<<<..>>" still passes through byte-for-byte (nothing leaks).
        let unknown = "<<<UNKNOWN_0000000000000000>>";
        assert_eq!(restore(unknown, &Recovery::default()).unwrap(), unknown);
        assert_eq!(Recovery::default().resolve(unknown), unknown);
    }

    #[test]
    fn serialize_load_round_trips_and_restores() {
        let key = [9u8; 32];
        let rec = sample_recovery(&key);
        let blob = rec.serialize(&key);
        let loaded = Recovery::load(&blob, &key).unwrap();
        assert_eq!(
            restore("id <<AWS_AKID_0011223344556677>>", &loaded).unwrap(),
            "id AKIAIOSFODNN7EXAMPLE"
        );
        // No plaintext secret sits in the serialized bytes.
        assert!(!contains(&blob, b"AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn load_fails_closed() {
        let key = [9u8; 32];
        let blob = sample_recovery(&key).serialize(&key);

        let err = |b: &[u8], k: &[u8; 32]| Recovery::load(b, k).err();
        // Wrong key -> integrity failure (not a wrong/partial mapping).
        assert_eq!(
            err(&blob, &[1u8; 32]),
            Some(RecoveryError::IntegrityFailure)
        );
        // Tampered body byte -> integrity failure.
        let mut t = blob.clone();
        *t.last_mut().unwrap() ^= 0x01;
        assert_eq!(err(&t, &key), Some(RecoveryError::IntegrityFailure));
        // Bad magic.
        let mut bad = blob.clone();
        bad[0] ^= 0xff;
        assert_eq!(err(&bad, &key), Some(RecoveryError::BadMagic));
        // Unsupported version.
        let mut ver = blob.clone();
        ver[4] = 99;
        assert_eq!(err(&ver, &key), Some(RecoveryError::UnsupportedVersion(99)));
        // Truncated body -> integrity failure; too-short -> malformed.
        assert_eq!(
            err(&blob[..40], &key),
            Some(RecoveryError::IntegrityFailure)
        );
        assert_eq!(err(b"short", &key), Some(RecoveryError::Malformed));
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    proptest::proptest! {
        // load must never panic on arbitrary bytes; it returns Err, never a map.
        #[test]
        fn load_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
            let _ = Recovery::load(&bytes, &[3u8; 32]);
        }

        // restore must never panic on arbitrary input, with or without entries.
        #[test]
        fn restore_never_panics(
            text in proptest::prelude::any::<String>(),
            k in "[A-Z_]{0,8}",
            v in ".{0,16}",
        ) {
            let rec = Recovery::seal(HashMap::from([(format!("<<{k}_aa>>"), v)]), &[0u8; 32]);
            let _ = restore(&text, &rec).unwrap();
        }

        // A well-formed placeholder with no mapping (e.g. an LLM hallucination)
        // restores byte-for-byte: nothing is invented, nothing leaks.
        #[test]
        fn unmapped_placeholder_is_byte_identical(
            label in "[A-Z][A-Z0-9_]{0,15}",
            hash in "[0-9a-f]{16}",
        ) {
            let token = format!("<<{label}_{hash}>>");
            let text = format!("before {token} after");
            let out = restore(&text, &Recovery::default()).unwrap();
            proptest::prop_assert_eq!(out, text);
        }
    }
}
