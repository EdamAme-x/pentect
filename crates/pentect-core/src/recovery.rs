use sha2::{Digest, Sha256};
use std::collections::HashMap;

const PAD_DOMAIN: &[u8] = b"pentect-recovery-pad-v1";

/// Local-only placeholder -> original mapping. Values are stored XOR-obfuscated,
/// not as cleartext: this is lightweight in-memory obfuscation, NOT encryption.
/// The pad is derived from the masking key and lives in the same process, so an
/// attacker with memory access still recovers the values; the point is only that
/// secrets don't sit as plaintext in a memory dump or trip a naive secret-scan.
/// Deliberately not serializable — persisting it to disk is a separate, gated
/// decision (a versioned, integrity-checked header), not a casual derive.
#[derive(Clone, Debug, Default)]
pub struct Recovery {
    pad: [u8; 32],
    map: HashMap<String, Vec<u8>>,
}

impl Recovery {
    /// Obfuscate a plaintext placeholder->value map for in-memory storage.
    pub fn seal(plaintext: HashMap<String, String>, key: &[u8; 32]) -> Self {
        let pad = derive_pad(key);
        let map = plaintext
            .into_iter()
            .map(|(ph, val)| {
                let obf = xor_keystream(&pad, ph.as_bytes(), val.as_bytes());
                (ph, obf)
            })
            .collect();
        Self { pad, map }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Deobfuscate the original value for `placeholder`, if present.
    fn reveal(&self, placeholder: &str) -> Option<String> {
        let obf = self.map.get(placeholder)?;
        let bytes = xor_keystream(&self.pad, placeholder.as_bytes(), obf);
        // Always valid UTF-8: we only ever sealed &str bytes and XOR is exact.
        String::from_utf8(bytes).ok()
    }
}

/// Uninhabited: `restore` cannot fail today. Reserved so a future versioned,
/// integrity-checked recovery header can fail closed without a breaking change to
/// `restore`'s signature.
#[derive(Clone, Debug)]
pub enum RestoreError {}

/// Replace known `<<...>>` tokens with their originals; leave unknown tokens
/// unchanged (a hallucinated placeholder has no mapping, so nothing can leak).
pub fn restore(text: &str, rec: &Recovery) -> Result<String, RestoreError> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'<' && i + 1 < bytes.len() && bytes[i + 1] == b'<' {
            if let Some(close) = find_from(bytes, i + 2, b">>") {
                let token = &text[i..close + 2];
                match rec.reveal(token) {
                    Some(v) => out.push_str(&v),
                    None => out.push_str(token),
                }
                i = close + 2;
                continue;
            }
        }
        let len = utf8_len(bytes[i]);
        out.push_str(&text[i..i + len]);
        i += len;
    }
    Ok(out)
}

/// Domain-separated pad derived from the masking key (so it isn't reused verbatim
/// for placeholder hashing).
fn derive_pad(key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PAD_DOMAIN);
    h.update(key);
    h.finalize().into()
}

/// XOR `data` with a per-entry keystream: block i is SHA256(pad || nonce || i).
/// `nonce` is the placeholder, unique per entry, so values never share a stream.
/// Reversible — calling it again on the output restores the input.
fn xor_keystream(pad: &[u8; 32], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut block = [0u8; 32];
    let mut bi = block.len();
    let mut counter: u64 = 0;
    for &b in data {
        if bi == block.len() {
            let mut h = Sha256::new();
            h.update(pad);
            h.update(nonce);
            h.update(counter.to_le_bytes());
            block = h.finalize().into();
            counter += 1;
            bi = 0;
        }
        out.push(b ^ block[bi]);
        bi += 1;
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
        // restore deobfuscates exactly,
        assert_eq!(
            restore("use <<AWS_AKID_0011223344556677>>", &rec).unwrap(),
            format!("use {secret}")
        );
        // but the stored bytes are not the plaintext secret.
        let stored = rec.map.get("<<AWS_AKID_0011223344556677>>").unwrap();
        assert_ne!(stored.as_slice(), secret.as_bytes());
    }

    proptest::proptest! {
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
