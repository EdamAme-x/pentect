use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Local-only mapping; never serialized into a MaskResult summary.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Recovery {
    pub map: HashMap<String, String>,
}

/// No failure modes yet; version/header mismatches will fail closed later.
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
                match rec.map.get(token) {
                    Some(v) => out.push_str(v),
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
