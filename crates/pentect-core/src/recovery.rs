//! Recovery & restore（REF.md §12）。core の primitive は `restore` 1つ（string→string）。
//! recovery map は **local-only**（summary/to_json に載せない, REF.md §14-5）。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Recovery {
    pub map: HashMap<String, String>,
}

/// slice 1 では失敗系を返さない。version/header mismatch の fail-closed（REF.md §12.1）は slice 2。
#[derive(Clone, Debug)]
pub enum RestoreError {}

/// `<<...>>` トークンを原値へ置換。未知 placeholder は **そのまま残す**
/// （原値が無い＝広がらない＝安全側, REF.md §12.1）。
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
