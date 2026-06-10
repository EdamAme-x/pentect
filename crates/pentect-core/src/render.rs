//! Renderer（REF.md §10/§11）: 値範囲を placeholder へ。
//! 同 identity → 同 placeholder（全域一貫の ID）。slice 1 は whole-value 粒度のみ。

use crate::model::*;
use crate::normalize::n_id;
use crate::placeholder::{identity_hash, render_placeholder};
use std::collections::HashMap;

pub struct Rendered {
    pub masked: String,
    /// placeholder -> 原値（first-seen の raw bytes）。recovery map の元。
    pub map: HashMap<String, String>,
}

pub fn render(raw: &str, key: &[u8; 32], mut spans: Vec<Span>) -> Rendered {
    spans.sort_by_key(|s| s.range.start);
    let mut masked = String::with_capacity(raw.len());
    let mut map: HashMap<String, String> = HashMap::new();
    let mut cursor = 0usize;

    for s in &spans {
        // 念のための非重複ガード（Merge/Sweep で保証済みだが防御的に）。
        if s.range.start < cursor {
            continue;
        }
        masked.push_str(&raw[cursor..s.range.start]);
        let val = &raw[s.range.start..s.range.end];
        let hash = identity_hash(key, &n_id(val));
        let ph = render_placeholder(&s.label, &hash);
        masked.push_str(&ph);
        map.entry(ph).or_insert_with(|| val.to_string());
        cursor = s.range.end;
    }
    masked.push_str(&raw[cursor..]);

    Rendered { masked, map }
}
