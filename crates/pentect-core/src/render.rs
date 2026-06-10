use crate::model::*;
use crate::normalize::n_id;
use crate::placeholder::{identity_hash, length_bucket, render_placeholder};
use std::collections::HashMap;

pub struct Rendered {
    pub masked: String,
    /// placeholder -> first-seen original bytes.
    pub map: HashMap<String, String>,
}

/// Replace each span with a placeholder. Same identity yields the same
/// placeholder, keeping the whole document consistent. Length is disclosed only
/// when opted in, and only for opaque entropy-flagged blobs.
pub fn render(raw: &str, key: &[u8; 32], mut spans: Vec<Span>, disclose_length: bool) -> Rendered {
    spans.sort_by_key(|s| s.range.start);
    let mut masked = String::with_capacity(raw.len());
    let mut map: HashMap<String, String> = HashMap::new();
    let mut cursor = 0usize;

    for s in &spans {
        // Spans are already non-overlapping; this is just defensive.
        if s.range.start < cursor {
            continue;
        }
        masked.push_str(&raw[cursor..s.range.start]);
        let val = &raw[s.range.start..s.range.end];
        let hash = identity_hash(key, &n_id(val));
        let bucket = if disclose_length && s.label == "LIKELY_SECRET" {
            length_bucket(val.chars().count())
        } else {
            None
        };
        let ph = render_placeholder(&s.label, &hash, bucket);
        masked.push_str(&ph);
        map.entry(ph).or_insert_with(|| val.to_string());
        cursor = s.range.end;
    }
    masked.push_str(&raw[cursor..]);

    Rendered { masked, map }
}
