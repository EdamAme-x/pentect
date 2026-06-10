use crate::model::*;
use crate::normalize::n_id;
use crate::placeholder::{approx_length, identity_hash, render_placeholder};
use std::collections::HashMap;

pub struct Rendered {
    pub masked: String,
    /// placeholder -> first-seen original bytes.
    pub map: HashMap<String, String>,
    /// Placeholders that two distinct values hashed to (would mis-restore).
    pub collisions: Vec<String>,
}

/// Replace each span with a placeholder. Same identity yields the same
/// placeholder, keeping the whole document consistent. Length is disclosed only
/// when opted in, and only for opaque entropy-flagged blobs.
pub fn render(raw: &str, key: &[u8; 32], mut spans: Vec<Span>, disclose_length: bool) -> Rendered {
    spans.sort_by_key(|s| s.range.start);
    let mut masked = String::with_capacity(raw.len());
    let mut map: HashMap<String, String> = HashMap::new();
    let mut collisions = Vec::new();
    let mut cursor = 0usize;

    for s in &spans {
        // Spans are already non-overlapping; this is just defensive.
        if s.range.start < cursor {
            continue;
        }
        masked.push_str(&raw[cursor..s.range.start]);
        let val = &raw[s.range.start..s.range.end];
        let hash = identity_hash(key, &n_id(val));
        let len = if disclose_length && s.label == "LIKELY_SECRET" {
            approx_length(val.chars().count())
        } else {
            None
        };
        let ph = render_placeholder(&s.label, &hash, len);
        if record(&mut map, &ph, val) {
            collisions.push(ph.clone());
        }
        masked.push_str(&ph);
        cursor = s.range.end;
    }
    masked.push_str(&raw[cursor..]);

    Rendered { masked, map, collisions }
}

/// Insert a placeholder->value mapping. Returns true on collision: the
/// placeholder already maps to a *different* value (same value is the expected
/// identity case). On collision the first mapping is kept and restore would
/// mis-expand the second, so the caller surfaces it rather than failing silently.
fn record(map: &mut HashMap<String, String>, ph: &str, val: &str) -> bool {
    match map.get(ph) {
        Some(existing) => existing != val,
        None => {
            map.insert(ph.to_string(), val.to_string());
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_flags_collision_only_on_different_value() {
        let mut map = HashMap::new();
        assert!(!record(&mut map, "<<X_aa>>", "alice")); // first
        assert!(!record(&mut map, "<<X_aa>>", "alice")); // same value, identity
        assert!(record(&mut map, "<<X_aa>>", "bob")); // collision
        assert_eq!(map["<<X_aa>>"], "alice"); // first mapping kept
    }

    #[test]
    fn same_value_twice_is_one_mapping_no_collision() {
        let key = [9u8; 32];
        let raw = "a@b.com x a@b.com";
        let spans = vec![
            Span { range: ByteRange::new(0, 7), category: Category::Pii, label: "IDENTITY".into(), confidence: Confidence::Medium, source: "rule".into() },
            Span { range: ByteRange::new(10, 17), category: Category::Pii, label: "IDENTITY".into(), confidence: Confidence::Medium, source: "rule".into() },
        ];
        let r = render(raw, &key, spans, false);
        assert_eq!(r.map.len(), 1);
        assert!(r.collisions.is_empty());
    }
}
