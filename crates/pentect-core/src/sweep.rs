use crate::model::*;
use crate::normalize::n_id;
use std::collections::BTreeMap;

/// Mask every other occurrence of an already-masked value across the whole input.
/// This is correctness, not optimization: a value left in plaintext anywhere leaks.
pub fn identity_sweep(raw: &str, accepted: Vec<Span>, protected: &[ByteRange]) -> Vec<Span> {
    // Earliest occurrence of each identity is the representative.
    let mut rep: BTreeMap<String, Span> = BTreeMap::new();
    for s in &accepted {
        let val = &raw[s.range.start..s.range.end];
        let id = n_id(val);
        rep.entry(id)
            .and_modify(|e| {
                if s.range.start < e.range.start {
                    *e = s.clone();
                }
            })
            .or_insert_with(|| s.clone());
    }

    // Add every literal occurrence that doesn't clash with an existing span or a
    // frozen placeholder.
    let mut all = accepted.clone();
    for r in rep.values() {
        let needle = &raw[r.range.start..r.range.end];
        if needle.is_empty() {
            continue;
        }
        let mut from = 0usize;
        while let Some(pos) = raw[from..].find(needle) {
            let abs = from + pos;
            let range = ByteRange::new(abs, abs + needle.len());
            from = abs + needle.len();
            let clash = all.iter().any(|a| a.range.overlaps(&range))
                || protected.iter().any(|p| p.overlaps(&range));
            if !clash {
                all.push(Span {
                    range,
                    category: r.category,
                    label: r.label.clone(),
                    confidence: r.confidence,
                    source: "sweep".to_string(),
                });
            }
        }
    }

    all.sort_by_key(|s| s.range.start);
    all
}
