use crate::model::*;

/// Resolve overlapping candidates into a non-overlapping set.
pub fn merge(mut spans: Vec<Span>, protected: &[ByteRange]) -> Vec<Span> {
    // Drop empties and anything touching a frozen placeholder.
    spans.retain(|s| !s.range.is_empty() && !protected.iter().any(|p| p.overlaps(&s.range)));

    // Priority: higher confidence, then larger span, then category, then a
    // deterministic (source, start, end) tie-break.
    spans.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(b.range.len().cmp(&a.range.len()))
            .then(b.category.priority().cmp(&a.category.priority()))
            .then(a.source.cmp(&b.source))
            .then(a.range.start.cmp(&b.range.start))
            .then(a.range.end.cmp(&b.range.end))
    });

    // Greedily keep non-overlapping spans in priority order.
    let mut accepted: Vec<Span> = Vec::new();
    for s in spans {
        if accepted.iter().all(|a| !a.range.overlaps(&s.range)) {
            accepted.push(s);
        }
    }
    accepted.sort_by_key(|s| s.range.start);
    accepted
}
