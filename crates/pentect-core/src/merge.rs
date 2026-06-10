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

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: usize, end: usize, conf: Confidence, src: &str) -> Span {
        Span {
            range: ByteRange::new(start, end),
            category: Category::Secret,
            label: "X".into(),
            confidence: conf,
            source: src.into(),
        }
    }

    #[test]
    fn higher_confidence_wins_overlap() {
        let out = merge(
            vec![span(0, 10, Confidence::Low, "entropy"), span(2, 8, Confidence::High, "rule")],
            &[],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].confidence, Confidence::High);
    }

    #[test]
    fn equal_confidence_prefers_larger_span() {
        let out = merge(
            vec![span(2, 6, Confidence::Medium, "a"), span(0, 10, Confidence::Medium, "b")],
            &[],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].range, ByteRange::new(0, 10));
    }

    #[test]
    fn protected_and_empty_dropped() {
        let out = merge(vec![span(0, 5, Confidence::High, "r"), span(7, 7, Confidence::High, "e")], &[ByteRange::new(0, 5)]);
        assert!(out.is_empty());
    }

    #[test]
    fn disjoint_spans_all_kept_sorted() {
        let out = merge(
            vec![span(10, 12, Confidence::Low, "a"), span(0, 3, Confidence::Low, "b")],
            &[],
        );
        assert_eq!(out.len(), 2);
        assert!(out[0].range.start < out[1].range.start);
    }
}
