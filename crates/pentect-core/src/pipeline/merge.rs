use crate::model::*;
use crate::policy::is_context_free;

/// Resolve overlapping candidates into a non-overlapping set.
pub fn merge(mut spans: Vec<Span>, protected: &[ByteRange]) -> Vec<Span> {
    // Drop empties and anything touching a frozen placeholder.
    spans.retain(|s| !s.range.is_empty() && !protected.iter().any(|p| p.overlaps(&s.range)));

    // Strongest first (Span::cmp_strength is the one canonical ordering).
    spans.sort_by(|a, b| b.cmp_strength(a));

    let mut accepted: Vec<Span> = Vec::new();
    for s in spans {
        if accepted.iter().all(|a| !a.range.overlaps(&s.range)) {
            accepted.push(s);
            continue;
        }
        // A context-free span ("this whole run is opaque") keeps the part not
        // already claimed by a stronger span, so the uncovered remainder is still
        // masked. Without this, masking the overlap leaves a maskable tail in
        // plaintext (a leak, and a break of idempotency: a second pass would mask
        // it). Anchored weaker spans still drop whole, so a vendor token is never
        // split into fragments.
        if is_context_free(&s) {
            let mut pieces = vec![s.range];
            for a in &accepted {
                pieces = pieces
                    .into_iter()
                    .flat_map(|p| subtract(p, &a.range))
                    .collect();
            }
            for range in pieces {
                if !range.is_empty() {
                    accepted.push(Span { range, ..s.clone() });
                }
            }
        }
    }
    accepted.sort_by_key(|s| s.range.start);
    accepted
}

/// `p` minus `a`: the 0–2 sub-ranges of `p` that `a` does not cover.
fn subtract(p: ByteRange, a: &ByteRange) -> Vec<ByteRange> {
    if !p.overlaps(a) {
        return vec![p];
    }
    let mut out = Vec::new();
    if p.start < a.start {
        out.push(ByteRange::new(p.start, a.start));
    }
    if a.end < p.end {
        out.push(ByteRange::new(a.end, p.end));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: usize, end: usize, conf: Confidence) -> Span {
        Span {
            range: ByteRange::new(start, end),
            category: Category::Secret,
            label: "X".into(),
            confidence: conf,
            source: DetectorId::Rule,
        }
    }

    #[test]
    fn higher_confidence_wins_overlap() {
        let out = merge(
            vec![span(0, 10, Confidence::Low), span(2, 8, Confidence::High)],
            &[],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].confidence, Confidence::High);
    }

    #[test]
    fn equal_confidence_prefers_larger_span() {
        let out = merge(
            vec![
                span(2, 6, Confidence::Medium),
                span(0, 10, Confidence::Medium),
            ],
            &[],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].range, ByteRange::new(0, 10));
    }

    #[test]
    fn protected_and_empty_dropped() {
        let out = merge(
            vec![span(0, 5, Confidence::High), span(7, 7, Confidence::High)],
            &[ByteRange::new(0, 5)],
        );
        assert!(out.is_empty());
    }

    #[test]
    fn disjoint_spans_all_kept_sorted() {
        let out = merge(
            vec![span(10, 12, Confidence::Low), span(0, 3, Confidence::Low)],
            &[],
        );
        assert_eq!(out.len(), 2);
        assert!(out[0].range.start < out[1].range.start);
    }

    fn entropy_span(start: usize, end: usize) -> Span {
        Span {
            range: ByteRange::new(start, end),
            category: Category::Secret,
            label: "LIKELY_SECRET".into(),
            confidence: Confidence::Low,
            source: DetectorId::Entropy,
        }
    }

    #[test]
    fn context_free_span_keeps_uncovered_remainder() {
        // A strong anchored hit claims [0,6); the entropy run [4,30) keeps [6,30)
        // so the tail is still masked (no leak, and idempotent).
        let out = merge(vec![span(0, 6, Confidence::High), entropy_span(4, 30)], &[]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].range, ByteRange::new(0, 6));
        assert_eq!(out[1].range, ByteRange::new(6, 30));
    }

    #[test]
    fn anchored_weaker_span_still_drops_whole() {
        // A non-context-free (Rule) span is not fragmented around a stronger hit.
        let out = merge(
            vec![span(2, 8, Confidence::High), span(0, 10, Confidence::Low)],
            &[],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].range, ByteRange::new(2, 8));
    }
}
