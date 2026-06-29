use crate::model::*;
use crate::policy::is_context_free;
use std::collections::HashSet;

use super::interval::RangeIndex;

/// Resolve overlapping candidates into a non-overlapping set.
pub fn merge(mut spans: Vec<Span>, protected: &[ByteRange]) -> Vec<Span> {
    let protected_index = RangeIndex::new(protected.to_vec());
    let protected_edges = (!protected.is_empty()).then(|| {
        protected
            .iter()
            .flat_map(|p| [p.start, p.end])
            .collect::<HashSet<_>>()
    });

    // Drop empties and anything overlapping a frozen placeholder. Spans that
    // only touch a placeholder are normally idempotency artifacts. Keep only
    // high-confidence, non-context-free secrets there; otherwise
    // `<<X_hash>>AKIA...` would leak the adjacent real secret.
    spans.retain(|s| {
        !s.range.is_empty()
            && !protected_index.overlaps(&s.range)
            && (protected_edges
                .as_ref()
                .is_none_or(|edges| !touches_protected(&s.range, edges))
                || can_touch_protected(s))
    });

    // Strongest first (Span::cmp_strength is the one canonical ordering).
    spans.sort_by(|a, b| b.cmp_strength(a));

    let mut accepted: Vec<Span> = Vec::new();
    let mut accepted_index = RangeIndex::default();
    for s in spans {
        if !accepted_index.overlaps(&s.range) {
            accepted_index.insert(s.range);
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
            for a in accepted_index.overlapping(&s.range) {
                pieces = pieces.into_iter().flat_map(|p| subtract(p, &a)).collect();
            }
            for range in pieces {
                if !range.is_empty() && !accepted_index.overlaps(&range) {
                    accepted_index.insert(range);
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

fn touches_protected(range: &ByteRange, protected_edges: &HashSet<usize>) -> bool {
    protected_edges.contains(&range.start) || protected_edges.contains(&range.end)
}

fn can_touch_protected(span: &Span) -> bool {
    span.category == Category::Secret
        && span.confidence == Confidence::High
        && !is_context_free(span)
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
    fn context_free_placeholder_adjacent_spans_are_dropped() {
        let out = merge(
            vec![entropy_span(5, 10), entropy_span(11, 16)],
            &[ByteRange::new(0, 5), ByteRange::new(16, 20)],
        );
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn anchored_placeholder_adjacent_spans_are_kept() {
        let out = merge(
            vec![
                span(5, 10, Confidence::High),
                span(11, 16, Confidence::High),
            ],
            &[ByteRange::new(0, 5), ByteRange::new(16, 20)],
        );
        assert_eq!(out.len(), 2, "{out:?}");
    }

    #[test]
    fn non_secret_placeholder_adjacent_spans_are_dropped() {
        let out = merge(
            vec![Span {
                range: ByteRange::new(0, 3),
                category: Category::Endpoint,
                label: "IP_ADDRESS_V6".into(),
                confidence: Confidence::High,
                source: DetectorId::Rule,
            }],
            &[ByteRange::new(3, 40)],
        );
        assert!(out.is_empty(), "{out:?}");
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
