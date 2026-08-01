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

    // A connected overlap is one sensitive value. Keeping only the strongest
    // candidate can expose another candidate's prefix or suffix, while splitting
    // candidates creates multiple handles for shared bytes. Mask the full union;
    // ranges that merely touch at an edge remain independent.
    spans.sort_by_key(|s| (s.range.start, s.range.end));
    let mut merged: Vec<Span> = Vec::new();
    let mut component: Option<(ByteRange, Span)> = None;
    for span in spans {
        match component.take() {
            None => component = Some((span.range, span)),
            Some((union, mut strongest)) if union.overlaps(&span.range) => {
                let union = ByteRange::new(
                    union.start.min(span.range.start),
                    union.end.max(span.range.end),
                );
                match span.cmp_strength(&strongest) {
                    core::cmp::Ordering::Greater => strongest = span,
                    core::cmp::Ordering::Equal if span.label != strongest.label => {
                        strongest.label = canonical_category_label(strongest.category).into();
                    }
                    core::cmp::Ordering::Equal | core::cmp::Ordering::Less => {}
                }
                component = Some((union, strongest));
            }
            Some((union, mut strongest)) => {
                strongest.range = union;
                merged.push(strongest);
                component = Some((span.range, span));
            }
        }
    }
    if let Some((union, mut strongest)) = component {
        strongest.range = union;
        merged.push(strongest);
    }
    merged
}

fn canonical_category_label(category: Category) -> &'static str {
    match category {
        Category::Secret => "SECRET",
        Category::Pii => "PII",
        Category::Identifier => "IDENTIFIER",
        Category::Endpoint => "ENDPOINT",
        Category::Other => "SENSITIVE",
    }
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
    fn higher_confidence_selects_metadata_and_union_masks_the_range() {
        let out = merge(
            vec![span(0, 10, Confidence::Low), span(2, 8, Confidence::High)],
            &[],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].confidence, Confidence::High);
        assert_eq!(out[0].range, ByteRange::new(0, 10));
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
    fn overlapping_spans_become_one_handle_for_the_full_union() {
        let out = merge(vec![span(0, 6, Confidence::High), entropy_span(4, 30)], &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].range, ByteRange::new(0, 30));
        assert_eq!(out[0].confidence, Confidence::High);
    }

    #[test]
    fn weaker_anchored_tail_is_not_left_in_plaintext() {
        let out = merge(
            vec![span(2, 8, Confidence::High), span(0, 10, Confidence::Low)],
            &[],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].range, ByteRange::new(0, 10));
    }

    #[test]
    fn same_range_conflicting_labels_are_order_independent() {
        let mut alpha = span(0, 10, Confidence::High);
        alpha.label = "ALPHA".into();
        let mut beta = alpha.clone();
        beta.label = "BETA".into();

        let forward = merge(vec![beta.clone(), alpha.clone()], &[]);
        let reverse = merge(vec![alpha, beta], &[]);
        assert_eq!(forward.len(), 1);
        assert_eq!(reverse.len(), 1);
        assert_eq!(forward[0].label, "SECRET");
        assert_eq!(forward[0].label, reverse[0].label);
    }

    #[test]
    fn unambiguous_stronger_finding_keeps_its_specific_label() {
        let mut weak = span(0, 10, Confidence::Medium);
        weak.label = "LIKELY_SECRET".into();
        let mut strong = span(0, 10, Confidence::High);
        strong.label = "API_KEY".into();

        let out = merge(vec![weak, strong], &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].label, "API_KEY");
    }

    #[test]
    fn transitive_overlaps_form_one_union_but_adjacent_range_stays_separate() {
        let out = merge(
            vec![
                span(0, 4, Confidence::Medium),
                span(3, 7, Confidence::Medium),
                span(6, 9, Confidence::Medium),
                span(9, 12, Confidence::Medium),
            ],
            &[],
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].range, ByteRange::new(0, 9));
        assert_eq!(out[1].range, ByteRange::new(9, 12));
    }

    #[test]
    fn union_length_does_not_distort_metadata_selection() {
        let mut left = span(0, 60, Confidence::High);
        left.label = "LEFT".into();
        let mut bridge = span(59, 61, Confidence::High);
        bridge.label = "BRIDGE".into();
        let mut right = span(60, 121, Confidence::High);
        right.label = "RIGHT".into();

        let out = merge(vec![left, bridge, right], &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].range, ByteRange::new(0, 121));
        assert_eq!(out[0].label, "RIGHT");
    }
}
