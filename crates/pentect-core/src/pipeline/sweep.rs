use crate::detect::is_token_byte;
use crate::model::*;
use crate::normalize::n_id;
use std::collections::BTreeMap;

/// Mask every other occurrence of an already-masked value across the input.
/// This is correctness, not optimization: a value left in plaintext anywhere
/// leaks. Added occurrences must fall inside a region (so JSON keys/punctuation
/// are untouched) and sit on token boundaries (so a short value can't carve a
/// fragment out of a longer unrelated token).
pub fn identity_sweep(
    raw: &str,
    accepted: Vec<Span>,
    protected: &[ByteRange],
    regions: &[Region],
) -> Vec<Span> {
    // One representative per identity, chosen by the canonical Span::cmp_strength,
    // so the strongest detection's label is what all occurrences inherit (a
    // specific High AWS_AKID is not overwritten by a generic Low LIKELY_SECRET).
    let mut rep: BTreeMap<String, Span> = BTreeMap::new();
    for s in &accepted {
        let id = n_id(&raw[s.range.start..s.range.end]);
        rep.entry(id)
            .and_modify(|e| {
                if s.cmp_strength(e).is_gt() {
                    *e = s.clone();
                }
            })
            .or_insert_with(|| s.clone());
    }

    // Longest needle first so a longer, more specific value claims an overlap
    // before a shorter one that is its substring.
    let mut reps: Vec<&Span> = rep.values().collect();
    reps.sort_by(|a, b| {
        (b.range.end - b.range.start)
            .cmp(&(a.range.end - a.range.start))
            .then(a.range.start.cmp(&b.range.start))
    });

    let bytes = raw.as_bytes();
    let mut all = accepted.clone();
    for r in reps {
        let needle = &raw[r.range.start..r.range.end];
        if needle.is_empty() {
            continue;
        }
        let mut from = 0usize;
        while let Some(pos) = raw[from..].find(needle) {
            let abs = from + pos;
            let end = abs + needle.len();
            let range = ByteRange::new(abs, end);
            from = end;

            let on_boundary =
                !continues_token(bytes, abs.wrapping_sub(1)) && !continues_token(bytes, end);
            let in_region = regions.iter().any(|rg| rg.span.contains(&range));
            let clash = all.iter().any(|a| a.range.overlaps(&range))
                || protected.iter().any(|p| p.overlaps(&range));
            if on_boundary && in_region && !clash {
                all.push(Span {
                    range,
                    category: r.category,
                    label: r.label.clone(),
                    confidence: r.confidence,
                    source: DetectorId::Sweep,
                });
            }
        }
    }

    all.sort_by_key(|s| s.range.start);
    all
}

/// True if the byte at `i` is part of the same token (would make a match a mere
/// substring of a longer identifier/codec run). Shares the detector scan alphabet
/// (`is_token_byte`), so `.`/`@`/whitespace are NOT continuations and emails/IPs
/// are still swept at their real boundaries.
fn continues_token(bytes: &[u8], i: usize) -> bool {
    bytes.get(i).is_some_and(|&b| is_token_byte(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(raw: &str) -> Region {
        Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context {
                path: None,
                key: None,
                kind: RegionKind::PlainText,
                format: Kind::Text,
            },
        }
    }

    fn span(raw: &str, needle: &str, label: &str, cat: Category, conf: Confidence) -> Span {
        let start = raw.find(needle).unwrap();
        Span {
            range: ByteRange::new(start, start + needle.len()),
            category: cat,
            label: label.into(),
            confidence: conf,
            source: DetectorId::Rule,
        }
    }

    fn swept_ranges(raw: &str, accepted: Vec<Span>) -> Vec<ByteRange> {
        let regions = vec![region(raw)];
        identity_sweep(raw, accepted, &[], &regions)
            .into_iter()
            .filter(|s| s.source == DetectorId::Sweep)
            .map(|s| s.range)
            .collect()
    }

    #[test]
    fn sweeps_real_repeat_but_not_substring_of_longer_token() {
        let raw = "to a@b.com cc a@b.com see a@b.commerce.io";
        let first = span(
            raw,
            "a@b.com",
            "IDENTITY",
            Category::Pii,
            Confidence::Medium,
        );
        let swept = swept_ranges(raw, vec![first]);
        // The second standalone a@b.com is swept; the prefix inside
        // a@b.commerce.io is NOT (next byte 'm' continues the token).
        assert_eq!(swept.len(), 1, "{swept:?}");
        let r = swept[0];
        assert_eq!(&raw[r.start..r.end], "a@b.com");
        assert!(r.start > 13, "should be the 2nd occurrence, got {r:?}");
    }

    #[test]
    fn does_not_carve_hex_prefix_out_of_longer_run() {
        let raw = "x abc123 y abc1234567";
        let first = span(
            raw,
            "abc123",
            "LIKELY_SECRET",
            Category::Secret,
            Confidence::Low,
        );
        let swept = swept_ranges(raw, vec![first]);
        assert!(
            swept.is_empty(),
            "abc123 must not be carved from abc1234567: {swept:?}"
        );
    }

    #[test]
    fn swept_occurrence_inherits_highest_priority_label() {
        let raw = "AKIAIOSFODNN7EXAMPLE here AKIAIOSFODNN7EXAMPLE then AKIAIOSFODNN7EXAMPLE";
        let weak = span(
            raw,
            "AKIAIOSFODNN7EXAMPLE",
            "LIKELY_SECRET",
            Category::Secret,
            Confidence::Low,
        );
        // A stronger hit on the same value at a later position.
        let second_at = raw.match_indices("AKIAIOSFODNN7EXAMPLE").nth(1).unwrap().0;
        let strong = Span {
            range: ByteRange::new(second_at, second_at + 20),
            category: Category::Secret,
            label: "AWS_AKID".into(),
            confidence: Confidence::High,
            source: DetectorId::Rule,
        };
        let out = identity_sweep(raw, vec![weak, strong], &[], &[region(raw)]);
        let swept: Vec<_> = out
            .iter()
            .filter(|s| s.source == DetectorId::Sweep)
            .collect();
        assert_eq!(swept.len(), 1, "third occurrence swept: {swept:?}");
        assert_eq!(
            swept[0].label, "AWS_AKID",
            "must inherit the stronger label"
        );
    }
}
