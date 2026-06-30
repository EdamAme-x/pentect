use aho_corasick::{AhoCorasickBuilder, MatchKind};

use crate::detect::is_token_byte;
use crate::model::*;
use crate::normalize::n_id;
use std::collections::BTreeMap;

use super::interval::RangeIndex;

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
        if !is_sweepable_identity(raw, s) {
            continue;
        }
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

    let needles: Vec<&str> = reps
        .iter()
        .map(|r| &raw[r.range.start..r.range.end])
        .filter(|needle| !needle.is_empty())
        .collect();
    if needles.is_empty() {
        return accepted;
    }

    let ac = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .build(&needles)
        .expect("non-empty patterns");
    let mut occupied = RangeIndex::new(
        accepted
            .iter()
            .map(|s| s.range)
            .chain(protected.iter().copied())
            .collect(),
    );
    let region_index = RangeIndex::new(regions.iter().map(|rg| rg.span).collect());
    let mut candidates: Vec<(usize, ByteRange)> = Vec::new();
    let bytes = raw.as_bytes();
    for m in ac.find_overlapping_iter(raw) {
        let range = ByteRange::new(m.start(), m.end());
        let on_boundary = !continues_token(bytes, range.start.wrapping_sub(1))
            && !continues_token(bytes, range.end);
        let in_region = region_index.contains(&range);
        if on_boundary && in_region && !occupied.overlaps(&range) {
            candidates.push((m.pattern().as_usize(), range));
        }
    }

    candidates.sort_by(|(ai, a), (bi, b)| {
        b.len()
            .cmp(&a.len())
            .then(a.start.cmp(&b.start))
            .then(ai.cmp(bi))
    });

    let mut all = accepted.clone();
    for (pattern, range) in candidates {
        if occupied.overlaps(&range) {
            continue;
        }
        let r = reps[pattern];
        occupied.insert(range);
        all.push(Span {
            range,
            category: r.category,
            label: r.label.clone(),
            confidence: r.confidence,
            source: DetectorId::Sweep,
        });
    }

    all.sort_by_key(|s| s.range.start);
    all
}

fn is_sweepable_identity(raw: &str, span: &Span) -> bool {
    // Identity sweep is propagation, not the original detection decision. Very
    // short or punctuation-only representatives such as `=` are almost always
    // syntax around a detected value; sweeping them creates noisy standalone
    // masks while the original detector hit remains masked.
    if !has_distinctive_sweep_identity_shape(&raw[span.range.start..span.range.end]) {
        return false;
    }
    // OTP/passcode values are short and time-bound. A repeated `123456` elsewhere
    // is not evidence of the same credential unless the local line has OTP
    // context, so the detector hit is masked but global identity propagation is
    // intentionally disabled for this label.
    if span.label.as_str() == labels::OTP {
        return false;
    }
    // KeyValueDetector hits are anchored by local key syntax. Repeating the same
    // bytes elsewhere without a key boundary is not enough evidence: code names,
    // fixtures, and public test labels collide heavily with keyed values. Keep
    // the anchored hit and let stronger detectors drive identity propagation.
    if span.label.as_str() == labels::KEYED_SECRET {
        return false;
    }
    // Structural JSON detections are anchored by local key context. Generated
    // labels such as `LOCKROOMPASSWORD`, `LABEL_PASSWORD`, or
    // `CREATEAUTHORIZERREQUEST` often come from UI/resource strings; seeing the
    // same prose elsewhere is not evidence of the same credential. Keep the
    // anchored structural span, but sweep only values with distinctive token
    // shape. Canonical labels alone are not enough: `PASSWORD: "Password"` in
    // localization JSON is a label, while `PASSWORD: "s3cr3t-prod-token"` has
    // enough identity evidence to propagate.
    if span.source == DetectorId::Structural && !is_structural_sweepable_identity(raw, span) {
        return false;
    }
    true
}

fn has_distinctive_sweep_identity_shape(value: &str) -> bool {
    let value = value.trim();
    value.len() >= 4 && value.bytes().any(|b| b.is_ascii_alphanumeric())
}

fn is_structural_sweepable_identity(raw: &str, span: &Span) -> bool {
    distinctive_secret_shape(&raw[span.range.start..span.range.end])
}

fn distinctive_secret_shape(value: &str) -> bool {
    let value = value.trim();
    let bytes = value.as_bytes();
    bytes.len() >= 16
        && !bytes.iter().any(u8::is_ascii_whitespace)
        && bytes.iter().any(u8::is_ascii_alphabetic)
        && bytes.iter().any(u8::is_ascii_digit)
        && bytes
            .iter()
            .any(|b| matches!(b, b'_' | b'-' | b'.' | b'+' | b'/' | b'='))
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
                hints: Vec::new(),
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

    #[test]
    fn otp_values_are_not_identity_swept() {
        let raw = "Your login code is 123456. Build number 123456 appears later.";
        let first = span(
            raw,
            "123456",
            labels::OTP,
            Category::Secret,
            Confidence::High,
        );
        let swept = swept_ranges(raw, vec![first]);
        assert!(
            swept.is_empty(),
            "short OTP values require local auth context, not global sweep: {swept:?}"
        );
    }

    #[test]
    fn short_keyed_values_are_not_identity_swept() {
        let raw = r#"password="secret" prose says secret later"#;
        let first = span(
            raw,
            "secret",
            labels::KEYED_SECRET,
            Category::Secret,
            Confidence::Medium,
        );
        let swept = swept_ranges(raw, vec![first]);
        assert!(
            swept.is_empty(),
            "short keyed values need local context, not global sweep: {swept:?}"
        );
    }

    #[test]
    fn punctuation_syntax_is_not_identity_swept() {
        let raw = "PrivPubKeyPair = A:B\nPrivPubKeyPair = C:D";
        let first = span(
            raw,
            "=",
            labels::LIKELY_SECRET,
            Category::Secret,
            Confidence::Low,
        );
        let swept = swept_ranges(raw, vec![first]);
        assert!(
            swept.is_empty(),
            "syntax-only identities must not be propagated: {swept:?}"
        );
    }

    #[test]
    fn keyed_source_identifiers_are_not_identity_swept() {
        for raw in [
            r#"key="UNSAFE_componentWillMount" code UNSAFE_componentWillMount"#,
            r#"key="_selectLength" code _selectLength"#,
            r#"password="x-pack-test-password" docs x-pack-test-password"#,
            r#"secret="secret_key_base" docs secret_key_base"#,
            r#"api_key="abcDEF123456" docs abcDEF123456"#,
            r#"password="tenant-7-trial" docs tenant-7-trial"#,
            r#"key="ALICE_secp256k1_PUB" docs ALICE_secp256k1_PUB"#,
        ] {
            let value = raw.split('"').nth(1).unwrap();
            let first = span(
                raw,
                value,
                labels::KEYED_SECRET,
                Category::Secret,
                Confidence::Medium,
            );
            let swept = swept_ranges(raw, vec![first]);
            assert!(
                swept.is_empty(),
                "no-digit keyed values need local context, not global sweep: {raw} {swept:?}"
            );
        }
    }

    #[test]
    fn keyed_values_are_not_identity_swept_without_local_context() {
        let raw = r#"api_key="sk-live-Abc1234567890" later sk-live-Abc1234567890"#;
        let value = raw.split('"').nth(1).unwrap();
        let first = span(
            raw,
            value,
            labels::KEYED_SECRET,
            Category::Secret,
            Confidence::Medium,
        );
        let swept = swept_ranges(raw, vec![first]);
        assert!(
            swept.is_empty(),
            "keyed values require local key context, not global sweep: {raw} {swept:?}"
        );
    }

    #[test]
    fn structural_ui_labels_are_not_identity_swept() {
        let raw = r#"{"lockRoomPassword":"Password","label":"Password"}"#;
        let first_start = raw.find("Password").unwrap();
        let first = Span {
            range: ByteRange::new(first_start, first_start + "Password".len()),
            category: Category::Secret,
            label: "LOCKROOMPASSWORD".into(),
            confidence: Confidence::High,
            source: DetectorId::Structural,
        };
        let swept = swept_ranges(raw, vec![first]);
        assert!(
            swept.is_empty(),
            "structural UI labels have only local key context: {swept:?}"
        );
    }

    #[test]
    fn structural_short_password_values_are_not_identity_swept() {
        let raw = r#"{"password":"Password","label":"Password"}"#;
        let first_start = raw.find("Password").unwrap();
        let first = Span {
            range: ByteRange::new(first_start, first_start + "Password".len()),
            category: Category::Secret,
            label: "PASSWORD".into(),
            confidence: Confidence::High,
            source: DetectorId::Structural,
        };
        let swept = swept_ranges(raw, vec![first]);
        assert!(
            swept.is_empty(),
            "canonical structural labels still need distinctive value shape: {swept:?}"
        );
    }
}
