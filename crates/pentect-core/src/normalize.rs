//! Two deliberately opposite normalizations live here, and conflating them is a
//! bug:
//! - `n_id` (identity): conservative NFC, so distinct values never merge. Used
//!   for placeholder hashing and the identity sweep — folding here would make two
//!   different secrets share one placeholder.
//! - `NormalizedView` (detection): aggressive NFKC + percent-decode, so spoofing
//!   tricks can't hide a secret from a detector. It keeps a map back to raw, so
//!   spans are always reported in raw coordinates.

use crate::model::{ByteRange, Region};
use memchr::{memchr2_iter, memchr_iter};
use std::borrow::Cow;
use unicode_normalization::UnicodeNormalization;

/// Identity normalization: NFC only (deliberately not NFKC, and deliberately
/// not dropping zero-width/bidi controls). Used for placeholder hashing and the
/// sweep, where merging distinct source bytes would make restore ambiguous.
pub fn n_id(s: &str) -> String {
    s.nfc().collect()
}

/// ASCII is already NFC, which covers the common secret/token path without an
/// allocation. Non-ASCII values retain the exact normalization semantics.
pub fn n_id_cow(s: &str) -> Cow<'_, str> {
    if s.is_ascii() {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(n_id(s))
    }
}

fn is_zero_width(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200D}' | '\u{FEFF}')
}

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn push_ascii_escape(norm: &mut String, segs: &mut Vec<Seg>, byte: u8, raw: ByteRange) {
    let norm_start = norm.len();
    norm.push(byte as char);
    segs.push(Seg {
        norm: ByteRange::new(norm_start, norm.len()),
        raw,
    });
}

fn html_numeric_escape(bytes: &[u8], start: usize) -> Option<(u8, usize)> {
    if bytes.get(start..start + 2)? != b"&#" {
        return None;
    }
    let mut i = start + 2;
    let radix = if matches!(bytes.get(i), Some(b'x' | b'X')) {
        i += 1;
        16u32
    } else {
        10u32
    };
    let digits_start = i;
    let mut value = 0u32;
    while let Some(&byte) = bytes.get(i) {
        let digit = match (radix, byte) {
            (16, b'0'..=b'9') => u32::from(byte - b'0'),
            (16, b'a'..=b'f') => u32::from(byte - b'a' + 10),
            (16, b'A'..=b'F') => u32::from(byte - b'A' + 10),
            (10, b'0'..=b'9') => u32::from(byte - b'0'),
            _ => break,
        };
        value = value.checked_mul(radix)?.checked_add(digit)?;
        i += 1;
    }
    if i == digits_start || bytes.get(i) != Some(&b';') || value > 0x7f {
        return None;
    }
    Some((value as u8, i + 1))
}

fn quoted_printable_runs(bytes: &[u8]) -> Vec<ByteRange> {
    let mut runs = Vec::new();
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        if bytes[i] != b'=' || hex_val(bytes[i + 1]).is_none() || hex_val(bytes[i + 2]).is_none() {
            i += 1;
            continue;
        }
        let start = i;
        let mut escapes = 0usize;
        while i + 2 < bytes.len()
            && bytes[i] == b'='
            && hex_val(bytes[i + 1]).is_some()
            && hex_val(bytes[i + 2]).is_some()
        {
            escapes += 1;
            i += 3;
        }
        if escapes >= 4 {
            runs.push(ByteRange::new(start, i));
        }
    }
    runs
}

/// A region's text after aggressive normalization for detection (NFKC, zero-width
/// /bidi stripping, percent/HTML/quoted-printable decoding, and source-literal
/// decoding of ASCII `\u00XX` / `\xXX` / octal escapes), with a map back to raw
/// byte ranges.
/// Detectors run on the normalized text so these tricks can't break a match; the
/// resulting spans are always reported in raw coordinates.
pub struct NormalizedView<'a> {
    pub region: &'a Region,
    norm: Cow<'a, str>,
    segs: Vec<Seg>,
    identity: bool,
}

/// One normalized run and the raw bytes it came from.
struct Seg {
    norm: ByteRange,
    raw: ByteRange,
}

impl<'a> NormalizedView<'a> {
    /// Normalization is per-character, so cross-character composition (e.g. a
    /// base letter plus a combining mark) is not folded. That is enough for the
    /// zero-width / bidi / full-width / percent cases we target.
    pub fn build(region: &'a Region, raw: &'a str) -> Self {
        let base = region.span.start;
        let slice = &raw[region.span.start..region.span.end];
        if is_identity_detection_slice(slice) {
            return NormalizedView {
                region,
                norm: Cow::Borrowed(slice),
                segs: Vec::new(),
                identity: true,
            };
        }
        let bytes = slice.as_bytes();
        // Adjacent escapes distinguish encoded data from independent assignments
        // such as `a=41 b=42`. Canonical QP leaves ordinary secret characters
        // unchanged for normal detectors, so only dense escaped runs need this.
        let quoted_printable = quoted_printable_runs(bytes);
        let mut quoted_printable_index = 0usize;
        let mut norm = String::with_capacity(slice.len());
        let mut segs = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            // Percent-encoded ASCII byte (%XX) -> one normalized char.
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    let byte = (hi << 4) | lo;
                    if byte.is_ascii() {
                        let raw = ByteRange::new(base + i, base + i + 3);
                        push_ascii_escape(&mut norm, &mut segs, byte, raw);
                        i += 3;
                        continue;
                    }
                }
            }
            // HTML numeric character references are self-delimiting and do not
            // need a heuristic. Named entities are intentionally excluded: they
            // are aliases rather than a general byte encoding.
            if bytes[i] == b'&' {
                if let Some((byte, end)) = html_numeric_escape(bytes, i) {
                    let raw = ByteRange::new(base + i, base + end);
                    push_ascii_escape(&mut norm, &mut segs, byte, raw);
                    i = end;
                    continue;
                }
            }
            // RFC 2045 quoted-printable. Decode only clearly encoded slices so
            // source assignments such as `code=41` retain their structure.
            while quoted_printable
                .get(quoted_printable_index)
                .is_some_and(|range| range.end <= i)
            {
                quoted_printable_index += 1;
            }
            let in_quoted_printable = quoted_printable
                .get(quoted_printable_index)
                .is_some_and(|range| range.start <= i && i < range.end);
            if in_quoted_printable && bytes[i] == b'=' && i + 2 < bytes.len() {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    let byte = (hi << 4) | lo;
                    if byte.is_ascii() {
                        let raw = ByteRange::new(base + i, base + i + 3);
                        push_ascii_escape(&mut norm, &mut segs, byte, raw);
                        i += 3;
                        continue;
                    }
                }
            }
            // Source-code / JSON-style ASCII escapes (`\u002d`, `\x2d`) are a
            // common way for logs and tool output to split a recognizable token.
            if bytes[i] == b'\\' {
                if i + 5 < bytes.len()
                    && bytes[i + 1] == b'u'
                    && bytes[i + 2] == b'0'
                    && bytes[i + 3] == b'0'
                {
                    if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 4]), hex_val(bytes[i + 5])) {
                        let byte = (hi << 4) | lo;
                        if byte.is_ascii() {
                            let raw = ByteRange::new(base + i, base + i + 6);
                            push_ascii_escape(&mut norm, &mut segs, byte, raw);
                            i += 6;
                            continue;
                        }
                    }
                }
                if i + 3 < bytes.len() && matches!(bytes[i + 1], b'x' | b'X') {
                    if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 2]), hex_val(bytes[i + 3])) {
                        let byte = (hi << 4) | lo;
                        if byte.is_ascii() {
                            let raw = ByteRange::new(base + i, base + i + 4);
                            push_ascii_escape(&mut norm, &mut segs, byte, raw);
                            i += 4;
                            continue;
                        }
                    }
                }
                // C-family octal escapes consume at most three octal digits.
                // Restrict to exactly three here to avoid treating ordinary
                // backslash-number paths as encoded text.
                if i + 3 < bytes.len()
                    && bytes[i + 1..i + 4]
                        .iter()
                        .all(|byte| matches!(byte, b'0'..=b'7'))
                {
                    let value = u16::from(bytes[i + 1] - b'0') * 64
                        + u16::from(bytes[i + 2] - b'0') * 8
                        + u16::from(bytes[i + 3] - b'0');
                    if value <= 0x7f {
                        let raw = ByteRange::new(base + i, base + i + 4);
                        push_ascii_escape(&mut norm, &mut segs, value as u8, raw);
                        i += 4;
                        continue;
                    }
                }
            }

            let ch = slice[i..].chars().next().expect("char boundary");
            let raw = ByteRange::new(base + i, base + i + ch.len_utf8());
            i += ch.len_utf8();
            if is_zero_width(ch) || is_bidi(ch) {
                continue; // dropped; recovered later by outward snapping
            }
            let norm_start = norm.len();
            for nc in ch.to_string().nfkc() {
                norm.push(nc);
            }
            if norm.len() > norm_start {
                segs.push(Seg {
                    norm: ByteRange::new(norm_start, norm.len()),
                    raw,
                });
            }
        }
        NormalizedView {
            region,
            norm: Cow::Owned(norm),
            segs,
            identity: false,
        }
    }

    pub fn text(&self) -> &str {
        &self.norm
    }

    /// Map a normalized byte range to a raw range, snapping outward to whole
    /// source characters so we never under-cover (under-covering would leak).
    pub fn to_raw(&self, norm: ByteRange) -> ByteRange {
        if self.identity {
            let start = self.region.span.start + norm.start;
            let end = self.region.span.start + norm.end;
            return ByteRange::new(start, end.max(start).min(self.region.span.end));
        }
        let start = self.raw_start_at(norm.start);
        let end = self.raw_end_at(norm.end);
        ByteRange::new(start, end.max(start))
    }

    /// Map a raw byte range inside this region back to normalized coordinates.
    ///
    /// This is primarily for detectors that run through a shared matcher which
    /// reports raw spans, but still need to inspect normalized local context.
    /// Ranges produced by `to_raw` round-trip; ranges covering dropped controls
    /// snap to the nearest normalized segment.
    pub(crate) fn to_norm(&self, raw: ByteRange) -> Option<ByteRange> {
        if raw.start < self.region.span.start
            || raw.end > self.region.span.end
            || raw.start > raw.end
        {
            return None;
        }
        if self.identity {
            return Some(ByteRange::new(
                raw.start - self.region.span.start,
                raw.end - self.region.span.start,
            ));
        }

        let start_idx = self.segs.partition_point(|s| s.raw.end <= raw.start);
        let end_idx = self.segs.partition_point(|s| s.raw.start < raw.end);
        let start = self
            .segs
            .get(start_idx)
            .map(|s| s.norm.start)
            .unwrap_or_else(|| self.norm.len());
        let end = end_idx
            .checked_sub(1)
            .and_then(|idx| self.segs.get(idx))
            .map(|s| s.norm.end)
            .unwrap_or(start);
        (start <= end).then_some(ByteRange::new(start, end))
    }

    fn raw_start_at(&self, pos: usize) -> usize {
        let idx = self.segs.partition_point(|s| s.norm.end <= pos);
        self.segs
            .get(idx)
            .map(|s| s.raw.start)
            .unwrap_or(self.region.span.end)
    }

    fn raw_end_at(&self, pos: usize) -> usize {
        let idx = self.segs.partition_point(|s| s.norm.start < pos);
        idx.checked_sub(1)
            .and_then(|i| self.segs.get(i))
            .map(|s| s.raw.end)
            .unwrap_or(self.region.span.start)
    }
}

fn is_identity_detection_slice(slice: &str) -> bool {
    let bytes = slice.as_bytes();
    if !bytes.is_ascii() {
        return false;
    }
    if !quoted_printable_runs(bytes).is_empty() {
        return false;
    }
    if memchr_iter(b'&', bytes).any(|i| html_numeric_escape(bytes, i).is_some()) {
        return false;
    }
    for i in memchr2_iter(b'%', b'\\', bytes) {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && hex_val(bytes[i + 1]).is_some()
            && hex_val(bytes[i + 2]).is_some()
        {
            return false;
        }
        if bytes[i] == b'\\' {
            if i + 5 < bytes.len()
                && bytes[i + 1] == b'u'
                && bytes[i + 2] == b'0'
                && bytes[i + 3] == b'0'
                && hex_val(bytes[i + 4]).is_some()
                && hex_val(bytes[i + 5]).is_some()
            {
                return false;
            }
            if i + 3 < bytes.len()
                && matches!(bytes[i + 1], b'x' | b'X')
                && hex_val(bytes[i + 2]).is_some()
                && hex_val(bytes[i + 3]).is_some()
            {
                return false;
            }
            if i + 3 < bytes.len()
                && bytes[i + 1..i + 4]
                    .iter()
                    .all(|byte| matches!(byte, b'0'..=b'7'))
            {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Context, Kind, RegionKind};

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

    #[test]
    fn strips_zero_width_and_maps_back() {
        let raw = "AB\u{200b}CD";
        let r = region(raw);
        let v = NormalizedView::build(&r, raw);
        assert_eq!(v.text(), "ABCD");
        assert_eq!(v.to_raw(ByteRange::new(0, 4)), ByteRange::new(0, raw.len()));
        assert_eq!(v.to_raw(ByteRange::new(2, 4)), ByteRange::new(5, 7));
    }

    #[test]
    fn folds_full_width_and_snaps_to_source_char() {
        let raw = "Ａ"; // full-width A, 3 bytes
        let r = region(raw);
        let v = NormalizedView::build(&r, raw);
        assert_eq!(v.text(), "A");
        assert_eq!(v.to_raw(ByteRange::new(0, 1)), ByteRange::new(0, raw.len()));
    }

    #[test]
    fn decodes_percent_encoded_ascii() {
        let raw = "a%2Db"; // %2D = '-'
        let r = region(raw);
        let v = NormalizedView::build(&r, raw);
        assert_eq!(v.text(), "a-b");
        assert_eq!(v.to_raw(ByteRange::new(1, 2)), ByteRange::new(1, 4));
    }

    #[test]
    fn decodes_ascii_source_escapes() {
        let raw = r"a\u002db\x2ec";
        let r = region(raw);
        let v = NormalizedView::build(&r, raw);
        assert_eq!(v.text(), "a-b.c");
        assert_eq!(v.to_raw(ByteRange::new(1, 2)), ByteRange::new(1, 7));
        assert_eq!(v.to_raw(ByteRange::new(3, 4)), ByteRange::new(8, 12));
    }

    #[test]
    fn decodes_html_numeric_and_octal_escapes() {
        let raw = r"a&#45;b\056c";
        let r = region(raw);
        let v = NormalizedView::build(&r, raw);
        assert_eq!(v.text(), "a-b.c");
        assert_eq!(v.to_raw(ByteRange::new(1, 2)), ByteRange::new(1, 6));
        assert_eq!(v.to_raw(ByteRange::new(3, 4)), ByteRange::new(7, 11));
    }

    #[test]
    fn decodes_quoted_printable_only_when_the_slice_is_clearly_encoded() {
        let raw = "=41=4b=49=41";
        let r = region(raw);
        assert_eq!(NormalizedView::build(&r, raw).text(), "AKIA");

        let assignment = "code=41";
        let r = region(assignment);
        assert_eq!(NormalizedView::build(&r, assignment).text(), assignment);

        let assignments = "a=41 b=42 c=43 d=44";
        let r = region(assignments);
        assert_eq!(NormalizedView::build(&r, assignments).text(), assignments);
    }

    #[test]
    fn raw_ranges_round_trip_to_normalized_offsets() {
        let raw = r#"a=https%3A%2F%2Fexample.test b=327146 c=x\u002dy"#;
        let r = region(raw);
        let v = NormalizedView::build(&r, raw);
        let b_start = raw.find("327146").unwrap();
        let raw_range = ByteRange::new(b_start, b_start + "327146".len());
        assert_eq!(
            v.to_norm(raw_range),
            Some(ByteRange::new(
                v.text().find("327146").unwrap(),
                v.text().find("327146").unwrap() + "327146".len()
            ))
        );
        let escaped = ByteRange::new(
            raw.find(r"\u002d").unwrap(),
            raw.find(r"\u002d").unwrap() + 6,
        );
        assert_eq!(
            v.to_norm(escaped),
            Some(ByteRange::new(
                v.text().find("x-y").unwrap() + 1,
                v.text().find("x-y").unwrap() + 2
            ))
        );
    }

    #[test]
    fn identity_keeps_controls_that_detection_drops() {
        assert_ne!(
            n_id("AKIAIOSFODNN7EXAMPLE"),
            n_id("AKIA\u{200b}IOSFODNN7EXAMPLE")
        );
        assert_ne!(n_id("abc"), n_id("a\u{202e}bc"));
    }

    proptest::proptest! {
        // Building a view and mapping any normalized range back must never panic
        // and must stay inside the region on char boundaries.
        #[test]
        fn build_and_to_raw_never_panic(s in proptest::prelude::any::<String>()) {
            let r = region(&s);
            let v = NormalizedView::build(&r, &s);
            let n = v.text().len();
            let raw = v.to_raw(ByteRange::new(0, n));
            proptest::prop_assert!(raw.start <= raw.end);
            proptest::prop_assert!(raw.end <= s.len());
            proptest::prop_assert!(s.is_char_boundary(raw.start));
            proptest::prop_assert!(s.is_char_boundary(raw.end));
        }
    }
}
