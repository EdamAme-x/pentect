//! Two deliberately opposite normalizations live here, and conflating them is a
//! bug:
//! - `n_id` (identity): conservative NFC, so distinct values never merge. Used
//!   for placeholder hashing and the identity sweep — folding here would make two
//!   different secrets share one placeholder.
//! - `NormalizedView` (detection): aggressive NFKC + percent-decode, so spoofing
//!   tricks can't hide a secret from a detector. It keeps a map back to raw, so
//!   spans are always reported in raw coordinates.

use crate::model::{ByteRange, Region};
use unicode_normalization::UnicodeNormalization;

/// Identity normalization: NFC (deliberately not NFKC) plus zero-width/bidi
/// stripping. Conservative so distinct values are never merged (full-width vs
/// ASCII digits stay distinct). Used for placeholder hashing and the sweep.
pub fn n_id(s: &str) -> String {
    s.nfc()
        .filter(|c| !is_zero_width(*c) && !is_bidi(*c))
        .collect()
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

/// A region's text after aggressive normalization for detection (NFKC, zero-width
/// /bidi stripping, and percent-decoding of `%XX` ASCII), with a map back to raw
/// byte ranges. Detectors run on the normalized text so these tricks can't break
/// a match; the resulting spans are always reported in raw coordinates.
pub struct NormalizedView<'a> {
    pub region: &'a Region,
    norm: String,
    segs: Vec<Seg>,
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
    pub fn build(region: &'a Region, raw: &str) -> Self {
        let base = region.span.start;
        let slice = &raw[region.span.start..region.span.end];
        let bytes = slice.as_bytes();
        let mut norm = String::new();
        let mut segs = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            // Percent-encoded ASCII byte (%XX) -> one normalized char.
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    let byte = (hi << 4) | lo;
                    if byte.is_ascii() {
                        let raw = ByteRange::new(base + i, base + i + 3);
                        let norm_start = norm.len();
                        norm.push(byte as char);
                        segs.push(Seg {
                            norm: ByteRange::new(norm_start, norm.len()),
                            raw,
                        });
                        i += 3;
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
        NormalizedView { region, norm, segs }
    }

    pub fn text(&self) -> &str {
        &self.norm
    }

    /// Map a normalized byte range to a raw range, snapping outward to whole
    /// source characters so we never under-cover (under-covering would leak).
    pub fn to_raw(&self, norm: ByteRange) -> ByteRange {
        let start = self.raw_start_at(norm.start);
        let end = self.raw_end_at(norm.end);
        ByteRange::new(start, end.max(start))
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
