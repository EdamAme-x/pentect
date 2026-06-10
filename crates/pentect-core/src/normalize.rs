use crate::model::{ByteRange, Region};
use unicode_normalization::UnicodeNormalization;

/// Identity normalization: NFC (deliberately not NFKC) plus zero-width/bidi
/// stripping. Conservative so distinct values are never merged (full-width vs
/// ASCII digits stay distinct). Used for placeholder hashing and the sweep.
pub fn n_id(s: &str) -> String {
    s.nfc().filter(|c| !is_zero_width(*c) && !is_bidi(*c)).collect()
}

fn is_zero_width(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200D}' | '\u{FEFF}')
}

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// A region's text after aggressive normalization for detection (NFKC plus
/// zero-width/bidi stripping), with a map back to raw byte ranges. Detectors run
/// on the normalized text so zero-width/full-width tricks can't break a match;
/// the resulting spans are always reported in raw coordinates.
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
    /// zero-width / bidi / full-width cases we target.
    pub fn build(region: &'a Region, raw: &str) -> Self {
        let slice = &raw[region.span.start..region.span.end];
        let mut norm = String::new();
        let mut segs = Vec::new();
        for (off, ch) in slice.char_indices() {
            if is_zero_width(ch) || is_bidi(ch) {
                continue; // dropped; recovered later by outward snapping
            }
            let raw_start = region.span.start + off;
            let raw = ByteRange::new(raw_start, raw_start + ch.len_utf8());
            let norm_start = norm.len();
            for nc in ch.to_string().nfkc() {
                norm.push(nc);
            }
            if norm.len() > norm_start {
                segs.push(Seg { norm: ByteRange::new(norm_start, norm.len()), raw });
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
        self.segs
            .iter()
            .find(|s| pos < s.norm.end)
            .map(|s| s.raw.start)
            .unwrap_or(self.region.span.end)
    }

    fn raw_end_at(&self, pos: usize) -> usize {
        let mut end = self.region.span.start;
        for s in &self.segs {
            if s.norm.start < pos {
                end = s.raw.end;
            } else {
                break;
            }
        }
        end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Context, Kind, RegionKind};

    fn region(raw: &str) -> Region {
        Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context { path: None, key: None, kind: RegionKind::PlainText, format: Kind::Text },
        }
    }

    #[test]
    fn strips_zero_width_and_maps_back() {
        let raw = "AB\u{200b}CD";
        let r = region(raw);
        let v = NormalizedView::build(&r, raw);
        assert_eq!(v.text(), "ABCD");
        assert_eq!(v.to_raw(ByteRange::new(0, 4)), ByteRange::new(0, raw.len())); // covers the zwsp
        assert_eq!(v.to_raw(ByteRange::new(2, 4)), ByteRange::new(5, 7)); // "CD" after the zwsp
    }

    #[test]
    fn folds_full_width_and_snaps_to_source_char() {
        let raw = "Ａ"; // full-width A, 3 bytes
        let r = region(raw);
        let v = NormalizedView::build(&r, raw);
        assert_eq!(v.text(), "A");
        assert_eq!(v.to_raw(ByteRange::new(0, 1)), ByteRange::new(0, raw.len()));
    }
}
