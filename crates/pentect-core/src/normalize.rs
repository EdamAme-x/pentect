//! 正規化（REF.md §6）。slice 1 は identity 正規化 `n_id` のみ実装。
//! 検出ビュー（NFKC + percent/entity decode）と OffsetMap は slice 2。

use unicode_normalization::UnicodeNormalization;

/// identity 正規化（conservative, REF.md §6.1）:
/// `NFC + zero-width/bidi strip`。**NFKC ではない**（全角/半角/homoglyph は畳まず、
/// 異なる値を誤って統合しない）。placeholder の同一性ハッシュと sweep のキーに使う。
pub fn n_id(s: &str) -> String {
    s.nfc().filter(|c| !is_zero_width(*c) && !is_bidi(*c)).collect()
}

fn is_zero_width(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200D}' | '\u{FEFF}')
}

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}
