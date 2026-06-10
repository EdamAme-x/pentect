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
