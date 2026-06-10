/// A byte that can be part of a codec/identifier token run (the unit detectors
/// scan). Excludes `.`/`@` so emails and IPs break at their real boundaries.
pub(crate) fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

#[cfg(test)]
pub(crate) fn region(raw: &str) -> crate::model::Region {
    use crate::model::*;
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
