/// A byte that can be part of a codec/identifier token run (the unit detectors
/// scan). Excludes `.`/`@` so emails and IPs break at their real boundaries.
pub(crate) fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

/// Yields the maximal `[start, end)` byte runs of token bytes in `s`. The single
/// definition of "token run" shared by entropy and decode (and, via
/// `is_token_byte`, the sweep boundary check) so the scan alphabet can't diverge.
pub(crate) fn token_runs(s: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = s.as_bytes();
    let mut i = 0;
    std::iter::from_fn(move || {
        while i < bytes.len() && !is_token_byte(bytes[i]) {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        let start = i;
        while i < bytes.len() && is_token_byte(bytes[i]) {
            i += 1;
        }
        Some((start, i))
    })
}

#[cfg(test)]
pub(crate) fn region(raw: &str) -> crate::model::Region {
    use crate::model::*;
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
