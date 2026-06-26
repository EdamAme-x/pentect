use super::util::token_runs;
use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

/// Default minimum run length before a token is entropy-eligible. Long enough to
/// skip short benign tokens (UUID segments, short ids) while catching real keys.
pub const DEFAULT_ENTROPY_MIN_LEN: usize = 24;
/// Default Shannon bits/char above which a run is opaque. base64 ciphertext sits
/// ~5-6, hex digests ~3.9; 3.2 catches those while sparing ordinary identifiers.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 3.2;

/// Flags long, high-entropy codec-alphabet runs as likely opaque secrets.
pub struct EntropyDetector {
    min_len: usize,
    threshold: f64,
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self::with(DEFAULT_ENTROPY_MIN_LEN, DEFAULT_ENTROPY_THRESHOLD)
    }
}

impl EntropyDetector {
    /// `min_len` is floored at the placeholder hash width: a run shorter than the
    /// hash we would emit isn't worth masking (the placeholder would be longer
    /// than the original and just as opaque), and Shannon needs that many symbols
    /// to mean much. Idempotency on already-rendered placeholders comes from
    /// placeholder protection, not from this floor.
    pub fn with(min_len: usize, threshold: f64) -> Self {
        Self {
            min_len: min_len.max(crate::placeholder::HASH_HEX_WIDTH),
            threshold,
        }
    }
}

impl Detector for EntropyDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        let mut out = Vec::new();
        for (start, end) in token_runs(text) {
            let run = &text[start..end];
            if let Some(value_start) = assignment_value_offset(run) {
                let value = &run.as_bytes()[value_start..];
                if value.len() >= self.min_len && shannon(value) >= self.threshold {
                    out.push(Span {
                        range: view.to_raw(ByteRange::new(start + value_start, end)),
                        category: Category::Secret,
                        label: labels::LIKELY_SECRET.to_string(),
                        confidence: Confidence::Low,
                        source: DetectorId::Entropy,
                    });
                }
                continue;
            }
            let run = run.as_bytes();
            if run.len() >= self.min_len && shannon(run) >= self.threshold {
                out.push(Span {
                    range: view.to_raw(ByteRange::new(start, end)),
                    category: Category::Secret,
                    label: labels::LIKELY_SECRET.to_string(),
                    confidence: Confidence::Low,
                    source: DetectorId::Entropy,
                });
            }
        }
        out
    }
}

fn assignment_value_offset(run: &str) -> Option<usize> {
    let eq = run.find('=')?;
    let key = &run[..eq];
    let value = &run[eq + 1..];
    if key.is_empty()
        || value.is_empty()
        || value.starts_with('=')
        || key.as_bytes()[0].is_ascii_digit()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return None;
    }
    let lower = key.to_ascii_lowercase();
    let assignment_like = key.bytes().any(|b| matches!(b, b'_' | b'.' | b'-'))
        || key.bytes().all(|b| !b.is_ascii_lowercase())
        || [
            "api_key",
            "apikey",
            "key",
            "secret",
            "token",
            "password",
            "auth",
            "credential",
            "session",
            "cookie",
        ]
        .iter()
        .any(|needle| lower.contains(needle));
    assignment_like.then_some(eq + 1)
}

fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    // Token runs are ASCII-only, so CJK prose never forms an entropy run even at
    // a lowered threshold.
    #[test]
    fn cjk_prose_not_flagged_as_entropy() {
        let raw = "これは日本語の散文でありパスワードではありません";
        let reg = region(raw);
        let v = NormalizedView::build(&reg, raw);
        assert!(EntropyDetector::with(16, 2.0).detect(&v).is_empty());
    }

    // A high-entropy run shorter than the hash width is not flagged even when
    // min_len is set below it: the floor wins.
    #[test]
    fn min_len_floored_at_hash_width() {
        let raw = "x aB3xZ9qW2pL5 y"; // 12-char token, < HASH_HEX_WIDTH
        let reg = region(raw);
        let v = NormalizedView::build(&reg, raw);
        assert!(EntropyDetector::with(8, 1.0).detect(&v).is_empty());
    }

    #[test]
    fn assignment_entropy_masks_value_not_key_prefix() {
        let raw = "RUNPOD_API_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
        let reg = region(raw);
        let v = NormalizedView::build(&reg, raw);
        let spans = EntropyDetector::with(16, 2.0).detect(&v);
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(
            &raw[spans[0].range.start..spans[0].range.end],
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"
        );
    }
}
