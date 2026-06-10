use super::util::is_token_byte;
use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

/// Flags long, high-entropy codec-alphabet runs as likely opaque secrets.
pub struct EntropyDetector {
    min_len: usize,
    threshold: f64,
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self {
            min_len: 24,
            threshold: 3.2,
        }
    }
}

impl EntropyDetector {
    /// `min_len` is clamped to the placeholder hash width so a lowered threshold
    /// can never re-fire on a rendered placeholder hash.
    pub fn with(min_len: usize, threshold: f64) -> Self {
        Self {
            min_len: min_len.max(crate::placeholder::HASH_HEX_WIDTH),
            threshold,
        }
    }
}

impl Detector for EntropyDetector {
    fn id(&self) -> &str {
        "entropy"
    }
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let bytes = view.text().as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if !is_token_byte(bytes[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && is_token_byte(bytes[i]) {
                i += 1;
            }
            let run = &bytes[start..i];
            if run.len() >= self.min_len && shannon(run) >= self.threshold {
                out.push(Span {
                    range: view.to_raw(ByteRange::new(start, i)),
                    category: Category::Secret,
                    label: "LIKELY_SECRET".to_string(),
                    confidence: Confidence::Low,
                    source: "entropy".to_string(),
                });
            }
        }
        out
    }
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
}
