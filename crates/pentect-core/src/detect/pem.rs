use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;
use regex::Regex;

/// Masks the base64 body of a PEM private-key block as one span, keeping the
/// BEGIN/END armor so the model still knows what it was. High-confidence and
/// anchored, so it masks under every profile (the body alone is only low-entropy
/// per-line and would otherwise be merely warned).
pub struct PemDetector {
    re: Regex,
}

impl Default for PemDetector {
    fn default() -> Self {
        Self {
            re: Regex::new(
                r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\r?\n(.*?)\r?\n-----END [A-Z0-9 ]*PRIVATE KEY-----",
            )
            .expect("pem regex compiles"),
        }
    }
}

impl Detector for PemDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let s = view.text();
        self.re
            .captures_iter(s)
            .filter_map(|c| c.get(1))
            .map(|m| Span {
                range: view.to_raw(ByteRange::new(m.start(), m.end())),
                category: Category::Secret,
                label: labels::PRIVATE_KEY.to_string(),
                confidence: Confidence::High,
                source: DetectorId::Pem,
            })
            .collect()
    }
}
