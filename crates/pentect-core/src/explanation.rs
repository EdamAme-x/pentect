//! Read-only presentation of evidence from the completed masking pipeline.
//! Never re-runs detection or reads the recovery map.

use crate::{MaskResult, MaskedItem};
use aho_corasick::{AhoCorasickBuilder, MatchKind};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ExplanationFinding {
    /// One-based occurrence in the final masked text, not a raw source offset.
    pub occurrence: usize,
    pub handle: String,
    /// Evidence retained for this value across all masking stages. A repeated
    /// value can have several sources; do not invent a single source for it.
    pub evidence: Vec<MaskedItem>,
}

impl MaskResult {
    pub fn explain(&self) -> Vec<ExplanationFinding> {
        if self.provenance.is_empty() {
            return Vec::new();
        }
        let handles: Vec<_> = self.provenance.keys().collect();
        let matcher = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&handles)
            .expect("nonempty, bounded rendered handles");
        matcher
            .find_iter(&self.masked)
            .enumerate()
            .map(|(index, found)| {
                let handle = handles[found.pattern().as_usize()];
                ExplanationFinding {
                    occurrence: index + 1,
                    handle: handle.clone(),
                    evidence: self.provenance[handle].clone(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::{ByteRange, Category, Confidence, Config, DetectorId, Engine, Input, Span};

    #[test]
    fn explanation_follows_rendered_occurrences_and_merged_evidence() {
        let input = "日本語🙂 first-private-value\nsecond-private-value first-private-value";
        let span = |value: &str, source| {
            let start = input.find(value).unwrap();
            Span {
                range: ByteRange::new(start, start + value.len()),
                label: "SAME_LABEL".into(),
                category: Category::Secret,
                confidence: Confidence::High,
                source,
            }
        };
        let engine = Engine::default();
        let result = engine.mask_spans(
            Input::text(input),
            vec![
                span("first-private-value", DetectorId::Explicit),
                span("first-private", DetectorId::Rule),
                span("second-private-value", DetectorId::Plugin),
            ],
            &Config::new([8; 32]),
        );
        let before = result.masked.clone();
        let findings = result.explain();
        assert_eq!(result.masked, before);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].handle, findings[2].handle);
        assert_ne!(findings[0].handle, findings[1].handle);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.source == DetectorId::Explicit));
        assert_eq!(findings[1].evidence[0].source, DetectorId::Plugin);
        let encoded = serde_json::to_string(&findings).unwrap();
        for value in [
            "first-private-value",
            "second-private-value",
            "日本語",
            "range",
            "offset",
        ] {
            assert!(!encoded.contains(value));
        }
        assert_eq!(result.recovery.resolve(&result.masked), input);
    }
}
