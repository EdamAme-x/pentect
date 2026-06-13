//! Date/time recognizer (ISO 8601, US/EU numeric, written month) — the shapes
//! Presidio's DateRecognizer covers. Shipped OFF by default: masking dates is
//! usually wrong for the paste-to-LLM use case (a date is context the model
//! needs, rarely the secret), so it is an opt-in built-in enabled with
//! `enable = ["DATE_TIME"]` (pack) or `--enable DATE_TIME` (CLI).

use super::rule::{RuleDetector, RuleSpec};
use super::validate::Validator;
use crate::model::{Category, Confidence};

pub fn date_detector() -> RuleDetector {
    #[rustfmt::skip]
    let patterns = [
        // ISO 8601 date (also matches the date inside a timestamp; no trailing \b).
        r"\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])",
        // US M/D/Y and EU D.M.Y / D/M/Y numeric dates.
        r"\b(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/\d{2,4}\b",
        r"\b(?:0?[1-9]|[12]\d|3[01])[./](?:0?[1-9]|1[0-2])[./]\d{2,4}\b",
        // Written month, e.g. "January 5, 1990" / "5 Jan 1990".
        r"(?i)\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}\b",
        r"(?i)\b\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{4}\b",
    ];
    let specs = patterns
        .into_iter()
        .map(|p| RuleSpec {
            pattern: p.to_string(),
            category: Category::Pii,
            label: "DATE_TIME".to_string(),
            confidence: Confidence::Medium,
            validator: Validator::None,
            capture: 0,
            prefilter: Vec::new(),
        })
        .collect();
    RuleDetector::from_specs(specs).expect("date regexes compile")
}

#[cfg(test)]
mod tests {
    use super::super::{region, Detector};
    use super::*;
    use crate::normalize::NormalizedView;

    fn masks(raw: &str) -> bool {
        !date_detector()
            .detect(&NormalizedView::build(&region(raw), raw))
            .is_empty()
    }

    #[test]
    fn matches_common_date_formats() {
        assert!(masks("on 2026-06-11 we shipped"));
        assert!(masks("due 12/31/2025 latest"));
        assert!(masks("dated 31.12.2025 here"));
        assert!(masks("January 5, 1990 was the day"));
        assert!(masks("born 5 Jan 1990"));
        assert!(!masks("order 100482931 and code ABCDEFGH"));
    }
}
