//! Phone numbers via the `phonenumber` crate (the Rust port of Google's
//! libphonenumber — the same engine Presidio uses). We find `+CC...`
//! international candidates and keep only the ones libphonenumber says are
//! *valid* (not merely phone-shaped), so a random `+` number or a bare digit
//! run does not mask. National numbers without a country code are ambiguous
//! (any 10 digits) and are left to the format-specific rules.

use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;
use regex::Regex;
use std::sync::LazyLock;

static CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\+[0-9][0-9 ().\-/]{5,18}[0-9]").unwrap());

pub struct PhoneDetector;

impl Detector for PhoneDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let s = view.text();
        let mut out = Vec::new();
        for m in CANDIDATE.find_iter(s) {
            match phonenumber::parse(None, m.as_str()) {
                Ok(n) if phonenumber::is_valid(&n) => out.push(Span {
                    range: view.to_raw(ByteRange::new(m.start(), m.end())),
                    category: Category::Pii,
                    label: "PHONE_NUMBER".to_string(),
                    confidence: Confidence::High, // libphonenumber-validated
                    source: DetectorId::Rule,
                }),
                _ => {}
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    fn labels(raw: &str) -> Vec<String> {
        PhoneDetector
            .detect(&NormalizedView::build(&region(raw), raw))
            .into_iter()
            .map(|s| s.label)
            .collect()
    }

    #[test]
    fn validates_international_numbers_across_regions() {
        // Real, valid numbers in several countries (test fixtures).
        assert_eq!(labels("call +14155552671 now"), ["PHONE_NUMBER"]); // US
        assert_eq!(labels("ring +442071838750"), ["PHONE_NUMBER"]); // UK
        assert_eq!(labels("dial +81363849000"), ["PHONE_NUMBER"]); // JP
        assert_eq!(labels("phone +4930901820"), ["PHONE_NUMBER"]); // DE
                                                                   // `+`-shaped but not a valid number, and a bare id, do not mask.
        assert!(labels("ref +12 000 0000").is_empty());
        assert!(labels("order 183920475 shipped").is_empty());
    }
}
