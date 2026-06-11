use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

/// Credit-card numbers: maximal 13–19 digit runs that pass the Luhn checksum.
/// The checksum is the precision lever — a random 16-digit number almost never
/// validates — so detection needs no key or context and is language-agnostic.
/// (Separator-formatted `4111 1111 ...` is left for later; machine artifacts
/// carry contiguous digits.)
pub struct CardDetector;

impl Detector for CardDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let s = view.text();
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if !b[i].is_ascii_digit() {
                i += 1;
                continue;
            }
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if (13..=19).contains(&(i - start)) && luhn(&b[start..i]) {
                out.push(Span {
                    range: view.to_raw(ByteRange::new(start, i)),
                    category: Category::Pii,
                    label: "CARD".to_string(),
                    confidence: Confidence::High,
                    source: DetectorId::Rule,
                });
            }
        }
        out
    }
}

fn luhn(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for &c in digits.iter().rev() {
        let mut d = u32::from(c - b'0');
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    fn labels(raw: &str) -> Vec<String> {
        CardDetector
            .detect(&NormalizedView::build(&region(raw), raw))
            .into_iter()
            .map(|s| s.label)
            .collect()
    }

    #[test]
    fn valid_card_detected_invalid_not() {
        assert_eq!(labels("pay 4242424242424242 now"), ["CARD"]); // valid Luhn
        assert!(labels("id 1234567812345678 x").is_empty()); // fails Luhn
    }

    #[test]
    fn wrong_length_runs_ignored() {
        assert!(labels("123456789012").is_empty()); // 12 digits, too short
        assert!(labels("12345678901234567890").is_empty()); // 20 digits, too long
    }

    #[test]
    fn luhn_basics() {
        assert!(luhn(b"4242424242424242"));
        assert!(!luhn(b"4242424242424243"));
    }
}
