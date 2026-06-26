//! Phone numbers via the `phonenumber` crate (the Rust port of Google's
//! libphonenumber — the same engine Presidio uses). We keep validated
//! international numbers at high confidence, and allow lower-confidence
//! phone-shaped fallbacks only when the shape is distinctive (`+CC...`) or a
//! nearby phone/contact keyword disambiguates national numbers.

use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;
use regex::Regex;
use std::sync::LazyLock;

static CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\+[0-9][0-9 ().\-/]{5,18}[0-9]").unwrap());
static CONTEXT_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:phone|telephone|mobile|contact|call|tel\.?|telefone|telefono|tel[eé]fono|t[eé]l[eé]phone|telefon|telepon|điện thoại|số điện thoại|телефон|телефонен номер|телефонен|電話|連絡先| 연락처|연락처)[^\r\n0-9+()]{0,48}(\+?[0-9(][0-9 ().\-/]{6,24}[0-9])"#,
    )
    .unwrap()
});
static TRAILING_CONTEXT_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(\+?[0-9(][0-9 ().\-/]{6,24}[0-9])[^\r\n]{0,32}(?:phone|telephone|mobile|contact|call|tel\.?|telefone|telefono|tel[eé]fono|t[eé]l[eé]phone|telefon|telepon|điện thoại|số điện thoại|телефон|телефонен|電話|連絡| 연락처|연락처)"#,
    )
    .unwrap()
});
static EMAIL_OR_PHONE_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:email|e-mail|mail|[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})[^\r\n]{0,96}\bor\s+(\+?[0-9(][0-9 ().\-/]{6,24}[0-9])"#)
        .unwrap()
});

pub struct PhoneDetector;

impl Detector for PhoneDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let s = view.text();
        let mut out = Vec::new();
        for m in CANDIDATE.find_iter(s) {
            match phonenumber::parse(None, m.as_str()) {
                Ok(n) if phonenumber::is_valid(&n) => {
                    push_phone(view, m.start(), m.end(), Confidence::High, &mut out);
                }
                _ if plausible_phone(m.as_str(), true) => {
                    push_phone(view, m.start(), m.end(), Confidence::Medium, &mut out);
                }
                _ => {}
            }
        }
        for captures in CONTEXT_CANDIDATE.captures_iter(s) {
            if let Some(m) = captures.get(1) {
                if plausible_phone(m.as_str(), false)
                    && !out
                        .iter()
                        .any(|span| span.range.start <= m.start() && m.end() <= span.range.end)
                {
                    push_phone(view, m.start(), m.end(), Confidence::Medium, &mut out);
                }
            }
        }
        for captures in TRAILING_CONTEXT_CANDIDATE.captures_iter(s) {
            if let Some(m) = captures.get(1) {
                if plausible_phone(m.as_str(), false)
                    && !out
                        .iter()
                        .any(|span| span.range.start <= m.start() && m.end() <= span.range.end)
                {
                    push_phone(view, m.start(), m.end(), Confidence::Medium, &mut out);
                }
            }
        }
        for captures in EMAIL_OR_PHONE_CANDIDATE.captures_iter(s) {
            if let Some(m) = captures.get(1) {
                if plausible_phone(m.as_str(), false)
                    && !out
                        .iter()
                        .any(|span| span.range.start <= m.start() && m.end() <= span.range.end)
                {
                    push_phone(view, m.start(), m.end(), Confidence::Medium, &mut out);
                }
            }
        }
        out
    }
}

fn push_phone(
    view: &NormalizedView,
    start: usize,
    end: usize,
    confidence: Confidence,
    out: &mut Vec<Span>,
) {
    out.push(Span {
        range: view.to_raw(ByteRange::new(start, end)),
        category: Category::Pii,
        label: "PHONE_NUMBER".to_string(),
        confidence,
        source: DetectorId::Rule,
    });
}

fn plausible_phone(value: &str, international: bool) -> bool {
    let digits = value.bytes().filter(u8::is_ascii_digit).count();
    if !(8..=15).contains(&digits) {
        return false;
    }
    if international && digits < 10 {
        return false;
    }
    let separators = value
        .bytes()
        .filter(|b| matches!(b, b' ' | b'.' | b'-' | b'/' | b'(' | b')'))
        .count();
    if separators == 0 && !value.starts_with('+') {
        return false;
    }
    let repeated = value.bytes().filter(u8::is_ascii_digit).collect::<Vec<_>>();
    !repeated
        .first()
        .is_some_and(|first| repeated.iter().all(|digit| digit == first))
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
        assert_eq!(labels("contact +397-252.426 1011"), ["PHONE_NUMBER"]); // phone-shaped fallback
        assert_eq!(labels("số điện thoại: 008458444 9610"), ["PHONE_NUMBER"]);
        assert_eq!(labels("連絡先: (635)-5366210"), ["PHONE_NUMBER"]);
        assert_eq!(labels("(635)-5366210でご連絡ください"), ["PHONE_NUMBER"]);
        assert_eq!(
            labels("questions can be directed to a@example.com or 01472.27346"),
            ["PHONE_NUMBER"]
        );
        assert_eq!(labels("телефонен номер 5977.025 7979"), ["PHONE_NUMBER"]);
        // `+`-shaped but too weak, and a bare id, do not mask.
        assert!(labels("ref +12 000 0000").is_empty());
        assert!(labels("order 183920475 shipped").is_empty());
    }
}
