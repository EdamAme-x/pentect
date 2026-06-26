use std::sync::LazyLock;

use regex::Regex;

use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

static CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:identification|identity|your\s+id\s+is|id[-‑ ]?number|id[-‑]?nummer|nummer|verified|verification|profile|eligibility|compliance|copy of|provide a copy|provide your|copie|kopij[ąa]|копие|submit|dostavite|priložite|registr(?:ation|acije)|registro|formulario|formular|felter som|fields such as|ingrese su|solicita|申し込み|申込|certification numbers?|reference number|referenznummer|αναφορά αριθ|sensitive data|občutljivimi podatki|official registration|anmeldung|ausweisen|secure portal|employee portal|receipt|receipts|expense|expenses|chi tiêu|biên lai|secret code|passport|passaporte|pasportu|passeport|passaporto|reisepass|paszport|паспорт|лична карта|contribuinte|porezni broj|tax[-_ ]?(?:id|number)|fiscal|fiscale|identification fiscale|данъчен номер|social security|социален номер|credit card|card number|num[eé]ro de carte|carte de cr[eé]dit|kreditnou kartou|číslo karty|bank account|account number|conto bancario|licencia de conducir|n[uú]mero de identificaci[oó]n|prawa jazdy|šofőr|шофьорски лиценз|ajokortin|galiojantį|patikrinimui|megadásával|deras respektive|im system hinterlegt|ταυτοτητας|ταυτότητας|κοινωνικής ασφάλισης|διπλώματος οδήγησης)",
    )
    .unwrap()
});

// No regex word boundaries here: CJK/Cyrillic prose often touches ASCII IDs
// directly. `ascii_token_boundary` keeps us from slicing inside real tokens.
static CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:[A-Z0-9][A-Z0-9-]{6,38}[A-Z0-9]|[0-9][0-9 .-]{6,28}[0-9])").unwrap()
});

/// Opt-in generic local document/account identifiers where the value's shape is
/// not enough by itself. This deliberately stays out of the default core stack:
/// language/context lexicons are useful for recall measurement, but too easy to
/// turn into benchmark-specific overreach.
pub struct ContextualIdDetector;

impl Detector for ContextualIdDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let s = view.text();
        let mut out = Vec::new();
        for m in CANDIDATE.find_iter(s) {
            if ascii_token_boundary(s, m.start(), m.end())
                && plausible_id(m.as_str())
                && has_near_context(s, m.start(), m.end())
            {
                out.push(Span {
                    range: view.to_raw(ByteRange::new(m.start(), m.end())),
                    category: Category::Pii,
                    label: "CONTEXTUAL_ID".to_string(),
                    confidence: Confidence::Low,
                    source: DetectorId::Rule,
                });
            }
        }
        out
    }
}

fn ascii_token_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = start == 0 || !text.as_bytes()[start.saturating_sub(1)].is_ascii_alphanumeric();
    let after = end == text.len() || !text.as_bytes()[end].is_ascii_alphanumeric();
    before && after
}

fn plausible_id(value: &str) -> bool {
    let mut digits = 0usize;
    let mut uppercase = 0usize;
    let mut lowercase = 0usize;
    let mut separators = 0usize;
    for b in value.bytes() {
        if b.is_ascii_digit() {
            digits += 1;
        } else if b.is_ascii_uppercase() {
            uppercase += 1;
        } else if b.is_ascii_lowercase() {
            lowercase += 1;
        } else if matches!(b, b'-' | b' ' | b'.') {
            separators += 1;
        } else {
            return false;
        }
    }

    if digits == 0 || lowercase > 0 || repeated_digits(value) {
        return false;
    }

    let compact = digits + uppercase;
    if uppercase > 0 {
        return (8..=20).contains(&compact) && digits >= 1;
    }

    let dense_numeric = separators == 0 && (8..=18).contains(&digits);
    let separated_numeric = separators > 0 && (8..=24).contains(&digits);
    dense_numeric || separated_numeric
}

fn repeated_digits(value: &str) -> bool {
    let mut first = None;
    let mut count = 0usize;
    for b in value.bytes().filter(u8::is_ascii_digit) {
        count += 1;
        match first {
            None => first = Some(b),
            Some(f) if f != b => return false,
            Some(_) => {}
        }
    }
    count >= 6
}

fn has_near_context(text: &str, start: usize, end: usize) -> bool {
    let left = nearest_left_boundary(text, start.saturating_sub(128));
    let right = nearest_right_boundary(text, (end + 96).min(text.len()));
    CONTEXT.is_match(&text[left..right])
}

fn nearest_left_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn nearest_right_boundary(text: &str, mut index: usize) -> usize {
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    fn labels(s: &str) -> Vec<String> {
        let reg = region(s);
        let view = NormalizedView::build(&reg, s);
        ContextualIdDetector
            .detect(&view)
            .into_iter()
            .map(|span| s[span.range.start..span.range.end].to_string())
            .collect()
    }

    #[test]
    fn masks_contextual_document_values() {
        assert_eq!(
            labels("verified with Y01TTLNJ8K and QJ3136353 to ensure compliance"),
            ["Y01TTLNJ8K", "QJ3136353"]
        );
        assert_eq!(
            labels("include a copy of your AOQJT3QJQF and, for verification, your 3010842850"),
            ["AOQJT3QJQF", "3010842850"]
        );
        assert_eq!(
            labels("certification numbers, such as KJY5EZON58 and UB1913941"),
            ["KJY5EZON58", "UB1913941"]
        );
        assert_eq!(
            labels("Din biljett har registrerats under ditt ID‑nummer 38678361"),
            ["38678361"]
        );
        assert_eq!(
            labels("reviewed by compliance office using your A5592159 for verification"),
            ["A5592159"]
        );
        assert_eq!(
            labels(
                "incluindo o número de passaporte PY212368 e o número de contribuinte 588555489"
            ),
            ["PY212368", "588555489"]
        );
        assert_eq!(
            labels("numéro d’identification fiscale: 05.35.725.893.505"),
            ["05.35.725.893.505"]
        );
        assert_eq!(
            labels("Numero di conto bancario (IBAN): 4072066117"),
            ["4072066117"]
        );
        assert_eq!(
            labels("copie di W7092595 e K0998030"),
            ["W7092595", "K0998030"]
        );
        assert_eq!(
            labels("licencia de conducir U22919175 y su número de identificación 84583423V"),
            ["U22919175", "84583423V"]
        );
        assert_eq!(labels("Your ID is 27788714668."), ["27788714668"]);
        assert_eq!(
            labels("formulario de registro solicita ingrese su TA5157584 y su 5295816902"),
            ["TA5157584", "5295816902"]
        );
        assert_eq!(
            labels("предоставите копие от вашия паспорт 102527975 и лична карта 831320376"),
            ["102527975", "831320376"]
        );
        assert_eq!(
            labels("opdateret den interne formular med felter som 070275-6753, 271257-1578 og BTA7SW40HX"),
            ["070275-6753", "271257-1578", "BTA7SW40HX"]
        );
        assert_eq!(
            labels("申し込みは(635)-5366210または208MG2ABSVでご連絡いただけます"),
            ["208MG2ABSV"]
        );
    }

    #[test]
    fn leaves_benign_ids_without_sensitive_context() {
        assert!(labels("Order code AB12-CD ships tomorrow").is_empty());
        assert!(labels("valid SKU WIDGETCO-2024 ships tomorrow").is_empty());
        assert!(labels("request_id=183920475 order=100482931").is_empty());
    }
}
