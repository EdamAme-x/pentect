use std::sync::LazyLock;

use super::pattern::{PatternMatchDetector, PatternSpec};
use super::validate::Validator;
use super::Detector;
use crate::model::{labels, Category, Confidence};
use crate::normalize::NormalizedView;

#[derive(Clone, Default)]
pub struct AuthCodeDetector;

static AUTH_CODE_PATTERNS: LazyLock<PatternMatchDetector> =
    LazyLock::new(|| PatternMatchDetector::from_specs(specs()).expect("auth code regexes compile"));

impl Detector for AuthCodeDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<crate::model::Span> {
        AUTH_CODE_PATTERNS.detect(view)
    }
}

fn specs() -> Vec<PatternSpec> {
    use Confidence::High;
    use Validator as V;

    #[rustfmt::skip]
    let patterns: &[(&str, usize)] = &[
        // Literal OTP / verification wording.
        (r#"(?i)\b(?:otp|one[-_ ]?time(?:[-_ ]?(?:password|passcode|code))?|verification[-_ ]?code|security[-_ ]?code|login[-_ ]?code|sign[-_ ]?in[-_ ]?code|2fa|mfa)\b[^\r\n0-9]{0,32}([0-9][0-9 -]{2,10}[0-9])(?:$|[\s<>"',;).!])"#, 1),
        (r#"(?:認証コード|確認コード|ワンタイム(?:パスワード|コード)|二段階認証)[^\r\n0-9]{0,32}([0-9][0-9 -]{2,10}[0-9])"#, 1),
        // Wider prose between the auth word and a numeric code.
        (r#"(?i)\b(?:otp|one[-_ ]?time(?:[-_ ]?(?:password|passcode|code))?|verification[-_ ]?code|security[-_ ]?code|login[-_ ]?code|sign[-_ ]?in[-_ ]?code|2fa|mfa)\b[^\r\n]{0,160}\b([0-9]{6,8})\b"#, 1),
        (r#"(?:認証コード|確認コード|ワンタイム(?:パスワード|コード)|二段階認証)[^\r\n]{0,160}\b([0-9]{6,8})\b"#, 1),
        // Auth flows may use short or alphanumeric codes without saying "OTP".
        (r#"(?i:\b(?:sign[-_ ]?in|log[-_ ]?in|login|authenticate|authentication|verify|account|security|two[-_ ]?step|two[-_ ]?factor|2fa|mfa)\b)[^.\r\n]{0,120}(?i:\b(?:code|passcode)\b)[^.\r\n]{0,80}\b([0-9]{4,10}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{3,9}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{1,6}[- ][A-Z0-9]{2,6}|[A-Z0-9]{2,6}[- ][A-Z0-9]{0,6}[0-9][A-Z0-9]{0,6})\b"#, 1),
        (r#"(?i:\b(?:code|passcode)\b)[^.\r\n]{0,80}\b([0-9]{4,10}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{3,9}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{1,6}[- ][A-Z0-9]{2,6}|[A-Z0-9]{2,6}[- ][A-Z0-9]{0,6}[0-9][A-Z0-9]{0,6})\b[^.\r\n]{0,120}(?i:\b(?:sign[-_ ]?in|log[-_ ]?in|login|authenticate|authentication|verify|account|security|two[-_ ]?step|two[-_ ]?factor|2fa|mfa)\b)"#, 1),
        (r#"(?i:\b(?:enter|use|input|type|paste)\b)[^.\r\n]{0,32}\b([0-9]{4,10}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{3,9}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{1,6}[- ][A-Z0-9]{2,6}|[A-Z0-9]{2,6}[- ][A-Z0-9]{0,6}[0-9][A-Z0-9]{0,6})\b[^.\r\n]{0,120}(?i:\b(?:sign[-_ ]?in|log[-_ ]?in|login|authenticate|authentication|verify|account)\b)"#, 1),
        (r#"(?:ログイン|サインイン|認証|本人確認|二段階認証)[^\r\n]{0,120}([0-9]{4,10}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{3,9}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{1,6}[- ][A-Z0-9]{2,6}|[A-Z0-9]{2,6}[- ][A-Z0-9]{0,6}[0-9][A-Z0-9]{0,6})"#, 1),
    ];

    patterns
        .iter()
        .map(|&(pattern, capture)| PatternSpec {
            pattern: pattern.to_string(),
            category: Category::Secret,
            label: labels::OTP.to_string(),
            confidence: High,
            validator: V::None,
            capture,
            prefilter: Vec::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    fn values_for(raw: &str) -> Vec<String> {
        let region = region(raw);
        let view = NormalizedView::build(&region, raw);
        AuthCodeDetector
            .detect(&view)
            .into_iter()
            .map(|span| raw[span.range.start..span.range.end].to_string())
            .collect()
    }

    fn has_value(raw: &str, value: &str) -> bool {
        values_for(raw).iter().any(|got| got == value)
    }

    #[test]
    fn detects_auth_codes_from_prose() {
        assert!(has_value("otp=100482 expires soon", "100482"));
        assert!(has_value("Your verification code is 837291.", "837291"));
        assert!(has_value(
            "Use security code: 402118 to continue.",
            "402118"
        ));
        assert!(has_value("認証コード: 483920 を入力してください", "483920"));
        assert!(has_value(
            "Your verification code expires in 10 minutes: 837291.",
            "837291"
        ));
        assert!(has_value("Your sign-in code is 1234.", "1234"));
        assert!(has_value("Use AB12-CD to sign in.", "AB12-CD"));
        assert!(has_value("Enter 7QK4P on the login page.", "7QK4P"));
        assert!(has_value(
            "サインインするには 7391 を入力してください",
            "7391"
        ));
    }

    #[test]
    fn avoids_plain_order_codes_and_promos() {
        assert!(values_for("order code 100482 remains visible").is_empty());
        assert!(values_for("Use SAVE10 to continue checkout").is_empty());
        assert!(values_for("Order code AB12-CD ships tomorrow").is_empty());
        assert!(!has_value(
            "Enter 7QK4P on the login page. Order code AB12-CD ships tomorrow.",
            "AB12-CD"
        ));
        assert!(!has_value(
            "Login page loaded. Order code 1234 ships tomorrow.",
            "1234"
        ));
    }
}
