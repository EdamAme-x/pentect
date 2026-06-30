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
        AUTH_CODE_PATTERNS
            .detect(view)
            .into_iter()
            .filter(|span| {
                !is_header_name_only_otp_context(view.text(), span.range.start)
                    && !is_git_file_mode_context(view.text(), span.range.start)
                    && !is_json_numeric_metadata_context(view.text(), span.range.start)
            })
            .collect()
    }
}

fn is_header_name_only_otp_context(text: &str, value_start: usize) -> bool {
    // Header names such as `X-GitHub-OTP` can appear in `Vary`/response header
    // lists next to unrelated numbers. Treat a hyphenated `*-OTP` name as OTP
    // context only when the candidate value follows a direct `:`/`=` assignment.
    if value_start > text.len() {
        return false;
    }
    let line_start = text[..value_start]
        .rfind('\n')
        .map_or(0, |offset| offset + 1);
    let prefix = &text[line_start..value_start];
    let lower = prefix.to_ascii_lowercase();
    let Some(otp_at) = lower.rfind("otp") else {
        return false;
    };
    let before = &lower[..otp_at];
    let headerish = before
        .chars()
        .next_back()
        .is_some_and(|ch| matches!(ch, '-' | '_'));
    if !headerish {
        return false;
    }
    let after = lower[otp_at + 3..].trim_start();
    !(after.starts_with(':') || after.starts_with('='))
}

fn is_git_file_mode_context(text: &str, value_start: usize) -> bool {
    // Git tree APIs and fixtures use mode values such as `100644`. They are
    // six-digit numbers near words like "code", but the immediate key is
    // filesystem metadata, not an authentication code.
    if value_start > text.len() {
        return false;
    }
    let line_start = text[..value_start]
        .rfind('\n')
        .map_or(0, |offset| offset + 1);
    let prefix = &text[line_start..value_start];
    let Some(colon) = prefix.rfind(':') else {
        return false;
    };
    if !prefix[colon + 1..].chars().all(char::is_whitespace) {
        return false;
    }
    let before = prefix[..colon].trim_end();
    before.ends_with("\"mode\"") || before.ends_with("'mode'") || before.ends_with("\\\"mode\\\"")
}

fn is_json_numeric_metadata_context(text: &str, value_start: usize) -> bool {
    // Saved API responses put many numeric ids/counts on the same long line as
    // auth-related field names (`login`, `X-GitHub-OTP`). A local JSON key such
    // as `"id": 327146` proves the number is metadata, not an OTP.
    if value_start > text.len() {
        return false;
    }
    let line_start = text[..value_start]
        .rfind('\n')
        .map_or(0, |offset| offset + 1);
    let prefix = &text[line_start..value_start];
    let Some(colon) = prefix.rfind(':') else {
        return false;
    };
    let before = prefix[..colon].trim_end();
    let Some(key) = quoted_key_suffix(before) else {
        return false;
    };
    let normalized = normalize_key_name(key);
    matches!(
        normalized.as_str(),
        "id" | "node_id"
            | "size"
            | "count"
            | "total_count"
            | "watchers_count"
            | "forks_count"
            | "open_issues_count"
            | "network_count"
            | "comments"
            | "additions"
            | "deletions"
            | "changes"
    ) || normalized.ends_with("_id")
        || normalized.ends_with("_count")
}

fn quoted_key_suffix(value: &str) -> Option<&str> {
    let quote = value.as_bytes().last().copied()?;
    if !matches!(quote, b'"' | b'\'') {
        return None;
    }
    let key_end = value.len() - 1;
    let key_start = value[..key_end].rfind(quote as char)? + 1;
    let key = &value[key_start..key_end];
    (!key.is_empty()).then_some(key)
}

fn normalize_key_name(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

fn specs() -> Vec<PatternSpec> {
    use Confidence::High;
    use Validator as V;

    #[rustfmt::skip]
    let patterns: &[(&str, usize, &[&str])] = &[
        // Literal OTP / verification wording.
        (r#"(?i)\b(?:otp|one[-_ ]?time(?:[-_ ]?(?:password|passcode|code))?|verification[-_ ]?code|security[-_ ]?code|login[-_ ]?code|sign[-_ ]?in[-_ ]?code|2fa|mfa)\b[^\r\n0-9]{0,32}([0-9][0-9 -]{2,10}[0-9])(?:$|[\s<>"',;).!])"#, 1, &["otp", "one-time", "one time", "one_time", "verification", "security", "login", "sign", "2fa", "mfa"]),
        (r#"(?:認証コード|確認コード|ワンタイム(?:パスワード|コード)|二段階認証)[^\r\n0-9]{0,32}([0-9][0-9 -]{2,10}[0-9])"#, 1, &["認証コード", "確認コード", "ワンタイム", "二段階認証"]),
        // Wider prose between the auth word and a numeric code.
        (r#"(?i)\b(?:otp|one[-_ ]?time(?:[-_ ]?(?:password|passcode|code))?|verification[-_ ]?code|security[-_ ]?code|login[-_ ]?code|sign[-_ ]?in[-_ ]?code|2fa|mfa)\b[^\r\n]{0,160}\b([0-9]{6,8})\b"#, 1, &["otp", "one-time", "one time", "one_time", "verification", "security", "login", "sign", "2fa", "mfa"]),
        (r#"(?:認証コード|確認コード|ワンタイム(?:パスワード|コード)|二段階認証)[^\r\n]{0,160}\b([0-9]{6,8})\b"#, 1, &["認証コード", "確認コード", "ワンタイム", "二段階認証"]),
        // Auth flows may use short or alphanumeric codes without saying "OTP".
        (r#"(?i:\b(?:sign[-_ ]?in|log[-_ ]?in|login|authenticate|authentication|verify|account|security|two[-_ ]?step|two[-_ ]?factor|2fa|mfa)\b)[^.\r\n]{0,120}(?i:\b(?:code|passcode)\b)[^.\r\n]{0,80}\b([0-9]{4,10}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{3,9}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{1,6}[- ][A-Z0-9]{2,6}|[A-Z0-9]{2,6}[- ][A-Z0-9]{0,6}[0-9][A-Z0-9]{0,6})\b"#, 1, &["sign", "log", "login", "authenticate", "authentication", "verify", "account", "security", "two-step", "two step", "two_factor", "two factor", "2fa", "mfa"]),
        (r#"(?i:\b(?:code|passcode)\b)[^.\r\n]{0,80}\b([0-9]{4,10}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{3,9}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{1,6}[- ][A-Z0-9]{2,6}|[A-Z0-9]{2,6}[- ][A-Z0-9]{0,6}[0-9][A-Z0-9]{0,6})\b[^.\r\n]{0,120}(?i:\b(?:sign[-_ ]?in|log[-_ ]?in|login|authenticate|authentication|verify|account|security|two[-_ ]?step|two[-_ ]?factor|2fa|mfa)\b)"#, 1, &["sign", "log", "login", "authenticate", "authentication", "verify", "account", "security", "two-step", "two step", "two_factor", "two factor", "2fa", "mfa"]),
        (r#"(?i:\b(?:enter|use|input|type|paste)\b)[^.\r\n]{0,32}\b([0-9]{4,10}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{3,9}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{1,6}[- ][A-Z0-9]{2,6}|[A-Z0-9]{2,6}[- ][A-Z0-9]{0,6}[0-9][A-Z0-9]{0,6})\b[^.\r\n]{0,120}(?i:\b(?:sign[-_ ]?in|log[-_ ]?in|login|authenticate|authentication|verify|account)\b)"#, 1, &["enter", "use", "input", "type", "paste"]),
        (r#"(?:ログイン|サインイン|認証|本人確認|二段階認証)[^\r\n]{0,120}([0-9]{4,10}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{3,9}|[A-Z0-9]{0,6}[0-9][A-Z0-9]{1,6}[- ][A-Z0-9]{2,6}|[A-Z0-9]{2,6}[- ][A-Z0-9]{0,6}[0-9][A-Z0-9]{0,6})"#, 1, &["ログイン", "サインイン", "認証", "本人確認", "二段階認証"]),
    ];

    patterns
        .iter()
        .map(|&(pattern, capture, prefilter)| PatternSpec {
            pattern: pattern.to_string(),
            category: Category::Secret,
            label: labels::OTP.to_string(),
            confidence: High,
            validator: V::None,
            context: Default::default(),
            capture,
            prefilter: prefilter.iter().map(|s| (*s).to_string()).collect(),
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
        assert!(values_for(
            "vary: Accept, Authorization, Cookie, X-GitHub-OTP, Accept-Encoding; mode 100644"
        )
        .is_empty());
        assert!(
            values_for(r#"Create code object with {"mode": "100644", "path": "foo.py"}"#)
                .is_empty()
        );
        assert!(values_for(
            r#"Create code object with {\"mode\": \"100644\", \"path\": \"foo.py\"}"#
        )
        .is_empty());
        assert!(values_for(
            r#"{"headers":"X-GitHub-OTP, Accept-Encoding","actor":{"id":327146,"login":"octo"}}"#
        )
        .is_empty());
        assert!(values_for(
            r#"{"title":"login code help","comments":42754194,"total_count":813448}"#
        )
        .is_empty());
        assert!(has_value(
            r#"{"headers":"X-GitHub-OTP","id":123,"otp":327146}"#,
            "327146"
        ));
        assert!(!has_value(
            "Enter 7QK4P on the login page. Order code AB12-CD ships tomorrow.",
            "AB12-CD"
        ));
        assert!(!has_value(
            "Login page loaded. Order code 1234 ships tomorrow.",
            "1234"
        ));
    }

    #[test]
    fn accepts_direct_otp_header_values() {
        assert!(has_value("X-GitHub-OTP: 837291", "837291"));
    }
}
