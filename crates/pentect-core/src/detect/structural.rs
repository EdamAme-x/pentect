use super::benign::{
    is_explicitly_non_sensitive_key_name, is_placeholder_value,
    is_structured_key_name_reference_value, normalize_identifier,
};
use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;
use std::sync::LazyLock;

static SENSITIVE_HEADERS: LazyLock<Vec<String>> =
    LazyLock::new(|| parse_sensitive_headers(include_str!("sensitive_header_names.txt")));

/// Masks values that are sensitive by protocol-defined structural position: a
/// cookie value or a credential-bearing HTTP header. Bounded and protocol-
/// grounded, so it is separate from key-name based structured value masking.
pub struct StructuralDetector;

/// `.env` value regions are masked wholesale. The parser already strips the
/// structural shell, so the core can treat every non-placeholder value as
/// secret without key-name guessing.
pub struct EnvValueDetector;

/// Masks values under explicit structured key/path context supplied by a parser.
/// It emits spans only; rendering and recovery remain the pipeline's job.
pub struct SensitiveKeyDetector;

impl Detector for StructuralDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let region = view.region;
        if region.span.is_empty() || is_benign_value(view.text()) {
            return vec![];
        }
        let fire = match region.ctx.kind {
            RegionKind::Cookie => true,
            RegionKind::Header => region
                .ctx
                .key
                .as_deref()
                .is_some_and(is_sensitive_header_name),
            _ => false,
        };
        if !fire {
            return vec![];
        }
        vec![Span {
            range: region.span,
            category: Category::Secret,
            label: labels::SECRET.to_string(),
            // Medium so a specific vendor rule keeps its label where it overlaps,
            // while structural still beats raw entropy.
            confidence: Confidence::Medium,
            source: DetectorId::Structural,
        }]
    }
}

fn parse_sensitive_headers(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_ascii_lowercase())
        .collect()
}

fn is_sensitive_header_name(header: &str) -> bool {
    // Closed list loaded from sensitive_header_names.txt. These names are
    // protocol-defined credential/cookie carriers, not arbitrary "token" words.
    let header = header.trim().to_ascii_lowercase();
    SENSITIVE_HEADERS.iter().any(|known| known == &header)
}

impl Detector for EnvValueDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let region = view.region;
        if region.span.is_empty()
            || region.ctx.format != Kind::Env
            || is_rendered_placeholder(view.text())
            || is_documentation_placeholder(view.text())
        {
            return vec![];
        }
        vec![Span {
            range: region.span,
            category: Category::Secret,
            label: labels::SECRET.to_string(),
            confidence: Confidence::High,
            source: DetectorId::Structural,
        }]
    }
}

impl Detector for SensitiveKeyDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let region = view.region;
        if region.span.is_empty() || is_benign_value(view.text()) {
            return vec![];
        }
        if region.ctx.kind != RegionKind::JsonValue {
            return vec![];
        }
        if region.ctx.key.as_deref().is_some_and(|key| {
            is_ui_copy_sensitive_key(key, view.text())
                || is_structured_token_prose(key, view.text())
                || is_structured_generic_key_name_reference(key, view.text())
        }) {
            return vec![];
        }
        let Some(label) = sensitive_context_label(&region.ctx) else {
            return vec![];
        };
        vec![Span {
            range: region.span,
            category: Category::Secret,
            label,
            confidence: Confidence::High,
            source: DetectorId::Structural,
        }]
    }
}

fn sensitive_context_label(ctx: &Context) -> Option<String> {
    if let Some(key) = ctx.key.as_deref().filter(|key| is_sensitive_key_name(key)) {
        return Some(sensitive_label_for_key(key));
    }
    if let Some(hint) = ctx.hints.iter().find(|hint| is_sensitive_key_name(hint)) {
        return Some(sensitive_label_for_key(hint));
    }
    ctx.path
        .as_deref()?
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .find(|segment| is_sensitive_key_name(segment))
        .map(sensitive_label_for_key)
}

fn is_sensitive_key_name(key: &str) -> bool {
    let name = normalize_identifier(key);
    if is_explicitly_non_sensitive_key(&name) {
        return false;
    }
    name == "key"
        || name == "auth"
        || name == "authorization"
        || name.contains("auth_")
        || name.contains("_auth")
        || name.contains("authorization")
        || [
            "api_key",
            "apikey",
            "access_key",
            "secret",
            "token",
            "password",
            "passwd",
            "passcode",
            "private",
            "credential",
            "otp",
            "totp",
            "mfa",
            "2fa",
            "verification_code",
            "verificationcode",
            "security_code",
            "securitycode",
            "login_code",
            "logincode",
            "signin_code",
            "signincode",
            "one_time",
            "onetime",
            "session",
            "cookie",
            "jwt",
            "bearer",
        ]
        .iter()
        .any(|needle| name.contains(needle))
}

fn is_ui_copy_sensitive_key(key: &str, value: &str) -> bool {
    // Translation/resource JSON often uses password/token words in UI message
    // identifiers (`incorrectPassword`, `tokenAuthFailed`,
    // `passwordNotSupportedTitle`). Those values are prose, not credentials.
    // Require both a UI-state/action component in the key and prose/localization
    // shape in the value so compact real secrets under `password` still detect.
    let name = normalize_identifier(key);
    let has_sensitive_word = name.split('_').any(|part| {
        matches!(
            part,
            "password" | "passwords" | "token" | "auth" | "authentication" | "credential"
        )
    }) || name.contains("token");
    if !has_sensitive_word {
        return false;
    }
    let has_ui_component = [
        "broken",
        "category",
        "add",
        "cancel",
        "changed",
        "current",
        "dialog",
        "forgot",
        "failed",
        "field",
        "incorrect",
        "invalid",
        "label",
        "length",
        "lock",
        "mandatory",
        "message",
        "new",
        "no",
        "not",
        "only",
        "prompt",
        "remove",
        "removed",
        "required",
        "room",
        "set",
        "successfully",
        "supported",
        "text",
        "title",
        "button",
        "advice",
        "uppercase",
        "digits",
        "matching",
    ]
    .iter()
    .any(|component| name.split('_').any(|part| part == *component));
    has_ui_component && is_prose_or_localization_value(value)
}

fn is_prose_or_localization_value(value: &str) -> bool {
    let value = value.trim();
    value.contains("$t(")
        || value.split_whitespace().count() >= 2
        || !value.is_ascii()
        || value.ends_with(['.', ':', '!', '?'])
        || is_short_ui_label_value(value)
}

fn is_short_ui_label_value(value: &str) -> bool {
    // Button/field/label/title keys often map to a single visible word such as
    // "Password". A real token/password can be low entropy too, so this helper
    // is only reached after the key has explicit UI/action components.
    (2..=32).contains(&value.len())
        && value.bytes().any(|b| b.is_ascii_alphabetic())
        && !value.bytes().any(|b| b.is_ascii_digit())
        && value.chars().all(|ch| {
            ch.is_ascii_alphabetic() || ch.is_whitespace() || matches!(ch, '-' | '\'' | '_')
        })
}

fn is_structured_token_prose(key: &str, value: &str) -> bool {
    // Structured token fields must contain compact token material. Fixture/UI
    // prose such as "Test Access Token" is not a usable bearer/session token.
    let name = normalize_identifier(key);
    let is_token_key = name == "token"
        || name.ends_with("_token")
        || name.contains("_token_")
        || name == "access_token"
        || name == "refresh_token"
        || name == "id_token";
    is_token_key && value.chars().any(char::is_whitespace)
}

fn is_structured_generic_key_name_reference(key: &str, value: &str) -> bool {
    // Generic JSON `"key"` fields often contain another field/config name
    // (`smtpUser`, `databaseName`). Concrete key values usually contain digits,
    // token punctuation, or entropy and remain eligible for masking.
    normalize_identifier(key) == "key" && is_structured_key_name_reference_value(value)
}

fn is_explicitly_non_sensitive_key(name: &str) -> bool {
    is_explicitly_non_sensitive_key_name(name)
}

fn sensitive_label_for_key(key: &str) -> String {
    if is_otp_key_name(key) {
        labels::OTP.to_string()
    } else {
        forced_label(key)
    }
}

fn is_otp_key_name(key: &str) -> bool {
    let name = normalize_key(key);
    [
        "otp",
        "totp",
        "mfa",
        "2fa",
        "passcode",
        "verification_code",
        "verificationcode",
        "security_code",
        "securitycode",
        "login_code",
        "logincode",
        "signin_code",
        "signincode",
        "one_time",
        "onetime",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

fn forced_label(key: &str) -> String {
    let mut out = String::new();
    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() || out.as_bytes()[0].is_ascii_digit() {
        labels::SECRET.to_string()
    } else {
        out
    }
}

fn normalize_key(key: &str) -> String {
    let mut out = String::new();
    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

/// Values that are never secrets even in a sensitive position: empty, JSON
/// literals, or an already-rendered placeholder (idempotency).
fn is_benign_value(v: &str) -> bool {
    let t = v.trim();
    t.is_empty()
        || matches!(t, "true" | "false" | "null")
        || is_rendered_placeholder(t)
        || is_version_literal(t)
        || is_documentation_placeholder(t)
}

fn is_documentation_placeholder(value: &str) -> bool {
    // Structural masking protects broad boundaries such as `.env`. We still
    // spare values that explicitly identify themselves as examples or redacted
    // placeholders; otherwise every sample config becomes a false positive wall.
    is_placeholder_value(value)
}

fn is_version_literal(value: &str) -> bool {
    let t = value
        .trim_start_matches(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '^' | '~'))
        .trim();
    if matches!(t, "*" | "latest") {
        return true;
    }
    if !(3..=64).contains(&t.len()) || !t.as_bytes()[0].is_ascii_digit() {
        return false;
    }
    t.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'*' | b'x' | b'X'))
        && t.bytes().filter(|b| *b == b'.').count() >= 1
}

fn is_rendered_placeholder(v: &str) -> bool {
    v.starts_with("<<") && v.ends_with(">>")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fires(kind: RegionKind, format: Kind, key: Option<&str>, value: &str) -> bool {
        let raw = value.to_string();
        let region = Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context {
                path: None,
                key: key.map(str::to_string),
                hints: Vec::new(),
                kind,
                format,
            },
        };
        !StructuralDetector
            .detect(&NormalizedView::build(&region, &raw))
            .is_empty()
    }

    fn env_fires(key: Option<&str>, value: &str) -> bool {
        let raw = value.to_string();
        let region = Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context {
                path: None,
                key: key.map(str::to_string),
                hints: Vec::new(),
                kind: RegionKind::Body,
                format: Kind::Env,
            },
        };
        !EnvValueDetector
            .detect(&NormalizedView::build(&region, &raw))
            .is_empty()
    }

    fn sensitive_key_fires(key: Option<&str>, value: &str) -> Option<String> {
        sensitive_key_fires_with_path(None, key, value)
    }

    fn sensitive_key_fires_with_path(
        path: Option<&str>,
        key: Option<&str>,
        value: &str,
    ) -> Option<String> {
        sensitive_key_fires_with_context(path, key, &[], value)
    }

    fn sensitive_key_fires_with_context(
        path: Option<&str>,
        key: Option<&str>,
        hints: &[&str],
        value: &str,
    ) -> Option<String> {
        let raw = value.to_string();
        let region = Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context {
                path: path.map(str::to_string),
                key: key.map(str::to_string),
                hints: hints.iter().map(|hint| hint.to_string()).collect(),
                kind: RegionKind::JsonValue,
                format: Kind::ToolResult,
            },
        };
        SensitiveKeyDetector
            .detect(&NormalizedView::build(&region, &raw))
            .into_iter()
            .next()
            .map(|span| span.label)
    }

    #[test]
    fn cookie_values_fire_by_structure() {
        assert!(fires(
            RegionKind::Cookie,
            Kind::Har,
            Some("anyname"),
            "sessabc123"
        ));
        assert!(fires(RegionKind::Cookie, Kind::Har, None, "x"));
    }

    #[test]
    fn sensitive_headers_fire_benign_headers_do_not() {
        assert!(fires(
            RegionKind::Header,
            Kind::Har,
            Some("Authorization"),
            "Bearer x"
        ));
        assert!(fires(
            RegionKind::Header,
            Kind::Har,
            Some("Proxy-Authorization"),
            "Basic dXNlcjpwYXNz"
        ));
        assert!(fires(RegionKind::Header, Kind::Har, Some("cookie"), "a=b"));
        assert!(fires(
            RegionKind::Header,
            Kind::Har,
            Some("Set-Cookie"),
            "sid=abc"
        ));
        assert!(!fires(
            RegionKind::Header,
            Kind::Har,
            Some("Content-Type"),
            "application/json"
        ));
        assert!(!fires(RegionKind::Header, Kind::Har, Some("Accept"), "*/*"));
        assert!(!fires(
            RegionKind::Header,
            Kind::Har,
            Some("WWW-Authenticate"),
            "Bearer realm=\"example\""
        ));
    }

    #[test]
    fn arbitrary_keys_are_not_guessed() {
        // Protocol structural masking itself does not guess key names; that is
        // handled by SensitiveKeyDetector with JsonValue context.
        assert!(!fires(
            RegionKind::JsonValue,
            Kind::Har,
            Some("password"),
            "hunter2"
        ));
        assert!(!fires(
            RegionKind::Body,
            Kind::Har,
            Some("db_password"),
            "hunter2"
        ));
    }

    #[test]
    fn env_values_fire_wholesale() {
        assert!(env_fires(Some("TEST_SECRET"), "114514810"));
        assert!(env_fires(Some("USERNAME"), "alice"));
        assert!(env_fires(Some("FLAG"), "false"));
        assert!(!env_fires(Some("USERNAME"), "<<SECRET_0123456789abcdef>>"));
    }

    #[test]
    fn sensitive_key_detector_uses_explicit_key_context() {
        assert_eq!(
            sensitive_key_fires(Some("password"), "hunter2"),
            Some("PASSWORD".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("otp"), "100482"),
            Some("OTP".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("verificationCode"), "100482"),
            Some("OTP".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("One-time passcode"), "100482"),
            Some("OTP".to_string())
        );
        assert_eq!(sensitive_key_fires(Some("note"), "hello"), None);
        assert_eq!(sensitive_key_fires(None, "hunter2"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "seedUser"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "smtpDomain"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "apiKey"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "Authorization"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "Content-Type"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "grant_type"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "scope"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "firstName"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "phoneNumber"), None);
        assert_eq!(
            sensitive_key_fires(Some("key"), "abcDEF123456"),
            Some("KEY".to_string())
        );
        assert_eq!(
            sensitive_key_fires_with_path(Some("structured.credentials.id"), Some("id"), "abc123"),
            Some("CREDENTIALS".to_string())
        );
        assert_eq!(
            sensitive_key_fires_with_context(None, Some("value"), &["One-time passcode"], "100482"),
            Some("OTP".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("nonSecret"), "invoice INV-100482"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("public_token_label"), "visible docs"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("incorrectPassword"), "Name or password is wrong"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("tokenAuthFailedTitle"), "Authentication failed"),
            None
        );
        assert_eq!(
            sensitive_key_fires(
                Some("passwordSetRemotely"),
                "$t(lockRoomPassword) was set remotely"
            ),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("lockRoomPassword"), "Meeting password"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("lockRoomPassword"), "Password"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("enableDialogPasswordField"), "Password"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("enterPasswordButton"), "Join"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("noPassword"), "No password is set"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("passwordDigitsOnly"), "Digits only"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("authDropboxText"), "Connect your Dropbox account"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("mandatoryNewPassword"), "New password is required"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("showPasswordAdvice"), "Show password advice"),
            None
        );
        assert_eq!(
            sensitive_key_fires(
                Some("passwordSuccessfullyChanged"),
                "Password successfully changed"
            ),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("forgotPassword"), "Forgot your password?"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("invalidPasswordLength"), "Password length is invalid"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("passwordsNotMatching"), "Passwords do not match"),
            None
        );
        assert_eq!(
            sensitive_key_fires(
                Some("categoryBrokenAuthentication"),
                "Broken authentication"
            ),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("title_tokensale"), "Token sale"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("access_token"), "Test Access Token"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("access_token"), "abcDEF123456"),
            Some("ACCESS_TOKEN".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("password"), "correct horse battery staple"),
            Some("PASSWORD".to_string())
        );
    }

    #[test]
    fn benign_values_skipped() {
        assert!(!fires(RegionKind::Cookie, Kind::Har, None, ""));
        assert!(!fires(
            RegionKind::Cookie,
            Kind::Har,
            None,
            "<<SECRET_0123456789abcdef>>"
        ));
        assert_eq!(sensitive_key_fires(Some("cookie-signature"), "1.2.2"), None);
        assert_eq!(sensitive_key_fires(Some("pbkdf2-password"), "^1.0.0"), None);
        assert!(!env_fires(Some("HIPCHAT_API_KEY"), "your_hipchat_api_key"));
        assert!(!env_fires(Some("GRAPHITE_USER"), "username"));
        assert!(!env_fires(Some("LOG_FILE"), "/dev/null"));
    }
}
