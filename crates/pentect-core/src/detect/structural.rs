use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

/// Header names that carry credentials *by protocol definition* — a closed,
/// RFC-defined, ASCII set, not an open-vocabulary guess. Compared lowercased.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// Masks values that are sensitive by their *structural position* in a known
/// format, not by guessing an arbitrary key name: a cookie value (carries session
/// state) or a credential-bearing HTTP header. Bounded and protocol-grounded.
/// Open-vocabulary, multilingual key sensitivity (`password`=`パスワード`=…) is a
/// model's job (ML sidecar), not core's — core does not enumerate key names.
pub struct StructuralDetector;

/// `.env` value regions are masked wholesale. The parser already strips the
/// structural shell, so the core can treat every non-placeholder value as
/// secret without key-name guessing.
pub struct EnvValueDetector;

/// Opt-in detector for agent/tool-result adapters. It uses explicit structural
/// key context supplied by a parser and emits spans only; rendering and recovery
/// remain the pipeline's job.
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
                .is_some_and(|k| SENSITIVE_HEADERS.contains(&k.to_ascii_lowercase().as_str())),
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

impl Detector for EnvValueDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let region = view.region;
        if region.span.is_empty()
            || region.ctx.format != Kind::Env
            || is_rendered_placeholder(view.text())
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
    let name = normalize_key(key);
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

fn is_explicitly_non_sensitive_key(name: &str) -> bool {
    name == "nonsecret"
        || name == "non_secret"
        || name == "notsecret"
        || name == "not_secret"
        || name == "public"
        || name.starts_with("public_")
        || name.ends_with("_public")
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
    t.is_empty() || matches!(t, "true" | "false" | "null") || is_rendered_placeholder(t)
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
        assert!(fires(RegionKind::Header, Kind::Har, Some("cookie"), "a=b"));
        assert!(!fires(
            RegionKind::Header,
            Kind::Har,
            Some("Content-Type"),
            "application/json"
        ));
        assert!(!fires(RegionKind::Header, Kind::Har, Some("Accept"), "*/*"));
    }

    #[test]
    fn arbitrary_keys_are_not_guessed() {
        // The whole point: open-vocabulary key names are NOT enumerated here.
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
    fn sensitive_key_detector_is_opt_in_key_context() {
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
    }
}
