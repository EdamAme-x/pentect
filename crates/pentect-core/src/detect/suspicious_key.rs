use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

/// Unambiguous secret-bearing key tokens: presence alone masks the value (High).
const STRONG_KEY_TOKENS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "credential",
    "cred",
    "authorization",
    "bearer",
    "otp",
    "jwt",
    "signature",
];

/// Sensitive but ambiguous tokens: the name alone is a weaker signal (e.g.
/// `public_key` is not a secret), so these mask at Medium rather than High. We
/// deliberately do NOT keep a denylist of benign modifiers ("public", "primary",
/// ...) to subtract: that list is unbounded and over-masking is the safe
/// direction. The lower confidence is the honest way to encode the ambiguity.
const WEAK_KEY_TOKENS: &[&str] = &["key", "auth", "session", "sid", "pin", "nonce"];

/// Masks a value when its key looks sensitive, regardless of the value's shape.
/// Relies only on `Context.key`, so it works without NER even in WASM builds.
pub struct SuspiciousKeyDetector;

impl Detector for SuspiciousKeyDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let region = view.region;
        let Some(k) = &region.ctx.key else {
            return vec![];
        };
        if region.span.is_empty() || is_benign_value(view.text()) {
            return vec![];
        }
        let toks = key_tokens(k);
        let strong = toks.iter().any(|t| STRONG_KEY_TOKENS.contains(&t.as_str()));
        let any_hit = strong || toks.iter().any(|t| WEAK_KEY_TOKENS.contains(&t.as_str()));
        if !any_hit {
            return vec![];
        }
        vec![Span {
            range: region.span,
            category: Category::Secret,
            label: labels::SECRET.to_string(),
            confidence: if strong {
                Confidence::High
            } else {
                Confidence::Medium
            },
            source: DetectorId::SuspiciousKey,
        }]
    }
}

/// Values that are never secrets even under a sensitive key: empty, JSON
/// literals, or an already-rendered placeholder (re-masking one would corrupt
/// earlier output). Masking these is pure noise.
fn is_benign_value(v: &str) -> bool {
    let t = v.trim();
    t.is_empty()
        || matches!(t, "true" | "false" | "null")
        || (t.starts_with("<<") && t.ends_with(">>"))
}

/// Split a key into lowercase word tokens on separators and camelCase humps, so
/// "db_password"/"apiKey"/"X-Auth-Token" expose "password"/"key"/"auth" while
/// "tokenizer" does not match "token".
fn key_tokens(k: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut prev: Option<char> = None;
    for c in k.chars() {
        if c.is_alphanumeric() {
            if let Some(p) = prev {
                if p.is_lowercase() && c.is_uppercase() && !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            cur.extend(c.to_lowercase());
        } else if !cur.is_empty() {
            tokens.push(std::mem::take(&mut cur));
        }
        prev = Some(c);
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_tokens_split_on_separators_and_camel() {
        assert_eq!(key_tokens("db_password"), ["db", "password"]);
        assert_eq!(key_tokens("apiKey"), ["api", "key"]);
        assert_eq!(key_tokens("X-Auth-Token"), ["x", "auth", "token"]);
        assert_eq!(key_tokens("tokenizer"), ["tokenizer"]);
    }

    fn fires(key: &str, value: &str) -> Option<Confidence> {
        use crate::model::*;
        let raw = value.to_string();
        let region = Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context {
                path: None,
                key: Some(key.to_string()),
                kind: RegionKind::JsonValue,
                format: Kind::Json,
            },
        };
        let view = NormalizedView::build(&region, &raw);
        SuspiciousKeyDetector
            .detect(&view)
            .first()
            .map(|s| s.confidence)
    }

    #[test]
    fn strong_tokens_fire_high() {
        assert_eq!(fires("db_password", "hunter2"), Some(Confidence::High));
        assert_eq!(fires("client_secret", "abc123"), Some(Confidence::High));
        assert_eq!(fires("auth_token", "xyz"), Some(Confidence::High));
    }

    // A name with only a weak token is a weaker signal, so it masks at Medium.
    // We do not try to exempt public_key/primary_key: over-masking is the safe
    // direction and the lower confidence already encodes the ambiguity.
    #[test]
    fn weak_token_fires_medium() {
        assert_eq!(fires("apiKey", "abc123"), Some(Confidence::Medium));
        assert_eq!(fires("public_key", "xyz"), Some(Confidence::Medium));
        assert_eq!(fires("X-Session-Id", "s"), Some(Confidence::Medium));
    }

    #[test]
    fn non_sensitive_keys_do_not_fire() {
        assert_eq!(fires("username", "alice"), None);
        assert_eq!(fires("tokenizer", "bert"), None);
        assert_eq!(fires("note", "hello"), None);
    }

    #[test]
    fn benign_values_are_skipped_even_under_sensitive_key() {
        assert_eq!(fires("password", ""), None);
        assert_eq!(fires("password", "null"), None);
        assert_eq!(fires("api_token", "<<SECRET_0123456789abcdef>>"), None);
    }
}
