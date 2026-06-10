use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

/// The shipped default vocabulary. A baseline has to exist — every scanner has
/// one — but it is *data*, not detector logic: `with_tokens` (and a TOML pack)
/// replaces it, and locale-aware / semantic key classification is a future
/// ML-sidecar concern, not core's. STRONG tokens are unambiguous secret names;
/// WEAK ones (e.g. `key`, which appears in `public_key`) are a weaker signal, so
/// the confidence tier carries the ambiguity rather than a denylist of benign
/// modifiers.
const DEFAULT_STRONG: &[&str] = &[
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
const DEFAULT_WEAK: &[&str] = &["key", "auth", "session", "sid", "pin", "nonce"];

/// Masks a value when its key looks sensitive, regardless of the value's shape.
/// Relies only on `Context.key`, so it works without NER even in WASM builds. The
/// detector is a pure mechanism; the sensitive-key vocabulary is injected data.
pub struct SuspiciousKeyDetector {
    strong: Vec<String>,
    weak: Vec<String>,
}

impl SuspiciousKeyDetector {
    /// The shipped default vocabulary.
    pub fn builtin() -> Self {
        Self::with_tokens(owned(DEFAULT_STRONG), owned(DEFAULT_WEAK))
    }

    /// A caller-supplied vocabulary (e.g. a rule pack or a locale-specific set).
    /// `strong` tokens mask at High, `weak` at Medium.
    pub fn with_tokens(strong: Vec<String>, weak: Vec<String>) -> Self {
        Self { strong, weak }
    }
}

fn owned(tokens: &[&str]) -> Vec<String> {
    tokens.iter().map(|t| t.to_string()).collect()
}

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
        let strong = toks.iter().any(|t| self.strong.contains(t));
        let any_hit = strong || toks.iter().any(|t| self.weak.contains(t));
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
        SuspiciousKeyDetector::builtin()
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

    #[test]
    fn vocabulary_is_injected_not_hardcoded() {
        // A custom set (here a non-English token) is honored, and a default token
        // outside it no longer fires — the knowledge is data, not detector logic.
        let det = SuspiciousKeyDetector::with_tokens(vec!["パスワード".into()], vec![]);
        let fire = |key: &str, raw: &str| {
            let region = Region {
                span: ByteRange::new(0, raw.len()),
                ctx: Context {
                    path: None,
                    key: Some(key.to_string()),
                    kind: RegionKind::JsonValue,
                    format: Kind::Json,
                },
            };
            !det.detect(&NormalizedView::build(&region, raw)).is_empty()
        };
        assert!(fire("パスワード", "hunter2"));
        assert!(!fire("password", "hunter2"));
    }
}
