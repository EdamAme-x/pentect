use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

const SENSITIVE_KEY_TOKENS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "auth",
    "authorization",
    "credential",
    "cred",
    "key",
    "apikey",
    "session",
    "sid",
    "signature",
    "nonce",
    "bearer",
    "passphrase",
    "otp",
    "pin",
    "jwt",
];

/// Masks a value when its key looks sensitive, regardless of the value's shape.
/// Relies only on `Context.key`, so it works without NER even in WASM builds.
pub struct SuspiciousKeyDetector;

impl Detector for SuspiciousKeyDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let region = view.region;
        let Some(k) = &region.ctx.key else {
            return vec![];
        };
        if region.span.is_empty() {
            return vec![];
        }
        let hit = key_tokens(k)
            .iter()
            .any(|t| SENSITIVE_KEY_TOKENS.contains(&t.as_str()));
        if hit {
            vec![Span {
                range: region.span,
                category: Category::Secret,
                label: "SECRET".to_string(),
                confidence: Confidence::Medium,
                source: DetectorId::SuspiciousKey,
            }]
        } else {
            vec![]
        }
    }
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
}
