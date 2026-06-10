use crate::model::*;
use crate::normalize::NormalizedView;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use regex::Regex;

/// Side-effect-free and deterministic. Runs on a region's normalized view and
/// returns spans in absolute raw coordinates.
pub trait Detector {
    fn id(&self) -> &str;
    fn detect(&self, view: &NormalizedView) -> Vec<Span>;
}

struct Rule {
    re: Regex,
    category: Category,
    label: &'static str,
    confidence: Confidence,
}

pub struct RuleDetector {
    rules: Vec<Rule>,
}

impl RuleDetector {
    pub fn builtin() -> Self {
        let r = |p: &str| Regex::new(p).expect("builtin regex compiles");
        let rules = vec![
            Rule {
                re: r(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"),
                category: Category::Secret,
                label: "JWT_SECRET",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"AKIA[0-9A-Z]{16}"),
                category: Category::Secret,
                label: "AWS_AKID",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"sk-[A-Za-z0-9_-]{20,}"),
                category: Category::Secret,
                label: "OPENAI_API_KEY",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"ghp_[A-Za-z0-9]{36}"),
                category: Category::Secret,
                label: "GITHUB_PAT",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
                category: Category::Secret,
                label: "SLACK_TOKEN",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
                category: Category::Pii,
                label: "IDENTITY",
                confidence: Confidence::Medium,
            },
        ];
        Self { rules }
    }

    /// First matching rule in a plain string, ignoring coordinates. Used by the
    /// base64 detector to identify what a decoded blob contains.
    fn probe(&self, s: &str) -> Option<(Category, &'static str, Confidence)> {
        self.rules
            .iter()
            .find(|rule| rule.re.is_match(s))
            .map(|rule| (rule.category, rule.label, rule.confidence))
    }
}

impl Detector for RuleDetector {
    fn id(&self) -> &str {
        "rule"
    }
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let s = view.text();
        let mut out = Vec::new();
        for rule in &self.rules {
            for m in rule.re.find_iter(s) {
                out.push(Span {
                    range: view.to_raw(ByteRange::new(m.start(), m.end())),
                    category: rule.category,
                    label: rule.label.to_string(),
                    confidence: rule.confidence,
                    source: format!("rule:{}", rule.label),
                });
            }
        }
        out
    }
}

/// Flags long, high-entropy codec-alphabet runs as likely opaque secrets.
pub struct EntropyDetector {
    min_len: usize,
    threshold: f64,
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self { min_len: 24, threshold: 3.2 }
    }
}

impl Detector for EntropyDetector {
    fn id(&self) -> &str {
        "entropy"
    }
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let bytes = view.text().as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if !is_token_byte(bytes[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && is_token_byte(bytes[i]) {
                i += 1;
            }
            let run = &bytes[start..i];
            if run.len() >= self.min_len && shannon(run) >= self.threshold {
                out.push(Span {
                    range: view.to_raw(ByteRange::new(start, i)),
                    category: Category::Secret,
                    label: "LIKELY_SECRET".to_string(),
                    confidence: Confidence::Low,
                    source: "entropy".to_string(),
                });
            }
        }
        out
    }
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

const MIN_B64_RUN: usize = 16;

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(s)
        .ok()
        .or_else(|| URL_SAFE.decode(s).ok())
        .or_else(|| STANDARD_NO_PAD.decode(s).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(s).ok())
}

/// Decodes base64-ish runs and, if the decoded content (possibly nested) matches
/// a known rule, masks the whole encoded blob under that label. The blob is
/// masked whole because a partial replacement could not be re-encoded.
pub struct Base64Detector {
    rules: RuleDetector,
    max_depth: u8,
}

impl Base64Detector {
    pub fn builtin() -> Self {
        Self { rules: RuleDetector::builtin(), max_depth: 3 }
    }

    fn probe(&self, run: &str, depth: u8) -> Option<(Category, String, Confidence)> {
        let decoded = b64_decode(run)?;
        let text = std::str::from_utf8(&decoded).ok()?;
        if let Some((cat, label, conf)) = self.rules.probe(text) {
            return Some((cat, label.to_string(), conf));
        }
        if depth > 0 {
            let bytes = text.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if !is_token_byte(bytes[i]) {
                    i += 1;
                    continue;
                }
                let start = i;
                while i < bytes.len() && is_token_byte(bytes[i]) {
                    i += 1;
                }
                if i - start >= MIN_B64_RUN {
                    if let Some(hit) = self.probe(&text[start..i], depth - 1) {
                        return Some(hit);
                    }
                }
            }
        }
        None
    }
}

impl Detector for Base64Detector {
    fn id(&self) -> &str {
        "base64_unwrap"
    }
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let s = view.text();
        let bytes = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if !is_token_byte(bytes[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && is_token_byte(bytes[i]) {
                i += 1;
            }
            if i - start >= MIN_B64_RUN {
                if let Some((cat, label, conf)) = self.probe(&s[start..i], self.max_depth) {
                    out.push(Span {
                        range: view.to_raw(ByteRange::new(start, i)),
                        category: cat,
                        label,
                        confidence: conf,
                        source: "base64_unwrap".to_string(),
                    });
                }
            }
        }
        out
    }
}

const SENSITIVE_KEY_TOKENS: &[&str] = &[
    "password", "passwd", "pwd", "secret", "token", "auth", "authorization",
    "credential", "cred", "key", "apikey", "session", "sid", "signature", "nonce",
    "bearer", "passphrase", "otp", "pin", "jwt",
];

/// Masks a value when its key looks sensitive, regardless of the value's shape.
/// Relies only on `Context.key`, so it works without NER even in WASM builds.
pub struct SuspiciousKeyDetector;

impl Detector for SuspiciousKeyDetector {
    fn id(&self) -> &str {
        "suspicious_key"
    }
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let region = view.region;
        let Some(k) = &region.ctx.key else { return vec![] };
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
                source: "suspicious_key".to_string(),
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
