use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Pre-keyed HMAC template. Rendering clones the initialized SHA-256 state for
/// each distinct value, avoiding key setup in the per-placeholder hot path.
pub(crate) struct IdentityHasher(HmacSha256);

impl IdentityHasher {
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        Self(HmacSha256::new_from_slice(key).expect("HMAC accepts any key length"))
    }

    pub(crate) fn hash(&self, n_id_value: &str) -> String {
        let mut mac = self.0.clone();
        mac.update(n_id_value.as_bytes());
        encode_hash(mac.finalize().into_bytes().as_slice())
    }
}

/// Hash width in hex chars. Fixed (not collision-adaptive) so it stays a pure
/// function of (key, value), independent of scan order.
pub const HASH_HEX_WIDTH: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaceholderParts {
    pub handle: String,
    pub label: String,
    pub hash: String,
    pub length_hint: Option<LengthHint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LengthHint {
    ExactChars(u32),
    AtLeastChars(u32),
    LegacyLen(u32),
}

impl LengthHint {
    pub fn chars(self) -> u32 {
        match self {
            LengthHint::ExactChars(n) | LengthHint::AtLeastChars(n) | LengthHint::LegacyLen(n) => n,
        }
    }

    pub fn short(self) -> String {
        match self {
            LengthHint::ExactChars(n) => n.to_string(),
            LengthHint::AtLeastChars(n) => format!("{n}+"),
            LengthHint::LegacyLen(n) => n.to_string(),
        }
    }
}

/// Keyed so the cloud side cannot dictionary-attack low-entropy values such as
/// emails, names, or "admin"; an unkeyed digest would be a reversible commitment.
pub fn identity_hash(key: &[u8; 32], n_id_value: &str) -> String {
    IdentityHasher::new(key).hash(n_id_value)
}

fn encode_hash(out: &[u8]) -> String {
    let mut s = String::with_capacity(HASH_HEX_WIDTH);
    for b in out.iter().take(HASH_HEX_WIDTH / 2) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// `<<LABEL_HASH>>`, or `<<LABEL_HASH_length_N_chars>>` when exact length is
/// disclosed. The suffix is deliberately verbose: it is still made of
/// shell/env-safe identifier characters, but an AI can read it without learning
/// a project-specific abbreviation.
pub fn render_placeholder(label: &str, hash: &str, char_len: Option<u32>) -> String {
    match char_len {
        Some(n) => format!("<<{label}_{hash}_length_{n}_chars>>"),
        None => format!("<<{label}_{hash}>>"),
    }
}

pub fn parse_placeholder(value: &str) -> Result<PlaceholderParts, String> {
    let raw = value.trim();
    if raw.is_empty() {
        return Err("placeholder is empty".to_string());
    }
    let inner = raw
        .strip_prefix("<<")
        .and_then(|v| v.strip_suffix(">>"))
        .unwrap_or(raw)
        .strip_prefix("PENTECT_")
        .unwrap_or_else(|| {
            raw.strip_prefix("<<")
                .and_then(|v| v.strip_suffix(">>"))
                .unwrap_or(raw)
        });
    let (core, length_hint) = split_length_hint(inner)?;
    let Some((label, hash)) = core.rsplit_once('_') else {
        return Err("placeholder must look like <<LABEL_hash>>".to_string());
    };
    validate_label(label)?;
    validate_hash(hash)?;
    Ok(PlaceholderParts {
        handle: format!("<<{inner}>>"),
        label: label.to_string(),
        hash: hash.to_string(),
        length_hint,
    })
}

fn split_length_hint(inner: &str) -> Result<(&str, Option<LengthHint>), String> {
    if let Some((prefix, suffix)) = inner.rsplit_once("_length_at_least_") {
        let Some(raw_n) = suffix.strip_suffix("_chars") else {
            return Err("placeholder length hint is malformed".to_string());
        };
        return Ok((prefix, Some(LengthHint::AtLeastChars(parse_u32(raw_n)?))));
    }
    if let Some((prefix, suffix)) = inner.rsplit_once("_length_") {
        let Some(raw_n) = suffix.strip_suffix("_chars") else {
            return Err("placeholder length hint is malformed".to_string());
        };
        return Ok((prefix, Some(LengthHint::ExactChars(parse_u32(raw_n)?))));
    }
    if let Some((prefix, raw_n)) = inner.rsplit_once("_len") {
        if !raw_n.is_empty() && raw_n.bytes().all(|b| b.is_ascii_digit()) {
            return Ok((prefix, Some(LengthHint::LegacyLen(parse_u32(raw_n)?))));
        }
    }
    Ok((inner, None))
}

fn validate_label(label: &str) -> Result<(), String> {
    let mut chars = label.chars();
    let Some(first) = chars.next() else {
        return Err("placeholder label is empty".to_string());
    };
    if !first.is_ascii_uppercase() {
        return Err("placeholder label must start with A-Z".to_string());
    }
    if !chars.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_') {
        return Err("placeholder label must use A-Z, 0-9, and underscore".to_string());
    }
    Ok(())
}

fn validate_hash(hash: &str) -> Result<(), String> {
    if hash.len() != HASH_HEX_WIDTH || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "placeholder hash must be {HASH_HEX_WIDTH} lowercase hex chars"
        ));
    }
    if !hash
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "placeholder hash must be {HASH_HEX_WIDTH} lowercase hex chars"
        ));
    }
    Ok(())
}

fn parse_u32(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| "placeholder length hint is malformed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_value_dependent() {
        let key = [3u8; 32];
        assert_eq!(identity_hash(&key, "alice"), identity_hash(&key, "alice"));
        assert_ne!(identity_hash(&key, "alice"), identity_hash(&key, "bob"));
        assert_eq!(identity_hash(&key, "alice").len(), HASH_HEX_WIDTH);
    }

    #[test]
    fn hash_depends_on_key() {
        assert_ne!(
            identity_hash(&[1u8; 32], "x"),
            identity_hash(&[2u8; 32], "x")
        );
    }

    #[test]
    fn placeholder_format() {
        assert_eq!(
            render_placeholder("AWS_AKID", "abc", None),
            "<<AWS_AKID_abc>>"
        );
        assert_eq!(
            render_placeholder("X", "abc", Some(24)),
            "<<X_abc_length_24_chars>>"
        );
    }

    #[test]
    fn placeholder_parse_splits_public_parts_without_recovery() {
        let parts =
            parse_placeholder("<<OPENAI_API_KEY_0123456789abcdef_length_64_chars>>").unwrap();
        assert_eq!(parts.label, "OPENAI_API_KEY");
        assert_eq!(parts.hash, "0123456789abcdef");
        assert_eq!(parts.length_hint, Some(LengthHint::ExactChars(64)));
        assert_eq!(
            parts.handle,
            "<<OPENAI_API_KEY_0123456789abcdef_length_64_chars>>"
        );

        let old = parse_placeholder("<<OPENAI_API_KEY_0123456789abcdef_length_at_least_64_chars>>")
            .unwrap();
        assert_eq!(old.length_hint, Some(LengthHint::AtLeastChars(64)));

        let env = parse_placeholder("PENTECT_TOKEN_0123456789abcdef_len24").unwrap();
        assert_eq!(env.label, "TOKEN");
        assert_eq!(env.hash, "0123456789abcdef");
        assert_eq!(env.length_hint, Some(LengthHint::LegacyLen(24)));
    }

    #[test]
    fn placeholder_parse_rejects_malformed_handles() {
        assert!(parse_placeholder("<<openai_0123456789abcdef>>").is_err());
        assert!(parse_placeholder("<<OPENAI_0123456789ABCDEf>>").is_err());
        assert!(parse_placeholder("OPENAI_short").is_err());
        assert!(parse_placeholder("<<OPENAI_0123456789abcdef_length_x_chars>>").is_err());
        assert!(parse_placeholder("<<OPENAI_0123456789abcdef_length_at_least_x_chars>>").is_err());
    }
}
