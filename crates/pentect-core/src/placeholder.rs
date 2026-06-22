use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Hash width in hex chars. Fixed (not collision-adaptive) so it stays a pure
/// function of (key, value), independent of scan order.
pub const HASH_HEX_WIDTH: usize = 16;

/// Keyed so the cloud side cannot dictionary-attack low-entropy values such as
/// emails, names, or "admin"; an unkeyed digest would be a reversible commitment.
pub fn identity_hash(key: &[u8; 32], n_id_value: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(n_id_value.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut s = String::with_capacity(HASH_HEX_WIDTH);
    for b in out.iter().take(HASH_HEX_WIDTH / 2) {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Length buckets for opt-in disclosure. Three fixed floors so only three values
/// are ever emitted and the exact length is never revealed.
const BUCKET_MED: usize = 24;
const BUCKET_LONG: usize = 64;
const BUCKET_XLONG: usize = 512;

/// `<<LABEL_HASH>>`, or `<<LABEL_HASH_length_at_least_N_chars>>` when a length
/// bucket is given. The suffix is deliberately verbose: it is still made of
/// shell/env-safe identifier characters, but an AI can read the meaning without
/// learning a project-specific abbreviation.
pub fn render_placeholder(label: &str, hash: &str, bucket: Option<u32>) -> String {
    match bucket {
        Some(n) => format!("<<{label}_{hash}_length_at_least_{n}_chars>>"),
        None => format!("<<{label}_{hash}>>"),
    }
}

/// Coarse length bucket for opaque blobs, opt-in. Returns the floor of one of
/// three buckets (24/64/512), so the value reads as "at least N chars" but the
/// exact length never leaks (only three possible outputs). Below BUCKET_MED
/// nothing is disclosed. Emits the legible floor (not ~med/~long) so a model
/// understands it.
pub fn approx_length(char_len: usize) -> Option<u32> {
    match char_len {
        n if n >= BUCKET_XLONG => Some(BUCKET_XLONG as u32),
        n if n >= BUCKET_LONG => Some(BUCKET_LONG as u32),
        n if n >= BUCKET_MED => Some(BUCKET_MED as u32),
        _ => None,
    }
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
            "<<X_abc_length_at_least_24_chars>>"
        );
    }

    #[test]
    fn approx_length_is_three_coarse_buckets() {
        assert_eq!(approx_length(23), None);
        assert_eq!(approx_length(24), Some(24));
        assert_eq!(approx_length(63), Some(24));
        assert_eq!(approx_length(64), Some(64));
        assert_eq!(approx_length(511), Some(64));
        assert_eq!(approx_length(512), Some(512));
    }
}
