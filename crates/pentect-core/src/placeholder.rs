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

/// `<<LABEL_HASH>>`, or `<<LABEL_HASH_lenN>>` when an approximate length is given.
/// `lenN` is self-describing so a model reads it as "about N characters".
pub fn render_placeholder(label: &str, hash: &str, approx_len: Option<u32>) -> String {
    match approx_len {
        Some(n) => format!("<<{label}_{hash}_len{n}>>"),
        None => format!("<<{label}_{hash}>>"),
    }
}

/// Approximate character length for opaque blobs, opt-in. Rounded to a coarse
/// step so it reads naturally but never reveals the exact length; below the
/// floor nothing is disclosed.
pub fn approx_length(char_len: usize) -> Option<u32> {
    const FLOOR: usize = 24;
    const STEP: usize = 8;
    if char_len < FLOOR {
        return None;
    }
    Some(((char_len + STEP / 2) / STEP * STEP) as u32)
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
        assert_eq!(render_placeholder("X", "abc", Some(32)), "<<X_abc_len32>>");
    }

    #[test]
    fn approx_length_floor_and_rounding() {
        assert_eq!(approx_length(20), None); // below floor
        assert_eq!(approx_length(29), Some(32)); // rounded to step
    }
}
