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

/// `<<LABEL_HASH>>`, or `<<LABEL_HASH_~BUCKET>>` when a length bucket is given.
pub fn render_placeholder(label: &str, hash: &str, length_bucket: Option<&str>) -> String {
    match length_bucket {
        Some(b) => format!("<<{label}_{hash}_~{b}>>"),
        None => format!("<<{label}_{hash}>>"),
    }
}

/// Coarse, opt-in length bucket for opaque blobs. Nothing is disclosed below the
/// floor, and exact length is never revealed.
pub fn length_bucket(char_len: usize) -> Option<&'static str> {
    match char_len {
        0..=23 => None,
        24..=63 => Some("med"),
        64..=511 => Some("long"),
        _ => Some("xlong"),
    }
}
