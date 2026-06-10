//! Placeholder 形式と keyed hash（REF.md §11）。

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// 既定の hash 幅（hex 文字数）= 16 → 64-bit（REF.md §11.1, §11.4）。
/// 固定幅: `(key, n_id(value))` の純粋関数で、co-occurrence / scan 順に依存しない。
pub const HASH_HEX_WIDTH: usize = 16;

/// 同一性ハッシュ（REF.md §11.2）: `HMAC-SHA256(key, n_id(value))[:HASH_HEX_WIDTH]`。
///
/// **必ず keyed**。unkeyed `SHA256(value)` は低エントロピー値（email/名前/'admin'）を
/// クラウドが辞書攻撃で復元できる隠れ漏洩になる（辞書攻撃は脅威モデル内, REF.md §3.1）。
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

/// `<<LABEL_HHHH...>>`（REF.md §11.1）。
pub fn render_placeholder(label: &str, hash: &str) -> String {
    format!("<<{}_{}>>", label, hash)
}
