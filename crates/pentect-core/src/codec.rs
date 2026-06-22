use data_encoding::{
    BASE32, BASE32_NOPAD, BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD, HEXLOWER_PERMISSIVE,
};

/// Decodes a contiguous encoded blob to bytes, or None if the run isn't valid in
/// this encoding. Injected into the decode detector so new encodings are added
/// without touching the detector.
pub trait Codec {
    fn decode(&self, run: &str) -> Option<Vec<u8>>;
}

pub struct Base64Codec;

impl Codec for Base64Codec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        if !plausible_base64(run.as_bytes()) {
            return None;
        }
        let b = run.as_bytes();
        BASE64
            .decode(b)
            .ok()
            .or_else(|| BASE64URL.decode(b).ok())
            .or_else(|| BASE64_NOPAD.decode(b).ok())
            .or_else(|| BASE64URL_NOPAD.decode(b).ok())
    }
}

pub struct Base32Codec;

impl Codec for Base32Codec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        if !plausible_base32(run.as_bytes()) {
            return None;
        }
        let b = run.as_bytes();
        BASE32
            .decode(b)
            .ok()
            .or_else(|| BASE32_NOPAD.decode(b).ok())
    }
}

pub struct HexCodec;

impl Codec for HexCodec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        let b = run.as_bytes();
        if !b.len().is_multiple_of(2) || !b.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        HEXLOWER_PERMISSIVE.decode(run.as_bytes()).ok()
    }
}

pub struct Base58Codec;

impl Codec for Base58Codec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        if !run.as_bytes().iter().all(|&b| {
            matches!(
                b,
                b'1'..=b'9'
                    | b'A'..=b'H'
                    | b'J'..=b'N'
                    | b'P'..=b'Z'
                    | b'a'..=b'k'
                    | b'm'..=b'z'
            )
        }) {
            return None;
        }
        bs58::decode(run).into_vec().ok()
    }
}

fn plausible_base64(bytes: &[u8]) -> bool {
    // Both padded and unpadded variants are supported; length mod 4 == 1 cannot
    // be valid base64 in either form.
    if bytes.len() % 4 == 1 {
        return false;
    }
    let mut padding = false;
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'-' | b'_' if !padding => {}
            b'=' => padding = true,
            _ => return false,
        }
    }
    true
}

fn plausible_base32(bytes: &[u8]) -> bool {
    let mut padding = false;
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'2'..=b'7' if !padding => {}
            b'=' => padding = true,
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codecs_round_trip_ascii() {
        let v = b"AKIAIOSFODNN7EXAMPLE".to_vec();
        assert_eq!(Base64Codec.decode(&BASE64.encode(&v)), Some(v.clone()));
        assert_eq!(Base32Codec.decode(&BASE32.encode(&v)), Some(v.clone()));
        assert_eq!(
            HexCodec.decode(&HEXLOWER_PERMISSIVE.encode(&v)),
            Some(v.clone())
        );
        assert_eq!(Base58Codec.decode(&bs58::encode(&v).into_string()), Some(v));
    }
}
