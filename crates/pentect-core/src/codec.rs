use data_encoding::{
    BASE32, BASE32_NOPAD, BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD, HEXLOWER_PERMISSIVE,
};

/// Decodes a contiguous encoded blob to bytes, or None if the run isn't valid in
/// this encoding. Injected into the decode detector so new encodings are added
/// without touching the detector.
pub trait Codec {
    fn name(&self) -> &str;
    fn decode(&self, run: &str) -> Option<Vec<u8>>;
}

pub struct Base64Codec;

impl Codec for Base64Codec {
    fn name(&self) -> &str {
        "base64"
    }
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
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
    fn name(&self) -> &str {
        "base32"
    }
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        let b = run.as_bytes();
        BASE32
            .decode(b)
            .ok()
            .or_else(|| BASE32_NOPAD.decode(b).ok())
    }
}

pub struct HexCodec;

impl Codec for HexCodec {
    fn name(&self) -> &str {
        "hex"
    }
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        HEXLOWER_PERMISSIVE.decode(run.as_bytes()).ok()
    }
}

pub struct Base58Codec;

impl Codec for Base58Codec {
    fn name(&self) -> &str {
        "base58"
    }
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        bs58::decode(run).into_vec().ok()
    }
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
