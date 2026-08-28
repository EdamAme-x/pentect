use data_encoding::{
    BASE32, BASE32HEX, BASE32HEX_NOPAD, BASE32_NOPAD, BASE64, BASE64URL, BASE64URL_NOPAD,
    BASE64_NOPAD, HEXLOWER_PERMISSIVE,
};
use std::borrow::Cow;

/// Decodes a contiguous encoded blob to bytes, or None if the run isn't valid in
/// this encoding. Injected into the decode detector so new encodings are added
/// without touching the detector.
pub trait Codec: Send + Sync {
    fn decode(&self, run: &str) -> Option<Vec<u8>>;
}

pub struct Base64Codec;

impl Codec for Base64Codec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        let compact = compact_ascii_whitespace(run);
        if !plausible_base64(compact.as_bytes()) {
            return None;
        }
        let b = compact.as_bytes();
        BASE64
            .decode(b)
            .ok()
            .or_else(|| BASE64URL.decode(b).ok())
            .or_else(|| BASE64_NOPAD.decode(b).ok())
            .or_else(|| BASE64URL_NOPAD.decode(b).ok())
    }
}

fn compact_ascii_whitespace(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        Cow::Owned(
            value
                .chars()
                .filter(|ch| !ch.is_ascii_whitespace())
                .collect(),
        )
    } else {
        Cow::Borrowed(value)
    }
}

pub struct Base32Codec;

impl Codec for Base32Codec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        if !plausible_base32(run.as_bytes()) {
            return None;
        }
        // RFC 4648 encoders conventionally emit uppercase, but decoders commonly
        // accept lowercase. Normalize only for decoding; source ranges are kept.
        let normalized;
        let b = if run.bytes().any(|byte| byte.is_ascii_lowercase()) {
            normalized = run.to_ascii_uppercase();
            normalized.as_bytes()
        } else {
            run.as_bytes()
        };
        BASE32
            .decode(b)
            .ok()
            .or_else(|| BASE32_NOPAD.decode(b).ok())
    }
}

/// RFC 4648's extended-hex Base32 alphabet. It is separate from Base32 because
/// an alphanumeric run can be valid under both alphabets and must be tried under
/// both interpretations before it is declared harmless.
pub struct Base32HexCodec;

impl Codec for Base32HexCodec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        if !plausible_base32hex(run.as_bytes()) {
            return None;
        }
        let normalized;
        let b = if run.bytes().any(|byte| byte.is_ascii_lowercase()) {
            normalized = run.to_ascii_uppercase();
            normalized.as_bytes()
        } else {
            run.as_bytes()
        };
        BASE32HEX
            .decode(b)
            .ok()
            .or_else(|| BASE32HEX_NOPAD.decode(b).ok())
    }
}

pub struct HexCodec;

impl Codec for HexCodec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        let run = run
            .strip_prefix("0x")
            .or_else(|| run.strip_prefix("0X"))
            .unwrap_or(run);
        let b = run.as_bytes();
        if !b.len().is_multiple_of(2) || !b.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        HEXLOWER_PERMISSIVE.decode(run.as_bytes()).ok()
    }
}

/// An RFC 3986 percent-encoded byte sequence. Unescaped bytes pass through, as
/// standard URL encoders preserve unreserved characters. At least one complete
/// escape is required so ordinary tokens are not treated as encoded input.
pub struct PercentCodec;

impl Codec for PercentCodec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        let bytes = run.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut cursor = 0;
        let mut escaped = false;
        while cursor < bytes.len() {
            if bytes[cursor] == b'%' {
                let high = hex_nibble(*bytes.get(cursor + 1)?)?;
                let low = hex_nibble(*bytes.get(cursor + 2)?)?;
                out.push((high << 4) | low);
                cursor += 3;
                escaped = true;
            } else {
                out.push(bytes[cursor]);
                cursor += 1;
            }
        }
        escaped.then_some(out)
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Byte-oriented binary representation: one eight-bit group per decoded byte.
pub struct BinaryCodec;

impl Codec for BinaryCodec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        let bytes = run.as_bytes();
        if bytes.is_empty()
            || !bytes.len().is_multiple_of(8)
            || !bytes.iter().all(|byte| matches!(byte, b'0' | b'1'))
        {
            return None;
        }
        bytes
            .chunks_exact(8)
            .map(|chunk| {
                chunk.iter().try_fold(0u8, |value, byte| {
                    value.checked_mul(2)?.checked_add(u8::from(*byte == b'1'))
                })
            })
            .collect()
    }
}

/// Byte-oriented octal representation: one zero-padded three-digit group per
/// decoded byte. Values above 377 are rejected rather than truncated.
pub struct OctalCodec;

impl Codec for OctalCodec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        let bytes = run.as_bytes();
        if bytes.is_empty()
            || !bytes.len().is_multiple_of(3)
            || !bytes.iter().all(|byte| matches!(byte, b'0'..=b'7'))
        {
            return None;
        }
        bytes
            .chunks_exact(3)
            .map(|chunk| {
                let value = u16::from(chunk[0] - b'0') * 64
                    + u16::from(chunk[1] - b'0') * 8
                    + u16::from(chunk[2] - b'0');
                u8::try_from(value).ok()
            })
            .collect()
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

/// Adobe Ascii85, both `<~...~>` framed and raw form. Whitespace and the `z`
/// zero-block shorthand follow the published Ascii85 format used by PDF/PostScript.
pub struct Ascii85Codec;

impl Codec for Ascii85Codec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        let trimmed = run.trim();
        let body = if let Some(inner) = trimmed
            .strip_prefix("<~")
            .and_then(|value| value.strip_suffix("~>"))
        {
            inner
        } else {
            trimmed
        };
        let mut out = Vec::with_capacity(body.len().saturating_mul(4) / 5);
        let mut group = [0u8; 5];
        let mut group_len = 0usize;

        for byte in body.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
            if byte == b'z' {
                if group_len != 0 {
                    return None;
                }
                out.extend_from_slice(&[0; 4]);
                continue;
            }
            if !(b'!'..=b'u').contains(&byte) {
                return None;
            }
            group[group_len] = byte - b'!';
            group_len += 1;
            if group_len == 5 {
                append_ascii85_group(&mut out, &group, 4)?;
                group_len = 0;
            }
        }

        if group_len == 1 {
            return None;
        }
        if group_len > 1 {
            group[group_len..].fill(84);
            append_ascii85_group(&mut out, &group, group_len - 1)?;
        }
        (!out.is_empty()).then_some(out)
    }
}

pub(crate) const RFC1924_BASE85_ALPHABET: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
pub(crate) const Z85_ALPHABET: &[u8; 85] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
const RFC1924_BASE85_REVERSE: [u8; 128] = base85_reverse(RFC1924_BASE85_ALPHABET);
const Z85_REVERSE: [u8; 128] = base85_reverse(Z85_ALPHABET);

/// RFC 1924/Base85 as exposed by common standard libraries (for example
/// Python's `b85encode`). Unlike Adobe Ascii85 it has no framing or `z` shorthand.
pub struct Base85Codec;

impl Codec for Base85Codec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        decode_fixed_base85(run, &RFC1924_BASE85_REVERSE, true)
    }
}

/// ZeroMQ Z85. Z85 deliberately requires complete five-character groups.
pub struct Z85Codec;

impl Codec for Z85Codec {
    fn decode(&self, run: &str) -> Option<Vec<u8>> {
        decode_fixed_base85(run, &Z85_REVERSE, false)
    }
}

const fn base85_reverse(alphabet: &[u8; 85]) -> [u8; 128] {
    let mut reverse = [u8::MAX; 128];
    let mut value = 0usize;
    while value < alphabet.len() {
        reverse[alphabet[value] as usize] = value as u8;
        value += 1;
    }
    reverse
}

pub(crate) fn is_rfc1924_base85_byte(byte: u8) -> bool {
    byte.is_ascii() && RFC1924_BASE85_REVERSE[usize::from(byte)] != u8::MAX
}

pub(crate) fn is_z85_byte(byte: u8) -> bool {
    byte.is_ascii() && Z85_REVERSE[usize::from(byte)] != u8::MAX
}

fn decode_fixed_base85(run: &str, reverse: &[u8; 128], allow_partial: bool) -> Option<Vec<u8>> {
    let bytes = run.as_bytes();
    if bytes.is_empty() || (!allow_partial && !bytes.len().is_multiple_of(5)) {
        return None;
    }
    let remainder = bytes.len() % 5;
    if remainder == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len().div_ceil(5) * 4);
    for chunk in bytes.chunks(5) {
        let mut group = [84u8; 5];
        for (index, &byte) in chunk.iter().enumerate() {
            if !byte.is_ascii() || reverse[usize::from(byte)] == u8::MAX {
                return None;
            }
            group[index] = reverse[usize::from(byte)];
        }
        append_ascii85_group(&mut out, &group, chunk.len().saturating_sub(1).min(4))?;
    }
    Some(out)
}

fn append_ascii85_group(out: &mut Vec<u8>, group: &[u8; 5], bytes: usize) -> Option<()> {
    let value = group.iter().try_fold(0u64, |value, digit| {
        value.checked_mul(85)?.checked_add(u64::from(*digit))
    })?;
    let value = u32::try_from(value).ok()?;
    out.extend_from_slice(&value.to_be_bytes()[..bytes]);
    Some(())
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
            b'A'..=b'Z' | b'a'..=b'z' | b'2'..=b'7' if !padding => {}
            b'=' => padding = true,
            _ => return false,
        }
    }
    true
}

fn plausible_base32hex(bytes: &[u8]) -> bool {
    let mut padding = false;
    for &b in bytes {
        match b {
            b'0'..=b'9' | b'A'..=b'V' | b'a'..=b'v' if !padding => {}
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

    #[test]
    fn base64_accepts_standard_url_and_padding_variants() {
        let value = [0xfb, 0xff, 0x00, 0x41];
        for encoded in [
            BASE64.encode(&value),
            BASE64_NOPAD.encode(&value),
            BASE64URL.encode(&value),
            BASE64URL_NOPAD.encode(&value),
        ] {
            assert_eq!(Base64Codec.decode(&encoded), Some(value.to_vec()));
        }
    }

    #[test]
    fn base32_accepts_lowercase_and_extended_hex() {
        let value = b"AKIAIOSFODNN7EXAMPLE";
        assert_eq!(
            Base32Codec.decode(&BASE32.encode(value).to_ascii_lowercase()),
            Some(value.to_vec())
        );
        assert_eq!(
            Base32HexCodec.decode(&BASE32HEX_NOPAD.encode(value)),
            Some(value.to_vec())
        );
    }

    #[test]
    fn hex_accepts_conventional_prefix() {
        assert_eq!(HexCodec.decode("0x414b4941"), Some(b"AKIA".to_vec()));
    }

    #[test]
    fn binary_and_octal_decode_byte_groups() {
        assert_eq!(BinaryCodec.decode("0100000101001011"), Some(b"AK".to_vec()));
        assert_eq!(OctalCodec.decode("101113"), Some(b"AK".to_vec()));
        assert_eq!(OctalCodec.decode("777"), None);
    }

    #[test]
    fn ascii85_decodes_framed_and_raw_payloads() {
        // The first group from Adobe's canonical "Man is distinguished" example.
        let encoded = "9jqo^";
        assert_eq!(Ascii85Codec.decode(encoded), Some(b"Man ".to_vec()));
        assert_eq!(
            Ascii85Codec.decode(&format!("<~{encoded}~>")),
            Some(b"Man ".to_vec())
        );
    }

    #[test]
    fn base85_decodes_rfc1924_and_z85() {
        assert_eq!(
            Base85Codec.decode("K}$(NNl#NoPee{mH$_-MO;Ail"),
            Some(b"AKIAIOSFODNN7EXAMPLE".to_vec())
        );
        // Z85's specification example.
        assert_eq!(
            Z85Codec.decode("HelloWorld"),
            Some(vec![0x86, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b])
        );
    }
}
