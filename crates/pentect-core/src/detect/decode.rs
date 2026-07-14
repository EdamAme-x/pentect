use super::util::token_runs;
use super::{AuthCodeDetector, Bip39Detector, Detector, RuleDetector};
use crate::codec::{
    is_rfc1924_base85_byte, is_z85_byte, Ascii85Codec, Base32Codec, Base32HexCodec, Base58Codec,
    Base64Codec, Base85Codec, BinaryCodec, Codec, HexCodec, OctalCodec, Z85Codec,
};
use crate::model::*;
use crate::normalize::NormalizedView;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use std::io::Read;

pub const DEFAULT_MIN_DECODE_BYTES: usize = 16;
pub const DEFAULT_MAX_DECODE_BYTES: usize = 256 * 1024;
pub const DEFAULT_DECODE_DEPTH: usize = 3;
/// Default minimum run length for the opaque-blob ("looks encrypted") path; kept
/// above MIN_DECODE_RUN so short decodable strings don't get masked as ciphertext.
pub const DEFAULT_MIN_OPAQUE_RUN: usize = 24;
pub const DEFAULT_MAX_INFLATE_BYTES: u64 = 8 * 1024 * 1024;
/// Fraction of C0 control bytes above which decoded text is treated as binary.
const BINARY_NONPRINT_RATIO: f64 = 0.3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeConfig {
    pub enabled: bool,
    /// `None` means unlimited. A numeric value counts codec and decompression
    /// transforms exactly, so `Some(3)` permits three transforms.
    pub max_depth: Option<usize>,
    pub min_bytes: usize,
    /// `None` means unlimited.
    pub max_bytes: Option<usize>,
    /// `None` means unlimited.
    pub max_inflate_bytes: Option<u64>,
    pub mask_unknown: bool,
    pub unknown_min_bytes: usize,
}

impl Default for DecodeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: Some(DEFAULT_DECODE_DEPTH),
            min_bytes: DEFAULT_MIN_DECODE_BYTES,
            max_bytes: Some(DEFAULT_MAX_DECODE_BYTES),
            max_inflate_bytes: Some(DEFAULT_MAX_INFLATE_BYTES),
            mask_unknown: false,
            unknown_min_bytes: DEFAULT_MIN_OPAQUE_RUN,
        }
    }
}

impl DecodeConfig {
    pub fn validate(self) -> Result<Self, String> {
        if self.enabled && self.max_depth == Some(0) {
            return Err("decode.max_depth must be positive or unlimited".to_string());
        }
        if self.min_bytes == 0 {
            return Err("decode.min_bytes must be positive".to_string());
        }
        if self.max_bytes.is_some_and(|max| max < self.min_bytes) {
            return Err("decode.max_bytes must be at least decode.min_bytes".to_string());
        }
        if self.max_inflate_bytes == Some(0) {
            return Err("decode.max_inflate_bytes must be positive or unlimited".to_string());
        }
        if self.mask_unknown && self.unknown_min_bytes < self.min_bytes {
            return Err("decode.unknown_min_bytes must be at least decode.min_bytes".to_string());
        }
        Ok(self)
    }
}

/// Tries injected codecs on each encoded-looking run; if the decoded content
/// (possibly nested) is identified by an injected detector, masks the whole
/// encoded blob under that label. The blob is masked whole because a partial
/// replacement could not be re-encoded. Codec- and detector-agnostic via DI.
pub struct DecodeDetector {
    codecs: Vec<Box<dyn Codec>>,
    identify: Vec<Box<dyn Detector>>,
    config: DecodeConfig,
}

impl DecodeDetector {
    pub fn new(
        codecs: Vec<Box<dyn Codec>>,
        identify: Vec<Box<dyn Detector>>,
        config: DecodeConfig,
    ) -> Self {
        Self {
            codecs,
            identify,
            config,
        }
    }

    pub fn builtin() -> Self {
        Self::builtin_with_config(DecodeConfig::default())
    }

    pub fn builtin_with_config(config: DecodeConfig) -> Self {
        Self::new(
            vec![
                Box::new(BinaryCodec),
                Box::new(OctalCodec),
                Box::new(HexCodec),
                Box::new(Base32Codec),
                Box::new(Base32HexCodec),
                Box::new(Base64Codec),
                Box::new(Base58Codec),
                Box::new(Ascii85Codec),
                Box::new(Base85Codec),
                Box::new(Z85Codec),
            ],
            vec![
                Box::new(RuleDetector::builtin()),
                Box::new(AuthCodeDetector),
                Box::new(Bip39Detector),
            ],
            config,
        )
    }

    pub fn with_opaque(mut self, mask_unknown: bool, min_run: usize) -> Self {
        self.config.mask_unknown = mask_unknown;
        self.config.unknown_min_bytes = min_run.max(self.config.min_bytes);
        self
    }

    /// True if some codec decodes the run into binary-looking bytes (a strong
    /// "this is ciphertext" signal, distinct from raw entropy).
    fn decodes_to_binary(&self, run: &str) -> bool {
        self.codecs
            .iter()
            .any(|c| c.decode(run).is_some_and(|b| looks_binary(&b)))
    }

    fn probe(
        &self,
        run: &str,
        remaining_depth: Option<usize>,
    ) -> Option<(Category, String, Confidence)> {
        let after_decode = consume_depth(remaining_depth)?;
        for codec in &self.codecs {
            if let Some(bytes) = codec.decode(run) {
                if let Some(hit) = self.scan_bytes(&bytes, after_decode) {
                    return Some(hit);
                }
            }
        }
        None
    }

    fn scan_bytes(
        &self,
        bytes: &[u8],
        remaining_depth: Option<usize>,
    ) -> Option<(Category, String, Confidence)> {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                if let Some(hit) = self.identify(text) {
                    return Some(hit);
                }
                if remaining_depth != Some(0) {
                    for (a, b) in token_runs(text) {
                        if self.accepts_run(b - a) {
                            if let Some(hit) = self.probe(&text[a..b], remaining_depth) {
                                return Some(hit);
                            }
                        }
                    }
                    for (a, b) in encoded85_runs(text, self.config.min_bytes) {
                        if self.accepts_run(b - a) {
                            if let Some(hit) =
                                self.probe_assignment_aware(&text[a..b], remaining_depth)
                            {
                                return Some(hit.0);
                            }
                        }
                    }
                    for (a, b) in wrapped_base64_runs(text, self.config.min_bytes) {
                        if self.accepts_run(b - a) {
                            if let Some(hit) = self.probe(&text[a..b], remaining_depth) {
                                return Some(hit);
                            }
                        }
                    }
                }
            }
            // Binary bytes might be compressed (e.g. SAML's base64(deflate(..))).
            Err(_) if remaining_depth != Some(0) => {
                let after_decompress = consume_depth(remaining_depth)?;
                if let Some(inflated) = decompress(bytes, self.config.max_inflate_bytes) {
                    return self.scan_bytes(&inflated, after_decompress);
                }
            }
            Err(_) => {}
        }
        None
    }

    fn identify(&self, text: &str) -> Option<(Category, String, Confidence)> {
        if looks_like_env_secret_text(text) {
            return Some((
                Category::Secret,
                labels::SECRET.to_string(),
                Confidence::High,
            ));
        }
        let region = Region {
            span: ByteRange::new(0, text.len()),
            ctx: Context {
                path: None,
                key: None,
                hints: Vec::new(),
                kind: RegionKind::PlainText,
                format: Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, text);
        let mut best: Option<Span> = None;
        for d in &self.identify {
            for span in d.detect(&view) {
                if best.as_ref().is_none_or(|b| span.cmp_strength(b).is_gt()) {
                    best = Some(span);
                }
            }
        }
        best.map(|s| (s.category, s.label, s.confidence))
    }

    fn probe_assignment_aware(
        &self,
        run: &str,
        remaining_depth: Option<usize>,
    ) -> Option<((Category, String, Confidence), usize)> {
        if let Some(hit) = self.probe(run, remaining_depth) {
            return Some((hit, 0));
        }
        let (prefix, value) = run.split_once('=')?;
        if prefix.is_empty() || !self.accepts_run(value.len()) {
            return None;
        }
        self.probe(value, remaining_depth)
            .map(|hit| (hit, prefix.len() + 1))
    }

    fn accepts_run(&self, len: usize) -> bool {
        len >= self.config.min_bytes && self.config.max_bytes.is_none_or(|max| len <= max)
    }
}

fn consume_depth(remaining: Option<usize>) -> Option<Option<usize>> {
    match remaining {
        None => Some(None),
        Some(0) => None,
        Some(value) => Some(Some(value - 1)),
    }
}

fn looks_like_env_secret_text(text: &str) -> bool {
    let mut assignments = 0usize;
    let mut strong_key = false;
    for line in text.lines().take(256) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed
            .strip_prefix("export ")
            .unwrap_or(trimmed)
            .split_once('=')
        else {
            continue;
        };
        if key.is_empty()
            || value.is_empty()
            || !key
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
        {
            continue;
        }
        assignments += 1;
        let lower = key.to_ascii_lowercase();
        strong_key |= key.chars().any(|ch| ch.is_ascii_uppercase())
            || lower.contains("secret")
            || lower.contains("token")
            || lower.contains("password")
            || lower.contains("api_key")
            || lower.contains("apikey")
            || lower == "key";
    }
    assignments >= 2 && strong_key
}

impl Detector for DecodeDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        if !self.config.enabled {
            return Vec::new();
        }
        let s = view.text();
        let mut out = Vec::new();
        for (start, end) in token_runs(s) {
            if !self.accepts_run(end - start) {
                continue;
            }
            let run = &s[start..end];
            let mut pushed = false;
            if let Some(((cat, label, conf), relative_start)) =
                self.probe_assignment_aware(run, self.config.max_depth)
            {
                out.push(Span {
                    range: view.to_raw(ByteRange::new(start + relative_start, end)),
                    category: cat,
                    label,
                    confidence: conf,
                    source: DetectorId::Decode,
                });
                pushed = true;
            }
            if !pushed
                && self.config.mask_unknown
                && end - start >= self.config.unknown_min_bytes
                && self.decodes_to_binary(run)
            {
                out.push(Span {
                    range: view.to_raw(ByteRange::new(start, end)),
                    category: Category::Secret,
                    label: labels::OPAQUE_BLOB.to_string(),
                    confidence: Confidence::Low,
                    source: DetectorId::DecodeOpaque,
                });
            }
        }
        for (start, end) in encoded85_runs(s, self.config.min_bytes) {
            if !self.accepts_run(end - start) {
                continue;
            }
            if let Some(((category, label, confidence), relative_start)) =
                self.probe_assignment_aware(&s[start..end], self.config.max_depth)
            {
                out.push(Span {
                    range: view.to_raw(ByteRange::new(start + relative_start, end)),
                    category,
                    label,
                    confidence,
                    source: DetectorId::Decode,
                });
            }
        }
        for (start, end) in wrapped_base64_runs(s, self.config.min_bytes) {
            if !self.accepts_run(end - start) {
                continue;
            }
            if let Some((category, label, confidence)) =
                self.probe(&s[start..end], self.config.max_depth)
            {
                out.push(Span {
                    range: view.to_raw(ByteRange::new(start, end)),
                    category,
                    label,
                    confidence,
                    source: DetectorId::Decode,
                });
            }
        }
        out
    }
}

fn encoded85_runs(text: &str, min_bytes: usize) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut framed = Vec::new();
    let mut cursor = 0usize;
    while let Some(open) = text[cursor..].find("<~").map(|index| cursor + index) {
        let body = open + 2;
        let Some(close) = text[body..].find("~>").map(|index| body + index + 2) else {
            break;
        };
        if close - open >= min_bytes {
            framed.push((open, close));
        }
        cursor = close;
    }

    let mut runs = framed.clone();
    collect_quoted_base85_runs(bytes, min_bytes, &framed, &mut runs);
    collect_base85_runs(
        bytes,
        min_bytes,
        |byte| (b'!'..=b'u').contains(&byte),
        &framed,
        &mut runs,
    );
    collect_base85_runs(bytes, min_bytes, is_rfc1924_base85_byte, &framed, &mut runs);
    collect_base85_runs(bytes, min_bytes, is_z85_byte, &framed, &mut runs);
    runs.sort_unstable();
    runs.dedup();
    runs
}

fn collect_quoted_base85_runs(
    bytes: &[u8],
    min_bytes: usize,
    framed: &[(usize, usize)],
    runs: &mut Vec<(usize, usize)>,
) {
    let mut i = 0usize;
    while i < bytes.len() {
        if !matches!(bytes[i], b'\'' | b'"') {
            i += 1;
            continue;
        }
        let quote = bytes[i];
        let start = i + 1;
        i = start;
        while i < bytes.len() && bytes[i] != quote {
            if bytes[i] == b'\\' {
                i = (i + 2).min(bytes.len());
            } else {
                i += 1;
            }
        }
        let end = i;
        if end - start >= min_bytes
            && looks_like_base85_run(&bytes[start..end])
            && !framed
                .iter()
                .any(|&(frame_start, frame_end)| start >= frame_start && end <= frame_end)
        {
            runs.push((start, end));
        }
        i = (i + 1).min(bytes.len());
    }
}

fn looks_like_base85_run(bytes: &[u8]) -> bool {
    let punctuation = bytes
        .iter()
        .filter(|byte| !byte.is_ascii_alphanumeric())
        .count();
    punctuation >= 2
        && (bytes
            .iter()
            .copied()
            .all(|byte| (b'!'..=b'u').contains(&byte))
            || bytes.iter().copied().all(is_rfc1924_base85_byte)
            || bytes.iter().copied().all(is_z85_byte))
}

fn wrapped_base64_runs(text: &str, min_bytes: usize) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let mut block_start = None;
    let mut block_end = 0usize;
    let mut lines = 0usize;
    let mut offset = 0usize;

    for line in text.split_inclusive('\n') {
        let content = line.trim();
        let leading = line.len() - line.trim_start().len();
        let is_base64_line = content.len() >= min_bytes
            && content.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
            });
        if is_base64_line {
            block_start.get_or_insert(offset + leading);
            block_end = offset + leading + content.len();
            lines += 1;
        } else {
            if let Some(start) = block_start.take() {
                if lines >= 2 {
                    runs.push((start, block_end));
                }
            }
            lines = 0;
        }
        offset += line.len();
    }
    if let Some(start) = block_start {
        if lines >= 2 {
            runs.push((start, block_end));
        }
    }
    runs
}

fn collect_base85_runs(
    bytes: &[u8],
    min_bytes: usize,
    accepts: fn(u8) -> bool,
    framed: &[(usize, usize)],
    runs: &mut Vec<(usize, usize)>,
) {
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && !accepts(bytes[i]) {
            i += 1;
        }
        let start = i;
        let mut punctuation = 0usize;
        while i < bytes.len() && accepts(bytes[i]) {
            punctuation += usize::from(!bytes[i].is_ascii_alphanumeric());
            i += 1;
        }
        if i - start >= min_bytes
            && punctuation >= 2
            && !framed
                .iter()
                .any(|&(frame_start, frame_end)| start >= frame_start && i <= frame_end)
        {
            runs.push((start, i));
        }
    }
}

/// Decoded bytes look like ciphertext: not valid UTF-8, or more than
/// BINARY_NONPRINT_RATIO C0 control bytes (TAB/LF/VT/FF/CR excepted). High bytes
/// are not counted here — in valid UTF-8 they are legitimate multibyte text.
fn looks_binary(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if std::str::from_utf8(bytes).is_err() {
        return true;
    }
    let nonprint = bytes
        .iter()
        .filter(|&&b| b < 0x09 || (0x0e..0x20).contains(&b))
        .count();
    nonprint as f64 > bytes.len() as f64 * BINARY_NONPRINT_RATIO
}

fn decompress(data: &[u8], max_bytes: Option<u64>) -> Option<Vec<u8>> {
    if data.starts_with(&[0x1f, 0x8b]) {
        return inflate(GzDecoder::new(data), max_bytes);
    }
    if looks_like_zlib(data) {
        return inflate(ZlibDecoder::new(data), max_bytes);
    }
    // Raw DEFLATE has no reliable magic bytes. Trying it on every random decoded
    // hash is expensive, so only keep it as a fallback for payload-sized blobs.
    if data.len() >= 32 {
        return inflate(DeflateDecoder::new(data), max_bytes);
    }
    None
}

fn looks_like_zlib(data: &[u8]) -> bool {
    let Some((&cmf, &flg)) = data.first().zip(data.get(1)) else {
        return false;
    };
    // RFC 1950: compression method must be deflate (8), window <= 32K, and the
    // two-byte header is divisible by 31.
    cmf & 0x0f == 8 && (cmf >> 4) <= 7 && u16::from_be_bytes([cmf, flg]).is_multiple_of(31)
}

fn inflate<R: Read>(mut reader: R, max_bytes: Option<u64>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match max_bytes {
        Some(max_bytes) => reader.take(max_bytes).read_to_end(&mut out).ok()?,
        None => reader.read_to_end(&mut out).ok()?,
    };
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    #[test]
    fn opaque_blob_only_when_mask_unknown() {
        // base64 of binary-looking bytes; no inner secret to identify.
        let enc = data_encoding::BASE64.encode(&[
            0x00, 0xff, 0x1a, 0x2c, 0x9b, 0x4e, 0xd1, 0x77, 0x88, 0x33, 0xaa, 0x55, 0xc0, 0x0d,
        ]);
        let raw = format!("x {enc} y");
        let reg = region(&raw);
        let v = NormalizedView::build(&reg, &raw);
        assert!(
            DecodeDetector::builtin().detect(&v).is_empty(),
            "off by default"
        );
        let spans = DecodeDetector::builtin().with_opaque(true, 16).detect(&v);
        assert!(spans.iter().any(|s| s.label == "OPAQUE_BLOB"), "{spans:?}");
    }

    #[test]
    fn looks_binary_ratio_boundary() {
        // Valid UTF-8 with C0 control bytes either side of the 30% threshold.
        let below: Vec<u8> = std::iter::repeat_n(0x01, 7)
            .chain(std::iter::repeat_n(b'a', 17))
            .collect(); // 7/24 = 29%
        let above: Vec<u8> = std::iter::repeat_n(0x01, 8)
            .chain(std::iter::repeat_n(b'a', 16))
            .collect(); // 8/24 = 33%
        assert!(!looks_binary(&below));
        assert!(looks_binary(&above));
    }

    #[test]
    fn encoded_dotenv_blob_is_identified() {
        let raw = "RUNPOD_API_KEY=rpa_FAKEPENTECTJAILBREAK1234567890abcdef\nTEST_SECRET=114514810\nNOTE=hello world\n";
        let enc = data_encoding::BASE64.encode(raw.as_bytes());
        let sample = format!("blob={enc}");
        let spans =
            DecodeDetector::builtin().detect(&NormalizedView::build(&region(&sample), &sample));
        assert!(
            spans.iter().any(|span| span.label == labels::SECRET),
            "{spans:?}"
        );
    }

    #[test]
    fn encoded_seed_phrase_is_identified_by_dedicated_detector() {
        let raw = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let enc = data_encoding::BASE64.encode(raw.as_bytes());
        let sample = format!("blob={enc}");
        let spans =
            DecodeDetector::builtin().detect(&NormalizedView::build(&region(&sample), &sample));
        assert!(
            spans
                .iter()
                .any(|span| span.label == labels::BIP39_MNEMONIC),
            "{spans:?}"
        );
    }

    fn nested_base64(value: &str, layers: usize) -> String {
        (0..layers).fold(value.to_string(), |value, _| {
            data_encoding::BASE64.encode(value.as_bytes())
        })
    }

    fn detects_with_config(value: &str, config: DecodeConfig) -> bool {
        let reg = region(value);
        !DecodeDetector::builtin_with_config(config)
            .detect(&NormalizedView::build(&reg, value))
            .is_empty()
    }

    #[test]
    fn configured_depth_counts_transforms_exactly() {
        let config = DecodeConfig {
            max_depth: Some(3),
            ..DecodeConfig::default()
        };
        assert!(detects_with_config(
            &nested_base64("AKIAIOSFODNN7EXAMPLE", 3),
            config
        ));
        assert!(!detects_with_config(
            &nested_base64("AKIAIOSFODNN7EXAMPLE", 4),
            config
        ));
    }

    #[test]
    fn unlimited_depth_and_size_are_not_silently_capped() {
        let config = DecodeConfig {
            max_depth: None,
            max_bytes: None,
            max_inflate_bytes: None,
            ..DecodeConfig::default()
        };
        assert!(detects_with_config(
            &nested_base64("AKIAIOSFODNN7EXAMPLE", 12),
            config
        ));
    }

    #[test]
    fn decode_can_be_disabled_explicitly() {
        let config = DecodeConfig {
            enabled: false,
            ..DecodeConfig::default()
        };
        assert!(!detects_with_config(
            &nested_base64("AKIAIOSFODNN7EXAMPLE", 1),
            config
        ));
    }
}
