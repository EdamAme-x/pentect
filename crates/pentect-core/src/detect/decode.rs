use super::util::is_token_byte;
use super::{Detector, RuleDetector};
use crate::codec::{Base32Codec, Base58Codec, Base64Codec, Codec, HexCodec};
use crate::model::*;
use crate::normalize::NormalizedView;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use std::io::Read;

const MIN_DECODE_RUN: usize = 16;
const MAX_INFLATE: u64 = 8 * 1024 * 1024;

/// Tries injected codecs on each encoded-looking run; if the decoded content
/// (possibly nested) is identified by an injected detector, masks the whole
/// encoded blob under that label. The blob is masked whole because a partial
/// replacement could not be re-encoded. Codec- and detector-agnostic via DI.
pub struct DecodeDetector {
    codecs: Vec<Box<dyn Codec>>,
    identify: Vec<Box<dyn Detector>>,
    max_depth: u8,
    /// When set, a run that decodes to binary-looking bytes but yields no inner
    /// secret is still masked as an opaque blob ("looks encrypted").
    mask_unknown: bool,
    min_unknown_run: usize,
}

impl DecodeDetector {
    pub fn new(
        codecs: Vec<Box<dyn Codec>>,
        identify: Vec<Box<dyn Detector>>,
        max_depth: u8,
    ) -> Self {
        Self {
            codecs,
            identify,
            max_depth,
            mask_unknown: false,
            min_unknown_run: MIN_DECODE_RUN,
        }
    }

    pub fn builtin() -> Self {
        Self::new(
            vec![
                Box::new(Base64Codec),
                Box::new(Base32Codec),
                Box::new(Base58Codec),
                Box::new(HexCodec),
            ],
            vec![Box::new(RuleDetector::builtin())],
            3,
        )
    }

    pub fn with_opaque(mut self, mask_unknown: bool, min_run: usize) -> Self {
        self.mask_unknown = mask_unknown;
        self.min_unknown_run = min_run.max(MIN_DECODE_RUN);
        self
    }

    /// True if some codec decodes the run into binary-looking bytes (a strong
    /// "this is ciphertext" signal, distinct from raw entropy).
    fn decodes_to_binary(&self, run: &str) -> bool {
        self.codecs
            .iter()
            .any(|c| c.decode(run).is_some_and(|b| looks_binary(&b)))
    }

    fn probe(&self, run: &str, depth: u8) -> Option<(Category, String, Confidence)> {
        for codec in &self.codecs {
            if let Some(bytes) = codec.decode(run) {
                if let Some(hit) = self.scan_bytes(&bytes, depth) {
                    return Some(hit);
                }
            }
        }
        None
    }

    fn scan_bytes(&self, bytes: &[u8], depth: u8) -> Option<(Category, String, Confidence)> {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                if let Some(hit) = self.identify(text) {
                    return Some(hit);
                }
                if depth > 0 {
                    for sub in token_runs(text) {
                        if let Some(hit) = self.probe(sub, depth - 1) {
                            return Some(hit);
                        }
                    }
                }
            }
            // Binary bytes might be compressed (e.g. SAML's base64(deflate(..))).
            Err(_) if depth > 0 => {
                if let Some(inflated) = decompress(bytes) {
                    return self.scan_bytes(&inflated, depth - 1);
                }
            }
            Err(_) => {}
        }
        None
    }

    fn identify(&self, text: &str) -> Option<(Category, String, Confidence)> {
        let region = Region {
            span: ByteRange::new(0, text.len()),
            ctx: Context {
                path: None,
                key: None,
                kind: RegionKind::PlainText,
                format: Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, text);
        let mut best: Option<Span> = None;
        for d in &self.identify {
            for span in d.detect(&view) {
                if best.as_ref().is_none_or(|b| is_stronger(&span, b)) {
                    best = Some(span);
                }
            }
        }
        best.map(|s| (s.category, s.label, s.confidence))
    }
}

impl Detector for DecodeDetector {
    fn id(&self) -> &str {
        "decode"
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
            if i - start >= MIN_DECODE_RUN {
                let run = &s[start..i];
                if let Some((cat, label, conf)) = self.probe(run, self.max_depth) {
                    out.push(Span {
                        range: view.to_raw(ByteRange::new(start, i)),
                        category: cat,
                        label,
                        confidence: conf,
                        source: "decode".to_string(),
                    });
                } else if self.mask_unknown
                    && i - start >= self.min_unknown_run
                    && self.decodes_to_binary(run)
                {
                    out.push(Span {
                        range: view.to_raw(ByteRange::new(start, i)),
                        category: Category::Secret,
                        label: "OPAQUE_BLOB".to_string(),
                        confidence: Confidence::Low,
                        source: "decode_opaque".to_string(),
                    });
                }
            }
        }
        out
    }
}

/// Decoded bytes look like ciphertext: not valid UTF-8, or a high fraction of
/// non-printable bytes.
fn looks_binary(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if std::str::from_utf8(bytes).is_err() {
        return true;
    }
    let nonprint = bytes
        .iter()
        .filter(|&&b| b < 0x09 || (0x0e..0x20).contains(&b) || b >= 0x7f)
        .count();
    nonprint * 10 > bytes.len() * 3
}

fn token_runs(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut runs = Vec::new();
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
        if i - start >= MIN_DECODE_RUN {
            runs.push(&s[start..i]);
        }
    }
    runs
}

fn is_stronger(a: &Span, b: &Span) -> bool {
    a.confidence > b.confidence
        || (a.confidence == b.confidence && a.category.priority() > b.category.priority())
}

/// Try gzip, zlib, then raw deflate. Output is capped to bound decompression
/// bombs; we only need enough to detect a secret, not the full payload.
fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    inflate(GzDecoder::new(data))
        .or_else(|| inflate(ZlibDecoder::new(data)))
        .or_else(|| inflate(DeflateDecoder::new(data)))
}

fn inflate<R: Read>(reader: R) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(MAX_INFLATE).read_to_end(&mut out).ok()?;
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
}
