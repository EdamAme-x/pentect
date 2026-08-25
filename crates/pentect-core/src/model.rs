use serde::{Deserialize, Serialize};

pub type Label = String;

/// The synthetic labels the core detectors emit. Vendor-token labels live inline
/// in the rule table instead, since that layer is meant to become data-driven.
/// All labels are UPPER_SNAKE so they render into well-formed `<<LABEL_hash>>`
/// placeholders; keeping the shared ones here stops the same string being
/// retyped (and drifting) across detectors.
pub mod labels {
    /// High-entropy run with no anchoring context (entropy detector).
    pub const LIKELY_SECRET: &str = "LIKELY_SECRET";
    /// Decodes to binary-looking bytes ("looks encrypted") with no inner secret.
    pub const OPAQUE_BLOB: &str = "OPAQUE_BLOB";
    /// Value masked because its key name looks sensitive.
    pub const SECRET: &str = "SECRET";
    /// Ambiguous personally identifying information.
    pub const PII: &str = "PII";
    /// Ambiguous identifier.
    pub const IDENTIFIER: &str = "IDENTIFIER";
    /// Ambiguous endpoint.
    pub const ENDPOINT: &str = "ENDPOINT";
    /// Sensitive value whose category could not be narrowed further.
    pub const SENSITIVE: &str = "SENSITIVE";
    /// Value masked because a plaintext key/value structure carries a sensitive key.
    pub const KEYED_SECRET: &str = "KEYED_SECRET";
    /// One-time password or verification code.
    pub const OTP: &str = "OTP";
    /// BIP-39 wallet recovery phrase.
    pub const BIP39_MNEMONIC: &str = "BIP39_MNEMONIC";
    /// Body of a PEM private-key block.
    pub const PRIVATE_KEY: &str = "PRIVATE_KEY";
    /// Host/authority of an internal service URL.
    pub const INTERNAL_ENDPOINT: &str = "INTERNAL_ENDPOINT";
    /// Resource identifier inside an internal URL path.
    pub const RESOURCE_ID: &str = "RESOURCE_ID";
    /// User-info credential portion of a URL authority.
    pub const URL_CREDENTIAL: &str = "URL_CREDENTIAL";
    /// Password-like value passed through a shell or PowerShell command option.
    pub const CMD_PASSWORD: &str = "CMD_PASSWORD";
    /// UUID/GUID value in an identifier-bearing slot.
    pub const UUID: &str = "UUID";
    /// Bucket name in an Amazon S3 hostname.
    pub const AWS_S3_BUCKET: &str = "AWS_S3_BUCKET";
    /// Firebase project/database prefix in a Realtime Database hostname.
    pub const FIREBASE_PROJECT_ID: &str = "FIREBASE_PROJECT_ID";
    /// Query parameter value in an internal URL.
    pub const URL_QUERY_VALUE: &str = "URL_QUERY_VALUE";
    /// Fragment value in an internal URL.
    pub const URL_FRAGMENT: &str = "URL_FRAGMENT";
    /// Location metadata embedded in image EXIF GPS tags.
    pub const IMAGE_GPS_METADATA: &str = "IMAGE_GPS_METADATA";
}

/// Half-open byte range into the raw input, aligned to UTF-8 char boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

impl ByteRange {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
    pub fn overlaps(&self, o: &ByteRange) -> bool {
        self.start < o.end && o.start < self.end
    }
    pub fn contains(&self, o: &ByteRange) -> bool {
        self.start <= o.start && o.end <= self.end
    }
}

/// Provenance tag for the input; only Text/Json/Env have a built-in parser so far.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Text,
    Json,
    Ndjson,
    ToolResult,
    Env,
    Har,
    Curl,
    Markdown,
    Other(String),
}

#[derive(Clone, Debug)]
pub struct Input {
    pub kind: Kind,
    pub data: String,
}

impl Input {
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            kind: Kind::Text,
            data: s.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    Secret,
    Identifier,
    Endpoint,
    Pii,
    Other,
}

impl Category {
    /// Tie-break weight when overlapping spans have equal confidence; higher wins.
    pub fn priority(self) -> u8 {
        match self {
            Category::Secret => 4,
            Category::Pii => 3,
            Category::Identifier => 2,
            Category::Endpoint => 1,
            Category::Other => 0,
        }
    }
}

/// Ordered Low < Medium < High.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionKind {
    PlainText,
    JsonKey,
    JsonValue,
    Header,
    Cookie,
    Url,
    Body,
}

/// Read-only context a detector or policy reads about a region.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Context {
    pub path: Option<String>,
    pub key: Option<String>,
    /// Non-secret structural clues from the adapter, such as a form label,
    /// aria-label, placeholder, or column heading. These are not values.
    #[serde(default)]
    pub hints: Vec<String>,
    pub kind: RegionKind,
    pub format: Kind,
}

/// A value range plus its context. Structural characters are excluded.
#[derive(Clone, Debug)]
pub struct Region {
    pub span: ByteRange,
    pub ctx: Context,
}

#[derive(Clone, Debug)]
pub struct Ir {
    pub raw: String,
    pub regions: Vec<Region>,
    /// Existing placeholders, frozen so re-masking is idempotent.
    pub protected: Vec<ByteRange>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(len: usize, cat: Category, conf: Confidence, src: DetectorId) -> Span {
        Span {
            range: ByteRange::new(0, len),
            category: cat,
            label: "X".into(),
            confidence: conf,
            source: src,
        }
    }

    #[test]
    fn confidence_dominates_then_length_then_category() {
        let high = span(6, Category::Secret, Confidence::High, DetectorId::Rule);
        let low = span(
            20,
            Category::Secret,
            Confidence::Low,
            DetectorId::DecodeOpaque,
        );
        // High wins despite being shorter (confidence dominates).
        assert!(high.cmp_strength(&low).is_gt());

        let small = span(4, Category::Secret, Confidence::Medium, DetectorId::Rule);
        let large = span(10, Category::Secret, Confidence::Medium, DetectorId::Rule);
        // Equal confidence -> larger span wins (never leak a prefix).
        assert!(large.cmp_strength(&small).is_gt());
    }

    #[test]
    fn strength_is_a_total_order() {
        let a = span(10, Category::Secret, Confidence::High, DetectorId::Rule);
        let b = span(10, Category::Secret, Confidence::High, DetectorId::Rule);
        assert!(a.cmp_strength(&b).is_eq()); // identical spans tie
        assert_eq!(a.cmp_strength(&b), b.cmp_strength(&a).reverse());
    }
}

/// Which detector produced a span. Typed (not a free-form string) so policy and
/// render branch on the variant and a rename can't silently change behaviour.
/// Declaration order is a *specificity rank* (most-specific/anchored first): on
/// an otherwise-tied overlap the lower variant wins, so the more informative
/// label is kept (e.g. OPAQUE_BLOB over a generic LIKELY_SECRET).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DetectorId {
    /// A value explicitly wrapped by the user as `pentect(value)`.
    Explicit,
    /// Span supplied by a plugin adapter outside deterministic core.
    Plugin,
    /// Native Rust port of embedded CredSweeper rule/model assets.
    CredSweeper,
    /// PII detected by the bundled Alcatraz helper.
    Alcatraz,
    Rule,
    /// A plaintext key/value assignment whose key and value features are secret-like.
    KeyValue,
    Pem,
    /// A codec-decoded blob whose decoded content was identified as a secret.
    Decode,
    /// A value sensitive by structural position (cookie value, auth header).
    Structural,
    /// A codec-decoded blob that only "looks encrypted" (no inner secret found).
    DecodeOpaque,
    /// Added by the global identity sweep, not a real detector.
    Sweep,
}

impl DetectorId {
    pub fn as_str(self) -> &'static str {
        match self {
            DetectorId::Explicit => "explicit",
            DetectorId::Plugin => "plugin",
            DetectorId::CredSweeper => "credsweeper",
            DetectorId::Alcatraz => "alcatraz",
            DetectorId::Rule => "rule",
            DetectorId::KeyValue => "key_value",
            DetectorId::Decode => "decode",
            DetectorId::DecodeOpaque => "decode_opaque",
            DetectorId::Pem => "pem",
            DetectorId::Structural => "structural",
            DetectorId::Sweep => "sweep",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Span {
    pub range: ByteRange,
    pub category: Category,
    pub label: Label,
    pub confidence: Confidence,
    pub source: DetectorId,
}

impl Span {
    /// Canonical "which span wins" ordering — the single source of truth for
    /// merge, the identity sweep, and decode's inner-hit selection. `Greater`
    /// means `self` is the stronger span. Higher confidence first (a High
    /// anchored hit beats a Low guess), then larger span (cover the whole secret,
    /// never leak a prefix), then higher category; ties broken deterministically
    /// by more-specific source then earliest position. Labels deliberately do
    /// not break a tie: two otherwise-identical findings with different labels
    /// are genuinely ambiguous and merge to their canonical category label.
    pub fn cmp_strength(&self, other: &Self) -> core::cmp::Ordering {
        self.confidence
            .cmp(&other.confidence)
            .then(self.range.len().cmp(&other.range.len()))
            .then(self.category.priority().cmp(&other.category.priority()))
            .then(other.source.cmp(&self.source))
            .then(other.range.start.cmp(&self.range.start))
            .then(other.range.end.cmp(&self.range.end))
    }
}
