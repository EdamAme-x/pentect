use serde::{Deserialize, Serialize};

pub type Label = String;

/// The synthetic labels the core detectors emit. Vendor-token labels live inline
/// in the rule table instead, since that layer is meant to become data-driven.
/// All labels are UPPER_SNAKE so they render into well-formed `<<LABEL_hash>>`
/// placeholders; keeping the shared ones here stops the same string being
/// retyped (and drifting) across detectors.
pub mod labels {
    macro_rules! define_canonical_labels {
        ($( $(#[$meta:meta])* $name:ident = $value:literal => $description:literal; )+) => {
            $(
                $(#[$meta])*
                pub const $name: &str = $value;
            )+

            /// Every synthetic label emitted by the core detectors.
            pub const ALL: &[&str] = &[$($name),+];

            /// Whether `value` is a fixed, core-defined label rather than input text.
            pub fn is_canonical(value: &str) -> bool {
                ALL.contains(&value)
            }

            /// A short user-facing explanation for a canonical detector label.
            pub fn description(value: &str) -> Option<&'static str> {
                match value {
                    $($value => Some($description),)+
                    _ => None,
                }
            }
        };
    }

    define_canonical_labels! {
        /// High-entropy run with no anchoring context (entropy detector).
        LIKELY_SECRET = "LIKELY_SECRET" => "high-entropy value that may be a secret";
        /// Decodes to binary-looking bytes ("looks encrypted") with no inner secret.
        OPAQUE_BLOB = "OPAQUE_BLOB" => "encoded or encrypted-looking data";
        /// Value masked because its key name looks sensitive.
        SECRET = "SECRET" => "value associated with a sensitive name";
        /// Ambiguous personally identifying information.
        PII = "PII" => "personally identifying information";
        /// Ambiguous identifier.
        IDENTIFIER = "IDENTIFIER" => "potentially sensitive identifier";
        /// Ambiguous endpoint.
        ENDPOINT = "ENDPOINT" => "potentially sensitive service endpoint";
        /// Sensitive value whose category could not be narrowed further.
        SENSITIVE = "SENSITIVE" => "sensitive value of an unspecified type";
        /// Value masked because a plaintext key/value structure carries a sensitive key.
        KEYED_SECRET = "KEYED_SECRET" => "value associated with a sensitive key";
        /// One-time password or verification code.
        OTP = "OTP" => "one-time password or verification code";
        /// BIP-39 wallet recovery phrase.
        BIP39_MNEMONIC = "BIP39_MNEMONIC" => "cryptocurrency wallet recovery phrase";
        /// Body of a PEM private-key block.
        PRIVATE_KEY = "PRIVATE_KEY" => "private cryptographic key";
        /// Host/authority of an internal service URL.
        INTERNAL_ENDPOINT = "INTERNAL_ENDPOINT" => "internal service host or authority";
        /// Resource identifier inside an internal URL path.
        RESOURCE_ID = "RESOURCE_ID" => "internal resource identifier";
        /// User-info credential portion of a URL authority.
        URL_CREDENTIAL = "URL_CREDENTIAL" => "credential embedded in a URL";
        /// Password-like value passed through a shell or PowerShell command option.
        CMD_PASSWORD = "CMD_PASSWORD" => "password supplied to a command";
        /// UUID/GUID value in an identifier-bearing slot.
        UUID = "UUID" => "UUID or GUID in an identifier field";
        /// Bucket name in an Amazon S3 hostname.
        AWS_S3_BUCKET = "AWS_S3_BUCKET" => "Amazon S3 bucket name";
        /// Firebase project/database prefix in a Realtime Database hostname.
        FIREBASE_PROJECT_ID = "FIREBASE_PROJECT_ID" => "Firebase project or database identifier";
        /// Query parameter value in an internal URL.
        URL_QUERY_VALUE = "URL_QUERY_VALUE" => "sensitive URL query value";
        /// Fragment value in an internal URL.
        URL_FRAGMENT = "URL_FRAGMENT" => "sensitive URL fragment";
        /// Location metadata embedded in image EXIF GPS tags.
        IMAGE_GPS_METADATA = "IMAGE_GPS_METADATA" => "GPS location stored in image metadata";
    }
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
    /// Temporary compatibility coverage pending an engine-level replacement.
    PentectTempParser,
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
            DetectorId::PentectTempParser => "pentect_temp_parser",
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
