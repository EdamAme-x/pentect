use serde::{Deserialize, Serialize};

pub type Label = String;

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

/// Which detector produced a span. Typed (not a free-form string) so policy and
/// render branch on the variant and a rename can't silently change behaviour.
/// Declaration order is a *specificity rank* (most-specific/anchored first): on
/// an otherwise-tied overlap the lower variant wins, so the more informative
/// label is kept (e.g. OPAQUE_BLOB over a generic LIKELY_SECRET).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DetectorId {
    Rule,
    Pem,
    /// A codec-decoded blob whose decoded content was identified as a secret.
    Decode,
    SuspiciousKey,
    /// A codec-decoded blob that only "looks encrypted" (no inner secret found).
    DecodeOpaque,
    Entropy,
    /// Added by the global identity sweep, not a real detector.
    Sweep,
}

impl DetectorId {
    pub fn as_str(self) -> &'static str {
        match self {
            DetectorId::Rule => "rule",
            DetectorId::Entropy => "entropy",
            DetectorId::Decode => "decode",
            DetectorId::DecodeOpaque => "decode_opaque",
            DetectorId::Pem => "pem",
            DetectorId::SuspiciousKey => "suspicious_key",
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
