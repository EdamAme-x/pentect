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
    /// Body of a PEM private-key block.
    pub const PRIVATE_KEY: &str = "PRIVATE_KEY";
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
        let low = span(20, Category::Secret, Confidence::Low, DetectorId::Entropy);
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

impl Span {
    /// Canonical "which span wins" ordering — the single source of truth for
    /// merge, the identity sweep, and decode's inner-hit selection. `Greater`
    /// means `self` is the stronger span. Higher confidence first (a High
    /// anchored hit beats a Low guess), then larger span (cover the whole secret,
    /// never leak a prefix), then higher category; ties broken deterministically
    /// by more-specific source then earliest position.
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
