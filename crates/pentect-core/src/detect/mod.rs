use crate::model::Span;
use crate::normalize::NormalizedView;

mod decode;
mod entropy;
mod pem;
mod rule;
mod suspicious_key;
mod util;

pub use decode::{DecodeDetector, DEFAULT_DECODE_DEPTH, DEFAULT_MIN_OPAQUE_RUN};
pub use entropy::{EntropyDetector, DEFAULT_ENTROPY_MIN_LEN, DEFAULT_ENTROPY_THRESHOLD};
pub use pem::PemDetector;
pub use rule::{RuleDetector, RuleSpec};
pub use suspicious_key::SuspiciousKeyDetector;

pub(crate) use util::is_token_byte;

#[cfg(test)]
pub(crate) use util::region;

/// Side-effect-free and deterministic. Runs on a region's normalized view and
/// returns spans in absolute raw coordinates (each tagged with its `DetectorId`).
pub trait Detector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span>;
}
