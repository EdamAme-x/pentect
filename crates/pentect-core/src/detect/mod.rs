use crate::model::Span;
use crate::normalize::NormalizedView;

mod card;
mod decode;
mod entropy;
#[cfg(feature = "ner")]
mod ner;
mod pem;
mod rule;
mod structural;
mod util;
mod validate;

pub use card::CardDetector;
pub use decode::{DecodeDetector, DEFAULT_DECODE_DEPTH, DEFAULT_MIN_OPAQUE_RUN};
pub use entropy::{EntropyDetector, DEFAULT_ENTROPY_MIN_LEN, DEFAULT_ENTROPY_THRESHOLD};
#[cfg(feature = "ner")]
pub use ner::NerDetector;
pub use pem::PemDetector;
pub use rule::{RuleDetector, RuleSpec};
pub use structural::StructuralDetector;
pub use validate::Validator;

pub(crate) use util::is_token_byte;

#[cfg(test)]
pub(crate) use util::region;

/// Side-effect-free and deterministic. Runs on a region's normalized view and
/// returns spans in absolute raw coordinates (each tagged with its `DetectorId`).
pub trait Detector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span>;
}
