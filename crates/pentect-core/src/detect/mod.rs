use crate::model::Span;
use crate::normalize::NormalizedView;

mod card;
mod date;
mod decode;
mod entropy;
#[cfg(feature = "semantic")]
mod ner;
mod pem;
mod phone;
mod rule;
mod structural;
mod util;
mod validate;

pub use card::CardDetector;
pub use decode::{DecodeDetector, DEFAULT_DECODE_DEPTH, DEFAULT_MIN_OPAQUE_RUN};
pub use entropy::{EntropyDetector, DEFAULT_ENTROPY_MIN_LEN, DEFAULT_ENTROPY_THRESHOLD};
#[cfg(feature = "semantic")]
pub use ner::SemanticDetector;
pub use pem::PemDetector;
pub use phone::PhoneDetector;
pub use rule::{RuleDetector, RuleSpec};
pub use structural::{EnvValueDetector, SensitiveKeyDetector, StructuralDetector};
pub use validate::Validator;

pub(crate) use util::is_token_byte;

#[cfg(test)]
pub(crate) use util::region;

/// Side-effect-free and deterministic. Runs on a region's normalized view and
/// returns spans in absolute raw coordinates (each tagged with its `DetectorId`).
pub trait Detector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span>;
}

/// Built-in detectors that are OFF by default (their default behaviour is wrong
/// for the paste-to-LLM use case) but available by label via `enable`. Returns
/// `None` for an unknown name.
pub fn enable_builtin(name: &str) -> Option<Box<dyn Detector>> {
    match name {
        "DATE_TIME" => Some(Box::new(date::date_detector())),
        _ => None,
    }
}
