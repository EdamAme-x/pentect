use crate::model::Span;
use crate::normalize::NormalizedView;

mod auth_code;
mod bip39;
mod card;
mod decode;
mod entropy;
mod pattern;
mod pem;
mod phone;
mod rule;
mod structural;
mod url;
mod util;
mod validate;

pub use auth_code::AuthCodeDetector;
pub use bip39::Bip39Detector;
pub use card::CardDetector;
pub use decode::{DecodeDetector, DEFAULT_DECODE_DEPTH, DEFAULT_MIN_OPAQUE_RUN};
pub use entropy::{EntropyDetector, DEFAULT_ENTROPY_MIN_LEN, DEFAULT_ENTROPY_THRESHOLD};
pub use pattern::{PatternMatchDetector, PatternSpec};
pub use pem::PemDetector;
pub use phone::PhoneDetector;
pub use rule::{RuleDetector, RuleSpec};
pub use structural::{EnvValueDetector, SensitiveKeyDetector, StructuralDetector};
pub use url::UrlDetector;
pub use validate::Validator;

pub(crate) use util::is_token_byte;

#[cfg(test)]
pub(crate) use util::region;

/// Side-effect-free and deterministic. Runs on a region's normalized view and
/// returns spans in absolute raw coordinates (each tagged with its `DetectorId`).
pub trait Detector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span>;
}
