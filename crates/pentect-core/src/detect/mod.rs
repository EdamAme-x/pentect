use crate::model::Span;
use crate::normalize::NormalizedView;

mod decode;
mod entropy;
mod pem;
mod rule;
mod suspicious_key;
mod util;

pub use decode::DecodeDetector;
pub use entropy::EntropyDetector;
pub use pem::PemDetector;
pub use rule::RuleDetector;
pub use suspicious_key::SuspiciousKeyDetector;

#[cfg(test)]
pub(crate) use util::region;

/// Side-effect-free and deterministic. Runs on a region's normalized view and
/// returns spans in absolute raw coordinates (each tagged with its `DetectorId`).
pub trait Detector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span>;
}
