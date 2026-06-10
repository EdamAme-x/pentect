//! pentect-core: translate secrets in text into reversible placeholders, locally.
//!
//! Pipeline: parse -> detect -> classify -> merge -> identity sweep -> render.
//! Invariants are property-tested in tests/invariants.rs.

pub mod detect;
pub mod json;
pub mod merge;
pub mod model;
pub mod normalize;
pub mod pipeline;
pub mod placeholder;
pub mod policy;
pub mod recovery;
pub mod render;
pub mod sweep;

pub use model::{ByteRange, Category, Confidence, Input, Kind, Span};
pub use pipeline::{mask, mask_ir, Config, MaskResult, Summary};
pub use recovery::{restore, Recovery, RestoreError};

/// Original-value-free summary for UI / audit.
pub fn explain(result: &MaskResult) -> Summary {
    result.summary.clone()
}
