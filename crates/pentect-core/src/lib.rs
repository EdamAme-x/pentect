//! pentect-core: translate secrets in text into reversible placeholders, locally.
//!
//! Roles are ports (traits) wired at a composition root (`Engine`): `Parser`,
//! `Detector`, `Policy`. The merge -> sweep -> render core is fixed because it
//! carries the invariants (reversible, idempotent, deterministic, global
//! identity, collision-free), which are property-tested in `engine`.

pub mod detect;
pub mod engine;
pub mod json;
pub mod merge;
pub mod model;
pub mod normalize;
pub mod parse;
pub mod placeholder;
pub mod policy;
pub mod recovery;
pub mod render;
pub mod sweep;

pub use detect::Detector;
pub use engine::{Config, Engine, EngineBuilder, MaskResult, Summary};
pub use model::{ByteRange, Category, Confidence, Input, Kind, Span};
pub use parse::{JsonParser, Parser, TextParser};
pub use policy::{Action, Granularity, MaskAll, Policy};
pub use recovery::{restore, Recovery, RestoreError};

/// Mask with the default engine. Build an `Engine` once for repeated calls.
pub fn mask(input: Input, config: &Config) -> MaskResult {
    Engine::default().mask(input, config)
}

/// Original-value-free summary for UI / audit.
pub fn explain(result: &MaskResult) -> Summary {
    result.summary.clone()
}
