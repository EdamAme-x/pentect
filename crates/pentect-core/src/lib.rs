//! pentect-core: translate secrets in text into reversible placeholders, locally.
//!
//! Layers: `model` (domain), the pluggable adapter layers `detect` / `codec` /
//! `parse` / `policy` (each with its port trait), and `pipeline` (the Engine
//! composition root plus the fixed merge -> sweep -> render core that carries the
//! invariants: reversible, idempotent, deterministic, global-identity,
//! collision-free). `normalize` / `placeholder` / `recovery` are shared
//! primitives.

pub mod codec;
pub mod detect;
pub mod model;
pub mod normalize;
pub mod pack;
pub mod parse;
pub mod pipeline;
pub mod placeholder;
pub mod policy;
pub mod recovery;

pub use codec::Codec;
#[cfg(feature = "ner")]
pub use detect::NerDetector;
pub use detect::{
    CardDetector, DecodeDetector, Detector, EntropyDetector, PemDetector, RuleDetector, RuleSpec,
    StructuralDetector,
};
pub use model::{ByteRange, Category, Confidence, Input, Kind, Span};
pub use pack::{load_pack, Pack};
pub use parse::{EnvParser, HarParser, JsonParser, Parser, TextParser};
pub use pipeline::{
    Config, Engine, EngineBuilder, MaskResult, MaskedItem, RenderSegment, ResidualNote, Summary,
};
pub use policy::guard::{OverMaskGuard, ShapeGuard};
pub use policy::{Action, MaskAll, OpaqueStance, Policy, Profile, ProfilePolicy};
pub use recovery::{restore, Recovery, RecoveryError, RestoreError};

/// Mask with the default engine. Build an `Engine` once for repeated calls.
pub fn mask(input: Input, config: &Config) -> MaskResult {
    Engine::default().mask(input, config)
}

/// Original-value-free summary for UI / audit.
pub fn explain(result: &MaskResult) -> Summary {
    result.summary.clone()
}
