//! pentect-core: a local bidirectional masking kernel for AI boundaries.
//!
//! Layers: `model` (domain), the pluggable adapter layers `detect` / `codec` /
//! `parse` / `policy` (each with its port trait), and `pipeline` (the Engine
//! composition root plus the fixed merge -> sweep -> render core that carries the
//! invariants: reversible, idempotent, deterministic, global-identity,
//! collision-free). `normalize` / `placeholder` / `recovery` are shared
//! primitives.
//!
//! The core loop is pure text transformation:
//!
//! 1. `Engine::mask` turns local plaintext into placeholders safe for a model.
//! 2. `Recovery::resolve` expands known placeholders immediately before a local
//!    adapter executes a command or tool call.
//! 3. `Recovery::remask` hides any echoed values before output returns to the
//!    model.
//!
//! Hook integration, command execution, key storage, session persistence, network
//! policy, and UI are adapter responsibilities; this crate does not perform
//! those side effects.

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
pub use detect::{
    AuthCodeDetector, Bip39Detector, CardDetector, DecodeDetector, Detector, EntropyDetector,
    KeyValueDetector, PatternMatchDetector, PatternSpec, PemDetector, RuleDetector, RuleSpec,
    SensitiveKeyDetector, StructuralDetector, UrlDetector,
};
pub use model::{
    ByteRange, Category, Confidence, Context, DetectorId, Input, Kind, Region, RegionKind, Span,
};
pub use pack::{load_pack, Pack};
pub use parse::{EnvParser, JsonParser, Parser, TextParser, ToolResultParser};
pub use pipeline::{
    Config, Engine, EngineBuilder, MaskResult, MaskedItem, RenderSegment, ResidualNote,
    SpanAnalysisResult, Summary,
};
pub use placeholder::{parse_placeholder, LengthHint, PlaceholderParts};
pub use policy::guard::{OverMaskGuard, ShapeGuard};
pub use policy::{Action, MaskAll, Policy, Profile, ProfilePolicy};
pub use recovery::{restore, Recovery, RecoveryError, RestoreError};

/// Mask with the default engine. Build an `Engine` once for repeated calls.
pub fn mask(input: Input, config: &Config) -> MaskResult {
    Engine::default().mask(input, config)
}

/// Original-value-free summary for UI / audit.
pub fn explain(result: &MaskResult) -> Summary {
    result.summary.clone()
}
