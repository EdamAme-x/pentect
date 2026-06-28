use crate::detect::{DEFAULT_ENTROPY_MIN_LEN, DEFAULT_ENTROPY_THRESHOLD, DEFAULT_MIN_OPAQUE_RUN};
use crate::model::{DetectorId, Span};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub mod guard;

#[derive(Clone, Debug)]
pub enum Action {
    Mask,
    Keep,
    Warn,
    Drop,
}

/// Decides what to do with each detected span. Injected into the engine.
/// Per-span and order-independent: it never looks at other spans.
pub trait Policy {
    fn classify(&self, span: &Span) -> Action;
}

/// Default policy: mask every candidate (strict).
pub struct MaskAll;

impl Policy for MaskAll {
    fn classify(&self, _span: &Span) -> Action {
        Action::Mask
    }
}

/// A span we couldn't anchor to a key, vendor rule, or identified decode.
pub fn is_context_free(s: &Span) -> bool {
    // Entropy and DecodeOpaque are the only sources that emit unanchored guesses
    // (always Low confidence), so the variant alone identifies a context-free span.
    matches!(s.source, DetectorId::Entropy | DetectorId::DecodeOpaque)
}

/// What to do with a context-free opaque/entropy span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpaqueStance {
    Mask,
    Warn,
    Keep,
}

/// Behaviour recipe derived from the built-in profile. Pure data, not a runtime
/// field of the engine.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProfileKnobs {
    pub context_free: OpaqueStance,
    pub entropy_min_len: usize,
    pub entropy_threshold: f64,
    pub mask_unknown_codec: bool,
    pub min_opaque_run: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Mask every candidate selected by the detector stack.
    #[default]
    Strict,
    /// Compatibility preset: anchored secrets mask; context-free guesses warn.
    Balanced,
    /// Compatibility preset: keep context-free guesses.
    Dev,
    /// Compatibility preset: tighten context-free opaque/entropy masking.
    Paranoid,
}

impl Profile {
    pub fn knobs(self) -> ProfileKnobs {
        match self {
            Profile::Strict => ProfileKnobs {
                context_free: OpaqueStance::Mask,
                entropy_min_len: DEFAULT_ENTROPY_MIN_LEN,
                entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
                mask_unknown_codec: false,
                min_opaque_run: DEFAULT_MIN_OPAQUE_RUN,
            },
            Profile::Balanced => ProfileKnobs {
                context_free: OpaqueStance::Warn,
                entropy_min_len: DEFAULT_ENTROPY_MIN_LEN,
                entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
                mask_unknown_codec: false,
                min_opaque_run: DEFAULT_MIN_OPAQUE_RUN,
            },
            Profile::Dev => ProfileKnobs {
                context_free: OpaqueStance::Keep,
                entropy_min_len: DEFAULT_ENTROPY_MIN_LEN + 4,
                entropy_threshold: DEFAULT_ENTROPY_THRESHOLD + 0.4,
                mask_unknown_codec: false,
                min_opaque_run: DEFAULT_MIN_OPAQUE_RUN + 4,
            },
            Profile::Paranoid => ProfileKnobs {
                context_free: OpaqueStance::Mask,
                entropy_min_len: DEFAULT_ENTROPY_MIN_LEN - 4,
                entropy_threshold: DEFAULT_ENTROPY_THRESHOLD - 0.4,
                mask_unknown_codec: true,
                min_opaque_run: DEFAULT_MIN_OPAQUE_RUN - 4,
            },
        }
    }
}

impl FromStr for Profile {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "strict" => Ok(Profile::Strict),
            "balanced" => Ok(Profile::Balanced),
            "dev" => Ok(Profile::Dev),
            "paranoid" => Ok(Profile::Paranoid),
            other => Err(format!("unknown profile: {other}")),
        }
    }
}

pub struct ProfilePolicy {
    stance: OpaqueStance,
}

impl ProfilePolicy {
    pub fn new(profile: Profile) -> Self {
        Self {
            stance: profile.knobs().context_free,
        }
    }
}

impl Policy for ProfilePolicy {
    fn classify(&self, s: &Span) -> Action {
        if !is_context_free(s) {
            return Action::Mask;
        }
        match self.stance {
            OpaqueStance::Mask => Action::Mask,
            OpaqueStance::Warn => Action::Warn,
            OpaqueStance::Keep => Action::Keep,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_from_str() {
        assert_eq!("strict".parse::<Profile>(), Ok(Profile::Strict));
        assert_eq!("balanced".parse::<Profile>(), Ok(Profile::Balanced));
        assert_eq!("dev".parse::<Profile>(), Ok(Profile::Dev));
        assert_eq!("paranoid".parse::<Profile>(), Ok(Profile::Paranoid));
        assert!("extra".parse::<Profile>().is_err());
        assert!("".parse::<Profile>().is_err());
    }

    // Pin every field so a detector-threshold change is a deliberate edit.
    #[test]
    fn knobs_table_pinned() {
        assert_eq!(
            Profile::Strict.knobs(),
            ProfileKnobs {
                context_free: OpaqueStance::Mask,
                entropy_min_len: DEFAULT_ENTROPY_MIN_LEN,
                entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
                mask_unknown_codec: false,
                min_opaque_run: DEFAULT_MIN_OPAQUE_RUN,
            }
        );
    }
}
