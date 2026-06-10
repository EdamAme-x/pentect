use crate::model::{Confidence, Span};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Granularity {
    Full,
    HashOnly,
}

#[derive(Clone, Debug)]
pub enum Action {
    Mask(Option<Granularity>),
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
        Action::Mask(None)
    }
}

/// A span we couldn't anchor to a key, vendor rule, or identified decode — only
/// raw entropy or an opaque decodable blob put it here. These are the
/// "when in doubt" candidates the aggressiveness setting governs.
pub fn is_context_free(s: &Span) -> bool {
    (s.source == "entropy" || s.source == "decode_opaque") && s.confidence == Confidence::Low
}

/// What to do with a context-free opaque/entropy span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpaqueStance {
    Mask,
    Warn,
    Keep,
}

/// Behaviour recipe derived from a Profile. Pure data, not a runtime field of
/// the engine.
#[derive(Clone, Copy, Debug)]
pub struct ProfileKnobs {
    pub context_free: OpaqueStance,
    pub entropy_min_len: usize,
    pub entropy_threshold: f64,
    pub mask_unknown_codec: bool,
    pub min_opaque_run: usize,
}

/// Aggressiveness preset, loadable as an option (e.g. TOML `profile = "paranoid"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Bare-library default. Mask every candidate, incl. context-free entropy.
    #[default]
    Strict,
    /// Recommended app default. Anchored secrets mask; lone opaque blobs are
    /// surfaced as warnings, not silently masked or kept.
    Balanced,
    /// Opt-in, loud. Keeps context-free entropy (relaxes recall); still masks
    /// every anchored secret.
    Dev,
    /// Opt-in, max leak-prevention. Masks all opaque/encrypted-looking content.
    Paranoid,
}

impl Profile {
    pub fn knobs(self) -> ProfileKnobs {
        match self {
            Profile::Strict => ProfileKnobs {
                context_free: OpaqueStance::Mask,
                entropy_min_len: 24,
                entropy_threshold: 3.2,
                mask_unknown_codec: false,
                min_opaque_run: 24,
            },
            Profile::Balanced => ProfileKnobs {
                context_free: OpaqueStance::Warn,
                entropy_min_len: 24,
                entropy_threshold: 3.2,
                mask_unknown_codec: false,
                min_opaque_run: 24,
            },
            Profile::Dev => ProfileKnobs {
                context_free: OpaqueStance::Keep,
                entropy_min_len: 28,
                entropy_threshold: 3.6,
                mask_unknown_codec: false,
                min_opaque_run: 28,
            },
            Profile::Paranoid => ProfileKnobs {
                context_free: OpaqueStance::Mask,
                entropy_min_len: 20,
                entropy_threshold: 2.8,
                mask_unknown_codec: true,
                min_opaque_run: 20,
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

/// Maps a profile's stance onto each span. Anchored spans always mask; the
/// context-free ones follow the stance.
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
        if is_context_free(s) {
            match self.stance {
                OpaqueStance::Mask => Action::Mask(None),
                OpaqueStance::Warn => Action::Warn,
                OpaqueStance::Keep => Action::Keep,
            }
        } else {
            Action::Mask(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_from_str() {
        assert_eq!("paranoid".parse::<Profile>(), Ok(Profile::Paranoid));
        assert!("casual".parse::<Profile>().is_err());
        assert!("".parse::<Profile>().is_err());
    }

    #[test]
    fn knobs_table_pinned() {
        assert!(!Profile::Balanced.knobs().mask_unknown_codec);
        assert!(Profile::Paranoid.knobs().mask_unknown_codec);
        assert_eq!(Profile::Paranoid.knobs().context_free, OpaqueStance::Mask);
        assert_eq!(Profile::Balanced.knobs().context_free, OpaqueStance::Warn);
        assert_eq!(Profile::Dev.knobs().context_free, OpaqueStance::Keep);
    }
}
