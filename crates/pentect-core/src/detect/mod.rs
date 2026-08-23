use crate::model::Span;
use crate::normalize::NormalizedView;

mod auth_code;
mod benign;
mod bip39;
mod card;
mod cli;
mod credsweeper;
mod credsweeper_ml;
mod decode;
mod documentation;
mod entropy;
mod explicit;
mod key_value;
mod pattern;
mod pem;
mod phone;
mod rule;
mod shell;
mod structural;
mod url;
mod util;
mod uuid;
mod validate;

pub use auth_code::AuthCodeDetector;
pub use bip39::Bip39Detector;
pub use card::CardDetector;
pub use cli::CliCredentialDetector;
pub use credsweeper::{
    CredSweeperNativeDetector, CredSweeperNativeFinding, CredSweeperNativeRelatedFinding,
    CredSweeperNativeStats,
};
pub use decode::{
    DecodeConfig, DecodeDetector, DEFAULT_DECODE_DEPTH, DEFAULT_MAX_DECODE_BYTES,
    DEFAULT_MAX_INFLATE_BYTES, DEFAULT_MIN_DECODE_BYTES, DEFAULT_MIN_OPAQUE_RUN,
};
pub use entropy::{EntropyDetector, DEFAULT_ENTROPY_MIN_LEN, DEFAULT_ENTROPY_THRESHOLD};
pub use explicit::ExplicitSecretDetector;
pub(crate) use explicit::EXPLICIT_SECRET_PREFIXES;
pub use key_value::KeyValueDetector;
pub use pattern::{PatternMatchDetector, PatternSpec};
pub use pem::PemDetector;
pub use phone::PhoneDetector;
pub use rule::{RuleDetector, RuleSpec};
pub(crate) use structural::SECRET_VALUE_HINT;
pub use structural::{EnvValueDetector, SensitiveKeyDetector, StructuralDetector};
pub use url::UrlDetector;
pub use uuid::UuidDetector;
pub use validate::Validator;

pub(crate) use util::is_token_byte;

#[cfg(test)]
pub(crate) use util::region;

/// Side-effect-free and deterministic. Runs on a region's normalized view and
/// returns spans in absolute raw coordinates (each tagged with its `DetectorId`).
pub trait Detector: Send + Sync {
    fn detect(&self, view: &NormalizedView) -> Vec<Span>;
}
