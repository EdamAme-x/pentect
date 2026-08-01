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
    AuthCodeDetector, Bip39Detector, CardDetector, CliCredentialDetector,
    CredSweeperNativeDetector, CredSweeperNativeFinding, CredSweeperNativeRelatedFinding,
    CredSweeperNativeStats, DecodeConfig, DecodeDetector, Detector, EntropyDetector,
    EnvValueDetector, KeyValueDetector, PatternMatchDetector, PatternSpec, PemDetector,
    RuleDetector, RuleSpec, SensitiveKeyDetector, StructuralDetector, UrlDetector,
};
pub use model::{
    ByteRange, Category, Confidence, Context, DetectorId, Input, Kind, Region, RegionKind, Span,
};
pub use pack::{load_pack, load_plugin_pack, Pack};
pub use parse::{
    EnvParser, JsonParser, NdjsonParser, Parser, StructuredParser, TextParser, ToolResultParser,
};
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

/// Infer the parser kind from a path without reading the file.
pub fn infer_kind(path: &std::path::Path) -> Kind {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if is_dotenv_name(&name) || is_aws_credentials_path(path) || is_github_env_path(path) {
        return Kind::Env;
    }
    if let Some(label) = mounted_secret_label(path) {
        return Kind::Other(format!("secret-file:{label}"));
    }
    if let Some(kind) = structured_config_kind(path, &name) {
        return Kind::Other(kind.to_string());
    }
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("json") => Kind::Json,
        Some("jsonl" | "ndjson") => Kind::Ndjson,
        Some("env") => Kind::Env,
        Some("har") => Kind::Har,
        Some("yaml" | "yml" | "toml" | "ini" | "conf" | "properties" | "tfvars") => {
            Kind::Other("structured".to_string())
        }
        _ => Kind::Text,
    }
}

/// Infer a parser from both provenance and content. Content sniffing is used
/// only for a high-confidence dotenv document; an arbitrary one-line
/// assignment remains ordinary text to avoid turning prose or source code into
/// an all-values secret boundary.
pub fn infer_kind_with_content(path: &std::path::Path, raw: &str) -> Kind {
    let inferred = infer_kind(path);
    if inferred != Kind::Text {
        return inferred;
    }
    if parse::looks_like_dotenv_document(raw) {
        return Kind::Env;
    }
    let trimmed = raw.trim_start_matches('\u{feff}').trim_start();
    if matches!(trimmed.as_bytes().first(), Some(b'{') | Some(b'['))
        && serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
    {
        return Kind::Json;
    }
    if looks_like_kubeconfig(raw) {
        return Kind::Other("structured:kubeconfig".to_string());
    }
    if looks_like_kubernetes_yaml(raw) {
        return Kind::Other("structured".to_string());
    }
    if looks_like_aws_config(raw) {
        return Kind::Other("structured:aws".to_string());
    }
    if looks_like_npm_config(raw) {
        return Kind::Other("structured:npm".to_string());
    }
    if looks_like_pypi_config(raw) {
        return Kind::Other("structured:pypi".to_string());
    }
    if looks_like_structured_document(raw) {
        return Kind::Other("structured".to_string());
    }
    Kind::Text
}

fn looks_like_kubernetes_yaml(raw: &str) -> bool {
    has_yaml_key_value(raw, "apiVersion", None) && has_yaml_key_value(raw, "kind", Some("Secret"))
}

fn looks_like_kubeconfig(raw: &str) -> bool {
    has_yaml_key_value(raw, "apiVersion", None)
        && ["clusters", "contexts", "users"]
            .iter()
            .filter(|key| has_yaml_key_value(raw, key, None))
            .count()
            >= 2
}

fn has_yaml_key_value(raw: &str, expected_key: &str, expected_value: Option<&str>) -> bool {
    raw.lines().any(|line| {
        let line = line.trim().trim_start_matches("- ");
        let Some((key, value)) = line.split_once(':') else {
            return false;
        };
        key.trim() == expected_key
            && expected_value.is_none_or(|expected| value.trim().eq_ignore_ascii_case(expected))
    })
}

fn looks_like_aws_config(raw: &str) -> bool {
    has_ini_section(raw)
        && raw.lines().any(|line| {
            line.split_once('=').is_some_and(|(key, _)| {
                matches!(
                    key.trim().to_ascii_lowercase().as_str(),
                    "aws_access_key_id" | "aws_secret_access_key" | "aws_session_token"
                )
            })
        })
}

fn looks_like_npm_config(raw: &str) -> bool {
    raw.lines().any(|line| {
        let key = line.split_once('=').map(|(key, _)| key.trim());
        key.is_some_and(|key| {
            matches!(key, "_auth" | "_authToken" | "_password")
                || (key.starts_with("//")
                    && matches!(
                        key.rsplit(':').next().unwrap_or_default(),
                        "_auth" | "_authToken" | "_password"
                    ))
        })
    })
}

fn looks_like_pypi_config(raw: &str) -> bool {
    raw.lines().any(|line| {
        matches!(
            line.trim().to_ascii_lowercase().as_str(),
            "[pypi]" | "[testpypi]" | "[distutils]"
        )
    }) && raw.lines().any(|line| {
        line.split_once('=').is_some_and(|(key, _)| {
            matches!(
                key.trim().to_ascii_lowercase().as_str(),
                "repository" | "username" | "password"
            )
        })
    })
}

fn has_ini_section(raw: &str) -> bool {
    raw.lines().any(|line| {
        let line = line.trim();
        line.starts_with('[') && line.ends_with(']') && line.len() > 2
    })
}

fn looks_like_structured_document(raw: &str) -> bool {
    let mut assignments = 0usize;
    let mut yaml_entries = 0usize;
    let mut sections = 0usize;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() > 2 {
            sections += 1;
            continue;
        }
        if matches!(trimmed, "{" | "}" | "[" | "]") {
            continue;
        }
        let body = trimmed.trim_start_matches("- ");
        if let Some((key, value)) = body.split_once('=') {
            if structured_key(key.trim()) && !value.trim().is_empty() {
                assignments += 1;
                continue;
            }
        }
        if let Some((key, _)) = body.split_once(':') {
            if structured_key(key.trim()) {
                yaml_entries += 1;
                continue;
            }
        }
        return false;
    }
    assignments >= 2 || yaml_entries >= 2 || (sections > 0 && yaml_entries + assignments > 0)
}

fn structured_key(key: &str) -> bool {
    let key = key.trim_matches(['"', '\'']);
    !key.is_empty()
        && key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.-/".contains(character))
}

fn is_dotenv_name(name: &str) -> bool {
    name == ".env"
        || name.starts_with(".env.")
        || name == ".dev.vars"
        || name.starts_with(".dev.vars.")
        || name == ".secret.local"
        || name.ends_with(".secret.local")
}

fn structured_config_kind(path: &std::path::Path, name: &str) -> Option<&'static str> {
    if name == ".npmrc" {
        return Some("structured:npm");
    }
    if name == ".pypirc" {
        return Some("structured:pypi");
    }
    if name == "kubeconfig"
        || (name == "config"
            && path
                .parent()
                .and_then(std::path::Path::file_name)
                .is_some_and(|parent| parent.to_string_lossy().eq_ignore_ascii_case(".kube")))
    {
        return Some("structured:kubeconfig");
    }
    if name == "config"
        && path
            .parent()
            .and_then(std::path::Path::file_name)
            .is_some_and(|parent| parent.to_string_lossy().eq_ignore_ascii_case(".aws"))
    {
        return Some("structured:aws");
    }
    None
}

fn is_aws_credentials_path(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("credentials"))
        && path
            .parent()
            .and_then(std::path::Path::file_name)
            .is_some_and(|parent| parent.to_string_lossy().eq_ignore_ascii_case(".aws"))
}

fn is_github_env_path(path: &std::path::Path) -> bool {
    path.to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
        .contains("/_runner_file_commands/set_env_")
}

fn mounted_secret_label(path: &std::path::Path) -> Option<String> {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    let in_named_secret_dir = path
        .parent()
        .and_then(std::path::Path::file_name)
        .is_some_and(|parent| parent.to_string_lossy().eq_ignore_ascii_case("secrets"))
        && path.extension().is_none();
    let has_secret_extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("secret"));
    let in_secret_mount = lower.contains("/run/secrets/")
        || lower.contains("/var/run/secrets/kubernetes.io/serviceaccount/")
        || in_named_secret_dir
        || has_secret_extension;
    if !in_secret_mount {
        return None;
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn infer_kind_recognizes_json_lines_files() {
        assert_eq!(infer_kind(Path::new("events.jsonl")), Kind::Ndjson);
        assert_eq!(infer_kind(Path::new("events.ndjson")), Kind::Ndjson);
    }

    #[test]
    fn infer_kind_recognizes_official_dotenv_families() {
        for path in [
            ".env.local",
            ".dev.vars",
            ".dev.vars.staging",
            ".secret.local",
            "extensions/image-resizer.secret.local",
            "service.env",
        ] {
            assert_eq!(infer_kind(Path::new(path)), Kind::Env, "{path}");
        }
    }

    #[test]
    fn infer_kind_recognizes_structured_and_mounted_sources() {
        assert_eq!(
            infer_kind(Path::new(".npmrc")),
            Kind::Other("structured:npm".into())
        );
        assert_eq!(infer_kind(Path::new(".aws/credentials")), Kind::Env);
        assert_eq!(
            infer_kind(Path::new(".kube/config")),
            Kind::Other("structured:kubeconfig".into())
        );
        assert_eq!(
            infer_kind(Path::new(
                "/home/runner/work/_temp/_runner_file_commands/set_env_1234"
            )),
            Kind::Env
        );
        assert_eq!(
            infer_kind(Path::new("/run/secrets/database-password")),
            Kind::Other("secret-file:database-password".into())
        );
        assert_eq!(
            infer_kind(Path::new("deploy/secrets/api-token")),
            Kind::Other("secret-file:api-token".into())
        );
        assert_eq!(
            infer_kind(Path::new("deploy/secrets/app-secret.yaml")),
            Kind::Other("structured".into())
        );
        assert_eq!(
            infer_kind(Path::new("deploy/secrets/values.json")),
            Kind::Json
        );
    }

    #[test]
    fn content_sniffing_requires_a_dotenv_document() {
        assert_eq!(
            infer_kind_with_content(Path::new("settings"), "API_KEY=abc\nMODE=dev\n"),
            Kind::Env
        );
        assert_eq!(
            infer_kind_with_content(Path::new("notes"), "example=value"),
            Kind::Text
        );
    }

    #[test]
    fn content_sniffing_recognizes_structured_stdin_formats() {
        assert_eq!(
            infer_kind_with_content(Path::new("stdin"), r#"{"token":"x"}"#),
            Kind::Json
        );
        assert_eq!(
            infer_kind_with_content(
                Path::new("stdin"),
                "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\nstringData:\n  password: x\n"
            ),
            Kind::Other("structured".into())
        );
        assert_eq!(
            infer_kind_with_content(
                Path::new("stdin"),
                "apiVersion: v1\nclusters: []\ncontexts: []\nusers: []\n"
            ),
            Kind::Other("structured:kubeconfig".into())
        );
        assert_eq!(
            infer_kind_with_content(
                Path::new("stdin"),
                "[default]\naws_access_key_id=x\naws_secret_access_key=y\n"
            ),
            Kind::Other("structured:aws".into())
        );
        assert_eq!(
            infer_kind_with_content(
                Path::new("stdin"),
                "_authToken=x\nregistry=https://example.com\n"
            ),
            Kind::Other("structured:npm".into())
        );
        assert_eq!(
            infer_kind_with_content(
                Path::new("stdin"),
                "[pypi]\nrepository = https://upload.pypi.org/legacy/\npassword = x\n"
            ),
            Kind::Other("structured:pypi".into())
        );
        assert_eq!(
            infer_kind_with_content(
                Path::new("stdin"),
                "region = \"us-east-1\"\ndb_password = \"x\"\n"
            ),
            Kind::Other("structured".into())
        );
        assert_eq!(
            infer_kind_with_content(Path::new("stdin"), "This is ordinary prose.\nSecond line."),
            Kind::Text
        );
    }
}
