use pentect_core::{
    ByteRange, Category, Confidence, Config, Context, DetectorId, Engine, Input, Kind, MaskResult,
    Span,
};
use serde::Deserialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) const ADAPTERS_ENV: &str = "PENTECT_EXTENSION_ADAPTERS";

const PENTECT_DIR: &str = ".pentect";
const EXTENSIONS_DATA_DIR: &str = "extensions-data";
const EXTENSION_CONFIG_FILE: &str = "config.toml";
const EXTENSION_CACHE_DIR: &str = "cache";
const EXTENSION_NAME_ENV: &str = "PENTECT_EXTENSION_NAME";
const EXTENSION_DATA_DIR_ENV: &str = "PENTECT_EXTENSION_DATA_DIR";
const EXTENSION_CACHE_DIR_ENV: &str = "PENTECT_EXTENSION_CACHE_DIR";
const EXTENSION_CONFIG_ENV: &str = "PENTECT_EXTENSION_CONFIG";
const DEFAULT_TIMEOUT_MS: u64 = 3_000;
const DEFAULT_MAX_INPUT_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_SPANS: usize = 512;
const MAX_STDOUT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub(crate) struct ModelAdapters {
    adapters: Vec<ModelAdapter>,
}

impl ModelAdapters {
    pub(crate) fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }

    pub(crate) fn from_env() -> Result<Self, String> {
        let Some(value) = std::env::var_os(ADAPTERS_ENV) else {
            return Ok(Self::default());
        };
        let mut adapters = Vec::new();
        for path in std::env::split_paths(&value) {
            if path.as_os_str().is_empty() {
                continue;
            }
            adapters.push(ModelAdapter::load(&path)?);
        }
        Ok(Self { adapters })
    }

    pub(crate) fn mask(
        &self,
        engine: &Engine,
        input: Input,
        context: Option<&Context>,
        cfg: &Config,
    ) -> Result<Option<MaskResult>, String> {
        if self.adapters.is_empty() {
            return Ok(None);
        }
        let mut spans = Vec::new();
        for adapter in &self.adapters {
            spans.extend(adapter.detect(&input.data, &input.kind, context)?);
        }
        if spans.is_empty() {
            return Ok(None);
        }
        Ok(Some(engine.mask_spans(input, spans, cfg)))
    }
}

#[derive(Clone, Debug)]
struct ModelAdapter {
    name: String,
    id: String,
    path: PathBuf,
    backend: AdapterBackend,
    timeout: Duration,
    max_input_bytes: usize,
    max_spans: usize,
}

#[derive(Clone, Debug)]
enum AdapterBackend {
    Command(Vec<String>),
    Builtin(BuiltinAdapter),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BuiltinAdapter {
    PiiNer,
}

impl ModelAdapter {
    fn load(path: &Path) -> Result<Self, String> {
        if !path.is_file() {
            return Err(format!(
                "extension adapter does not exist: {}",
                path.display()
            ));
        }
        let src = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read extension adapter '{}': {e}", path.display()))?;
        let file: AdapterFile = toml::from_str(&src)
            .map_err(|e| format!("extension adapter '{}' is invalid: {e}", path.display()))?;
        if let Some(schema) = &file.schema {
            if schema != "pentect.model_adapter.v1" {
                return Err(format!(
                    "extension adapter '{}' has unsupported schema: {schema}",
                    path.display()
                ));
            }
        }
        if let Some(kind) = &file.kind {
            if kind != "model" {
                return Err(format!(
                    "extension adapter '{}' has unsupported kind: {kind}",
                    path.display()
                ));
            }
        }
        let backend = adapter_backend(path, file.command, file.builtin.as_deref())?;
        let name = file
            .name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| adapter_default_name(path));
        let id = extension_id(&name);
        Ok(Self {
            name,
            id,
            path: path.to_path_buf(),
            backend,
            timeout: Duration::from_millis(file.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
            max_input_bytes: file.max_input_bytes.unwrap_or(DEFAULT_MAX_INPUT_BYTES),
            max_spans: file.max_spans.unwrap_or(DEFAULT_MAX_SPANS),
        })
    }

    fn detect(
        &self,
        text: &str,
        kind: &Kind,
        context: Option<&Context>,
    ) -> Result<Vec<Span>, String> {
        if text.len() > self.max_input_bytes {
            return Ok(Vec::new());
        }
        if let AdapterBackend::Builtin(builtin) = &self.backend {
            return self.detect_builtin(*builtin, text);
        }
        let request = json!({
            "schema": "pentect.model_adapter.v1",
            "kind": kind_name(kind),
            "text": text,
            "context": context,
        })
        .to_string();
        let response = self.run(&request)?;
        let parsed: AdapterResponse = serde_json::from_str(&response).map_err(|e| {
            format!(
                "extension adapter '{}' returned invalid JSON: {e}",
                self.name
            )
        })?;
        if parsed.spans.len() > self.max_spans {
            return Err(format!(
                "extension adapter '{}' returned too many spans: {} > {}",
                self.name,
                parsed.spans.len(),
                self.max_spans
            ));
        }
        parsed
            .spans
            .into_iter()
            .map(|span| adapter_span(text, span, &self.name))
            .collect()
    }

    fn run(&self, request: &str) -> Result<String, String> {
        let AdapterBackend::Command(command) = &self.backend else {
            return Err(format!("extension adapter '{}' has no command", self.name));
        };
        let mut cmd = Command::new(&command[0]);
        apply_adapter_child_env(&mut cmd, &self.id)?;
        cmd.args(&command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(parent) = self.path.parent() {
            cmd.current_dir(parent);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("could not start extension adapter '{}': {e}", self.name))?;
        {
            let mut stdin = child.stdin.take().ok_or_else(|| {
                format!("could not open stdin for extension adapter '{}'", self.name)
            })?;
            use std::io::Write as _;
            stdin.write_all(request.as_bytes()).map_err(|e| {
                format!("could not write to extension adapter '{}': {e}", self.name)
            })?;
        }

        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return Err(format!(
                            "extension adapter '{}' exited with status {status}",
                            self.name
                        ));
                    }
                    break;
                }
                Ok(None) if start.elapsed() >= self.timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("extension adapter '{}' timed out", self.name));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "could not wait for extension adapter '{}': {e}",
                        self.name
                    ));
                }
            }
        }

        let output = child.wait_with_output().map_err(|e| {
            format!(
                "could not read stdout from extension adapter '{}': {e}",
                self.name
            )
        })?;
        if output.stdout.len() > MAX_STDOUT_BYTES {
            return Err(format!(
                "extension adapter '{}' returned too much output",
                self.name
            ));
        }
        String::from_utf8(output.stdout).map_err(|e| {
            format!(
                "extension adapter '{}' returned non-UTF-8 output: {e}",
                self.name
            )
        })
    }

    fn detect_builtin(&self, builtin: BuiltinAdapter, text: &str) -> Result<Vec<Span>, String> {
        let spans = match builtin {
            BuiltinAdapter::PiiNer => detect_pii_ner(text)?,
        };
        if spans.len() > self.max_spans {
            return Err(format!(
                "extension adapter '{}' returned too many spans: {} > {}",
                self.name,
                spans.len(),
                self.max_spans
            ));
        }
        spans
            .into_iter()
            .map(|span| {
                adapter_span(
                    text,
                    AdapterSpan {
                        start: span.start,
                        end: span.end,
                        label: span.label,
                        category: Some("pii".to_string()),
                        confidence: Some(span.confidence.to_string()),
                    },
                    &self.name,
                )
            })
            .collect()
    }
}

#[cfg(feature = "ner")]
fn detect_pii_ner(text: &str) -> Result<Vec<BuiltinNerSpan>, String> {
    crate::model_ner::detect_pii(text).map(|spans| {
        spans
            .into_iter()
            .map(|span| BuiltinNerSpan {
                start: span.start,
                end: span.end,
                label: span.label,
                confidence: span.confidence,
            })
            .collect()
    })
}

#[cfg(not(feature = "ner"))]
fn detect_pii_ner(_text: &str) -> Result<Vec<BuiltinNerSpan>, String> {
    Err("builtin adapter 'pii-ner' requires a Pentect build with ner support".to_string())
}

struct BuiltinNerSpan {
    start: usize,
    end: usize,
    label: String,
    confidence: &'static str,
}

fn apply_adapter_child_env(command: &mut Command, id_or_name: &str) -> Result<(), String> {
    command.env_clear();
    for name in safe_adapter_env_names() {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let id = extension_id(id_or_name);
    let dirs = extension_runtime_dirs(&id)?;
    command.env(EXTENSION_NAME_ENV, id);
    command.env(EXTENSION_DATA_DIR_ENV, dirs.data_dir);
    command.env(EXTENSION_CACHE_DIR_ENV, dirs.cache_dir);
    command.env(EXTENSION_CONFIG_ENV, dirs.config_file);
    Ok(())
}

#[derive(Debug)]
struct ExtensionRuntimeDirs {
    data_dir: PathBuf,
    cache_dir: PathBuf,
    config_file: PathBuf,
}

fn extension_runtime_dirs(id_or_name: &str) -> Result<ExtensionRuntimeDirs, String> {
    let id = extension_id(id_or_name);
    let data_dir = PathBuf::from(PENTECT_DIR)
        .join(EXTENSIONS_DATA_DIR)
        .join(&id);
    let cache_dir = data_dir.join(EXTENSION_CACHE_DIR);
    std::fs::create_dir_all(&cache_dir).map_err(|e| {
        format!(
            "could not create extension data '{}': {e}",
            cache_dir.display()
        )
    })?;
    let config_file = data_dir.join(EXTENSION_CONFIG_FILE);
    Ok(ExtensionRuntimeDirs {
        data_dir,
        cache_dir,
        config_file,
    })
}

fn adapter_default_name(path: &Path) -> String {
    if path.file_name().and_then(|name| name.to_str()) == Some("adapter.toml") {
        if let Some(name) = path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .filter(|name| !name.trim().is_empty())
        {
            return name.to_string();
        }
    }
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("extension")
        .to_string()
}

fn extension_id(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in value.trim().chars() {
        let next = if ch.is_ascii_alphanumeric() {
            Some(ch.to_ascii_lowercase())
        } else if matches!(ch, '-' | '_' | '.' | ' ') {
            Some('-')
        } else {
            None
        };
        let Some(next) = next else {
            continue;
        };
        if next == '-' {
            if out.is_empty() || last_dash {
                continue;
            }
            last_dash = true;
        } else {
            last_dash = false;
        }
        out.push(next);
        if out.len() >= 64 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "extension".to_string()
    } else {
        out
    }
}

fn safe_adapter_env_names() -> &'static [&'static str] {
    if cfg!(windows) {
        &[
            "Path",
            "PATH",
            "PATHEXT",
            "SystemRoot",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
            "USERPROFILE",
        ]
    } else {
        &["PATH", "HOME", "SHELL", "TERM", "LANG", "LC_ALL", "TMPDIR"]
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterFile {
    schema: Option<String>,
    kind: Option<String>,
    name: Option<String>,
    command: Option<Vec<String>>,
    builtin: Option<String>,
    timeout_ms: Option<u64>,
    max_input_bytes: Option<usize>,
    max_spans: Option<usize>,
}

fn adapter_backend(
    path: &Path,
    command: Option<Vec<String>>,
    builtin: Option<&str>,
) -> Result<AdapterBackend, String> {
    match (command, builtin) {
        (Some(command), None) => {
            if command.is_empty() || command.iter().any(|part| part.is_empty()) {
                return Err(format!(
                    "extension adapter '{}' requires a non-empty command array",
                    path.display()
                ));
            }
            Ok(AdapterBackend::Command(command))
        }
        (None, Some(name)) => parse_builtin_adapter(name)
            .map(AdapterBackend::Builtin)
            .map_err(|e| format!("extension adapter '{}' {e}", path.display())),
        (Some(_), Some(_)) => Err(format!(
            "extension adapter '{}' must set either command or builtin, not both",
            path.display()
        )),
        (None, None) => Err(format!(
            "extension adapter '{}' requires command or builtin",
            path.display()
        )),
    }
}

fn parse_builtin_adapter(name: &str) -> Result<BuiltinAdapter, String> {
    match name {
        "pii-ner" => Ok(BuiltinAdapter::PiiNer),
        other => Err(format!("has unknown builtin adapter: {other}")),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterResponse {
    #[serde(default)]
    spans: Vec<AdapterSpan>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterSpan {
    start: usize,
    end: usize,
    label: String,
    category: Option<String>,
    confidence: Option<String>,
}

fn adapter_span(raw: &str, span: AdapterSpan, adapter: &str) -> Result<Span, String> {
    if span.start >= span.end
        || span.end > raw.len()
        || !raw.is_char_boundary(span.start)
        || !raw.is_char_boundary(span.end)
    {
        return Err(format!(
            "extension adapter '{adapter}' returned an invalid byte span {}..{}",
            span.start, span.end
        ));
    }
    Ok(Span {
        range: ByteRange::new(span.start, span.end),
        category: parse_category(span.category.as_deref().unwrap_or("pii"), adapter)?,
        label: normalize_label(&span.label),
        confidence: parse_confidence(span.confidence.as_deref().unwrap_or("medium"), adapter)?,
        source: DetectorId::Extension,
    })
}

fn normalize_label(value: &str) -> String {
    let up: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    let mut out = String::new();
    let mut last_underscore = false;
    for ch in up.trim_matches('_').chars() {
        if ch == '_' {
            if !last_underscore {
                out.push(ch);
            }
            last_underscore = true;
        } else {
            out.push(ch);
            last_underscore = false;
        }
    }
    match out.chars().next() {
        Some(ch) if ch.is_ascii_alphabetic() => out,
        _ => "EXTENSION_VALUE".to_string(),
    }
}

fn parse_category(value: &str, adapter: &str) -> Result<Category, String> {
    match value.to_ascii_lowercase().as_str() {
        "secret" => Ok(Category::Secret),
        "identifier" => Ok(Category::Identifier),
        "endpoint" => Ok(Category::Endpoint),
        "pii" => Ok(Category::Pii),
        "other" => Ok(Category::Other),
        other => Err(format!(
            "extension adapter '{adapter}' returned unknown category: {other}"
        )),
    }
}

fn parse_confidence(value: &str, adapter: &str) -> Result<Confidence, String> {
    match value.to_ascii_lowercase().as_str() {
        "high" => Ok(Confidence::High),
        "medium" => Ok(Confidence::Medium),
        "low" => Ok(Confidence::Low),
        other => Err(format!(
            "extension adapter '{adapter}' returned unknown confidence: {other}"
        )),
    }
}

fn kind_name(kind: &Kind) -> String {
    match kind {
        Kind::Text => "text".to_string(),
        Kind::Json => "json".to_string(),
        Kind::Ndjson => "ndjson".to_string(),
        Kind::ToolResult => "tool_result".to_string(),
        Kind::Env => "env".to_string(),
        Kind::Har => "har".to_string(),
        Kind::Curl => "curl".to_string(),
        Kind::Markdown => "markdown".to_string(),
        Kind::Other(name) => name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentect_core::{Config, Engine, Input, Profile};

    #[test]
    fn adapter_spans_mask_through_core_renderer() {
        let adapter = ModelAdapter {
            name: "test-ner".to_string(),
            id: "test-ner".to_string(),
            path: std::env::current_dir().unwrap().join("adapter.toml"),
            backend: AdapterBackend::Command(echo_adapter_command(
                r#"{"spans":[{"start":0,"end":5,"label":"person name","category":"pii","confidence":"high"}]}"#,
            )),
            timeout: Duration::from_secs(3),
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_spans: DEFAULT_MAX_SPANS,
        };
        let adapters = ModelAdapters {
            adapters: vec![adapter],
        };
        let engine = Engine::with_profile(Profile::Strict);
        let result = adapters
            .mask(
                &engine,
                Input::text("Alice met Bob"),
                None,
                &Config::insecure_testing(),
            )
            .unwrap()
            .unwrap();
        assert!(!result.masked.contains("Alice"), "{}", result.masked);
        assert!(
            result.masked.contains("<<PERSON_NAME_"),
            "{}",
            result.masked
        );
    }

    #[test]
    fn invalid_adapter_span_is_rejected() {
        let err = adapter_span(
            "abc",
            AdapterSpan {
                start: 0,
                end: 99,
                label: "x".to_string(),
                category: None,
                confidence: None,
            },
            "bad",
        )
        .unwrap_err();
        assert!(err.contains("invalid byte span"), "{err}");
    }

    #[test]
    fn adapter_env_does_not_inherit_in_memory_manager_credentials() {
        let mut command = Command::new("echo");
        apply_adapter_child_env(&mut command, "test-env").unwrap();
        let names = command
            .get_envs()
            .map(|(name, _)| name.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_IN_MEMORY_MANAGER_ADDR"));
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_IN_MEMORY_MANAGER_TOKEN"));
    }

    #[test]
    fn adapter_env_exposes_project_local_extension_data() {
        let mut command = Command::new("echo");
        apply_adapter_child_env(&mut command, "My Ext!").unwrap();
        let envs = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().to_string(),
                    value
                        .map(|value| value.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_default(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            envs.get(EXTENSION_NAME_ENV).map(String::as_str),
            Some("my-ext")
        );
        assert!(
            envs.get(EXTENSION_DATA_DIR_ENV)
                .is_some_and(|path| path.ends_with(".pentect/extensions-data/my-ext")),
            "{envs:?}"
        );
        assert!(
            envs.get(EXTENSION_CACHE_DIR_ENV)
                .is_some_and(|path| path.ends_with(".pentect/extensions-data/my-ext/cache")),
            "{envs:?}"
        );
        assert!(
            envs.get(EXTENSION_CONFIG_ENV)
                .is_some_and(|path| path.ends_with(".pentect/extensions-data/my-ext/config.toml")),
            "{envs:?}"
        );
    }

    #[cfg(windows)]
    fn echo_adapter_command(json: &str) -> Vec<String> {
        vec![
            "powershell".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            format!(
                "$Input | Out-Null; [Console]::Out.Write('{}')",
                json.replace('\'', "''")
            ),
        ]
    }

    #[cfg(not(windows))]
    fn echo_adapter_command(json: &str) -> Vec<String> {
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "cat >/dev/null; printf '%s' '{}'",
                json.replace('\'', "'\\''")
            ),
        ]
    }
}
