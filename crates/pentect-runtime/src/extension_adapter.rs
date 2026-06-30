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
    path: PathBuf,
    command: Vec<String>,
    timeout: Duration,
    max_input_bytes: usize,
    max_spans: usize,
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
        if file.command.is_empty() || file.command.iter().any(|part| part.is_empty()) {
            return Err(format!(
                "extension adapter '{}' requires a non-empty command array",
                path.display()
            ));
        }
        Ok(Self {
            name: file
                .name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| {
                    path.file_stem()
                        .and_then(|stem| stem.to_str())
                        .unwrap_or("adapter")
                        .to_string()
                }),
            path: path.to_path_buf(),
            command: file.command,
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
        let mut cmd = Command::new(&self.command[0]);
        apply_adapter_child_env(&mut cmd);
        cmd.args(&self.command[1..])
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
}

fn apply_adapter_child_env(command: &mut Command) {
    command.env_clear();
    for name in safe_adapter_env_names() {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
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
    command: Vec<String>,
    timeout_ms: Option<u64>,
    max_input_bytes: Option<usize>,
    max_spans: Option<usize>,
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
            path: std::env::current_dir().unwrap().join("adapter.toml"),
            command: echo_adapter_command(
                r#"{"spans":[{"start":0,"end":5,"label":"person name","category":"pii","confidence":"high"}]}"#,
            ),
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
    fn adapter_env_does_not_inherit_memory_vault_credentials() {
        let mut command = Command::new("echo");
        apply_adapter_child_env(&mut command);
        let names = command
            .get_envs()
            .map(|(name, _)| name.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(!names.iter().any(|name| name == "PENTECT_MEMORY_VAULT_ADDR"));
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_MEMORY_VAULT_TOKEN"));
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
