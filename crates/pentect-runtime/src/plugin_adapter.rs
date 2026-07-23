use pentect_core::{
    ByteRange, Category, Confidence, Config, Context, DetectorId, Engine, Input, Kind, MaskResult,
    Span,
};
use serde::Deserialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub(crate) const BINARIES_ENV: &str = "PENTECT_PLUGIN_BINARIES";

const PENTECT_DIR: &str = ".pentect";
const PLUGINS_DATA_DIR: &str = "plugins-data";
const PLUGIN_CONFIG_FILE: &str = "config.toml";
const PLUGIN_CACHE_DIR: &str = "cache";
const PLUGIN_NAME_ENV: &str = "PENTECT_PLUGIN_NAME";
const PLUGIN_DATA_DIR_ENV: &str = "PENTECT_PLUGIN_DATA_DIR";
const PLUGIN_CACHE_DIR_ENV: &str = "PENTECT_PLUGIN_CACHE_DIR";
const PLUGIN_CONFIG_ENV: &str = "PENTECT_PLUGIN_CONFIG";
const DEFAULT_TIMEOUT_MS: u64 = 10_000;
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
        let Some(value) = std::env::var_os(BINARIES_ENV) else {
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
    command: Vec<String>,
    timeout: Duration,
    max_input_bytes: usize,
    max_spans: usize,
}

impl ModelAdapter {
    fn load(path: &Path) -> Result<Self, String> {
        if !path.is_file() {
            return Err(format!(
                "plugin manifest does not exist: {}",
                path.display()
            ));
        }
        let src = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read plugin manifest '{}': {e}", path.display()))?;
        let file: PluginFile = toml::from_str(&src)
            .map_err(|e| format!("plugin manifest '{}' is invalid: {e}", path.display()))?;
        if file.schema.as_deref() != Some("pentect.plugin.v1") {
            return Err(format!(
                "plugin manifest '{}' requires schema = \"pentect.plugin.v1\"",
                path.display()
            ));
        }
        let name = file
            .name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| adapter_default_name(path));
        let id = plugin_id(&name);
        let binary = file
            .binary
            .filter(|binary| !binary.trim().is_empty())
            .ok_or_else(|| format!("plugin '{name}' requires binary"))?;
        let execution = file.execution.unwrap_or_default();
        let command = binary_command(&name, &binary, execution.args)?;
        Ok(Self {
            name,
            id,
            path: path.to_path_buf(),
            command,
            timeout: Duration::from_millis(execution.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
            max_input_bytes: execution.max_input_bytes.unwrap_or(DEFAULT_MAX_INPUT_BYTES),
            max_spans: execution.max_spans.unwrap_or(DEFAULT_MAX_SPANS),
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
        let parsed: AdapterResponse = serde_json::from_str(&response)
            .map_err(|e| format!("plugin '{}' returned invalid JSON: {e}", self.name))?;
        if parsed.spans.len() > self.max_spans {
            return Err(format!(
                "plugin '{}' returned too many spans: {} > {}",
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
        let cwd = self.path.parent().unwrap_or_else(|| Path::new("."));
        let program = adapter_program(&self.command[0], cwd, &self.id);
        let mut cmd = Command::new(program);
        apply_adapter_child_env(&mut cmd, &self.id)?;
        cmd.args(&self.command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(parent) = self.path.parent() {
            cmd.current_dir(parent);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("could not start plugin '{}': {e}", self.name))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("could not open stdout for plugin '{}'", self.name))?;
        let stdout_reader = spawn_adapter_stdout_reader(stdout);
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("could not open stdin for plugin '{}'", self.name))?;
        let stdin_writer = spawn_adapter_stdin_writer(stdin, request.as_bytes().to_vec());

        let status = match wait_for_adapter_child(&mut child, &self.name, self.timeout) {
            Ok(status) => status,
            Err(err) => {
                let _ = join_adapter_stdin(stdin_writer, &self.name);
                let _ = join_adapter_stdout(stdout_reader, &self.name);
                return Err(err);
            }
        };
        join_adapter_stdin(stdin_writer, &self.name)?;
        let stdout = join_adapter_stdout(stdout_reader, &self.name)?;
        if stdout.len() > MAX_STDOUT_BYTES {
            return Err(format!("plugin '{}' returned too much output", self.name));
        }
        if !status.success() {
            return Err(format!(
                "plugin '{}' exited with status {status}",
                self.name
            ));
        }
        String::from_utf8(stdout)
            .map_err(|e| format!("plugin '{}' returned non-UTF-8 output: {e}", self.name))
    }
}

fn spawn_adapter_stdin_writer(
    mut stdin: ChildStdin,
    request: Vec<u8>,
) -> JoinHandle<Result<(), String>> {
    std::thread::spawn(move || {
        use std::io::Write as _;
        stdin
            .write_all(&request)
            .map_err(|e| format!("could not write plugin stdin: {e}"))
    })
}

fn spawn_adapter_stdout_reader(stdout: ChildStdout) -> JoinHandle<Result<Vec<u8>, String>> {
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut stdout = stdout.take(MAX_STDOUT_BYTES as u64 + 1);
        let mut out = Vec::new();
        stdout
            .read_to_end(&mut out)
            .map_err(|e| format!("could not read plugin stdout: {e}"))?;
        Ok(out)
    })
}

fn wait_for_adapter_child(
    child: &mut Child,
    name: &str,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("plugin '{name}' timed out"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not wait for plugin '{name}': {e}"));
            }
        }
    }
}

fn join_adapter_stdin(writer: JoinHandle<Result<(), String>>, name: &str) -> Result<(), String> {
    writer
        .join()
        .map_err(|_| format!("plugin '{name}' stdin writer panicked"))?
        .map_err(|e| format!("plugin '{name}' {e}"))
}

fn join_adapter_stdout(
    reader: JoinHandle<Result<Vec<u8>, String>>,
    name: &str,
) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| format!("plugin '{name}' stdout reader panicked"))?
        .map_err(|e| format!("plugin '{name}' {e}"))
}

fn apply_adapter_child_env(command: &mut Command, id_or_name: &str) -> Result<(), String> {
    command.env_clear();
    for name in safe_adapter_env_names() {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let id = plugin_id(id_or_name);
    let dirs = plugin_runtime_dirs(&id)?;
    command.env(PLUGIN_NAME_ENV, id);
    command.env(PLUGIN_DATA_DIR_ENV, dirs.data_dir);
    command.env(PLUGIN_CACHE_DIR_ENV, dirs.cache_dir);
    command.env(PLUGIN_CONFIG_ENV, dirs.config_file);
    Ok(())
}

#[derive(Debug)]
struct PluginRuntimeDirs {
    data_dir: PathBuf,
    cache_dir: PathBuf,
    config_file: PathBuf,
}

fn plugin_runtime_dirs(id_or_name: &str) -> Result<PluginRuntimeDirs, String> {
    let id = plugin_id(id_or_name);
    let data_dir = std::env::current_dir()
        .map_err(|e| format!("could not resolve plugin data directory: {e}"))?
        .join(PENTECT_DIR)
        .join(PLUGINS_DATA_DIR)
        .join(&id);
    let cache_dir = data_dir.join(PLUGIN_CACHE_DIR);
    std::fs::create_dir_all(&cache_dir).map_err(|e| {
        format!(
            "could not create plugin data '{}': {e}",
            cache_dir.display()
        )
    })?;
    let config_file = data_dir.join(PLUGIN_CONFIG_FILE);
    Ok(PluginRuntimeDirs {
        data_dir,
        cache_dir,
        config_file,
    })
}

fn adapter_default_name(path: &Path) -> String {
    if path.file_name().and_then(|name| name.to_str()) == Some("plugin.toml") {
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
        .unwrap_or("plugin")
        .to_string()
}

fn adapter_program(program: &str, cwd: &Path, id: &str) -> PathBuf {
    let path = Path::new(program);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    if looks_like_path_command(program) {
        return cwd.join(path);
    }
    installed_plugin_program(program, id)
        .or_else(|| adapter_sidecar_program(program))
        .unwrap_or_else(|| path.to_path_buf())
}

fn installed_plugin_program(program: &str, id: &str) -> Option<PathBuf> {
    let bin = PathBuf::from(PENTECT_DIR)
        .join(PLUGINS_DATA_DIR)
        .join(plugin_id(id))
        .join("bin");
    for name in command_names(program) {
        let candidate = bin.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn looks_like_path_command(program: &str) -> bool {
    program.contains('/') || program.contains('\\')
}

fn adapter_sidecar_program(program: &str) -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    for name in command_names(program) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(windows)]
fn command_names(name: &str) -> Vec<String> {
    if Path::new(name).extension().is_some() {
        return vec![name.to_string()];
    }
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    pathext
        .split(';')
        .filter(|ext| !ext.is_empty())
        .map(|ext| format!("{name}{ext}"))
        .collect()
}

#[cfg(not(windows))]
fn command_names(name: &str) -> Vec<String> {
    vec![name.to_string()]
}

fn plugin_id(value: &str) -> String {
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
        "plugin".to_string()
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
struct PluginFile {
    schema: Option<String>,
    name: Option<String>,
    binary: Option<String>,
    execution: Option<ExecutionFile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionFile {
    #[serde(default)]
    args: Vec<String>,
    timeout_ms: Option<u64>,
    max_input_bytes: Option<usize>,
    max_spans: Option<usize>,
}

fn binary_command(name: &str, binary: &str, args: Vec<String>) -> Result<Vec<String>, String> {
    if binary.is_empty()
        || binary.len() > 128
        || binary.contains('/')
        || binary.contains('\\')
        || !binary
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        || args.iter().any(|arg| arg.contains('\0'))
    {
        return Err(format!("plugin '{name}' has an invalid binary name"));
    }
    let filename = if cfg!(windows) && !binary.to_ascii_lowercase().ends_with(".exe") {
        format!("{binary}.exe")
    } else {
        binary.to_string()
    };
    let program = plugin_runtime_dirs(name)?
        .data_dir
        .join("bin")
        .join(filename);
    let mut command = Vec::with_capacity(args.len() + 1);
    command.push(program.to_string_lossy().into_owned());
    command.extend(args);
    Ok(command)
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
            "plugin '{adapter}' returned an invalid byte span {}..{}",
            span.start, span.end
        ));
    }
    Ok(Span {
        range: ByteRange::new(span.start, span.end),
        category: parse_category(span.category.as_deref().unwrap_or("pii"), adapter)?,
        label: normalize_label(&span.label),
        confidence: parse_confidence(span.confidence.as_deref().unwrap_or("medium"), adapter)?,
        source: DetectorId::Plugin,
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
        _ => "PLUGIN_VALUE".to_string(),
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
            "plugin '{adapter}' returned unknown category: {other}"
        )),
    }
}

fn parse_confidence(value: &str, adapter: &str) -> Result<Confidence, String> {
    match value.to_ascii_lowercase().as_str() {
        "high" => Ok(Confidence::High),
        "medium" => Ok(Confidence::Medium),
        "low" => Ok(Confidence::Low),
        other => Err(format!(
            "plugin '{adapter}' returned unknown confidence: {other}"
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
            path: std::env::current_dir().unwrap().join("plugin.toml"),
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
    fn plugin_manifest_rejects_invalid_binary() {
        let root = std::env::temp_dir().join(format!(
            "pentect-invalid-binary-reject-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("plugin.toml");
        std::fs::write(
            &path,
            "schema = \"pentect.plugin.v1\"\nname = \"bad\"\nbinary = \"../tool\"\n",
        )
        .unwrap();
        let err = ModelAdapter::load(&path).unwrap_err();
        std::fs::remove_dir_all(root).unwrap();
        assert!(err.contains("invalid binary name"), "{err}");
    }

    #[test]
    fn plugin_manifest_requires_schema() {
        let root = std::env::temp_dir().join(format!(
            "pentect-plugin-requires-schema-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("plugin.toml");
        std::fs::write(&path, "name = \"bad\"\nbinary = \"tool\"\n").unwrap();
        let err = ModelAdapter::load(&path).unwrap_err();
        std::fs::remove_dir_all(root).unwrap();
        assert!(
            err.contains("requires schema = \"pentect.plugin.v1\""),
            "{err}"
        );
    }

    #[test]
    fn binary_is_scoped_to_plugin_data() {
        let command = binary_command("pii-ner", "pentect-pii-ner", Vec::new()).unwrap();
        let expected = std::env::current_dir()
            .unwrap()
            .join(".pentect")
            .join("plugins-data")
            .join("pii-ner")
            .join("bin")
            .join(if cfg!(windows) {
                "pentect-pii-ner.exe"
            } else {
                "pentect-pii-ner"
            });
        assert_eq!(PathBuf::from(&command[0]), expected);
    }

    #[test]
    fn adapter_env_does_not_inherit_memory_store_credentials() {
        let mut command = Command::new("echo");
        apply_adapter_child_env(&mut command, "test-env").unwrap();
        let names = command
            .get_envs()
            .map(|(name, _)| name.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(!names.iter().any(|name| name == "PENTECT_MEMORY_STORE_ADDR"));
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_MEMORY_STORE_TOKEN"));
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_PROCESS_HOST_READ_TOKEN"));
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_PROCESS_HOST_WRITE_TOKEN"));
    }

    #[test]
    fn adapter_env_exposes_project_local_plugin_data() {
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
            envs.get(PLUGIN_NAME_ENV).map(String::as_str),
            Some("my-ext")
        );
        assert!(
            envs.get(PLUGIN_DATA_DIR_ENV)
                .is_some_and(|path| path.ends_with(".pentect/plugins-data/my-ext")),
            "{envs:?}"
        );
        assert!(
            envs.get(PLUGIN_CACHE_DIR_ENV)
                .is_some_and(|path| path.ends_with(".pentect/plugins-data/my-ext/cache")),
            "{envs:?}"
        );
        assert!(
            envs.get(PLUGIN_CONFIG_ENV)
                .is_some_and(|path| path.ends_with(".pentect/plugins-data/my-ext/config.toml")),
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
