use crate::{embedded_ipv4, read_bounded_bytes, read_bounded_utf8};
use pentect_core::{
    ByteRange, Category, Confidence, Config, Context, DetectorId, Engine, Input, Kind, MaskResult,
    Span,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const BINARIES_ENV: &str = "PENTECT_PLUGIN_BINARIES";

const PLUGIN_APPROVAL_FILE: &str = "approval.toml";
const PLUGIN_BINARY_LOCK_FILE: &str = "binary.lock";
const PLUGIN_CACHE_DIR: &str = "cache";
const PLUGIN_CONFIG_FILE: &str = "config.toml";
const MAX_PLUGIN_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_PLUGIN_METADATA_BYTES: u64 = 64 * 1024;
const MAX_PLUGIN_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_PLUGIN_WASM_BYTES: u64 = 32 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_MAX_INPUT_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_SPANS: usize = 512;
const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_PLUGIN_INPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PLUGIN_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PLUGIN_SPANS: usize = 4096;
const PROTOCOL_SCHEMA: &str = "pentect.plugin.v1";
pub const DEFAULT_PUBLISHER_WORKFLOW: &str = ".github/workflows/release.yml";
static REQUEST_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE_PLUGIN_DNS_THREADS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MiddlewareStage {
    Prepare,
    Inspect,
    Finalize,
    Request,
    Response,
    ToolCall,
    File,
}

impl MiddlewareStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Inspect => "inspect",
            Self::Finalize => "finalize",
            Self::Request => "request",
            Self::Response => "response",
            Self::ToolCall => "tool_call",
            Self::File => "file",
        }
    }

    fn export_name(self) -> &'static str {
        match self {
            Self::Prepare => "pentect_prepare",
            Self::Inspect => "pentect_inspect",
            Self::Finalize => "pentect_finalize",
            Self::Request => "pentect_request",
            Self::Response => "pentect_response",
            Self::ToolCall => "pentect_tool_call",
            Self::File => "pentect_file",
        }
    }

    fn from_export_name(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|hook| hook.export_name() == value)
    }

    const ALL: [Self; 7] = [
        Self::Prepare,
        Self::Inspect,
        Self::Finalize,
        Self::Request,
        Self::Response,
        Self::ToolCall,
        Self::File,
    ];
}

pub fn inspect_wasm_plugin_hooks(bytes: &[u8]) -> Result<Vec<String>, String> {
    let engine = wasmi::Engine::default();
    let module = wasmi::Module::new(&engine, bytes)
        .map_err(|error| format!("WebAssembly plugin is invalid: {error}"))?;
    Ok(validated_module_hooks(&module, "WebAssembly plugin")?
        .into_iter()
        .map(|hook| hook.as_str().to_string())
        .collect())
}

/// Validate and invoke a local development module without installing it.
///
/// This intentionally grants no network access. Configuration reads return
/// from an empty table, so author tests cannot reach user state.
pub fn test_local_wasm_plugin(bytes: &[u8], name: &str) -> Result<usize, String> {
    let wasm = WasmProgram::load_bytes(
        bytes,
        name,
        None,
        Some(toml::Value::Table(toml::map::Map::new())),
    )?;
    let hooks = wasm.hooks.clone();
    PluginMiddleware {
        plugins: vec![PluginBinary {
            name: name.to_string(),
            wasm,
            hooks,
            required: true,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_spans: DEFAULT_MAX_SPANS,
        }],
    }
    .test_hooks()
}

fn validated_module_hooks(
    module: &wasmi::Module,
    name: &str,
) -> Result<BTreeSet<MiddlewareStage>, String> {
    let mut hooks = BTreeSet::new();
    let mut has_memory = false;
    let mut has_alloc = false;
    for export in module.exports() {
        if export.name() == WASM_ABI_MEMORY {
            has_memory = export.ty().memory().is_some();
        }
        if export.name() == WASM_ABI_ALLOC {
            has_alloc = export.ty().func().is_some_and(|function| {
                function.params() == [wasmi::ValType::I32]
                    && function.results() == [wasmi::ValType::I32]
            });
        }
        let Some(hook) = MiddlewareStage::from_export_name(export.name()) else {
            continue;
        };
        let valid = export.ty().func().is_some_and(|function| {
            function.params() == [wasmi::ValType::I32, wasmi::ValType::I32]
                && function.results() == [wasmi::ValType::I64]
        });
        if !valid {
            return Err(format!(
                "{name} exports {} with the wrong signature",
                hook.export_name()
            ));
        }
        hooks.insert(hook);
    }
    if !has_memory {
        return Err(format!("{name} does not export memory"));
    }
    if !has_alloc {
        return Err(format!(
            "{name} does not export {WASM_ABI_ALLOC}(i32) -> i32"
        ));
    }
    if hooks.is_empty() {
        return Err(format!("{name} does not export a Pentect hook"));
    }
    Ok(hooks)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MiddlewareCoverage {
    Full,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopOutcome {
    Block,
    Respond,
}

#[derive(Debug)]
pub struct MiddlewareRun {
    pub payload: Value,
    pub coverage: MiddlewareCoverage,
    pub stopped: Option<StopOutcome>,
    pub message: Option<String>,
}

pub struct DetectRun {
    pub result: Option<MaskResult>,
    pub coverage: MiddlewareCoverage,
}

pub struct DetectSpansRun {
    pub spans: Vec<Span>,
    pub coverage: MiddlewareCoverage,
}

#[derive(Clone, Debug, Default)]
pub struct PluginMiddleware {
    plugins: Vec<PluginBinary>,
}

impl PluginMiddleware {
    pub fn from_env() -> Result<Self, String> {
        let Some(value) = std::env::var_os(BINARIES_ENV) else {
            return Ok(Self::default());
        };
        Self::from_paths(std::env::split_paths(&value).filter(|path| !path.as_os_str().is_empty()))
    }

    pub fn from_paths(paths: impl IntoIterator<Item = PathBuf>) -> Result<Self, String> {
        let plugins = paths
            .into_iter()
            .map(|path| PluginBinary::load(&path))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { plugins })
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    pub fn has_hook(&self, hook: MiddlewareStage) -> bool {
        self.plugins
            .iter()
            .any(|plugin| plugin.hooks.contains(&hook))
    }

    /// Invoke every exported hook once with a value-free fixture. This checks
    /// the actual ABI and handler, not only module loading.
    pub fn test_hooks(&self) -> Result<usize, String> {
        let mut invoked = 0;
        for plugin in &self.plugins {
            for hook in plugin.hooks.iter().copied() {
                let payload = hook_test_input(hook);
                let response = plugin.invoke(hook, &payload, None)?;
                if response.action == Action::Stop {
                    let outcome = response.outcome.unwrap_or(StopOutcomeFile::Block);
                    if matches!(outcome, StopOutcomeFile::Respond)
                        && hook != MiddlewareStage::Request
                    {
                        return Err(format!(
                            "plugin '{}' can only respond from the request hook",
                            plugin.name
                        ));
                    }
                }
                if hook == MiddlewareStage::Inspect {
                    let text = payload
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    for span in response.spans {
                        plugin_span(text, span, &plugin.name)?;
                    }
                }
                invoked += 1;
            }
        }
        Ok(invoked)
    }

    pub fn run(
        &self,
        hook: MiddlewareStage,
        mut payload: Value,
        context: Option<Value>,
    ) -> Result<MiddlewareRun, String> {
        let mut coverage = MiddlewareCoverage::Full;
        for plugin in self
            .plugins
            .iter()
            .filter(|plugin| plugin.hooks.contains(&hook))
        {
            let response = match plugin.invoke(hook, &payload, context.as_ref()) {
                Ok(response) => response,
                Err(error) if !plugin.required => {
                    coverage = MiddlewareCoverage::Partial;
                    eprintln!(
                        "[pentect] optional plugin '{}' skipped: {error}",
                        plugin.name
                    );
                    continue;
                }
                Err(error) => return Err(error),
            };
            let stop = if response.action == Action::Stop {
                let outcome = response.outcome.unwrap_or(StopOutcomeFile::Block);
                if matches!(outcome, StopOutcomeFile::Respond) && hook != MiddlewareStage::Request {
                    let error = format!(
                        "plugin '{}' can only respond from the request hook",
                        plugin.name
                    );
                    if plugin.required {
                        return Err(error);
                    }
                    coverage = MiddlewareCoverage::Partial;
                    eprintln!("[pentect] optional {error}");
                    continue;
                }
                Some(outcome)
            } else {
                None
            };
            if let Some(next_payload) = response.payload {
                payload = next_payload;
            }
            if let Some(outcome) = stop {
                return Ok(MiddlewareRun {
                    payload,
                    coverage,
                    stopped: Some(outcome.into()),
                    message: response.message,
                });
            }
        }
        Ok(MiddlewareRun {
            payload,
            coverage,
            stopped: None,
            message: None,
        })
    }

    pub fn detect_and_mask(
        &self,
        engine: &Engine,
        input: Input,
        context: Option<&Context>,
        cfg: &Config,
    ) -> Result<DetectRun, String> {
        let detected = self.detect_spans(&input, context)?;
        let result =
            (!detected.spans.is_empty()).then(|| engine.mask_spans(input, detected.spans, cfg));
        Ok(DetectRun {
            result,
            coverage: detected.coverage,
        })
    }

    pub fn detect_spans(
        &self,
        input: &Input,
        context: Option<&Context>,
    ) -> Result<DetectSpansRun, String> {
        let mut spans = Vec::new();
        let mut coverage = MiddlewareCoverage::Full;
        let plugins = self
            .plugins
            .iter()
            .filter(|plugin| plugin.hooks.contains(&MiddlewareStage::Inspect))
            .collect::<Vec<_>>();
        for plugin in plugins {
            if input.data.len() > plugin.max_input_bytes {
                if plugin.required {
                    return Err(format!(
                        "required plugin '{}' input exceeds its limit",
                        plugin.name
                    ));
                }
                coverage = MiddlewareCoverage::Partial;
                continue;
            }
            let payload = json!({
                "kind": kind_name(&input.kind),
                "text": input.data,
            });
            let metadata = context
                .map(serde_json::to_value)
                .transpose()
                .map_err(|error| format!("plugin context encode failed: {error}"))?;
            let response =
                match plugin.invoke(MiddlewareStage::Inspect, &payload, metadata.as_ref()) {
                    Ok(response) => response,
                    Err(error) if !plugin.required => {
                        coverage = MiddlewareCoverage::Partial;
                        eprintln!(
                            "[pentect] optional plugin '{}' skipped: {error}",
                            plugin.name
                        );
                        continue;
                    }
                    Err(error) => return Err(error),
                };
            if response.action == Action::Stop {
                let outcome = response.outcome.unwrap_or(StopOutcomeFile::Block);
                if matches!(outcome, StopOutcomeFile::Respond) {
                    let error = format!(
                        "plugin '{}' can only respond from the request hook",
                        plugin.name
                    );
                    if plugin.required {
                        return Err(error);
                    }
                    coverage = MiddlewareCoverage::Partial;
                    eprintln!("[pentect] optional {error}");
                    continue;
                }
                return Err(format!(
                    "plugin blocked: {}: {}",
                    plugin.name,
                    response
                        .message
                        .unwrap_or_else(|| "request blocked".to_string())
                ));
            }
            if response.payload.is_some() {
                let error = format!(
                    "plugin '{}' cannot replace input from the inspect hook; add findings instead",
                    plugin.name
                );
                if plugin.required {
                    return Err(error);
                }
                coverage = MiddlewareCoverage::Partial;
                eprintln!("[pentect] optional {error}");
                continue;
            }
            if response.spans.len() > plugin.max_spans {
                let error = format!(
                    "plugin '{}' returned too many spans: {} > {}",
                    plugin.name,
                    response.spans.len(),
                    plugin.max_spans
                );
                if plugin.required {
                    return Err(error);
                }
                coverage = MiddlewareCoverage::Partial;
                eprintln!("[pentect] optional {error}");
                continue;
            }
            let plugin_spans = response
                .spans
                .into_iter()
                .map(|span| plugin_span(&input.data, span, &plugin.name))
                .collect::<Result<Vec<_>, _>>();
            match plugin_spans {
                Ok(plugin_spans) => spans.extend(plugin_spans),
                Err(error) if !plugin.required => {
                    coverage = MiddlewareCoverage::Partial;
                    eprintln!(
                        "[pentect] optional plugin '{}' skipped: {error}",
                        plugin.name
                    );
                }
                Err(error) => return Err(error),
            }
        }
        Ok(DetectSpansRun { spans, coverage })
    }
}

fn hook_test_input(hook: MiddlewareStage) -> Value {
    match hook {
        MiddlewareStage::Request | MiddlewareStage::Response => {
            json!({"model": "pentect-plugin-test", "messages": []})
        }
        MiddlewareStage::ToolCall => {
            json!({"type": "function_call", "name": "pentect_plugin_test", "arguments": "{}"})
        }
        MiddlewareStage::File => {
            json!({"filename": "test.txt", "media_type": "text/plain", "size": 4})
        }
        MiddlewareStage::Prepare | MiddlewareStage::Finalize | MiddlewareStage::Inspect => {
            json!({"kind": "text", "text": "Alice Smith"})
        }
    }
}

#[derive(Clone, Debug)]
struct PluginBinary {
    name: String,
    wasm: WasmProgram,
    hooks: BTreeSet<MiddlewareStage>,
    required: bool,
    timeout: Duration,
    max_input_bytes: usize,
    max_output_bytes: usize,
    max_spans: usize,
}

impl PluginBinary {
    fn load(path: &Path) -> Result<Self, String> {
        if !path.is_file() {
            return Err(format!(
                "plugin manifest does not exist: {}",
                path.display()
            ));
        }
        let source = read_bounded_utf8(path, MAX_PLUGIN_MANIFEST_BYTES, "plugin manifest")?;
        let file: PluginFile = toml::from_str(&source)
            .map_err(|error| format!("plugin manifest '{}' is invalid: {error}", path.display()))?;
        if file.schema.as_deref() != Some("pentect.plugin.v1") {
            return Err(format!(
                "plugin manifest '{}' requires schema = \"pentect.plugin.v1\"",
                path.display()
            ));
        }
        if !file.postscript.is_empty() {
            return Err(format!(
                "plugin '{}' contains unsupported postscripts",
                path.display()
            ));
        }
        let name = file
            .name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| plugin_default_name(path));
        let binary = file
            .binary
            .filter(|binary| !binary.trim().is_empty())
            .ok_or_else(|| format!("plugin '{name}' requires binary"))?;
        let publisher_workflow = file
            .publisher
            .as_ref()
            .and_then(|publisher| publisher.workflow.as_deref())
            .unwrap_or(DEFAULT_PUBLISHER_WORKFLOW);
        if !valid_plugin_publisher_workflow(publisher_workflow) {
            return Err(format!(
                "plugin '{name}' publisher workflow must be a repository-relative YAML path"
            ));
        }
        if !binary.to_ascii_lowercase().ends_with(".wasm") {
            return Err(format!(
                "plugin '{name}' binary must be a portable .wasm module"
            ));
        }
        let execution = file.execution.unwrap_or_default();
        if execution
            .runtime
            .as_deref()
            .is_some_and(|value| value != "wasm")
        {
            return Err(format!(
                "plugin '{name}' only supports execution.runtime = \"wasm\""
            ));
        }
        if execution
            .mode
            .as_deref()
            .is_some_and(|value| value != "oneshot")
        {
            return Err(format!(
                "plugin '{name}' only supports execution.mode = \"oneshot\""
            ));
        }
        if !execution.args.is_empty() {
            return Err(format!(
                "plugin '{name}' WebAssembly execution cannot use args"
            ));
        }
        let timeout_ms = execution.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        let max_input_bytes = execution.max_input_bytes.unwrap_or(DEFAULT_MAX_INPUT_BYTES);
        let max_output_bytes = execution
            .max_output_bytes
            .unwrap_or(DEFAULT_MAX_OUTPUT_BYTES);
        let max_spans = execution.max_spans.unwrap_or(DEFAULT_MAX_SPANS);
        if timeout_ms == 0
            || timeout_ms > MAX_TIMEOUT_MS
            || max_input_bytes == 0
            || max_input_bytes > MAX_PLUGIN_INPUT_BYTES
            || max_output_bytes == 0
            || max_output_bytes > MAX_PLUGIN_OUTPUT_BYTES
            || max_spans == 0
            || max_spans > MAX_PLUGIN_SPANS
        {
            return Err(format!(
                "plugin '{name}' execution limits exceed Pentect's sandbox limits"
            ));
        }
        let network = validate_network(&name, file.network)?;
        let runtime_dirs = plugin_runtime_dirs_for_manifest(&name, path)?;
        let wasm_path = wasm_binary_path(&name, &binary, &runtime_dirs)?;
        let wasm_bytes = load_approved_plugin_binary(&wasm_path, &runtime_dirs, &name)?;
        let config = Some(load_plugin_config(&runtime_dirs)?);
        let wasm = WasmProgram::load_bytes(&wasm_bytes, &name, network, config)?;
        let hooks = wasm.hooks.clone();
        verify_plugin_approval(path, &runtime_dirs)?;
        Ok(Self {
            name,
            wasm,
            hooks,
            required: file.required,
            timeout: Duration::from_millis(timeout_ms),
            max_input_bytes,
            max_output_bytes,
            max_spans,
        })
    }

    fn invoke(
        &self,
        hook: MiddlewareStage,
        payload: &Value,
        context: Option<&Value>,
    ) -> Result<PluginResponse, String> {
        let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let request = json!({
            "schema": PROTOCOL_SCHEMA,
            "id": request_id,
            "payload": payload,
            "metadata": context,
        });
        let encoded = serde_json::to_vec(&request)
            .map_err(|error| format!("plugin '{}' request encode failed: {error}", self.name))?;
        if encoded.len() > self.max_input_bytes {
            return Err(format!("plugin '{}' input exceeds its limit", self.name));
        }
        let output = self.wasm.invoke(
            hook,
            &encoded,
            self.timeout,
            self.max_output_bytes,
            &self.name,
        )?;
        let response: PluginResponse = serde_json::from_slice(&output)
            .map_err(|error| format!("plugin '{}' returned invalid JSON: {error}", self.name))?;
        if response.schema.as_deref() != Some(PROTOCOL_SCHEMA)
            || response.kind.as_deref() != Some("result")
            || response.id != Some(request_id)
        {
            return Err(format!(
                "plugin '{}' returned a mismatched protocol response",
                self.name
            ));
        }
        if let Some(error) = response.error.as_ref() {
            if error.code.is_empty()
                || error.code.len() > 64
                || !error.code.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
                })
            {
                return Err(format!(
                    "plugin '{}' returned an invalid error code",
                    self.name
                ));
            }
            return Err(format!(
                "plugin '{}' handler failed ({})",
                self.name, error.code
            ));
        }
        Ok(response)
    }
}

pub fn valid_plugin_publisher_workflow(workflow: &str) -> bool {
    !workflow.is_empty()
        && workflow.len() <= 256
        && !workflow.starts_with('/')
        && !workflow.contains('\\')
        && workflow.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
        })
        && (workflow.ends_with(".yml") || workflow.ends_with(".yaml"))
}

#[derive(Deserialize)]
struct PluginApproval {
    schema: String,
    manifest_sha256: String,
}

#[derive(Deserialize)]
struct PluginBinaryLock {
    schema: String,
    sha256: String,
}

fn verify_plugin_approval(manifest: &Path, runtime_dirs: &PluginRuntimeDirs) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let path = runtime_dirs.data_dir.join(PLUGIN_APPROVAL_FILE);
    let source =
        read_bounded_utf8(&path, MAX_PLUGIN_METADATA_BYTES, "plugin approval").map_err(|_| {
            format!(
                "plugin '{}' is not approved; run `pentect plugins setup {} --yes`",
                plugin_default_name(manifest),
                manifest.display()
            )
        })?;
    let approval: PluginApproval =
        toml::from_str(&source).map_err(|error| format!("plugin approval is invalid: {error}"))?;
    let bytes = read_bounded_bytes(manifest, MAX_PLUGIN_MANIFEST_BYTES, "plugin manifest")
        .map_err(|error| format!("could not verify plugin manifest: {error}"))?;
    let digest = data_encoding::HEXLOWER.encode(&Sha256::digest(bytes));
    if approval.schema != "pentect.plugin-approval.v1" || approval.manifest_sha256 != digest {
        return Err(format!(
            "plugin '{}' changed after approval; run `pentect plugins setup {} --yes` again",
            plugin_default_name(manifest),
            manifest.display()
        ));
    }
    Ok(())
}

fn load_approved_plugin_binary(
    path: &Path,
    runtime_dirs: &PluginRuntimeDirs,
    name: &str,
) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};

    let lock_path = runtime_dirs.data_dir.join(PLUGIN_BINARY_LOCK_FILE);
    let source = read_bounded_utf8(&lock_path, MAX_PLUGIN_METADATA_BYTES, "plugin binary lock")
        .map_err(|_| {
            format!("plugin '{name}' binary is not locked; run `pentect plugins setup` again")
        })?;
    let lock: PluginBinaryLock =
        toml::from_str(&source).map_err(|_| format!("plugin '{name}' binary lock is invalid"))?;
    if lock.schema != "pentect.plugin-lock.v1"
        || lock.sha256.len() != 64
        || !lock.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!("plugin '{name}' binary lock is invalid"));
    }
    let bytes = read_bounded_bytes(path, MAX_PLUGIN_WASM_BYTES, "WebAssembly plugin")
        .map_err(|error| format!("could not load plugin '{name}': {error}"))?;
    let digest = data_encoding::HEXLOWER.encode(&Sha256::digest(&bytes));
    if !digest.eq_ignore_ascii_case(&lock.sha256) {
        return Err(format!(
            "plugin '{name}' binary changed after verification; run `pentect plugins setup` again"
        ));
    }
    Ok(bytes)
}

const WASM_ABI_ALLOC: &str = "pentect_alloc";
const WASM_ABI_MEMORY: &str = "memory";
const WASM_HTTP_MODULE: &str = "pentect:http";
const WASM_HTTP_REQUEST: &str = "request";
const WASM_CONFIG_MODULE: &str = "pentect:config";
const WASM_CONFIG_READ: &str = "read";
const WASM_MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;
const HTTP_MAX_REQUEST_BYTES: usize = 1024 * 1024;
const HTTP_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const HTTP_MAX_REQUESTS: usize = 16;
const HTTP_DEFAULT_REQUESTS: usize = 4;
const HTTP_MAX_ORIGINS: usize = 64;
const HTTP_MAX_HEADERS: usize = 64;
const HTTP_MAX_HEADER_BYTES: usize = 64 * 1024;
const HTTP_MAX_DNS_THREADS: usize = 32;
// Fuel is a short scheduling quantum. The wall clock below is authoritative.
const WASM_FUEL_SLICE: u64 = 100_000;

#[derive(Clone, Debug)]
struct WasmProgram {
    engine: wasmi::Engine,
    module: wasmi::Module,
    hooks: BTreeSet<MiddlewareStage>,
    network: Option<NetworkPolicy>,
    config: Option<toml::Value>,
}

impl WasmProgram {
    fn load_bytes(
        bytes: &[u8],
        name: &str,
        network: Option<NetworkPolicy>,
        config: Option<toml::Value>,
    ) -> Result<Self, String> {
        let mut engine_config = wasmi::Config::default();
        engine_config.consume_fuel(true);
        let engine = wasmi::Engine::new(&engine_config);
        let module = wasmi::Module::new(&engine, bytes)
            .map_err(|error| format!("plugin '{name}' WebAssembly is invalid: {error}"))?;
        let hooks = validated_module_hooks(&module, &format!("plugin '{name}'"))?;
        for import in module.imports() {
            let permitted = (import.module() == WASM_HTTP_MODULE
                && import.name() == WASM_HTTP_REQUEST
                && network.is_some())
                || (import.module() == WASM_CONFIG_MODULE
                    && import.name() == WASM_CONFIG_READ
                    && config.is_some());
            if !permitted {
                return Err(format!(
                    "plugin '{name}' imports unapproved host function '{}:{}'",
                    import.module(),
                    import.name()
                ));
            }
        }
        Ok(Self {
            engine,
            module,
            hooks,
            network,
            config,
        })
    }

    fn invoke(
        &self,
        hook: MiddlewareStage,
        request: &[u8],
        timeout: Duration,
        max_output_bytes: usize,
        name: &str,
    ) -> Result<Vec<u8>, String> {
        let limits = wasmi::StoreLimitsBuilder::new()
            .memory_size(WASM_MAX_MEMORY_BYTES)
            .memories(1)
            .instances(1)
            .tables(1)
            .build();
        let started = Instant::now();
        let mut store = wasmi::Store::new(
            &self.engine,
            WasmHostState {
                limits,
                network: self.network.clone(),
                network_requests: 0,
                config: self.config.clone(),
                deadline: started + timeout,
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(WASM_FUEL_SLICE)
            .map_err(|error| format!("plugin '{name}' fuel setup failed: {error}"))?;
        let mut linker = wasmi::Linker::new(&self.engine);
        if self.network.is_some() {
            linker
                .func_wrap(WASM_HTTP_MODULE, WASM_HTTP_REQUEST, wasm_http_request)
                .map_err(|error| format!("plugin '{name}' network setup failed: {error}"))?;
        }
        if self.config.is_some() {
            linker
                .func_wrap(WASM_CONFIG_MODULE, WASM_CONFIG_READ, wasm_config_read)
                .map_err(|error| format!("plugin '{name}' config setup failed: {error}"))?;
        }
        let instance = linker
            .instantiate_and_start(&mut store, &self.module)
            .map_err(|error| format!("plugin '{name}' WebAssembly start failed: {error}"))?;
        let memory = instance
            .get_memory(&store, WASM_ABI_MEMORY)
            .ok_or_else(|| format!("plugin '{name}' does not export memory"))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&store, WASM_ABI_ALLOC)
            .map_err(|_| format!("plugin '{name}' does not export {WASM_ABI_ALLOC}(i32) -> i32"))?;
        let export = hook.export_name();
        let handle = instance
            .get_typed_func::<(i32, i32), i64>(&store, export)
            .map_err(|_| format!("plugin '{name}' does not export {export}(i32, i32) -> i64"))?;
        let request_len = i32::try_from(request.len())
            .map_err(|_| format!("plugin '{name}' request is too large"))?;
        let request_ptr = alloc
            .call(&mut store, request_len)
            .map_err(|error| format!("plugin '{name}' allocation failed: {error}"))?;
        let request_offset = usize::try_from(request_ptr)
            .map_err(|_| format!("plugin '{name}' returned an invalid allocation"))?;
        memory
            .write(&mut store, request_offset, request)
            .map_err(|error| format!("plugin '{name}' request write failed: {error}"))?;
        store
            .set_fuel(WASM_FUEL_SLICE)
            .map_err(|error| format!("plugin '{name}' fuel setup failed: {error}"))?;
        let mut call = handle
            .call_resumable(&mut store, (request_ptr, request_len))
            .map_err(|error| format!("plugin '{name}' execution failed: {error}"))?;
        let packed = loop {
            match call {
                wasmi::TypedResumableCall::Finished(value) => break value as u64,
                wasmi::TypedResumableCall::HostTrap(trap) => {
                    return Err(format!(
                        "plugin '{name}' host call failed: {}",
                        trap.host_error()
                    ));
                }
                wasmi::TypedResumableCall::OutOfFuel(pending) => {
                    if started.elapsed() >= timeout {
                        return Err(format!("plugin '{name}' timed out"));
                    }
                    store
                        .set_fuel(WASM_FUEL_SLICE.max(pending.required_fuel()))
                        .map_err(|error| format!("plugin '{name}' fuel resume failed: {error}"))?;
                    call = pending
                        .resume(&mut store)
                        .map_err(|error| format!("plugin '{name}' execution failed: {error}"))?;
                }
            }
        };
        let output_ptr = usize::try_from(packed >> 32)
            .map_err(|_| format!("plugin '{name}' returned an invalid output pointer"))?;
        let output_len = usize::try_from(packed & u64::from(u32::MAX))
            .map_err(|_| format!("plugin '{name}' returned an invalid output length"))?;
        if output_len > max_output_bytes {
            return Err(format!("plugin '{name}' returned too much output"));
        }
        let mut output = vec![0; output_len];
        memory
            .read(&store, output_ptr, &mut output)
            .map_err(|error| format!("plugin '{name}' output read failed: {error}"))?;
        Ok(output)
    }
}

struct WasmHostState {
    limits: wasmi::StoreLimits,
    network: Option<NetworkPolicy>,
    network_requests: usize,
    config: Option<toml::Value>,
    deadline: Instant,
}

#[derive(Clone, Debug)]
struct NetworkPolicy {
    origins: BTreeSet<HttpOrigin>,
    methods: BTreeSet<String>,
    private_network: bool,
    allow_insecure: bool,
    max_request_bytes: usize,
    max_response_bytes: usize,
    max_requests: usize,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct HttpOrigin {
    scheme: String,
    host: String,
    port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginHttpRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Serialize)]
pub struct PluginHttpResponse {
    pub status: Option<u16>,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub error: Option<String>,
}

fn load_plugin_config(runtime_dirs: &PluginRuntimeDirs) -> Result<toml::Value, String> {
    let path = &runtime_dirs.config_file;
    if !path.is_file() {
        return Ok(toml::Value::Table(toml::Table::new()));
    }
    let source = read_bounded_utf8(path, MAX_PLUGIN_CONFIG_BYTES, "plugin config")?;
    toml::from_str(&source)
        .map_err(|error| format!("plugin config '{}' is invalid: {error}", path.display()))
}

fn wasm_config_read(
    mut caller: wasmi::Caller<'_, WasmHostState>,
    key_ptr: i32,
    key_len: i32,
    response_ptr: i32,
    response_capacity: i32,
) -> i32 {
    let Some(memory) = caller
        .get_export(WASM_ABI_MEMORY)
        .and_then(wasmi::Extern::into_memory)
    else {
        return -1;
    };
    let (Ok(key_offset), Ok(key_len), Ok(response_offset), Ok(response_capacity)) = (
        usize::try_from(key_ptr),
        usize::try_from(key_len),
        usize::try_from(response_ptr),
        usize::try_from(response_capacity),
    ) else {
        return -1;
    };
    if key_len == 0 || key_len > 256 || response_capacity > DEFAULT_MAX_OUTPUT_BYTES {
        return -2;
    }
    let mut key = vec![0; key_len];
    if memory.read(&caller, key_offset, &mut key).is_err() {
        return -1;
    }
    let Ok(key) = std::str::from_utf8(&key) else {
        return -2;
    };
    if key.split('.').any(|part| {
        part.is_empty()
            || !part.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
    }) {
        return -2;
    }
    let value = caller
        .data()
        .config
        .as_ref()
        .and_then(|root| config_value(root, key))
        .cloned();
    let Ok(encoded) = serde_json::to_vec(&value) else {
        return -3;
    };
    if encoded.len() > response_capacity {
        return -2;
    }
    if memory
        .write(&mut caller, response_offset, &encoded)
        .is_err()
    {
        return -1;
    }
    i32::try_from(encoded.len()).unwrap_or(-2)
}

fn config_value<'a>(root: &'a toml::Value, key: &str) -> Option<&'a toml::Value> {
    key.split('.')
        .try_fold(root, |value, part| value.as_table()?.get(part))
}

fn wasm_http_request(
    mut caller: wasmi::Caller<'_, WasmHostState>,
    request_ptr: i32,
    request_len: i32,
    response_ptr: i32,
    response_capacity: i32,
) -> i32 {
    let Some(memory) = caller
        .get_export(WASM_ABI_MEMORY)
        .and_then(wasmi::Extern::into_memory)
    else {
        return -1;
    };
    let Ok(request_offset) = usize::try_from(request_ptr) else {
        return -1;
    };
    let Ok(request_len) = usize::try_from(request_len) else {
        return -1;
    };
    let Ok(response_offset) = usize::try_from(response_ptr) else {
        return -1;
    };
    let Ok(response_capacity) = usize::try_from(response_capacity) else {
        return -1;
    };
    if request_len > HTTP_MAX_REQUEST_BYTES || response_capacity > HTTP_MAX_RESPONSE_BYTES {
        return -2;
    }
    let mut request = vec![0; request_len];
    if memory.read(&caller, request_offset, &mut request).is_err() {
        return -1;
    }
    let policy = caller.data().network.clone();
    let request_allowed = policy.as_ref().is_some_and(|policy| {
        if caller.data().network_requests >= policy.max_requests {
            return false;
        }
        caller.data_mut().network_requests += 1;
        true
    });
    let response = match (policy.as_ref(), request_allowed) {
        (Some(_), false) => PluginHttpResponse {
            status: None,
            headers: BTreeMap::new(),
            body: String::new(),
            error: Some("network request limit exceeded".to_string()),
        },
        (Some(policy), true) => match serde_json::from_slice::<PluginHttpRequest>(&request) {
            Ok(request) => match perform_plugin_http(policy, caller.data().deadline, request) {
                Ok(response) => response,
                Err(error) => PluginHttpResponse {
                    status: None,
                    headers: BTreeMap::new(),
                    body: String::new(),
                    error: Some(error),
                },
            },
            Err(_) => PluginHttpResponse {
                status: None,
                headers: BTreeMap::new(),
                body: String::new(),
                error: Some("invalid network request".to_string()),
            },
        },
        (None, _) => PluginHttpResponse {
            status: None,
            headers: BTreeMap::new(),
            body: String::new(),
            error: Some("network access is not approved".to_string()),
        },
    };
    let Ok(encoded) = serde_json::to_vec(&response) else {
        return -3;
    };
    if encoded.len() > response_capacity {
        return -2;
    }
    if memory
        .write(&mut caller, response_offset, &encoded)
        .is_err()
    {
        return -1;
    }
    i32::try_from(encoded.len()).unwrap_or(-2)
}

fn perform_plugin_http(
    policy: &NetworkPolicy,
    deadline: Instant,
    request: PluginHttpRequest,
) -> Result<PluginHttpResponse, String> {
    let now = Instant::now();
    if now >= deadline {
        return Err("plugin HTTP request timed out".to_string());
    }
    if request.body.len() > policy.max_request_bytes {
        return Err("plugin HTTP request body exceeds its approved limit".to_string());
    }
    let method = request.method.trim().to_ascii_uppercase();
    if !policy.methods.contains(&method) {
        return Err(format!("HTTP method {method} is not approved"));
    }
    let url = reqwest::Url::parse(&request.url)
        .map_err(|_| "plugin HTTP request URL is invalid".to_string())?;
    let origin = http_origin(&url)?;
    if !policy.origins.contains(&origin) {
        return Err("plugin HTTP request origin is not approved".to_string());
    }
    if origin.scheme == "http" && !policy.allow_insecure {
        return Err("insecure HTTP is not approved".to_string());
    }
    let private_origin = private_access_for_origin(&origin, policy.private_network);
    let addresses = resolve_http_origin(&origin, private_origin, deadline)?;
    let request_timeout = deadline.saturating_duration_since(Instant::now());
    if request_timeout.is_zero() {
        return Err("plugin HTTP request timed out".to_string());
    }
    let mut builder = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(request_timeout)
        .resolve_to_addrs(&origin.host, &addresses);
    builder = builder.user_agent("pentect-plugin-http/1");
    let client = builder
        .build()
        .map_err(|_| "could not initialize plugin HTTP client".to_string())?;
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| "plugin HTTP method is invalid".to_string())?;
    let mut pending = client.request(method, url);
    if request.headers.len() > HTTP_MAX_HEADERS
        || request
            .headers
            .iter()
            .any(|(name, value)| name.len().saturating_add(value.len()) > HTTP_MAX_HEADER_BYTES)
        || request
            .headers
            .iter()
            .map(|(name, value)| name.len().saturating_add(value.len()))
            .sum::<usize>()
            > HTTP_MAX_HEADER_BYTES
    {
        return Err("plugin HTTP request headers exceed their limit".to_string());
    }
    for (name, value) in request.headers {
        if transport_controlled_header(&name) {
            return Err(format!("HTTP header {name} is controlled by Pentect"));
        }
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| "plugin HTTP header name is invalid".to_string())?;
        let value = reqwest::header::HeaderValue::from_str(&value)
            .map_err(|_| "plugin HTTP header value is invalid".to_string())?;
        pending = pending.header(name, value);
    }
    if !request.body.is_empty() {
        pending = pending.body(request.body);
    }
    let mut response = pending
        .send()
        .map_err(|_| "plugin HTTP request failed".to_string())?;
    let status = response.status().as_u16();
    let mut headers = BTreeMap::new();
    let mut header_bytes = 0_usize;
    let mut header_count = 0_usize;
    for (name, value) in response.headers() {
        if let Ok(value) = value.to_str() {
            header_count += 1;
            header_bytes =
                header_bytes.saturating_add(name.as_str().len().saturating_add(value.len()));
            if header_count > HTTP_MAX_HEADERS || header_bytes > HTTP_MAX_HEADER_BYTES {
                return Err("plugin HTTP response headers exceed their limit".to_string());
            }
            headers.insert(name.as_str().to_string(), value.to_string());
        }
    }
    let mut body = Vec::new();
    response
        .by_ref()
        .take(policy.max_response_bytes as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| "could not read plugin HTTP response".to_string())?;
    if body.len() > policy.max_response_bytes {
        return Err("plugin HTTP response exceeds its approved limit".to_string());
    }
    let body =
        String::from_utf8(body).map_err(|_| "plugin HTTP response is not UTF-8".to_string())?;
    Ok(PluginHttpResponse {
        status: Some(status),
        headers,
        body,
        error: None,
    })
}

fn private_access_for_origin(origin: &HttpOrigin, approved: bool) -> bool {
    approved
        && origin.host.parse::<IpAddr>().is_ok_and(|ip| match ip {
            IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
            IpAddr::V6(ip) => {
                ip.is_loopback()
                    || (ip.segments().first().copied().unwrap_or_default() & 0xfe00) == 0xfc00
            }
        })
}

fn transport_controlled_header(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "proxy-connection"
            | "upgrade"
    )
}

fn resolve_http_origin(
    origin: &HttpOrigin,
    private_network: bool,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("plugin HTTP request timed out".to_string());
    }
    if ACTIVE_PLUGIN_DNS_THREADS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            (active < HTTP_MAX_DNS_THREADS).then_some(active + 1)
        })
        .is_err()
    {
        return Err("plugin HTTP origin resolution is busy".to_string());
    }
    let host = origin.host.clone();
    let port = origin.port;
    let (sender, receiver) = mpsc::sync_channel(1);
    if std::thread::Builder::new()
        .name("pentect-plugin-dns".to_string())
        .spawn(move || {
            let result = (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| {
                    addresses
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                })
                .map_err(|_| ());
            let _ = sender.send(result);
            ACTIVE_PLUGIN_DNS_THREADS.fetch_sub(1, Ordering::AcqRel);
        })
        .is_err()
    {
        ACTIVE_PLUGIN_DNS_THREADS.fetch_sub(1, Ordering::AcqRel);
        return Err("plugin HTTP origin resolution could not start".to_string());
    }
    let addresses = receiver
        .recv_timeout(remaining)
        .map_err(|_| "plugin HTTP origin resolution timed out".to_string())?
        .map_err(|()| "plugin HTTP origin could not be resolved".to_string())?;
    if addresses.is_empty() {
        return Err("plugin HTTP origin resolved to no addresses".to_string());
    }
    if addresses
        .iter()
        .any(|address| !plugin_network_ip_allowed(address.ip(), private_network))
    {
        return Err("plugin HTTP origin resolved to a disallowed address".to_string());
    }
    Ok(addresses)
}

#[cfg(test)]
fn public_ip(ip: IpAddr) -> bool {
    plugin_network_ip_allowed(ip, false)
}

fn plugin_network_ip_allowed(ip: IpAddr, private_network: bool) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            if ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_multicast()
                || ip.is_unspecified()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && matches!(octets[1], 18 | 19))
                || octets[0] >= 240
            {
                return false;
            }
            if ip.is_private() || ip.is_loopback() {
                return private_network;
            }
            true
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            if ip.is_loopback() {
                return private_network;
            }
            if let Some(embedded) = embedded_ipv4(ip) {
                return plugin_network_ip_allowed(IpAddr::V4(embedded), private_network);
            }
            if ip.is_multicast()
                || ip.is_unspecified()
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0
                || (segments[0] == 0x2001 && segments[1] == 0)
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
            {
                return false;
            }
            if (segments[0] & 0xfe00) == 0xfc00 {
                return private_network;
            }
            true
        }
    }
}

fn http_origin(url: &reqwest::Url) -> Result<HttpOrigin, String> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err("plugin HTTP URLs cannot contain user information".to_string());
    }
    let scheme = url.scheme().to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err("plugin HTTP URL must use http or https".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "plugin HTTP URL requires a host".to_string())?
        .to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "plugin HTTP URL requires a port".to_string())?;
    Ok(HttpOrigin { scheme, host, port })
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginFile {
    schema: Option<String>,
    name: Option<String>,
    #[serde(rename = "description")]
    _description: Option<String>,
    #[serde(rename = "repository")]
    _repository: Option<String>,
    #[serde(default)]
    #[serde(rename = "assets")]
    _assets: BTreeMap<String, String>,
    #[serde(default)]
    #[serde(rename = "detector")]
    _detector: Vec<toml::Value>,
    #[serde(default)]
    postscript: Vec<toml::Value>,
    binary: Option<String>,
    publisher: Option<PublisherFile>,
    execution: Option<ExecutionFile>,
    #[serde(default)]
    required: bool,
    network: Option<NetworkFile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublisherFile {
    workflow: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionFile {
    #[serde(default)]
    args: Vec<String>,
    runtime: Option<String>,
    mode: Option<String>,
    timeout_ms: Option<u64>,
    max_input_bytes: Option<usize>,
    max_output_bytes: Option<usize>,
    max_spans: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkFile {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    private_network: bool,
    #[serde(default)]
    allow_insecure: bool,
    max_request_bytes: Option<usize>,
    max_response_bytes: Option<usize>,
    max_requests: Option<usize>,
}

fn validate_network(
    name: &str,
    network: Option<NetworkFile>,
) -> Result<Option<NetworkPolicy>, String> {
    let Some(network) = network else {
        return Ok(None);
    };
    if network.allow.is_empty() || network.allow.len() > HTTP_MAX_ORIGINS {
        return Err(format!(
            "plugin '{name}' network access requires 1 to {HTTP_MAX_ORIGINS} allowed origins"
        ));
    }
    if network.methods.is_empty() {
        return Err(format!(
            "plugin '{name}' network access requires at least one method"
        ));
    }
    let mut origins = BTreeSet::new();
    for raw in network.allow {
        let url = reqwest::Url::parse(&raw)
            .map_err(|_| format!("plugin '{name}' has an invalid HTTP origin"))?;
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(format!(
                "plugin '{name}' HTTP origins must not contain a path, query, or fragment"
            ));
        }
        let origin = http_origin(&url)?;
        if origin.scheme == "http" && !network.allow_insecure {
            return Err(format!(
                "plugin '{name}' must set allow_insecure = true to approve an http origin"
            ));
        }
        origins.insert(origin);
    }
    let mut methods = BTreeSet::new();
    for method in network.methods {
        let method = method.trim().to_ascii_uppercase();
        reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| format!("plugin '{name}' has an invalid HTTP method"))?;
        if !allowed_network_method(&method) {
            return Err(format!(
                "plugin '{name}' requests unsupported HTTP method {method}"
            ));
        }
        methods.insert(method);
    }
    let max_request_bytes = network.max_request_bytes.unwrap_or(DEFAULT_MAX_INPUT_BYTES);
    let max_response_bytes = network
        .max_response_bytes
        .unwrap_or(DEFAULT_MAX_OUTPUT_BYTES);
    let max_requests = network.max_requests.unwrap_or(HTTP_DEFAULT_REQUESTS);
    if max_request_bytes == 0 || max_response_bytes == 0 {
        return Err(format!(
            "plugin '{name}' HTTP byte limits must be greater than zero"
        ));
    }
    if max_request_bytes > HTTP_MAX_REQUEST_BYTES
        || max_response_bytes > HTTP_MAX_RESPONSE_BYTES
        || max_requests == 0
        || max_requests > HTTP_MAX_REQUESTS
    {
        return Err(format!(
            "plugin '{name}' network limits exceed Pentect's sandbox limits"
        ));
    }
    Ok(Some(NetworkPolicy {
        origins,
        methods,
        private_network: network.private_network,
        allow_insecure: network.allow_insecure,
        max_request_bytes,
        max_response_bytes,
        max_requests,
    }))
}

fn allowed_network_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    )
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Action {
    #[default]
    Next,
    Stop,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StopOutcomeFile {
    Block,
    Respond,
}

impl From<StopOutcomeFile> for StopOutcome {
    fn from(value: StopOutcomeFile) -> Self {
        match value {
            StopOutcomeFile::Block => Self::Block,
            StopOutcomeFile::Respond => Self::Respond,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginResponse {
    schema: Option<String>,
    id: Option<u64>,
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    action: Action,
    outcome: Option<StopOutcomeFile>,
    payload: Option<Value>,
    message: Option<String>,
    #[serde(default)]
    spans: Vec<PluginSpan>,
    error: Option<PluginErrorFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginErrorFile {
    code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginSpan {
    start: usize,
    end: usize,
    label: String,
    category: Option<String>,
    confidence: Option<String>,
}

fn plugin_span(raw: &str, span: PluginSpan, plugin: &str) -> Result<Span, String> {
    if span.start >= span.end
        || span.end > raw.len()
        || !raw.is_char_boundary(span.start)
        || !raw.is_char_boundary(span.end)
    {
        return Err(format!(
            "plugin '{plugin}' returned an invalid byte span {}..{}",
            span.start, span.end
        ));
    }
    Ok(Span {
        range: ByteRange::new(span.start, span.end),
        category: parse_category(span.category.as_deref().unwrap_or("pii"), plugin)?,
        label: normalize_label(&span.label),
        confidence: parse_confidence(span.confidence.as_deref().unwrap_or("medium"), plugin)?,
        source: DetectorId::Plugin,
    })
}

fn parse_category(value: &str, plugin: &str) -> Result<Category, String> {
    match value.to_ascii_lowercase().as_str() {
        "secret" => Ok(Category::Secret),
        "identifier" => Ok(Category::Identifier),
        "endpoint" => Ok(Category::Endpoint),
        "pii" => Ok(Category::Pii),
        "other" => Ok(Category::Other),
        other => Err(format!(
            "plugin '{plugin}' returned unknown category: {other}"
        )),
    }
}

fn parse_confidence(value: &str, plugin: &str) -> Result<Confidence, String> {
    match value.to_ascii_lowercase().as_str() {
        "high" => Ok(Confidence::High),
        "medium" => Ok(Confidence::Medium),
        "low" => Ok(Confidence::Low),
        other => Err(format!(
            "plugin '{plugin}' returned unknown confidence: {other}"
        )),
    }
}

fn normalize_label(value: &str) -> String {
    let upper = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    let mut output = String::new();
    let mut underscore = false;
    for character in upper.trim_matches('_').chars() {
        if character == '_' {
            if !underscore {
                output.push(character);
            }
            underscore = true;
        } else {
            output.push(character);
            underscore = false;
        }
    }
    match output.chars().next() {
        Some(character) if character.is_ascii_alphabetic() => output,
        _ => "PLUGIN_VALUE".to_string(),
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

#[derive(Debug)]
pub struct PluginRuntimeDirs {
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub config_file: PathBuf,
}

pub fn plugin_runtime_dirs(id_or_name: &str) -> Result<PluginRuntimeDirs, String> {
    let id = plugin_id(id_or_name);
    let project = std::env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(|error| format!("could not resolve plugin project directory: {error}"))?;
    let mut digest = sha2::Sha256::new();
    use sha2::Digest as _;
    digest.update(b"pentect-plugin-project-v1");
    digest.update(project.to_string_lossy().as_bytes());
    let project_id = data_encoding::HEXLOWER.encode(&digest.finalize());
    let user_root = plugin_user_data_root()?;
    if !user_root.is_absolute() {
        return Err("Pentect plugin data directory must be absolute".to_string());
    }
    std::fs::create_dir_all(&user_root)
        .map_err(|error| format!("could not create '{}': {error}", user_root.display()))?;
    let user_root = std::fs::canonicalize(&user_root)
        .map_err(|error| format!("could not resolve '{}': {error}", user_root.display()))?;
    if user_root.starts_with(&project) {
        return Err("Pentect plugin data directory must be outside the project".to_string());
    }
    restrict_plugin_directory(&user_root)?;
    let data_dir = user_root.join("projects").join(project_id).join(&id);
    let cache_dir = data_dir.join(PLUGIN_CACHE_DIR);
    std::fs::create_dir_all(&cache_dir)
        .map_err(|error| format!("could not create '{}': {error}", cache_dir.display()))?;
    restrict_plugin_directory(&data_dir)?;
    Ok(PluginRuntimeDirs {
        config_file: data_dir.join(PLUGIN_CONFIG_FILE),
        data_dir,
        cache_dir,
    })
}

/// Resolve storage for one concrete plugin source. The source path is part of
/// the identity so two publishers may safely use the same display name.
pub fn plugin_runtime_dirs_for_manifest(
    name: &str,
    manifest: &Path,
) -> Result<PluginRuntimeDirs, String> {
    let manifest = std::fs::canonicalize(manifest).map_err(|error| {
        format!(
            "could not resolve plugin manifest '{}': {error}",
            manifest.display()
        )
    })?;
    let mut digest = sha2::Sha256::new();
    use sha2::Digest as _;
    digest.update(b"pentect-plugin-source-v1");
    digest.update(manifest.to_string_lossy().as_bytes());
    let source_id = data_encoding::HEXLOWER.encode(&digest.finalize()[..12]);
    let mut name = plugin_id(name);
    name.truncate(64usize.saturating_sub(source_id.len() + 1));
    while name.ends_with('-') {
        name.pop();
    }
    plugin_runtime_dirs(&format!("{name}-{source_id}"))
}

fn plugin_user_data_root() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = home_dir().map(|home| home.join("Library").join("Application Support"));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".local").join("share")));
    base.map(|base| base.join("pentect").join("plugins"))
        .ok_or_else(|| "could not find a local data directory for Pentect plugins".to_string())
}

#[cfg(not(windows))]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(unix)]
fn restrict_plugin_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not restrict '{}': {error}", path.display()))
}

#[cfg(not(unix))]
fn restrict_plugin_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn wasm_binary_path(
    name: &str,
    binary: &str,
    runtime_dirs: &PluginRuntimeDirs,
) -> Result<PathBuf, String> {
    if binary.is_empty()
        || binary.len() > 128
        || binary.contains('/')
        || binary.contains('\\')
        || !binary.to_ascii_lowercase().ends_with(".wasm")
        || !binary.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(format!("plugin '{name}' has an invalid binary name"));
    }
    Ok(runtime_dirs.data_dir.join("bin").join(binary))
}

fn plugin_default_name(path: &Path) -> String {
    if path.file_name().and_then(|name| name.to_str()) == Some("plugin.toml") {
        if let Some(name) = path
            .parent()
            .and_then(Path::file_name)
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

fn plugin_id(value: &str) -> String {
    let mut id = String::new();
    let mut separator = false;
    for character in value.trim().chars() {
        if character.is_ascii_alphanumeric() {
            id.push(character.to_ascii_lowercase());
            separator = false;
        } else if !separator && !id.is_empty() {
            id.push('-');
            separator = true;
        }
        if id.len() >= 64 {
            break;
        }
    }
    while id.ends_with('-') {
        id.pop();
    }
    if id.is_empty() {
        "plugin".to_string()
    } else {
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_public_hooks() {
        for hook in MiddlewareStage::ALL {
            assert_eq!(
                MiddlewareStage::from_export_name(hook.export_name()),
                Some(hook)
            );
        }
    }

    #[test]
    fn long_same_name_from_different_sources_has_distinct_storage() {
        let root =
            std::env::temp_dir().join(format!("pentect-plugin-identity-{}", std::process::id()));
        let left = root.join("left").join("plugin.toml");
        let right = root.join("right").join("plugin.toml");
        std::fs::create_dir_all(left.parent().unwrap()).unwrap();
        std::fs::create_dir_all(right.parent().unwrap()).unwrap();
        std::fs::write(&left, "schema = \"pentect.plugin.v1\"\n").unwrap();
        std::fs::write(&right, "schema = \"pentect.plugin.v1\"\n").unwrap();
        let name = "a".repeat(64);
        let left_dirs = plugin_runtime_dirs_for_manifest(&name, &left).unwrap();
        let right_dirs = plugin_runtime_dirs_for_manifest(&name, &right).unwrap();
        assert_ne!(left_dirs.data_dir, right_dirs.data_dir);
        let _ = std::fs::remove_dir_all(left_dirs.data_dir);
        let _ = std::fs::remove_dir_all(right_dirs.data_dir);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn plugin_files_are_read_with_a_hard_size_limit() {
        let path =
            std::env::temp_dir().join(format!("pentect-plugin-size-limit-{}", std::process::id()));
        std::fs::write(&path, b"12345").unwrap();

        let error = read_bounded_bytes(&path, 4, "test plugin").unwrap_err();
        assert!(error.contains("exceeds 4 bytes"), "{error}");

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn plugin_spans_are_byte_checked_and_normalized() {
        let span = plugin_span(
            "Alice",
            PluginSpan {
                start: 0,
                end: 5,
                label: "person name".to_string(),
                category: Some("pii".to_string()),
                confidence: Some("high".to_string()),
            },
            "test",
        )
        .unwrap();
        assert_eq!(span.label, "PERSON_NAME");
        assert!(plugin_span(
            "Alice",
            PluginSpan {
                start: 0,
                end: 6,
                label: "person".to_string(),
                category: None,
                confidence: None,
            },
            "test",
        )
        .is_err());
    }

    #[test]
    fn wasm_plugin_runs_without_host_imports() {
        let output = br#"{"schema":"pentect.plugin.v1","id":7,"type":"result","action":"next"}"#;
        let packed = ((2048_u64) << 32) | output.len() as u64;
        let wat = format!(
            r#"(module
                (memory (export "memory") 1)
                (data (i32.const 2048) "{}")
                (func (export "pentect_alloc") (param i32) (result i32)
                    (i32.const 1024))
                (func (export "pentect_inspect") (param i32 i32) (result i64)
                    (i64.const {packed}))
            )"#,
            String::from_utf8_lossy(output).replace('"', "\\22")
        );
        let bytes = wat::parse_str(wat).unwrap();
        let program = WasmProgram::load_bytes(&bytes, "fixture", None, None).unwrap();
        let result = program
            .invoke(
                MiddlewareStage::Inspect,
                b"{}",
                Duration::from_secs(1),
                4096,
                "fixture",
            )
            .unwrap();
        assert_eq!(result, output);
    }

    #[test]
    fn wasm_plugin_enforces_wall_clock_timeout() {
        let bytes = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "pentect_alloc") (param i32) (result i32)
                    (i32.const 1024))
                (func (export "pentect_inspect") (param i32 i32) (result i64)
                    (loop (br 0))
                    (i64.const 0))
            )"#,
        )
        .unwrap();
        let program = WasmProgram::load_bytes(&bytes, "fixture", None, None).unwrap();
        let error = program
            .invoke(
                MiddlewareStage::Inspect,
                b"{}",
                Duration::from_millis(1),
                4096,
                "fixture",
            )
            .unwrap_err();
        assert!(error.contains("timed out"), "{error}");
    }

    #[test]
    fn wasm_host_imports_require_matching_network_approval() {
        let bytes = wat::parse_str(
            r#"(module
                (import "pentect:http" "request"
                    (func $request (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "pentect_alloc") (param i32) (result i32)
                    (i32.const 1024))
                (func (export "pentect_inspect") (param i32 i32) (result i64)
                    (i64.const 0))
            )"#,
        )
        .unwrap();
        let denied = WasmProgram::load_bytes(&bytes, "fixture", None, None).unwrap_err();
        assert!(denied.contains("unapproved host function"), "{denied}");

        let policy = NetworkPolicy {
            origins: BTreeSet::from([HttpOrigin {
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                port: 443,
            }]),
            methods: BTreeSet::from(["GET".to_string()]),
            private_network: false,
            allow_insecure: false,
            max_request_bytes: 1024,
            max_response_bytes: 1024,
            max_requests: 1,
        };
        WasmProgram::load_bytes(&bytes, "fixture", Some(policy), None).unwrap();
    }

    #[test]
    fn wasm_config_import_requires_config_read_approval() {
        let bytes = wat::parse_str(
            r#"(module
                (import "pentect:config" "read"
                    (func $read (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "pentect_alloc") (param i32) (result i32)
                    (i32.const 1024))
                (func (export "pentect_inspect") (param i32 i32) (result i64)
                    (i64.const 0))
            )"#,
        )
        .unwrap();
        let denied = WasmProgram::load_bytes(&bytes, "fixture", None, None).unwrap_err();
        assert!(denied.contains("unapproved host function"), "{denied}");
        let config = toml::Value::Table(toml::Table::from_iter([(
            "model".to_string(),
            toml::Value::Table(toml::Table::from_iter([(
                "threshold".to_string(),
                toml::Value::Float(0.8),
            )])),
        )]));
        assert_eq!(
            config_value(&config, "model.threshold").and_then(toml::Value::as_float),
            Some(0.8)
        );
        WasmProgram::load_bytes(&bytes, "fixture", None, Some(config)).unwrap();
    }

    #[test]
    fn network_policy_blocks_private_addresses_by_default() {
        assert!(!public_ip("127.0.0.1".parse().unwrap()));
        assert!(!public_ip("10.0.0.1".parse().unwrap()));
        assert!(!public_ip("::1".parse().unwrap()));
        assert!(!public_ip("::127.0.0.1".parse().unwrap()));
        assert!(!public_ip("64:ff9b::127.0.0.1".parse().unwrap()));
        assert!(public_ip("1.1.1.1".parse().unwrap()));
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn private_network_never_allows_link_local_or_special_addresses() {
        assert!(plugin_network_ip_allowed(
            "127.0.0.1".parse().unwrap(),
            true
        ));
        assert!(plugin_network_ip_allowed("::1".parse().unwrap(), true));
        assert!(plugin_network_ip_allowed("10.0.0.1".parse().unwrap(), true));
        assert!(!plugin_network_ip_allowed(
            "169.254.169.254".parse().unwrap(),
            true
        ));
        assert!(!plugin_network_ip_allowed("0.0.0.0".parse().unwrap(), true));
        assert!(!plugin_network_ip_allowed("ff02::1".parse().unwrap(), true));
        assert!(!plugin_network_ip_allowed("fe80::1".parse().unwrap(), true));
    }

    #[test]
    fn private_network_approval_does_not_apply_to_dns_names() {
        assert!(!private_access_for_origin(
            &HttpOrigin {
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                port: 443,
            },
            true,
        ));
        assert!(private_access_for_origin(
            &HttpOrigin {
                scheme: "http".to_string(),
                host: "127.0.0.1".to_string(),
                port: 8080,
            },
            true,
        ));
    }

    #[test]
    fn approved_private_network_request_is_bounded_and_direct() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        });
        let origin = HttpOrigin {
            scheme: "http".to_string(),
            host: "127.0.0.1".to_string(),
            port: address.port(),
        };
        let policy = NetworkPolicy {
            origins: BTreeSet::from([origin]),
            methods: BTreeSet::from(["GET".to_string()]),
            private_network: true,
            allow_insecure: true,
            max_request_bytes: 1024,
            max_response_bytes: 1024,
            max_requests: 1,
        };
        let response = perform_plugin_http(
            &policy,
            Instant::now() + Duration::from_secs(2),
            PluginHttpRequest {
                method: "GET".to_string(),
                url: format!("http://127.0.0.1:{}/health", address.port()),
                headers: BTreeMap::new(),
                body: String::new(),
            },
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(response.status, Some(200));
        assert_eq!(response.body, "ok");
        assert!(response.error.is_none());
    }
}
