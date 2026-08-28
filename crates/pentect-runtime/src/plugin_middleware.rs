use crate::{activity_log, embedded_ipv4, read_bounded_bytes, read_bounded_utf8};
use pentect_core::{
    ByteRange, Category, Confidence, Config, Context, DetectorId, Engine, Input, Kind, MaskResult,
    Span,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

pub const BINARIES_ENV: &str = "PENTECT_PLUGIN_BINARIES";
pub const GLOBAL_BINARIES_ENV: &str = "PENTECT_GLOBAL_PLUGIN_BINARIES";
pub const GLOBAL_BINARY_IDS_ENV: &str = "PENTECT_GLOBAL_PLUGIN_IDS";

const PLUGIN_APPROVAL_FILE: &str = "approval.toml";
const PLUGIN_BINARY_LOCK_FILE: &str = "binary.lock";
const PLUGIN_COMMAND_LOCK_FILE: &str = "command.lock";
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
const MAX_STARTUP_TIMEOUT_MS: u64 = 600_000;
const MAX_PLUGIN_INPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PLUGIN_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PLUGIN_SPANS: usize = 4096;
// These are request-wide ceilings. Individual plugin limits still apply and
// can only make an invocation stricter.
const MAX_PLUGIN_CHAIN_DURATION: Duration = Duration::from_secs(60);
const MAX_PLUGIN_CHAIN_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_PLUGIN_CHAIN_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_PLUGIN_CHAIN_SPANS: usize = 8192;
const MAX_PLUGIN_CHAIN_NETWORK_REQUESTS: usize = 32;
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

    fn from_name(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|hook| hook.as_str() == value)
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
    let mut config = wasmi::Config::default();
    config.enforced_limits(wasmi::EnforcedLimits::strict());
    let engine = wasmi::Engine::new(&config);
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
        None,
    )?;
    let hooks = wasm.hooks.clone();
    PluginMiddleware {
        plugins: vec![PluginBinary {
            name: name.to_string(),
            program: PluginProgram::Wasm(Box::new(wasm)),
            hooks,
            required: true,
            command_config: None,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            startup_timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
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

#[derive(Debug)]
struct PluginChainBudget {
    deadline: Instant,
    input_bytes: usize,
    output_bytes: usize,
    spans: usize,
    network_requests: Arc<AtomicUsize>,
}

impl PluginChainBudget {
    fn new() -> Self {
        Self {
            deadline: Instant::now() + MAX_PLUGIN_CHAIN_DURATION,
            input_bytes: 0,
            output_bytes: 0,
            spans: 0,
            network_requests: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn remaining(&self) -> Result<Duration, String> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err("plugin chain deadline exceeded".to_string())
        } else {
            Ok(remaining)
        }
    }

    fn charge_input(&mut self, bytes: usize) -> Result<(), String> {
        charge_chain_total(
            &mut self.input_bytes,
            bytes,
            MAX_PLUGIN_CHAIN_INPUT_BYTES,
            "input bytes",
        )
    }

    fn charge_output(&mut self, bytes: usize) -> Result<(), String> {
        charge_chain_total(
            &mut self.output_bytes,
            bytes,
            MAX_PLUGIN_CHAIN_OUTPUT_BYTES,
            "output bytes",
        )
    }

    fn charge_spans(&mut self, spans: usize) -> Result<(), String> {
        charge_chain_total(&mut self.spans, spans, MAX_PLUGIN_CHAIN_SPANS, "findings")
    }
}

fn charge_chain_total(
    current: &mut usize,
    amount: usize,
    limit: usize,
    resource: &str,
) -> Result<(), String> {
    let next = current
        .checked_add(amount)
        .ok_or_else(|| format!("plugin chain {resource} limit exceeded"))?;
    if next > limit {
        return Err(format!("plugin chain {resource} limit exceeded"));
    }
    *current = next;
    Ok(())
}

fn charge_chain_network_request(requests: &AtomicUsize) -> bool {
    requests
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |requests| {
            (requests < MAX_PLUGIN_CHAIN_NETWORK_REQUESTS).then_some(requests + 1)
        })
        .is_ok()
}

#[derive(Clone, Debug, Default)]
pub struct PluginMiddleware {
    plugins: Vec<PluginBinary>,
}

impl PluginMiddleware {
    pub fn from_env() -> Result<Self, String> {
        let mut plugins = Vec::new();
        if let Some(value) = std::env::var_os(GLOBAL_BINARIES_ENV) {
            let paths = std::env::split_paths(&value)
                .filter(|path| !path.as_os_str().is_empty())
                .collect::<Vec<_>>();
            let ids = std::env::var_os(GLOBAL_BINARY_IDS_ENV)
                .map(|value| {
                    std::env::split_paths(&value)
                        .filter(|path| !path.as_os_str().is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if paths.len() != ids.len() {
                return Err("global plugin path and identity counts do not match".to_string());
            }
            for (path, id) in paths.into_iter().zip(ids) {
                let id = id
                    .to_str()
                    .ok_or_else(|| "global plugin identity is not UTF-8".to_string())?;
                plugins.push(PluginBinary::load_global(&path, id)?);
            }
        }
        if let Some(value) = std::env::var_os(BINARIES_ENV) {
            for path in std::env::split_paths(&value).filter(|path| !path.as_os_str().is_empty()) {
                plugins.push(PluginBinary::load(&path)?);
            }
        }
        Ok(Self { plugins })
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
        let mut budget = PluginChainBudget::new();
        for plugin in &self.plugins {
            for hook in plugin.hooks.iter().copied() {
                let payload = hook_test_input(hook);
                let response = plugin.invoke_bounded(hook, &payload, None, &mut budget)?;
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
        let mut budget = PluginChainBudget::new();
        for plugin in self
            .plugins
            .iter()
            .filter(|plugin| plugin.hooks.contains(&hook))
        {
            let response =
                match plugin.invoke_bounded(hook, &payload, context.as_ref(), &mut budget) {
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
        let mut budget = PluginChainBudget::new();
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
            let response = match plugin.invoke_bounded(
                MiddlewareStage::Inspect,
                &payload,
                metadata.as_ref(),
                &mut budget,
            ) {
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
            if let Err(error) = budget.charge_spans(response.spans.len()) {
                if plugin.required {
                    return Err(format!("plugin '{}': {error}", plugin.name));
                }
                coverage = MiddlewareCoverage::Partial;
                eprintln!(
                    "[pentect] optional plugin '{}' skipped: {error}",
                    plugin.name
                );
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
    program: PluginProgram,
    hooks: BTreeSet<MiddlewareStage>,
    required: bool,
    command_config: Option<Value>,
    timeout: Duration,
    startup_timeout: Duration,
    max_input_bytes: usize,
    max_output_bytes: usize,
    max_spans: usize,
}

impl PluginBinary {
    fn load(path: &Path) -> Result<Self, String> {
        Self::load_scoped(path, None)
    }

    fn load_global(path: &Path, id: &str) -> Result<Self, String> {
        Self::load_scoped(path, Some(id))
    }

    fn load_scoped(path: &Path, global_id: Option<&str>) -> Result<Self, String> {
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
        let legacy_wasm = file.binary.filter(|value| !value.trim().is_empty());
        let wasm = file.wasm.filter(|value| !value.trim().is_empty());
        if legacy_wasm.is_some() && wasm.is_some() {
            return Err(format!(
                "plugin '{name}' cannot set both wasm and legacy binary"
            ));
        }
        let wasm = wasm.or(legacy_wasm);
        if !file.command.is_empty() && file.commands.is_some() {
            return Err(format!(
                "plugin '{name}' cannot set both command and [commands]"
            ));
        }
        let command_form = !file.command.is_empty() || file.commands.is_some();
        let command_variants = if !file.command.is_empty() {
            vec![file.command.as_slice()]
        } else {
            file.commands
                .iter()
                .flat_map(PlatformCommandsFile::variants)
                .collect::<Vec<_>>()
        };
        if command_form
            && (command_variants.is_empty()
                || command_variants.iter().any(|argv| {
                    argv.is_empty()
                        || argv[0].trim().is_empty()
                        || argv.len() > 256
                        || argv.iter().any(|argument| argument.len() > 32 * 1024)
                }))
        {
            return Err(format!("plugin '{name}' has an invalid command argv"));
        }
        let command = if !file.command.is_empty() {
            Some(file.command)
        } else {
            file.commands
                .as_ref()
                .and_then(PlatformCommandsFile::current)
                .cloned()
        };
        let has_detectors = !file.detector.is_empty();
        let forms =
            usize::from(has_detectors) + usize::from(wasm.is_some()) + usize::from(command_form);
        if forms != 1 {
            return Err(format!(
                "plugin '{name}' must contain exactly one of detector, wasm, or command"
            ));
        }
        if has_detectors {
            return Err(format!(
                "plugin '{name}' is manifest-only and has no middleware runtime"
            ));
        }
        if command_form && command.is_none() {
            return Err(format!(
                "plugin '{name}' is unsupported on {}",
                std::env::consts::OS
            ));
        }
        let execution = file.execution.unwrap_or_default();
        if execution
            .runtime
            .as_deref()
            .is_some_and(|value| value != "wasm")
        {
            return Err(format!(
                "plugin '{name}' legacy execution.runtime only supports \"wasm\""
            ));
        }
        if execution
            .mode
            .as_deref()
            .is_some_and(|value| value != "oneshot")
        {
            return Err(format!(
                "plugin '{name}' legacy execution.mode only supports \"oneshot\""
            ));
        }
        if !execution.args.is_empty() {
            return Err(format!(
                "plugin '{name}' execution.args is obsolete; put the complete argv in command"
            ));
        }
        let timeout_ms = execution.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        let startup_timeout_ms = execution.startup_timeout_ms.unwrap_or(timeout_ms);
        let max_input_bytes = execution.max_input_bytes.unwrap_or(DEFAULT_MAX_INPUT_BYTES);
        let max_output_bytes = execution
            .max_output_bytes
            .unwrap_or(DEFAULT_MAX_OUTPUT_BYTES);
        let max_spans = execution.max_spans.unwrap_or(DEFAULT_MAX_SPANS);
        if timeout_ms == 0
            || timeout_ms > MAX_TIMEOUT_MS
            || startup_timeout_ms == 0
            || startup_timeout_ms > MAX_STARTUP_TIMEOUT_MS
            || max_input_bytes == 0
            || max_input_bytes > MAX_PLUGIN_INPUT_BYTES
            || max_output_bytes == 0
            || max_output_bytes > MAX_PLUGIN_OUTPUT_BYTES
            || max_spans == 0
            || max_spans > MAX_PLUGIN_SPANS
        {
            return Err(format!(
                "plugin '{name}' execution limits exceed Pentect's runtime limits"
            ));
        }
        let runtime_dirs = match global_id {
            Some(id) => global_plugin_runtime_dirs(id)?,
            None => plugin_runtime_dirs_for_manifest(&name, path)?,
        };
        let mut permissions_file = file.permissions;
        let permission_network = permissions_file
            .as_mut()
            .and_then(|permissions| permissions.network.take());
        if file.network.is_some() && permission_network.is_some() {
            return Err(format!(
                "plugin '{name}' cannot set both [permissions.network] and legacy [network]"
            ));
        }
        let network_file = permission_network.or(file.network);
        let (program, hooks, command_config) = if let Some(wasm) = wasm {
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
            if !wasm.to_ascii_lowercase().ends_with(".wasm") {
                return Err(format!(
                    "plugin '{name}' wasm must name a portable .wasm module"
                ));
            }
            let network = validate_network(&name, network_file)?;
            let permissions = validate_permissions(&name, permissions_file, path, &runtime_dirs)?;
            let wasm_path = wasm_binary_path(&name, &wasm, &runtime_dirs)?;
            let wasm_bytes = load_approved_plugin_binary(&wasm_path, &runtime_dirs, &name)?;
            let config = Some(load_plugin_config(&runtime_dirs)?);
            let wasm = WasmProgram::load_bytes(&wasm_bytes, &name, network, config, permissions)?;
            let hooks = wasm.hooks.clone();
            (PluginProgram::Wasm(Box::new(wasm)), hooks, None)
        } else {
            if network_file.is_some() || permissions_file.is_some() {
                return Err(format!(
                    "plugin '{name}' command runs natively; Wasm permissions do not apply"
                ));
            }
            let command = command.expect("validated command form");
            let hooks = parse_declared_hooks(&name, &file.hooks)?;
            let manifest_root = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            let installed_root = runtime_dirs.data_dir.join("command");
            let command_root = if installed_root.is_dir() {
                installed_root
            } else {
                manifest_root
            };
            let executable = verify_command_files(&name, &command, &command_root, &runtime_dirs)?;
            let mut command = expand_plugin_command(&name, command, &command_root)?;
            command[0] = executable.to_string_lossy().into_owned();
            let config = serde_json::to_value(load_plugin_config(&runtime_dirs)?)
                .map_err(|error| format!("plugin '{name}' config encode failed: {error}"))?;
            (
                PluginProgram::Command(CommandProgram::new(
                    command,
                    command_root,
                    max_output_bytes,
                )?),
                hooks,
                Some(config),
            )
        };
        verify_plugin_approval(path, &runtime_dirs, &hooks, command_form)?;
        Ok(Self {
            name,
            program,
            hooks,
            required: file.required,
            command_config,
            timeout: Duration::from_millis(timeout_ms),
            startup_timeout: Duration::from_millis(startup_timeout_ms),
            max_input_bytes,
            max_output_bytes,
            max_spans,
        })
    }

    fn invoke_bounded(
        &self,
        hook: MiddlewareStage,
        payload: &Value,
        context: Option<&Value>,
        budget: &mut PluginChainBudget,
    ) -> Result<PluginResponse, String> {
        let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let request = json!({
            "schema": PROTOCOL_SCHEMA,
            "id": request_id,
            "hook": hook.as_str(),
            "payload": payload,
            "metadata": context,
            "config": self.command_config,
        });
        let encoded = serde_json::to_vec(&request)
            .map_err(|error| format!("plugin '{}' request encode failed: {error}", self.name))?;
        if encoded.len() > self.max_input_bytes {
            return Err(format!("plugin '{}' input exceeds its limit", self.name));
        }
        budget
            .charge_input(encoded.len())
            .map_err(|error| format!("plugin '{}': {error}", self.name))?;
        let timeout = self.timeout.min(
            budget
                .remaining()
                .map_err(|error| format!("plugin '{}': {error}", self.name))?,
        );
        let output = match &self.program {
            PluginProgram::Wasm(wasm) => wasm.invoke_bounded(
                hook,
                &encoded,
                timeout,
                self.max_output_bytes,
                &self.name,
                budget.deadline,
                Arc::clone(&budget.network_requests),
            )?,
            PluginProgram::Command(command) => command.invoke_with_startup_timeout(
                &encoded,
                timeout,
                self.startup_timeout,
                &self.name,
                budget,
            )?,
        };
        budget
            .charge_output(output.len())
            .map_err(|error| format!("plugin '{}': {error}", self.name))?;
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

fn parse_declared_hooks(
    name: &str,
    values: &[String],
) -> Result<BTreeSet<MiddlewareStage>, String> {
    if values.is_empty() {
        return Err(format!(
            "plugin '{name}' command requires at least one hook"
        ));
    }
    let mut hooks = BTreeSet::new();
    for value in values {
        let hook = MiddlewareStage::from_name(value)
            .ok_or_else(|| format!("plugin '{name}' declares unknown hook '{value}'"))?;
        if !hooks.insert(hook) {
            return Err(format!(
                "plugin '{name}' declares hook '{value}' more than once"
            ));
        }
    }
    Ok(hooks)
}

fn expand_plugin_command(
    name: &str,
    argv: Vec<String>,
    root: &Path,
) -> Result<Vec<String>, String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("plugin '{name}' command root is unavailable: {error}"))?;
    argv.into_iter()
        .map(|argument| {
            let relative = if argument == "{plugin}" {
                Some("")
            } else {
                argument.strip_prefix("{plugin}/")
            };
            let Some(relative) = relative else {
                return Ok(argument);
            };
            let relative = Path::new(relative);
            if relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
                && !relative.as_os_str().is_empty()
            {
                return Err(format!(
                    "plugin '{name}' command path must stay inside the plugin directory"
                ));
            }
            let path = if relative.as_os_str().is_empty() {
                canonical_root.clone()
            } else {
                canonical_root
                    .join(relative)
                    .canonicalize()
                    .map_err(|error| {
                        format!("plugin '{name}' command file '{argument}' is unavailable: {error}")
                    })?
            };
            if !path.starts_with(&canonical_root) {
                return Err(format!(
                    "plugin '{name}' command path escapes the plugin directory"
                ));
            }
            Ok(path.to_string_lossy().into_owned())
        })
        .collect()
}

#[derive(Clone, Debug)]
enum PluginProgram {
    Wasm(Box<WasmProgram>),
    Command(CommandProgram),
}

#[derive(Clone)]
struct CommandProgram {
    argv: Arc<Vec<String>>,
    cwd: Arc<PathBuf>,
    state: Arc<Mutex<Option<CommandSession>>>,
    max_output_bytes: usize,
}

impl std::fmt::Debug for CommandProgram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandProgram")
            .field("argv", &self.argv)
            .field("cwd", &self.cwd)
            .field("max_output_bytes", &self.max_output_bytes)
            .finish_non_exhaustive()
    }
}

impl CommandProgram {
    fn new(argv: Vec<String>, cwd: PathBuf, max_output_bytes: usize) -> Result<Self, String> {
        if argv.is_empty() || argv[0].trim().is_empty() {
            return Err("plugin command requires a non-empty executable".to_string());
        }
        if argv.len() > 256 || argv.iter().any(|argument| argument.len() > 32 * 1024) {
            return Err("plugin command argv exceeds its limit".to_string());
        }
        Ok(Self {
            argv: Arc::new(argv),
            cwd: Arc::new(cwd),
            state: Arc::new(Mutex::new(None)),
            max_output_bytes,
        })
    }

    #[cfg(test)]
    fn invoke(&self, request: &[u8], timeout: Duration, name: &str) -> Result<Vec<u8>, String> {
        let mut budget = PluginChainBudget::new();
        self.invoke_with_startup_timeout(request, timeout, timeout, name, &mut budget)
    }

    fn invoke_with_startup_timeout(
        &self,
        request: &[u8],
        timeout: Duration,
        startup_timeout: Duration,
        name: &str,
        budget: &mut PluginChainBudget,
    ) -> Result<Vec<u8>, String> {
        record_plugin_access(name, "command");
        let mut state = self.lock_state_until(budget.deadline, name)?;
        let starting = state.is_none();
        if starting {
            *state = Some(CommandSession::start(
                &self.argv,
                &self.cwd,
                self.max_output_bytes,
                name,
            )?);
        }
        let remaining = budget.remaining().map_err(|_| {
            format!("plugin '{name}' command chain deadline exceeded before execution")
        })?;
        let (exchange_timeout, phase) =
            command_exchange_timeout(starting, timeout, startup_timeout, remaining);
        let result = state
            .as_mut()
            .expect("command session initialized")
            .exchange(request, exchange_timeout, name, phase);
        if result.is_err() {
            record_plugin_access(name, phase.diagnostic_operation());
        }
        if result.is_err() {
            if let Some(mut session) = state.take() {
                session.stop();
            }
        }
        result
    }

    fn lock_state_until<'a>(
        &'a self,
        deadline: Instant,
        name: &str,
    ) -> Result<MutexGuard<'a, Option<CommandSession>>, String> {
        loop {
            match self.state.try_lock() {
                Ok(state) => return Ok(state),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(format!("plugin '{name}' command state is unavailable"));
                }
                Err(TryLockError::WouldBlock) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        record_plugin_access(name, "command-lock-timeout");
                        return Err(format!("plugin '{name}' command lock wait timed out"));
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(5)));
                }
            }
        }
    }
}

fn command_exchange_timeout(
    starting: bool,
    timeout: Duration,
    startup_timeout: Duration,
    remaining: Duration,
) -> (Duration, CommandExchangePhase) {
    if starting {
        (
            startup_timeout.min(remaining),
            CommandExchangePhase::Startup,
        )
    } else {
        (timeout.min(remaining), CommandExchangePhase::Request)
    }
}

struct CommandSession {
    child: Child,
    tree: CommandTree,
    stdin: Option<ChildStdin>,
    responses: mpsc::Receiver<Result<Vec<u8>, String>>,
}

#[derive(Clone, Copy)]
enum CommandExchangePhase {
    Startup,
    Request,
}

impl CommandExchangePhase {
    fn timeout_error(self, name: &str) -> String {
        match self {
            Self::Startup => format!("plugin '{name}' command startup timed out"),
            Self::Request => format!("plugin '{name}' command request timed out"),
        }
    }

    fn diagnostic_operation(self) -> &'static str {
        match self {
            Self::Startup => "command-startup-failed",
            Self::Request => "command-request-failed",
        }
    }
}

impl CommandSession {
    fn start(
        argv: &[String],
        cwd: &Path,
        max_output_bytes: usize,
        name: &str,
    ) -> Result<Self, String> {
        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        sanitize_command_environment(&mut command);
        configure_command_tree(&mut command);
        let mut child = command
            .spawn()
            .map_err(|error| format!("plugin '{name}' command could not start: {error}"))?;
        let tree = CommandTree::attach(&child).map_err(|error| {
            let _ = child.kill();
            let _ = child.wait();
            format!("plugin '{name}' command isolation failed: {error}")
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("plugin '{name}' command stdin is unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("plugin '{name}' command stdout is unavailable"))?;
        // Keep draining stdout even while the caller is busy writing or processing a
        // previous response. The byte limit is enforced before anything is queued.
        let (sender, responses) = mpsc::channel();
        std::thread::Builder::new()
            .name(format!("pentect-plugin-{name}"))
            .spawn(move || {
                let mut stdout = BufReader::new(stdout);
                loop {
                    let mut line = Vec::new();
                    let read = stdout
                        .by_ref()
                        .take(max_output_bytes.saturating_add(2) as u64)
                        .read_until(b'\n', &mut line);
                    let result = match read {
                        Ok(0) => Err("command closed stdout".to_string()),
                        Ok(_) if line.len() > max_output_bytes => {
                            Err("command response exceeds its limit".to_string())
                        }
                        Ok(_) if line.last() != Some(&b'\n') => {
                            Err("command returned an incomplete protocol line".to_string())
                        }
                        Ok(_) => {
                            while matches!(line.last(), Some(b'\n' | b'\r')) {
                                line.pop();
                            }
                            Ok(line)
                        }
                        Err(_) => Err("command response could not be read".to_string()),
                    };
                    let stop = result.is_err();
                    if sender.send(result).is_err() || stop {
                        break;
                    }
                }
            })
            .map_err(|error| format!("plugin '{name}' response reader could not start: {error}"))?;
        Ok(Self {
            child,
            tree,
            stdin: Some(stdin),
            responses,
        })
    }

    fn exchange(
        &mut self,
        request: &[u8],
        timeout: Duration,
        name: &str,
        phase: CommandExchangePhase,
    ) -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + timeout;
        let mut stdin = self
            .stdin
            .take()
            .ok_or_else(|| format!("plugin '{name}' command input is unavailable"))?;
        let payload = request.to_vec();
        let (write_tx, write_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name(format!("pentect-plugin-{name}-stdin"))
            .spawn(move || {
                let result = stdin
                    .write_all(&payload)
                    .and_then(|_| stdin.write_all(b"\n"))
                    .and_then(|_| stdin.flush());
                let _ = write_tx.send((stdin, result));
            })
            .map_err(|error| format!("plugin '{name}' input writer could not start: {error}"))?;
        match write_rx.recv_timeout(timeout) {
            Ok((stdin, Ok(()))) => self.stdin = Some(stdin),
            Ok((_stdin, Err(_))) => return Err(format!("plugin '{name}' command input failed")),
            Err(mpsc::RecvTimeoutError::Timeout) => return Err(phase.timeout_error(name)),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(format!("plugin '{name}' command input failed"));
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(phase.timeout_error(name));
        }
        self.responses
            .recv_timeout(remaining)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => phase.timeout_error(name),
                mpsc::RecvTimeoutError::Disconnected => {
                    format!("plugin '{name}' command stopped without a response")
                }
            })?
            .map_err(|error| format!("plugin '{name}' {error}"))
    }

    fn stop(&mut self) {
        self.tree.terminate();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for CommandSession {
    fn drop(&mut self) {
        self.stop();
    }
}

fn sanitize_command_environment(command: &mut Command) {
    const KEEP: &[&str] = &[
        "HOME",
        "USERPROFILE",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
    ];
    let kept = KEEP
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (*name, value)))
        .collect::<Vec<_>>();
    command.env_clear();
    command.envs(kept);
}

#[cfg(unix)]
fn configure_command_tree(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
}

#[cfg(windows)]
fn configure_command_tree(_command: &mut Command) {}

#[cfg(not(any(unix, windows)))]
fn configure_command_tree(_command: &mut Command) {}

#[cfg(unix)]
struct CommandTree {
    process_group: i32,
}

#[cfg(unix)]
impl CommandTree {
    fn attach(child: &Child) -> Result<Self, String> {
        Ok(Self {
            process_group: i32::try_from(child.id())
                .map_err(|_| "child process id is invalid".to_string())?,
        })
    }

    fn terminate(&self) {
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
    }
}

#[cfg(unix)]
impl Drop for CommandTree {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(windows)]
struct CommandTree {
    job: usize,
}

#[cfg(windows)]
impl CommandTree {
    fn attach(child: &Child) -> Result<Self, String> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err("could not create a Windows Job Object".to_string());
        }
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(information).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } != 0;
        let assigned = configured
            && unsafe { AssignProcessToJobObject(job, child.as_raw_handle().cast()) } != 0;
        if !assigned {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(job);
            }
            return Err("could not assign the process to a Windows Job Object".to_string());
        }
        Ok(Self { job: job as usize })
    }

    fn terminate(&self) {
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job as _, 1);
        }
    }
}

#[cfg(windows)]
impl Drop for CommandTree {
    fn drop(&mut self) {
        self.terminate();
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.job as _);
        }
    }
}

#[cfg(not(any(unix, windows)))]
struct CommandTree;

#[cfg(not(any(unix, windows)))]
impl CommandTree {
    fn attach(_child: &Child) -> Result<Self, String> {
        Ok(Self)
    }

    fn terminate(&self) {}
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
    hooks: Vec<String>,
    command_lock_sha256: Option<String>,
}

#[derive(Deserialize)]
struct PluginBinaryLock {
    schema: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginCommandLock {
    schema: String,
    executable: String,
    #[serde(default)]
    managed: bool,
    #[serde(default)]
    file: Vec<PluginCommandLockFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginCommandLockFile {
    path: String,
    sha256: String,
}

fn verify_command_files(
    name: &str,
    argv: &[String],
    root: &Path,
    runtime_dirs: &PluginRuntimeDirs,
) -> Result<PathBuf, String> {
    use sha2::{Digest, Sha256};

    let lock_path = runtime_dirs.data_dir.join(PLUGIN_COMMAND_LOCK_FILE);
    let source = read_bounded_utf8(&lock_path, MAX_PLUGIN_METADATA_BYTES, "plugin command lock")
        .map_err(|_| {
            format!("plugin '{name}' command is not locked; run `pentect plugins setup` again")
        })?;
    let lock: PluginCommandLock =
        toml::from_str(&source).map_err(|_| format!("plugin '{name}' command lock is invalid"))?;
    if lock.schema != "pentect.plugin-command-lock.v1" {
        return Err(format!("plugin '{name}' command lock is invalid"));
    }
    if lock.file.len() > 64 {
        return Err(format!("plugin '{name}' command lock is invalid"));
    }
    let executable = resolve_plugin_command_executable(&argv[0], root, name)?;
    let locked_executable = Path::new(&lock.executable)
        .canonicalize()
        .map_err(|_| format!("plugin '{name}' command executable is unavailable"))?;
    if executable != locked_executable {
        return Err(format!(
            "plugin '{name}' command executable changed after setup"
        ));
    }
    let expected = argv
        .iter()
        .filter_map(|argument| argument.strip_prefix("{plugin}/"))
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let locked = lock
        .file
        .iter()
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>();
    // The setup command may reference additional reviewed files that are also
    // hashed into the approval lock. Runtime argv must be covered by that lock,
    // but it need not be the entire locked set.
    if !expected.is_subset(&locked) || locked.len() != lock.file.len() {
        return Err(format!(
            "plugin '{name}' command file set changed after setup"
        ));
    }
    let canonical_root = root
        .canonicalize()
        .map_err(|_| format!("plugin '{name}' command root is unavailable"))?;
    if lock.managed {
        let actual = walk_regular_files(root)?;
        if actual != locked {
            return Err(format!(
                "plugin '{name}' command file set changed after setup"
            ));
        }
    }
    for file in lock.file {
        if file.sha256.len() != 64 || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("plugin '{name}' command lock is invalid"));
        }
        let relative = Path::new(&file.path);
        if relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(format!("plugin '{name}' command lock path is invalid"));
        }
        let path = canonical_root.join(relative).canonicalize().map_err(|_| {
            format!(
                "plugin '{name}' command file '{}' is unavailable",
                file.path
            )
        })?;
        if !path.starts_with(&canonical_root) || !path.is_file() {
            return Err(format!(
                "plugin '{name}' command file '{}' is invalid",
                file.path
            ));
        }
        let bytes = read_bounded_bytes(&path, MAX_PLUGIN_WASM_BYTES, "plugin command file")?;
        let digest = data_encoding::HEXLOWER.encode(&Sha256::digest(bytes));
        if !digest.eq_ignore_ascii_case(&file.sha256) {
            return Err(format!(
                "plugin '{name}' command file '{}' changed after setup",
                file.path
            ));
        }
    }
    Ok(executable)
}

fn walk_regular_files(root: &Path) -> Result<BTreeSet<String>, String> {
    let mut result = BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)
            .map_err(|_| "plugin command directory is unavailable".to_string())?
        {
            let entry = entry.map_err(|_| "plugin command directory is unavailable".to_string())?;
            let kind = entry
                .file_type()
                .map_err(|_| "plugin command directory is unavailable".to_string())?;
            if kind.is_symlink() {
                return Err("plugin command directory contains a symbolic link".to_string());
            }
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| "plugin command path is invalid".to_string())?
                    .to_string_lossy()
                    .replace('\\', "/");
                result.insert(relative);
            }
        }
    }
    Ok(result)
}

fn resolve_plugin_command_executable(
    value: &str,
    root: &Path,
    name: &str,
) -> Result<PathBuf, String> {
    let Some(relative) = value.strip_prefix("{plugin}/") else {
        return resolve_command_executable(value);
    };
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "plugin '{name}' command executable path is invalid"
        ));
    }
    let canonical_root = root
        .canonicalize()
        .map_err(|_| format!("plugin '{name}' command root is unavailable"))?;
    let executable = canonical_root
        .join(relative)
        .canonicalize()
        .map_err(|_| format!("plugin '{name}' command executable is unavailable"))?;
    if !executable.starts_with(&canonical_root) || !supported_command_executable(&executable) {
        return Err(format!("plugin '{name}' command executable is invalid"));
    }
    Ok(executable)
}

fn resolve_command_executable(value: &str) -> Result<PathBuf, String> {
    let candidate = Path::new(value);
    if candidate.components().count() > 1 || candidate.is_absolute() {
        let resolved = candidate
            .canonicalize()
            .map_err(|_| format!("command executable is unavailable: {value}"));
        return resolved.and_then(|path| {
            supported_command_executable(&path)
                .then_some(path)
                .ok_or_else(|| format!("command executable is unavailable: {value}"))
        });
    }
    let paths = std::env::var_os("PATH").unwrap_or_default();
    #[cfg(windows)]
    let extensions = std::env::var_os("PATHEXT")
        .map(|value| {
            value
                .to_string_lossy()
                .split(';')
                .filter(|extension| {
                    matches!(extension.to_ascii_uppercase().as_str(), ".EXE" | ".COM")
                })
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![".EXE".to_string(), ".COM".to_string()]);
    #[cfg(not(windows))]
    let extensions = vec![String::new()];
    for directory in std::env::split_paths(&paths) {
        for extension in &extensions {
            let path = if extension.is_empty()
                || value
                    .to_ascii_lowercase()
                    .ends_with(&extension.to_ascii_lowercase())
            {
                directory.join(value)
            } else {
                directory.join(format!("{value}{extension}"))
            };
            if let Ok(path) = path.canonicalize() {
                if supported_command_executable(&path) {
                    return Ok(path);
                }
            }
        }
    }
    Err(format!("command executable is unavailable: {value}"))
}

#[cfg(unix)]
fn supported_command_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
fn supported_command_executable(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                matches!(extension.to_ascii_lowercase().as_str(), "exe" | "com")
            })
}

fn verify_plugin_approval(
    manifest: &Path,
    runtime_dirs: &PluginRuntimeDirs,
    hooks: &BTreeSet<MiddlewareStage>,
    command: bool,
) -> Result<(), String> {
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
    let installed_hooks = hooks
        .iter()
        .map(|hook| hook.as_str().to_string())
        .collect::<Vec<_>>();
    let command_lock_sha256 = command
        .then(|| {
            read_bounded_bytes(
                &runtime_dirs.data_dir.join(PLUGIN_COMMAND_LOCK_FILE),
                MAX_PLUGIN_METADATA_BYTES,
                "plugin command lock",
            )
            .map(|bytes| data_encoding::HEXLOWER.encode(&Sha256::digest(bytes)))
        })
        .transpose()?;
    if approval.schema != "pentect.plugin-approval.v1"
        || approval.manifest_sha256 != digest
        || approval.hooks != installed_hooks
        || approval.command_lock_sha256 != command_lock_sha256
    {
        return Err(format!(
            "plugin '{}' manifest or hook access changed after approval; run `pentect plugins setup {} --yes` again",
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
const WASM_HOST_MODULE: &str = "pentect:host";
const WASM_HOST_REQUEST: &str = "request";
const WASM_MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;
const HTTP_MAX_REQUEST_BYTES: usize = 1024 * 1024;
const HTTP_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const HTTP_MAX_REQUESTS: usize = 16;
const HTTP_DEFAULT_REQUESTS: usize = 4;
const HTTP_MAX_ORIGINS: usize = 64;
const HTTP_MAX_HEADERS: usize = 64;
const HTTP_MAX_HEADER_BYTES: usize = 64 * 1024;
const HTTP_MAX_DNS_THREADS: usize = 32;
const HOST_MAX_REQUESTS: usize = 64;
const HOST_MAX_VALUE_BYTES: usize = 128 * 1024;
const HOST_MAX_COMMAND_STREAM_BYTES: usize = 64 * 1024;
// Each invocation gets a fixed fuel budget derived from its configured time
// limit. This keeps untrusted Wasm bounded without resumable execution around
// compound instructions. HTTP calls also use the wall-clock deadline stored
// in WasmHostState.
const WASM_FUEL_PER_MS: u64 = 1_000;
const WASM_MIN_FUEL: u64 = 100_000;

#[derive(Clone, Debug)]
struct WasmProgram {
    engine: wasmi::Engine,
    module: wasmi::Module,
    hooks: BTreeSet<MiddlewareStage>,
    network: Option<NetworkPolicy>,
    config: Option<toml::Value>,
    permissions: Option<PermissionPolicy>,
}

impl WasmProgram {
    fn load_bytes(
        bytes: &[u8],
        name: &str,
        network: Option<NetworkPolicy>,
        config: Option<toml::Value>,
        permissions: Option<PermissionPolicy>,
    ) -> Result<Self, String> {
        let mut engine_config = wasmi::Config::default();
        engine_config.consume_fuel(true);
        engine_config.enforced_limits(wasmi::EnforcedLimits::strict());
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
                    && config.is_some())
                || (import.module() == WASM_HOST_MODULE
                    && import.name() == WASM_HOST_REQUEST
                    && permissions.is_some());
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
            permissions,
        })
    }

    #[cfg(test)]
    fn invoke(
        &self,
        hook: MiddlewareStage,
        request: &[u8],
        timeout: Duration,
        max_output_bytes: usize,
        name: &str,
    ) -> Result<Vec<u8>, String> {
        self.invoke_bounded(
            hook,
            request,
            timeout,
            max_output_bytes,
            name,
            Instant::now() + timeout,
            Arc::new(AtomicUsize::new(0)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn invoke_bounded(
        &self,
        hook: MiddlewareStage,
        request: &[u8],
        timeout: Duration,
        max_output_bytes: usize,
        name: &str,
        chain_deadline: Instant,
        chain_network_requests: Arc<AtomicUsize>,
    ) -> Result<Vec<u8>, String> {
        let limits = wasmi::StoreLimitsBuilder::new()
            .memory_size(WASM_MAX_MEMORY_BYTES)
            .table_elements(4096)
            .memories(1)
            .instances(1)
            .tables(1)
            .trap_on_grow_failure(true)
            .build();
        let started = Instant::now();
        let fuel = u64::try_from(timeout.as_millis())
            .unwrap_or(u64::MAX)
            .saturating_mul(WASM_FUEL_PER_MS)
            .max(WASM_MIN_FUEL);
        let mut store = wasmi::Store::new(
            &self.engine,
            WasmHostState {
                limits,
                network: self.network.clone(),
                network_requests: 0,
                chain_network_requests,
                config: self.config.clone(),
                permissions: self.permissions.clone(),
                host_requests: 0,
                pending_host_response: None,
                deadline: (started + timeout).min(chain_deadline),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(fuel)
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
        if self.permissions.is_some() {
            linker
                .func_wrap(WASM_HOST_MODULE, WASM_HOST_REQUEST, wasm_host_request)
                .map_err(|error| format!("plugin '{name}' host setup failed: {error}"))?;
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
        let packed = handle
            .call(&mut store, (request_ptr, request_len))
            .map_err(|error| {
                if error.as_trap_code() == Some(wasmi::TrapCode::OutOfFuel) {
                    format!("plugin '{name}' timed out")
                } else {
                    format!("plugin '{name}' execution failed: {error}")
                }
            })? as u64;
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
    chain_network_requests: Arc<AtomicUsize>,
    config: Option<toml::Value>,
    permissions: Option<PermissionPolicy>,
    host_requests: usize,
    pending_host_response: Option<(Vec<u8>, Vec<u8>)>,
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

#[derive(Clone, Debug)]
struct PermissionPolicy {
    name: String,
    read: Vec<PathPermission>,
    write: Vec<PathPermission>,
    env: BTreeSet<String>,
    run: BTreeMap<Vec<String>, Vec<String>>,
    storage: bool,
    project_root: PathBuf,
    plugin_root: PathBuf,
    storage_root: PathBuf,
}

#[derive(Clone, Debug)]
struct PathPermission {
    scope: PathScope,
    relative: PathBuf,
    recursive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathScope {
    Project,
    Plugin,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum HostRequest {
    EnvRead {
        name: String,
    },
    FileRead {
        path: String,
    },
    FileWrite {
        path: String,
        data: String,
    },
    StorageGet {
        key: String,
    },
    StorageSet {
        key: String,
        value: Value,
    },
    CommandRun {
        argv: Vec<String>,
        #[serde(default)]
        stdin: String,
    },
}

#[derive(Debug, Serialize)]
struct HostResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

impl HostResponse {
    fn ok(value: impl Into<Value>) -> Self {
        Self {
            ok: true,
            value: Some(value.into()),
            error: None,
        }
    }

    fn denied() -> Self {
        Self {
            ok: false,
            value: None,
            error: Some("permission_denied"),
        }
    }

    fn failed() -> Self {
        Self {
            ok: false,
            value: None,
            error: Some("operation_failed"),
        }
    }
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
        return i32::try_from(encoded.len()).unwrap_or(-2);
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

fn wasm_host_request(
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
    let (Ok(request_offset), Ok(request_len), Ok(response_offset), Ok(response_capacity)) = (
        usize::try_from(request_ptr),
        usize::try_from(request_len),
        usize::try_from(response_ptr),
        usize::try_from(response_capacity),
    ) else {
        return -1;
    };
    if request_len > DEFAULT_MAX_INPUT_BYTES || response_capacity > DEFAULT_MAX_OUTPUT_BYTES {
        return -2;
    }
    let mut request = vec![0; request_len];
    if memory.read(&caller, request_offset, &mut request).is_err() {
        return -1;
    }
    let encoded = if caller
        .data()
        .pending_host_response
        .as_ref()
        .is_some_and(|(pending, _)| pending == &request)
    {
        caller.data_mut().pending_host_response.take().unwrap().1
    } else {
        caller.data_mut().pending_host_response = None;
        if caller.data().host_requests >= HOST_MAX_REQUESTS {
            return -2;
        }
        caller.data_mut().host_requests += 1;
        let response = match (
            caller.data().permissions.as_ref(),
            serde_json::from_slice::<HostRequest>(&request),
        ) {
            (Some(policy), Ok(request)) => {
                perform_host_request(policy, request, caller.data().deadline)
            }
            _ => HostResponse::denied(),
        };
        let Ok(encoded) = serde_json::to_vec(&response) else {
            return -3;
        };
        encoded
    };
    if encoded.len() > response_capacity {
        caller.data_mut().pending_host_response = Some((request, encoded.clone()));
        return i32::try_from(encoded.len()).unwrap_or(-2);
    }
    if memory
        .write(&mut caller, response_offset, &encoded)
        .is_err()
    {
        return -1;
    }
    i32::try_from(encoded.len()).unwrap_or(-2)
}

fn perform_host_request(
    policy: &PermissionPolicy,
    request: HostRequest,
    deadline: Instant,
) -> HostResponse {
    if Instant::now() >= deadline {
        return HostResponse::failed();
    }
    record_plugin_access(
        &policy.name,
        match &request {
            HostRequest::EnvRead { .. } => "env-read",
            HostRequest::FileRead { .. } => "file-read",
            HostRequest::FileWrite { .. } => "file-write",
            HostRequest::StorageGet { .. } => "storage-read",
            HostRequest::StorageSet { .. } => "storage-write",
            HostRequest::CommandRun { .. } => "command-run",
        },
    );
    match request {
        HostRequest::EnvRead { name } => {
            if !policy.env.contains(&name) {
                return HostResponse::denied();
            }
            HostResponse::ok(
                std::env::var_os(name)
                    .map(|value| Value::String(value.to_string_lossy().into_owned()))
                    .unwrap_or(Value::Null),
            )
        }
        HostRequest::FileRead { path } => {
            let Some(path) = approved_file_path(policy, &path, false) else {
                return HostResponse::denied();
            };
            match read_bounded_utf8(&path, HOST_MAX_VALUE_BYTES as u64, "plugin file") {
                Ok(value) => HostResponse::ok(value),
                Err(_) => HostResponse::failed(),
            }
        }
        HostRequest::FileWrite {
            path: requested_path,
            data,
        } => {
            if data.len() > HOST_MAX_VALUE_BYTES {
                return HostResponse::failed();
            }
            let Some(path) = approved_file_path(policy, &requested_path, true) else {
                return HostResponse::denied();
            };
            let Some(parent) = path.parent() else {
                return HostResponse::denied();
            };
            if std::fs::create_dir_all(parent).is_err() {
                return HostResponse::failed();
            }
            // Re-resolve after creating the path so a symlink introduced in an
            // absent component cannot redirect the write outside its scope.
            let Some(path) = approved_file_path(policy, &requested_path, true) else {
                return HostResponse::denied();
            };
            let temporary = path.with_extension(format!(
                "pentect-tmp-{}-{}",
                std::process::id(),
                REQUEST_ID.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::write(&temporary, data)
                .map_err(|error| error.to_string())
                .and_then(|_| replace_host_file(&temporary, &path))
            {
                Ok(()) => HostResponse::ok(true),
                Err(_) => {
                    let _ = std::fs::remove_file(temporary);
                    HostResponse::failed()
                }
            }
        }
        HostRequest::StorageGet { key } => {
            if !policy.storage || !valid_storage_key(&key) {
                return HostResponse::denied();
            }
            let path = storage_path(&policy.storage_root, &key);
            if !path.is_file() {
                return HostResponse::ok(Value::Null);
            }
            match read_bounded_utf8(&path, HOST_MAX_VALUE_BYTES as u64, "plugin storage").and_then(
                |source| {
                    serde_json::from_str::<Value>(&source)
                        .map_err(|_| "plugin storage value is invalid".to_string())
                },
            ) {
                Ok(value) => HostResponse::ok(value),
                Err(_) => HostResponse::failed(),
            }
        }
        HostRequest::StorageSet { key, value } => {
            if !policy.storage || !valid_storage_key(&key) {
                return HostResponse::denied();
            }
            let Ok(encoded) = serde_json::to_vec(&value) else {
                return HostResponse::failed();
            };
            if encoded.len() > HOST_MAX_VALUE_BYTES {
                return HostResponse::failed();
            }
            let path = storage_path(&policy.storage_root, &key);
            let temporary = path.with_extension(format!(
                "tmp-{}-{}",
                std::process::id(),
                REQUEST_ID.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::write(&temporary, encoded)
                .map_err(|error| error.to_string())
                .and_then(|_| replace_host_file(&temporary, &path))
            {
                Ok(()) => HostResponse::ok(true),
                Err(_) => {
                    let _ = std::fs::remove_file(temporary);
                    HostResponse::failed()
                }
            }
        }
        HostRequest::CommandRun { argv, stdin } => {
            let Some(resolved) = policy.run.get(&argv) else {
                return HostResponse::denied();
            };
            if stdin.len() > DEFAULT_MAX_INPUT_BYTES {
                return HostResponse::denied();
            }
            match run_brokered_command(&policy.project_root, resolved, &stdin, deadline) {
                Ok(value) => HostResponse::ok(value),
                Err(_) => HostResponse::failed(),
            }
        }
    }
}

fn approved_file_path(policy: &PermissionPolicy, value: &str, write: bool) -> Option<PathBuf> {
    let (scope, relative) = value.split_once(':')?;
    let (scope, root) = match scope {
        "project" => (PathScope::Project, &policy.project_root),
        "plugin" => (PathScope::Plugin, &policy.plugin_root),
        _ => return None,
    };
    let relative = PathBuf::from(relative);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    let allowed = if write { &policy.write } else { &policy.read };
    let candidate = root.join(&relative);
    if !allowed.iter().any(|permission| {
        permission.scope == scope
            && if permission.recursive {
                relative.starts_with(&permission.relative)
                    || canonical_permission_contains(root, &candidate, permission)
            } else {
                relative == permission.relative
                    || canonical_paths_match(root, &candidate, permission)
            }
    }) {
        return None;
    }
    if write {
        let mut existing = candidate.parent()?;
        while !existing.exists() {
            existing = existing.parent()?;
        }
        let existing = existing.canonicalize().ok()?;
        if !existing.starts_with(root) {
            return None;
        }
        if candidate.exists() {
            let canonical = candidate.canonicalize().ok()?;
            canonical.starts_with(root).then_some(canonical)
        } else {
            Some(candidate)
        }
    } else {
        let canonical = candidate.canonicalize().ok()?;
        (canonical.starts_with(root) && canonical.is_file()).then_some(canonical)
    }
}

fn canonical_paths_match(root: &Path, candidate: &Path, permission: &PathPermission) -> bool {
    let Ok(candidate) = candidate.canonicalize() else {
        return false;
    };
    let Ok(allowed) = root.join(&permission.relative).canonicalize() else {
        return false;
    };
    candidate == allowed
}

fn canonical_permission_contains(
    root: &Path,
    candidate: &Path,
    permission: &PathPermission,
) -> bool {
    let Ok(allowed) = root.join(&permission.relative).canonicalize() else {
        return false;
    };
    let mut existing = candidate;
    while !existing.exists() {
        let Some(parent) = existing.parent() else {
            return false;
        };
        existing = parent;
    }
    existing
        .canonicalize()
        .is_ok_and(|candidate| candidate.starts_with(allowed))
}

fn valid_storage_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 256
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn record_plugin_access(name: &str, operation: &str) {
    activity_log::record_summary(
        "plugin",
        name,
        1,
        BTreeMap::from([(operation.to_string(), 1)]),
        None,
    );
}

fn replace_host_file(staged: &Path, destination: &Path) -> Result<(), String> {
    if !destination.exists() {
        return std::fs::rename(staged, destination).map_err(|error| error.to_string());
    }
    let backup = destination.with_extension(format!(
        "pentect-backup-{}-{}",
        std::process::id(),
        REQUEST_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::rename(destination, &backup).map_err(|error| error.to_string())?;
    if let Err(error) = std::fs::rename(staged, destination) {
        let _ = std::fs::rename(&backup, destination);
        return Err(error.to_string());
    }
    std::fs::remove_file(backup).map_err(|error| error.to_string())
}

fn storage_path(root: &Path, key: &str) -> PathBuf {
    let mut digest = sha2::Sha256::new();
    use sha2::Digest as _;
    digest.update(b"pentect-plugin-storage-v1");
    digest.update(key.as_bytes());
    root.join(format!(
        "{}.json",
        data_encoding::HEXLOWER.encode(&digest.finalize())
    ))
}

fn run_brokered_command(
    cwd: &Path,
    argv: &[String],
    stdin: &str,
    deadline: Instant,
) -> Result<Value, String> {
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    sanitize_command_environment(&mut command);
    configure_command_tree(&mut command);
    let mut child = command
        .spawn()
        .map_err(|_| "approved command could not start".to_string())?;
    let tree = CommandTree::attach(&child).map_err(|error| {
        let _ = child.kill();
        let _ = child.wait();
        format!("approved command isolation failed: {error}")
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "stdout unavailable".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "stderr unavailable".to_string())?;
    let stdout_reader = std::thread::spawn(move || {
        let mut value = Vec::new();
        stdout
            .take((HOST_MAX_COMMAND_STREAM_BYTES + 1) as u64)
            .read_to_end(&mut value)
            .map(|_| value)
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut value = Vec::new();
        stderr
            .take((HOST_MAX_COMMAND_STREAM_BYTES + 1) as u64)
            .read_to_end(&mut value)
            .map(|_| value)
    });
    if let Some(mut input) = child.stdin.take() {
        let bytes = stdin.as_bytes().to_vec();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = input.write_all(&bytes);
            let _ = sender.send(result);
        });
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                tree.terminate();
                let _ = child.kill();
                let _ = child.wait();
                return Err("approved command input failed".to_string());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                tree.terminate();
                let _ = child.kill();
                let _ = child.wait();
                return Err("approved command timed out".to_string());
            }
        }
    }
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| "approved command wait failed".to_string())?
        {
            break status;
        }
        if Instant::now() >= deadline {
            tree.terminate();
            let _ = child.kill();
            let _ = child.wait();
            return Err("approved command timed out".to_string());
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    // A command may leave descendants alive with inherited stdout/stderr handles.
    // Stop the whole approved tree before joining the readers so those handles close.
    tree.terminate();
    let stdout = stdout_reader
        .join()
        .map_err(|_| "approved command output failed".to_string())?
        .map_err(|_| "approved command output failed".to_string())?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "approved command error output failed".to_string())?
        .map_err(|_| "approved command error output failed".to_string())?;
    if stdout.len() > HOST_MAX_COMMAND_STREAM_BYTES || stderr.len() > HOST_MAX_COMMAND_STREAM_BYTES
    {
        return Err("approved command output exceeds its limit".to_string());
    }
    Ok(json!({
        "status": status.code(),
        "success": status.success(),
        "stdout": String::from_utf8_lossy(&stdout),
        "stderr": String::from_utf8_lossy(&stderr),
    }))
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
        if !charge_chain_network_request(&caller.data().chain_network_requests) {
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
        && origin.host.parse::<IpAddr>().map_or(true, |ip| match ip {
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
    detector: Vec<toml::Value>,
    #[serde(default)]
    postscript: Vec<toml::Value>,
    wasm: Option<String>,
    binary: Option<String>,
    #[serde(default)]
    command: Vec<String>,
    commands: Option<PlatformCommandsFile>,
    #[serde(default)]
    hooks: Vec<String>,
    // Setup is executed and validated by pentect-cli before approval. The
    // runtime only needs to tolerate this CLI-owned metadata when it loads an
    // already approved command plugin.
    #[serde(rename = "setup")]
    _setup: Option<toml::Value>,
    publisher: Option<PublisherFile>,
    execution: Option<ExecutionFile>,
    #[serde(default)]
    required: bool,
    network: Option<NetworkFile>,
    permissions: Option<PermissionsFile>,
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
    startup_timeout_ms: Option<u64>,
    max_input_bytes: Option<usize>,
    max_output_bytes: Option<usize>,
    max_spans: Option<usize>,
}

#[derive(Clone, Debug, Default, Deserialize)]
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

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PermissionsFile {
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    write: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    run: Vec<Vec<String>>,
    #[serde(default)]
    storage: bool,
    network: Option<NetworkFile>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformCommandsFile {
    windows: Option<Vec<String>>,
    macos: Option<Vec<String>>,
    linux: Option<Vec<String>>,
}

impl PlatformCommandsFile {
    fn current(&self) -> Option<&Vec<String>> {
        #[cfg(windows)]
        let selected = self.windows.as_ref();
        #[cfg(target_os = "macos")]
        let selected = self.macos.as_ref();
        #[cfg(target_os = "linux")]
        let selected = self.linux.as_ref();
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        let selected = None;
        selected
    }

    fn variants(&self) -> impl Iterator<Item = &[String]> {
        [
            self.windows.as_deref(),
            self.macos.as_deref(),
            self.linux.as_deref(),
        ]
        .into_iter()
        .flatten()
    }
}

fn validate_permissions(
    name: &str,
    permissions: Option<PermissionsFile>,
    manifest: &Path,
    runtime_dirs: &PluginRuntimeDirs,
) -> Result<Option<PermissionPolicy>, String> {
    let Some(permissions) = permissions else {
        return Ok(None);
    };
    if permissions.read.len() > 64
        || permissions.write.len() > 64
        || permissions.env.len() > 64
        || permissions.run.len() > 64
    {
        return Err(format!("plugin '{name}' declares too many permissions"));
    }
    if permissions.read.is_empty()
        && permissions.write.is_empty()
        && permissions.env.is_empty()
        && permissions.run.is_empty()
        && !permissions.storage
    {
        return Ok(None);
    }
    let project_root = std::env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(|_| format!("plugin '{name}' project directory is unavailable"))?;
    let plugin_root = manifest
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(|_| format!("plugin '{name}' source directory is unavailable"))?;
    let read = permissions
        .read
        .iter()
        .map(|value| parse_path_permission(name, value))
        .collect::<Result<Vec<_>, _>>()?;
    let write = permissions
        .write
        .iter()
        .map(|value| parse_path_permission(name, value))
        .collect::<Result<Vec<_>, _>>()?;
    let mut env = BTreeSet::new();
    for variable in permissions.env {
        if variable.is_empty()
            || variable.len() > 128
            || variable.as_bytes()[0].is_ascii_digit()
            || !variable
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || !env.insert(variable.clone())
        {
            return Err(format!(
                "plugin '{name}' has an invalid environment permission"
            ));
        }
    }
    let mut run = BTreeMap::new();
    for argv in permissions.run {
        if argv.is_empty()
            || argv.len() > 64
            || argv
                .iter()
                .any(|argument| argument.len() > 8192 || argument.contains('\0'))
            || run.contains_key(&argv)
        {
            return Err(format!("plugin '{name}' has an invalid run permission"));
        }
        let mut resolved = argv.clone();
        resolved[0] = resolve_command_executable(&argv[0])?
            .to_string_lossy()
            .into_owned();
        run.insert(argv, resolved);
    }
    let storage_root = runtime_dirs.data_dir.join("storage");
    if permissions.storage {
        std::fs::create_dir_all(&storage_root)
            .map_err(|_| format!("plugin '{name}' storage is unavailable"))?;
        restrict_plugin_directory(&storage_root)?;
    }
    Ok(Some(PermissionPolicy {
        name: name.to_string(),
        read,
        write,
        env,
        run,
        storage: permissions.storage,
        project_root,
        plugin_root,
        storage_root,
    }))
}

fn parse_path_permission(name: &str, value: &str) -> Result<PathPermission, String> {
    let (scope, relative) = value
        .split_once(':')
        .ok_or_else(|| format!("plugin '{name}' has an invalid file permission"))?;
    let scope = match scope {
        "project" => PathScope::Project,
        "plugin" => PathScope::Plugin,
        _ => {
            return Err(format!(
                "plugin '{name}' has an invalid file permission root"
            ))
        }
    };
    let recursive = relative.ends_with("/**");
    let relative = relative.strip_suffix("/**").unwrap_or(relative);
    let relative = PathBuf::from(relative);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "plugin '{name}' has an invalid file permission path"
        ));
    }
    Ok(PathPermission {
        scope,
        relative,
        recursive,
    })
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

/// Resolve device-wide storage for a plugin explicitly enabled in the user's
/// global Pentect configuration. The caller supplies a stable source identity
/// so the same approval and managed command are reused from every project.
pub fn global_plugin_runtime_dirs(source_id: &str) -> Result<PluginRuntimeDirs, String> {
    if source_id.len() != 32
        || !source_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(
            "global plugin identity must be a 32-character lowercase hex digest".to_string(),
        );
    }
    let id = source_id.to_string();
    let user_root = plugin_user_data_root()?;
    if !user_root.is_absolute() {
        return Err("Pentect plugin data directory must be absolute".to_string());
    }
    std::fs::create_dir_all(&user_root)
        .map_err(|error| format!("could not create '{}': {error}", user_root.display()))?;
    let user_root = std::fs::canonicalize(&user_root)
        .map_err(|error| format!("could not resolve '{}': {error}", user_root.display()))?;
    restrict_plugin_directory(&user_root)?;
    let data_dir = user_root.join("global").join(id);
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

    fn command_fixture(response: &str) -> Vec<String> {
        #[cfg(windows)]
        {
            vec![
                "powershell".to_string(),
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                format!(
                    "$null = [Console]::In.ReadLine(); [Console]::Out.WriteLine({})",
                    powershell_single_quoted(response)
                ),
            ]
        }
        #[cfg(not(windows))]
        {
            vec![
                "sh".to_string(),
                "-c".to_string(),
                format!(
                    "IFS= read -r line; printf '%s\\n' {}",
                    shell_single_quoted(response)
                ),
            ]
        }
    }

    fn sleeping_command_fixture() -> Vec<String> {
        #[cfg(windows)]
        {
            vec![
                "powershell".to_string(),
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                "$null = [Console]::In.ReadLine(); Start-Sleep -Seconds 2".to_string(),
            ]
        }
        #[cfg(not(windows))]
        {
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "IFS= read -r line; sleep 2".to_string(),
            ]
        }
    }

    fn incomplete_command_fixture() -> Vec<String> {
        #[cfg(windows)]
        {
            vec![
                "powershell".to_string(),
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                "$null = [Console]::In.ReadLine(); [Console]::Out.Write('partial')".to_string(),
            ]
        }
        #[cfg(not(windows))]
        {
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "IFS= read -r line; printf partial".to_string(),
            ]
        }
    }

    fn crashing_command_fixture() -> Vec<String> {
        #[cfg(windows)]
        {
            vec![
                "powershell".to_string(),
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                "$null = [Console]::In.ReadLine(); exit 7".to_string(),
            ]
        }
        #[cfg(not(windows))]
        {
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "IFS= read -r line; exit 7".to_string(),
            ]
        }
    }

    fn python_protocol_fixture(code: &str) -> Option<Vec<String>> {
        let executable = ["python3", "python"].into_iter().find(|candidate| {
            std::process::Command::new(candidate)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        })?;
        Some(vec![
            executable.to_string(),
            "-u".to_string(),
            "-c".to_string(),
            code.to_string(),
        ])
    }

    #[cfg(windows)]
    fn powershell_single_quoted(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    #[cfg(not(windows))]
    fn shell_single_quoted(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    #[test]
    fn command_program_exchanges_one_json_line() {
        let response = r#"{"schema":"pentect.plugin.v1","id":42,"type":"result","action":"next"}"#;
        let program = CommandProgram::new(
            command_fixture(response),
            std::env::current_dir().unwrap(),
            4096,
        )
        .unwrap();
        let output = program
            .invoke(
                br#"{"id":42}"#,
                Duration::from_millis(DEFAULT_TIMEOUT_MS),
                "fixture",
            )
            .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&output).unwrap()["id"], 42);
    }

    #[test]
    fn command_program_cold_start_consumes_the_chain_deadline() {
        let Some(command) = python_protocol_fixture(
            "import json,sys,time; time.sleep(0.15);\nfor line in sys.stdin:\n r=json.loads(line); time.sleep(0.10); print(json.dumps({'id':r['id']}), flush=True)",
        ) else {
            return;
        };
        let program = CommandProgram::new(command, std::env::current_dir().unwrap(), 4096).unwrap();
        let mut budget = PluginChainBudget::new();
        let deadline_before_start = budget.deadline;

        let first = program
            .invoke_with_startup_timeout(
                br#"{"id":1}"#,
                Duration::from_millis(50),
                Duration::from_millis(DEFAULT_TIMEOUT_MS),
                "fixture",
                &mut budget,
            )
            .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&first).unwrap()["id"], 1);
        assert_eq!(budget.deadline, deadline_before_start);

        let second = program
            .invoke_with_startup_timeout(
                br#"{"id":2}"#,
                Duration::from_millis(50),
                Duration::from_millis(DEFAULT_TIMEOUT_MS),
                "fixture",
                &mut budget,
            )
            .unwrap_err();
        assert!(second.contains("timed out"), "{second}");
    }

    #[test]
    fn command_program_cold_start_is_capped_by_remaining_chain_budget() {
        let remaining = Duration::from_millis(50);
        let (timeout, phase) = command_exchange_timeout(
            true,
            Duration::from_secs(5),
            Duration::from_secs(10),
            remaining,
        );

        assert_eq!(timeout, remaining);
        assert!(matches!(phase, CommandExchangePhase::Startup));
    }

    #[test]
    fn command_program_warm_request_is_capped_by_remaining_chain_budget() {
        let remaining = Duration::from_millis(50);
        let (timeout, phase) = command_exchange_timeout(
            false,
            Duration::from_secs(5),
            Duration::from_secs(10),
            remaining,
        );

        assert_eq!(timeout, remaining);
        assert!(matches!(phase, CommandExchangePhase::Request));
    }

    #[test]
    fn command_program_state_wait_is_bounded_by_chain_deadline() {
        let Some(command) = python_protocol_fixture("pass") else {
            return;
        };
        let program = CommandProgram::new(command, std::env::current_dir().unwrap(), 4096).unwrap();
        let held_state = program.state.lock().unwrap();
        let error = match program.lock_state_until(Instant::now(), "fixture") {
            Ok(_) => panic!("locked command state was unexpectedly available"),
            Err(error) => error,
        };
        drop(held_state);
        assert!(error.contains("lock wait timed out"));
    }

    #[test]
    fn local_command_lock_may_include_reviewed_setup_file() {
        use sha2::{Digest, Sha256};

        let Some(command) = python_protocol_fixture("pass") else {
            return;
        };
        let directory = std::env::temp_dir().join(format!(
            "pentect-command-setup-lock-{}-{}",
            std::process::id(),
            REQUEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let root = directory.join("plugin");
        let data = directory.join("runtime");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(root.join("server.py"), "print('server')\n").unwrap();
        std::fs::write(root.join("setup.py"), "print('setup')\n").unwrap();
        let digest = |name: &str| {
            data_encoding::HEXLOWER.encode(&Sha256::digest(std::fs::read(root.join(name)).unwrap()))
        };
        let executable = resolve_command_executable(&command[0]).unwrap();
        std::fs::write(
            data.join(PLUGIN_COMMAND_LOCK_FILE),
            format!(
                "schema = \"pentect.plugin-command-lock.v1\"\nexecutable = {:?}\nmanaged = false\n\n[[file]]\npath = \"server.py\"\nsha256 = \"{}\"\n\n[[file]]\npath = \"setup.py\"\nsha256 = \"{}\"\n",
                executable.to_string_lossy(),
                digest("server.py"),
                digest("setup.py"),
            ),
        )
        .unwrap();
        let dirs = PluginRuntimeDirs {
            data_dir: data,
            cache_dir: directory.join("cache"),
            config_file: directory.join("config.toml"),
        };
        let argv = vec![command[0].clone(), "{plugin}/server.py".to_string()];
        verify_command_files("fixture", &argv, &root, &dirs).unwrap();
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn command_program_enforces_deadline_and_output_limit() {
        let timeout = CommandProgram::new(
            sleeping_command_fixture(),
            std::env::current_dir().unwrap(),
            4096,
        )
        .unwrap()
        .invoke(b"{}", Duration::from_millis(20), "fixture")
        .unwrap_err();
        assert!(timeout.contains("timed out"), "{timeout}");

        let oversized = CommandProgram::new(
            command_fixture(&"x".repeat(64)),
            std::env::current_dir().unwrap(),
            16,
        )
        .unwrap()
        .invoke(b"{}", Duration::from_secs(15), "fixture")
        .unwrap_err();
        assert!(oversized.contains("exceeds its limit"), "{oversized}");
    }

    #[test]
    fn command_program_rejects_partial_lines_and_crashes() {
        let partial = CommandProgram::new(
            incomplete_command_fixture(),
            std::env::current_dir().unwrap(),
            4096,
        )
        .unwrap()
        .invoke(b"{}", Duration::from_millis(DEFAULT_TIMEOUT_MS), "fixture")
        .unwrap_err();
        assert!(partial.contains("incomplete protocol line"), "{partial}");

        let crash = CommandProgram::new(
            crashing_command_fixture(),
            std::env::current_dir().unwrap(),
            4096,
        )
        .unwrap()
        .invoke(b"{}", Duration::from_millis(DEFAULT_TIMEOUT_MS), "fixture")
        .unwrap_err();
        assert!(crash.contains("closed stdout"), "{crash}");
    }

    #[test]
    fn command_session_stop_reaps_the_child() {
        let mut session = CommandSession::start(
            &sleeping_command_fixture(),
            &std::env::current_dir().unwrap(),
            4096,
            "fixture",
        )
        .unwrap();
        session.stop();
        assert!(session.child.try_wait().unwrap().is_some());
    }

    #[test]
    fn command_protocol_rejects_a_wrong_response_id() {
        let Some(command) = python_protocol_fixture(
            "import json,sys; r=json.loads(sys.stdin.readline()); print(json.dumps({'schema':'pentect.plugin.v1','id':r['id']+1,'type':'result','action':'next'}), flush=True)",
        ) else {
            return;
        };
        let plugin = PluginBinary {
            name: "wrong-id".to_string(),
            program: PluginProgram::Command(
                CommandProgram::new(command, std::env::current_dir().unwrap(), 4096).unwrap(),
            ),
            hooks: BTreeSet::from([MiddlewareStage::Inspect]),
            required: true,
            command_config: Some(json!({})),
            timeout: Duration::from_secs(5),
            startup_timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: 4096,
            max_spans: DEFAULT_MAX_SPANS,
        };
        let error = plugin
            .invoke_bounded(
                MiddlewareStage::Inspect,
                &json!({"kind": "text", "text": "safe"}),
                None,
                &mut PluginChainBudget::new(),
            )
            .unwrap_err();
        assert!(error.contains("mismatched protocol response"), "{error}");
    }

    fn invalid_command_plugin(required: bool) -> PluginBinary {
        PluginBinary {
            name: "invalid-command".to_string(),
            program: PluginProgram::Command(
                CommandProgram::new(
                    command_fixture("not-json"),
                    std::env::current_dir().unwrap(),
                    4096,
                )
                .unwrap(),
            ),
            hooks: BTreeSet::from([MiddlewareStage::Inspect]),
            required,
            command_config: Some(json!({})),
            timeout: Duration::from_secs(5),
            startup_timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: 4096,
            max_spans: DEFAULT_MAX_SPANS,
        }
    }

    #[test]
    fn required_command_failure_blocks_and_optional_failure_marks_partial_coverage() {
        let required = PluginMiddleware {
            plugins: vec![invalid_command_plugin(true)],
        };
        let error = match required.detect_spans(&Input::text("safe"), None) {
            Ok(_) => panic!("required invalid command unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(error.contains("invalid JSON"), "{error}");

        let optional = PluginMiddleware {
            plugins: vec![invalid_command_plugin(false)],
        };
        let result = optional.detect_spans(&Input::text("safe"), None).unwrap();
        assert_eq!(result.coverage, MiddlewareCoverage::Partial);
        assert!(result.spans.is_empty());
    }

    #[test]
    fn command_plugin_runs_end_to_end_with_approval_and_file_lock() {
        use sha2::Digest as _;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pentect-command-e2e-{nonce}"));
        std::fs::create_dir_all(&root).unwrap();
        let name = format!("command-e2e-{nonce}");
        let manifest = root.join("plugin.toml");
        std::fs::write(
            &manifest,
            format!(
                "schema = \"pentect.plugin.v1\"\nname = \"{name}\"\ncommand = [\"python\", \"{{plugin}}/server.py\"]\nhooks = [\"inspect\"]\nrequired = true\n"
            ),
        )
        .unwrap();
        let script = root.join("server.py");
        std::fs::write(
            &script,
            r#"import json, sys
for line in sys.stdin:
    request = json.loads(line)
    label = request.get("config", {}).get("label", "TOKEN")
    response = {"schema":"pentect.plugin.v1","id":request["id"],"type":"result","action":"next","spans":[{"start":0,"end":6,"label":label,"category":"secret","confidence":"high"}]}
    print(json.dumps(response, separators=(",", ":")), flush=True)
"#,
        )
        .unwrap();
        let dirs = plugin_runtime_dirs_for_manifest(&name, &manifest).unwrap();
        std::fs::write(&dirs.config_file, "label = \"CONFIGURED\"\n").unwrap();
        let manifest_hash = data_encoding::HEXLOWER
            .encode(&sha2::Sha256::digest(std::fs::read(&manifest).unwrap()));
        let script_hash =
            data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(std::fs::read(&script).unwrap()));
        let executable = toml::Value::String(
            resolve_command_executable("python")
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        let command_lock = format!(
            "schema = \"pentect.plugin-command-lock.v1\"\nexecutable = {executable}\n\n[[file]]\npath = \"server.py\"\nsha256 = \"{script_hash}\"\n"
        );
        std::fs::write(dirs.data_dir.join(PLUGIN_COMMAND_LOCK_FILE), &command_lock).unwrap();
        let command_lock_sha256 =
            data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(command_lock.as_bytes()));
        std::fs::write(
            dirs.data_dir.join(PLUGIN_APPROVAL_FILE),
            format!(
                "schema = \"pentect.plugin-approval.v1\"\nmanifest_sha256 = \"{manifest_hash}\"\nhooks = [\"inspect\"]\ncommand_lock_sha256 = \"{command_lock_sha256}\"\n"
            ),
        )
        .unwrap();

        let middleware = PluginMiddleware::from_paths([manifest.clone()]).unwrap();
        let result = middleware
            .detect_spans(&Input::text("SECRET"), None)
            .unwrap();
        assert_eq!(result.spans.len(), 1);
        assert_eq!(result.spans[0].range, ByteRange::new(0, 6));
        assert_eq!(result.spans[0].label, "CONFIGURED");

        drop(middleware);
        let global_id = format!("{nonce:032x}");
        let global_dirs = global_plugin_runtime_dirs(&global_id).unwrap();
        std::fs::write(&global_dirs.config_file, "label = \"GLOBAL_CONFIGURED\"\n").unwrap();
        std::fs::write(
            global_dirs.data_dir.join(PLUGIN_COMMAND_LOCK_FILE),
            &command_lock,
        )
        .unwrap();
        std::fs::write(
            global_dirs.data_dir.join(PLUGIN_APPROVAL_FILE),
            format!(
                "schema = \"pentect.plugin-approval.v1\"\nmanifest_sha256 = \"{manifest_hash}\"\nhooks = [\"inspect\"]\ncommand_lock_sha256 = \"{command_lock_sha256}\"\n"
            ),
        )
        .unwrap();
        let global = PluginMiddleware {
            plugins: vec![PluginBinary::load_global(&manifest, &global_id).unwrap()],
        };
        let result = global.detect_spans(&Input::text("SECRET"), None).unwrap();
        assert_eq!(result.spans.len(), 1);
        assert_eq!(result.spans[0].label, "GLOBAL_CONFIGURED");
        drop(global);

        std::fs::write(&script, "print('changed')\n").unwrap();
        let error = PluginMiddleware::from_paths([manifest.clone()]).unwrap_err();
        assert!(error.contains("changed after setup"), "{error}");

        let _ = std::fs::remove_dir_all(dirs.data_dir);
        let _ = std::fs::remove_dir_all(global_dirs.data_dir);
        let _ = std::fs::remove_dir_all(root);
    }

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
    fn runtime_manifest_accepts_cli_owned_setup_metadata() {
        let file: PluginFile = toml::from_str(
            r#"
schema = "pentect.plugin.v1"
command = ["python", "{plugin}/server.py"]
hooks = ["inspect"]

[setup]
command = ["python", "{plugin}/setup.py"]
profiles = ["auto", "cpu", "cuda"]
profile_arg = "--profile"
download = "CPU: about 3 GB"
disk = "CPU: about 5 GB"
"#,
        )
        .unwrap();
        assert!(file._setup.is_some());
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
    fn global_plugin_identity_rejects_normalization_collisions() {
        for invalid in [
            "",
            "plugin",
            "A0000000000000000000000000000000",
            "--------------------------------",
        ] {
            assert!(global_plugin_runtime_dirs(invalid).is_err(), "{invalid}");
        }
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
        let program = WasmProgram::load_bytes(&bytes, "fixture", None, None, None).unwrap();
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
    fn wasm_plugin_enforces_execution_budget() {
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
        let program = WasmProgram::load_bytes(&bytes, "fixture", None, None, None).unwrap();
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
    fn wasm_plugin_enforces_compile_limits() {
        let parameters = (0..33).map(|_| "i32").collect::<Vec<_>>().join(" ");
        let bytes = wat::parse_str(format!(
            "(module (func (param {parameters})) (memory (export \"memory\") 1) \
             (func (export \"pentect_alloc\") (param i32) (result i32) i32.const 0) \
             (func (export \"pentect_inspect\") (param i32 i32) (result i64) i64.const 0))"
        ))
        .unwrap();
        let error = WasmProgram::load_bytes(&bytes, "fixture", None, None, None).unwrap_err();
        assert!(error.contains("exceeds the limit"), "{error}");
        assert!(inspect_wasm_plugin_hooks(&bytes).is_err());
    }

    #[test]
    fn plugin_chain_budget_is_aggregate_and_fail_before_mutation() {
        let mut budget = PluginChainBudget::new();
        budget
            .charge_input(MAX_PLUGIN_CHAIN_INPUT_BYTES - 1)
            .unwrap();
        assert!(budget.charge_input(2).is_err());
        assert_eq!(budget.input_bytes, MAX_PLUGIN_CHAIN_INPUT_BYTES - 1);

        budget.charge_output(MAX_PLUGIN_CHAIN_OUTPUT_BYTES).unwrap();
        assert!(budget.charge_output(1).is_err());
        budget.charge_spans(MAX_PLUGIN_CHAIN_SPANS).unwrap();
        assert!(budget.charge_spans(1).is_err());

        budget.deadline = Instant::now();
        assert!(budget.remaining().is_err());

        for _ in 0..MAX_PLUGIN_CHAIN_NETWORK_REQUESTS {
            assert!(charge_chain_network_request(&budget.network_requests));
        }
        assert!(!charge_chain_network_request(&budget.network_requests));
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
        let denied = WasmProgram::load_bytes(&bytes, "fixture", None, None, None).unwrap_err();
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
        WasmProgram::load_bytes(&bytes, "fixture", Some(policy), None, None).unwrap();
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
        let denied = WasmProgram::load_bytes(&bytes, "fixture", None, None, None).unwrap_err();
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
        WasmProgram::load_bytes(&bytes, "fixture", None, Some(config), None).unwrap();
    }

    #[test]
    fn wasm_host_import_requires_permissions_and_file_access_is_exact() {
        let bytes = wat::parse_str(
            r#"(module
                (import "pentect:host" "request"
                    (func $request (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "pentect_alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "pentect_inspect") (param i32 i32) (result i64) (i64.const 0)))"#,
        )
        .unwrap();
        let denied = WasmProgram::load_bytes(&bytes, "fixture", None, None, None).unwrap_err();
        assert!(denied.contains("unapproved host function"), "{denied}");

        let root = std::env::temp_dir().join(format!(
            "pentect-plugin-host-permissions-{}",
            std::process::id()
        ));
        let project = root.join("project");
        let plugin = root.join("plugin");
        let storage = root.join("storage");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&plugin).unwrap();
        std::fs::create_dir_all(&storage).unwrap();
        std::fs::write(project.join("allowed.txt"), "visible").unwrap();
        std::fs::write(project.join("denied.txt"), "hidden").unwrap();
        #[cfg(windows)]
        {
            std::fs::create_dir(project.join("Config")).unwrap();
            std::fs::write(project.join("Config/settings.json"), "case-safe").unwrap();
        }
        let requested_command = vec!["rustc".to_string(), "--version".to_string()];
        let mut resolved_command = requested_command.clone();
        resolved_command[0] = resolve_command_executable("rustc")
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let read_permissions = vec![
            PathPermission {
                scope: PathScope::Project,
                relative: PathBuf::from("allowed.txt"),
                recursive: false,
            },
            PathPermission {
                scope: PathScope::Project,
                relative: PathBuf::from("config/settings.json"),
                recursive: false,
            },
        ];
        let policy = PermissionPolicy {
            name: "fixture".to_string(),
            read: read_permissions,
            write: vec![
                PathPermission {
                    scope: PathScope::Project,
                    relative: PathBuf::from("written.txt"),
                    recursive: false,
                },
                PathPermission {
                    scope: PathScope::Project,
                    relative: PathBuf::from("output"),
                    recursive: true,
                },
            ],
            env: BTreeSet::from(["PATH".to_string()]),
            run: BTreeMap::from([(requested_command.clone(), resolved_command)]),
            storage: true,
            project_root: project.canonicalize().unwrap(),
            plugin_root: plugin.canonicalize().unwrap(),
            storage_root: storage.canonicalize().unwrap(),
        };
        WasmProgram::load_bytes(&bytes, "fixture", None, None, Some(policy.clone())).unwrap();
        let allowed = perform_host_request(
            &policy,
            HostRequest::FileRead {
                path: "project:allowed.txt".to_string(),
            },
            Instant::now() + Duration::from_secs(1),
        );
        assert!(allowed.ok);
        assert_eq!(allowed.value, Some(Value::String("visible".to_string())));
        #[cfg(windows)]
        {
            let case_variant = perform_host_request(
                &policy,
                HostRequest::FileRead {
                    path: "project:Config/settings.json".to_string(),
                },
                Instant::now() + Duration::from_secs(1),
            );
            assert_eq!(
                case_variant.value,
                Some(Value::String("case-safe".to_string()))
            );
        }
        let denied = perform_host_request(
            &policy,
            HostRequest::FileRead {
                path: "project:denied.txt".to_string(),
            },
            Instant::now() + Duration::from_secs(1),
        );
        assert!(!denied.ok);

        let environment = perform_host_request(
            &policy,
            HostRequest::EnvRead {
                name: "PATH".to_string(),
            },
            Instant::now() + Duration::from_secs(1),
        );
        assert!(environment.ok);
        let denied_environment = perform_host_request(
            &policy,
            HostRequest::EnvRead {
                name: "PENTECT_UNAPPROVED".to_string(),
            },
            Instant::now() + Duration::from_secs(1),
        );
        assert!(!denied_environment.ok);

        let written = perform_host_request(
            &policy,
            HostRequest::FileWrite {
                path: "project:written.txt".to_string(),
                data: "generated".to_string(),
            },
            Instant::now() + Duration::from_secs(1),
        );
        assert!(written.ok);
        assert_eq!(
            std::fs::read_to_string(project.join("written.txt")).unwrap(),
            "generated"
        );
        let nested = perform_host_request(
            &policy,
            HostRequest::FileWrite {
                path: "project:output/session/result.json".to_string(),
                data: "nested".to_string(),
            },
            Instant::now() + Duration::from_secs(1),
        );
        assert!(nested.ok);
        assert_eq!(
            std::fs::read_to_string(project.join("output/session/result.json")).unwrap(),
            "nested"
        );

        let stored = perform_host_request(
            &policy,
            HostRequest::StorageSet {
                key: "state".to_string(),
                value: json!({"count": 1}),
            },
            Instant::now() + Duration::from_secs(1),
        );
        assert!(stored.ok);
        let loaded = perform_host_request(
            &policy,
            HostRequest::StorageGet {
                key: "state".to_string(),
            },
            Instant::now() + Duration::from_secs(1),
        );
        assert_eq!(loaded.value, Some(json!({"count": 1})));
        let command = perform_host_request(
            &policy,
            HostRequest::CommandRun {
                argv: requested_command,
                stdin: String::new(),
            },
            Instant::now() + Duration::from_secs(5),
        );
        assert!(command.ok);
        let denied_command = perform_host_request(
            &policy,
            HostRequest::CommandRun {
                argv: vec!["rustc".to_string(), "-Vv".to_string()],
                stdin: String::new(),
            },
            Instant::now() + Duration::from_secs(5),
        );
        assert!(!denied_command.ok);
        let _ = std::fs::remove_dir_all(root);
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
    fn private_network_approval_applies_to_explicitly_allowed_dns_origins() {
        assert!(private_access_for_origin(
            &HttpOrigin {
                scheme: "http".to_string(),
                host: "localhost".to_string(),
                port: 8080,
            },
            true,
        ));
        assert!(!private_access_for_origin(
            &HttpOrigin {
                scheme: "http".to_string(),
                host: "localhost".to_string(),
                port: 8080,
            },
            false,
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
