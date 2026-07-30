use pentect_core::{
    ByteRange, Category, Confidence, Config, Context, DetectorId, Engine, Input, Kind, MaskResult,
    Span,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const BINARIES_ENV: &str = "PENTECT_PLUGIN_BINARIES";

const PLUGIN_CONFIG_FILE: &str = "config.toml";
const PLUGIN_APPROVAL_FILE: &str = "approval.toml";
const PLUGIN_CACHE_DIR: &str = "cache";
const PLUGIN_NAME_ENV: &str = "PENTECT_PLUGIN_NAME";
const PLUGIN_DATA_DIR_ENV: &str = "PENTECT_PLUGIN_DATA_DIR";
const PLUGIN_CACHE_DIR_ENV: &str = "PENTECT_PLUGIN_CACHE_DIR";
const PLUGIN_CONFIG_ENV: &str = "PENTECT_PLUGIN_CONFIG";
const DEFAULT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_MAX_INPUT_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_SPANS: usize = 512;
const PROTOCOL_SCHEMA: &str = "pentect.plugin.v1";
static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MiddlewareStage {
    Ingest,
    Decode,
    Detect,
    Policy,
    Mask,
    ProviderRequest,
    ProviderResponse,
    ToolCall,
    Output,
    FileDiscover,
    FileDecode,
    FileDetect,
    FileTransform,
    Finding,
    Report,
}

impl MiddlewareStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
            Self::Decode => "decode",
            Self::Detect => "detect",
            Self::Policy => "policy",
            Self::Mask => "mask",
            Self::ProviderRequest => "provider_request",
            Self::ProviderResponse => "provider_response",
            Self::ToolCall => "tool_call",
            Self::Output => "output",
            Self::FileDiscover => "file_discover",
            Self::FileDecode => "file_decode",
            Self::FileDetect => "file_detect",
            Self::FileTransform => "file_transform",
            Self::Finding => "finding",
            Self::Report => "report",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "ingest" => Self::Ingest,
            "decode" => Self::Decode,
            "detect" => Self::Detect,
            "policy" => Self::Policy,
            "mask" => Self::Mask,
            "provider_request" => Self::ProviderRequest,
            "provider_response" => Self::ProviderResponse,
            "tool_call" => Self::ToolCall,
            "output" => Self::Output,
            "file_discover" => Self::FileDiscover,
            "file_decode" => Self::FileDecode,
            "file_detect" => Self::FileDetect,
            "file_transform" => Self::FileTransform,
            "finding" => Self::Finding,
            "report" => Self::Report,
            _ => return None,
        })
    }
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
    Handled,
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

    pub fn has_stage(&self, stage: MiddlewareStage) -> bool {
        self.plugins
            .iter()
            .any(|plugin| plugin.stages.contains(&stage))
    }

    pub fn run(
        &self,
        stage: MiddlewareStage,
        mut payload: Value,
        context: Option<Value>,
    ) -> Result<MiddlewareRun, String> {
        let total = self
            .plugins
            .iter()
            .filter(|plugin| plugin.stages.contains(&stage))
            .count();
        let mut coverage = MiddlewareCoverage::Full;
        let mut index = 0usize;
        for plugin in self
            .plugins
            .iter()
            .filter(|plugin| plugin.stages.contains(&stage))
        {
            let response = match plugin.invoke(stage, &payload, context.as_ref(), index, total) {
                Ok(response) => response,
                Err(error) if !plugin.required => {
                    coverage = MiddlewareCoverage::Partial;
                    eprintln!(
                        "[pentect] optional plugin '{}' skipped: {error}",
                        plugin.name
                    );
                    index += 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            index += 1;
            if response.payload.is_some() && !plugin.permissions.contains("payload:write") {
                let error = format!(
                    "plugin '{}' returned a payload without payload:write permission",
                    plugin.name
                );
                if plugin.required {
                    return Err(error);
                }
                coverage = MiddlewareCoverage::Partial;
                eprintln!("[pentect] optional {error}");
                continue;
            }
            let stop = if response.action == Action::Stop {
                let outcome = response.outcome.unwrap_or(StopOutcomeFile::Block);
                let permission = match outcome {
                    StopOutcomeFile::Block => "pipeline:block",
                    StopOutcomeFile::Respond | StopOutcomeFile::Handled => "pipeline:respond",
                };
                if !plugin.permissions.contains(permission) {
                    let error = format!(
                        "plugin '{}' tried to stop without {permission} permission",
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
        let mut spans = Vec::new();
        let mut coverage = MiddlewareCoverage::Full;
        let plugins = self
            .plugins
            .iter()
            .filter(|plugin| plugin.stages.contains(&MiddlewareStage::Detect))
            .collect::<Vec<_>>();
        let total = plugins.len();
        for (index, plugin) in plugins.into_iter().enumerate() {
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
                "context": context,
            });
            let response =
                match plugin.invoke(MiddlewareStage::Detect, &payload, None, index, total) {
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
                let permission = match outcome {
                    StopOutcomeFile::Block => "pipeline:block",
                    StopOutcomeFile::Respond | StopOutcomeFile::Handled => "pipeline:respond",
                };
                if !plugin.permissions.contains(permission) {
                    let error = format!(
                        "plugin '{}' tried to stop without {permission} permission",
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
                    "plugin '{}' cannot replace payload during detect; return spans instead",
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
        let result = (!spans.is_empty()).then(|| engine.mask_spans(input, spans, cfg));
        Ok(DetectRun { result, coverage })
    }
}

#[derive(Clone, Debug)]
struct PluginBinary {
    name: String,
    id: String,
    path: PathBuf,
    command: Vec<String>,
    stages: BTreeSet<MiddlewareStage>,
    permissions: BTreeSet<String>,
    required: bool,
    mode: ExecutionMode,
    timeout: Duration,
    max_input_bytes: usize,
    max_output_bytes: usize,
    max_spans: usize,
    process: Arc<Mutex<Option<PersistentProcess>>>,
}

impl PluginBinary {
    fn load(path: &Path) -> Result<Self, String> {
        if !path.is_file() {
            return Err(format!(
                "plugin manifest does not exist: {}",
                path.display()
            ));
        }
        let source = std::fs::read_to_string(path)
            .map_err(|error| format!("could not read '{}': {error}", path.display()))?;
        let file: PluginFile = toml::from_str(&source)
            .map_err(|error| format!("plugin manifest '{}' is invalid: {error}", path.display()))?;
        if file.schema.as_deref() != Some("pentect.plugin.v1") {
            return Err(format!(
                "plugin manifest '{}' requires schema = \"pentect.plugin.v1\"",
                path.display()
            ));
        }
        let name = file
            .name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| plugin_default_name(path));
        let id = plugin_id(&name);
        let binary = file
            .binary
            .filter(|binary| !binary.trim().is_empty())
            .ok_or_else(|| format!("plugin '{name}' requires binary"))?;
        let execution = file.execution.unwrap_or_default();
        let mode = execution.mode.unwrap_or_default();
        let command = binary_command(&name, &binary, execution.args)?;
        let middleware = file
            .middleware
            .ok_or_else(|| format!("plugin '{name}' requires [middleware]"))?;
        let stages = middleware
            .stages
            .iter()
            .map(|stage| {
                MiddlewareStage::parse(stage)
                    .ok_or_else(|| format!("plugin '{name}' has unknown stage: {stage}"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if stages.is_empty() {
            return Err(format!("plugin '{name}' must declare at least one stage"));
        }
        let permissions = validate_permissions(&name, middleware.permissions)?;
        if !permissions.contains("input:read") {
            return Err(format!(
                "plugin '{name}' middleware requires input:read permission"
            ));
        }
        verify_plugin_approval(path, &id, &stages, &permissions)?;
        Ok(Self {
            name,
            id,
            path: path.to_path_buf(),
            command,
            stages,
            permissions,
            required: middleware.required,
            mode,
            timeout: Duration::from_millis(execution.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
            max_input_bytes: execution.max_input_bytes.unwrap_or(DEFAULT_MAX_INPUT_BYTES),
            max_output_bytes: execution
                .max_output_bytes
                .unwrap_or(DEFAULT_MAX_OUTPUT_BYTES),
            max_spans: execution.max_spans.unwrap_or(DEFAULT_MAX_SPANS),
            process: Arc::new(Mutex::new(None)),
        })
    }

    fn invoke(
        &self,
        stage: MiddlewareStage,
        payload: &Value,
        context: Option<&Value>,
        index: usize,
        total: usize,
    ) -> Result<PluginResponse, String> {
        let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let request = json!({
            "schema": PROTOCOL_SCHEMA,
            "id": request_id,
            "type": "event",
            "stage": stage,
            "payload": payload,
            "context": context,
            "chain": {
                "index": index,
                "total": total,
                "has_next": index + 1 < total,
            },
        });
        let encoded = serde_json::to_vec(&request)
            .map_err(|error| format!("plugin '{}' request encode failed: {error}", self.name))?;
        if encoded.len() > self.max_input_bytes {
            return Err(format!("plugin '{}' input exceeds its limit", self.name));
        }
        let output = match self.mode {
            ExecutionMode::Persistent => self.run_persistent(&encoded)?,
            ExecutionMode::Oneshot => self.run_once(&encoded)?,
        };
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
        Ok(response)
    }

    fn run_persistent(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let mut slot = self
            .process
            .lock()
            .map_err(|_| format!("plugin '{}' process lock is poisoned", self.name))?;
        if slot.is_none() {
            *slot = Some(PersistentProcess::start(self)?);
        }
        let result = slot
            .as_mut()
            .expect("persistent process initialized")
            .exchange(request, self.timeout, self.max_output_bytes);
        if result.is_err() {
            if let Some(mut process) = slot.take() {
                process.terminate();
            }
        }
        result.map_err(|error| format!("plugin '{}' {error}", self.name))
    }

    fn run_once(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let cwd = self.path.parent().unwrap_or_else(|| Path::new("."));
        let program = plugin_program(&self.command[0], cwd, &self.id);
        let mut command = Command::new(program);
        apply_plugin_env(&mut command, &self.id, &self.permissions)?;
        command
            .args(&self.command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(parent) = self.path.parent() {
            command.current_dir(parent);
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("could not start plugin '{}': {error}", self.name))?;
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not open stdout for plugin '{}'", self.name));
            }
        };
        let stdout_reader = spawn_stdout_reader(stdout, self.max_output_bytes);
        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = join_stdout(stdout_reader, &self.name);
                return Err(format!("could not open stdin for plugin '{}'", self.name));
            }
        };
        let stdin_writer = spawn_stdin_writer(stdin, request.to_vec());
        let status = match wait_for_child(&mut child, &self.name, self.timeout) {
            Ok(status) => status,
            Err(error) => {
                let _ = join_stdin(stdin_writer, &self.name);
                let _ = join_stdout(stdout_reader, &self.name);
                return Err(error);
            }
        };
        join_stdin(stdin_writer, &self.name)?;
        let output = join_stdout(stdout_reader, &self.name)?;
        if output.len() > self.max_output_bytes {
            return Err(format!("plugin '{}' returned too much output", self.name));
        }
        if !status.success() {
            return Err(format!(
                "plugin '{}' exited with status {status}",
                self.name
            ));
        }
        Ok(output)
    }
}

#[derive(Deserialize)]
struct PluginApproval {
    schema: String,
    manifest_sha256: String,
    stages: Vec<String>,
    permissions: Vec<String>,
}

fn verify_plugin_approval(
    manifest: &Path,
    id: &str,
    stages: &BTreeSet<MiddlewareStage>,
    permissions: &BTreeSet<String>,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let path = plugin_runtime_dirs(id)?.data_dir.join(PLUGIN_APPROVAL_FILE);
    let source = std::fs::read_to_string(&path).map_err(|_| {
        format!(
            "plugin '{}' is not approved; run `pentect plugins setup {} --yes`",
            id,
            manifest.display()
        )
    })?;
    let approval: PluginApproval = toml::from_str(&source)
        .map_err(|error| format!("plugin '{id}' approval is invalid: {error}"))?;
    let bytes = std::fs::read(manifest)
        .map_err(|error| format!("could not verify plugin '{id}' manifest: {error}"))?;
    let digest = data_encoding::HEXLOWER.encode(&Sha256::digest(bytes));
    let approved_stages = approval
        .stages
        .iter()
        .filter_map(|stage| MiddlewareStage::parse(stage))
        .collect::<BTreeSet<_>>();
    let approved_permissions = approval.permissions.into_iter().collect::<BTreeSet<_>>();
    if approval.schema != "pentect.plugin-approval.v1"
        || approval.manifest_sha256 != digest
        || &approved_stages != stages
        || &approved_permissions != permissions
    {
        return Err(format!(
            "plugin '{id}' changed after approval; run `pentect plugins setup {} --yes` again",
            manifest.display()
        ));
    }
    Ok(())
}

struct PersistentProcess {
    child: Child,
    stdin: ChildStdin,
    output: mpsc::Receiver<Result<Vec<u8>, String>>,
}

impl std::fmt::Debug for PersistentProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PersistentProcess")
            .field("pid", &self.child.id())
            .finish_non_exhaustive()
    }
}

impl PersistentProcess {
    fn start(plugin: &PluginBinary) -> Result<Self, String> {
        let cwd = plugin.path.parent().unwrap_or_else(|| Path::new("."));
        let program = plugin_program(&plugin.command[0], cwd, &plugin.id);
        let mut command = Command::new(program);
        apply_plugin_env(&mut command, &plugin.id, &plugin.permissions)?;
        command
            .args(&plugin.command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(parent) = plugin.path.parent() {
            command.current_dir(parent);
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("could not start plugin '{}': {error}", plugin.name))?;
        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not open stdin for plugin '{}'", plugin.name));
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "could not open stdout for plugin '{}'",
                    plugin.name
                ));
            }
        };
        let output = spawn_line_reader(stdout, plugin.max_output_bytes);
        let mut process = Self {
            child,
            stdin,
            output,
        };
        let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let initialize = serde_json::to_vec(&json!({
            "schema": PROTOCOL_SCHEMA,
            "id": request_id,
            "type": "initialize",
            "host": {
                "name": "pentect",
                "protocol": 1,
            },
            "plugin": {
                "name": plugin.name,
                "stages": plugin.stages,
                "permissions": plugin.permissions,
            },
        }))
        .map_err(|error| format!("initialize request encode failed: {error}"))?;
        let response = process
            .exchange(&initialize, plugin.timeout, plugin.max_output_bytes)
            .map_err(|error| format!("plugin '{}' initialization failed: {error}", plugin.name))?;
        let response: PluginResponse = serde_json::from_slice(&response).map_err(|error| {
            format!(
                "plugin '{}' initialize response is invalid: {error}",
                plugin.name
            )
        })?;
        if response.schema.as_deref() != Some(PROTOCOL_SCHEMA)
            || response.id != Some(request_id)
            || response.kind.as_deref() != Some("initialized")
        {
            process.terminate();
            return Err(format!(
                "plugin '{}' returned a mismatched initialize response",
                plugin.name
            ));
        }
        Ok(process)
    }

    fn exchange(
        &mut self,
        request: &[u8],
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        self.stdin
            .write_all(request)
            .and_then(|()| self.stdin.write_all(b"\n"))
            .and_then(|()| self.stdin.flush())
            .map_err(|error| format!("could not write stdin: {error}"))?;
        let output = self
            .output
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => "timed out".to_string(),
                mpsc::RecvTimeoutError::Disconnected => "closed stdout before replying".to_string(),
            })??;
        if output.len() > max_output_bytes {
            return Err("returned too much output".to_string());
        }
        Ok(output)
    }

    fn terminate(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for PersistentProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn spawn_line_reader(
    stdout: ChildStdout,
    max_output_bytes: usize,
) -> mpsc::Receiver<Result<Vec<u8>, String>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = Vec::new();
            let result = match reader
                .by_ref()
                .take(max_output_bytes as u64 + 2)
                .read_until(b'\n', &mut line)
            {
                Ok(0) => break,
                Ok(_) if line.len() > max_output_bytes + 1 => {
                    Err("returned a line larger than its output limit".to_string())
                }
                Ok(_) => {
                    if line.last() == Some(&b'\n') {
                        line.pop();
                    }
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    Ok(line)
                }
                Err(error) => Err(format!("could not read stdout: {error}")),
            };
            if sender.send(result).is_err() {
                break;
            }
        }
    });
    receiver
}

#[derive(Debug, Default, Deserialize)]
struct PluginFile {
    schema: Option<String>,
    name: Option<String>,
    binary: Option<String>,
    execution: Option<ExecutionFile>,
    middleware: Option<MiddlewareFile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionFile {
    #[serde(default)]
    args: Vec<String>,
    mode: Option<ExecutionMode>,
    timeout_ms: Option<u64>,
    max_input_bytes: Option<usize>,
    max_output_bytes: Option<usize>,
    max_spans: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ExecutionMode {
    #[default]
    Persistent,
    Oneshot,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MiddlewareFile {
    #[serde(default)]
    stages: Vec<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    required: bool,
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
    Handled,
}

impl From<StopOutcomeFile> for StopOutcome {
    fn from(value: StopOutcomeFile) -> Self {
        match value {
            StopOutcomeFile::Block => Self::Block,
            StopOutcomeFile::Respond => Self::Respond,
            StopOutcomeFile::Handled => Self::Handled,
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

fn validate_permissions(name: &str, values: Vec<String>) -> Result<BTreeSet<String>, String> {
    let allowed = [
        "input:read",
        "payload:write",
        "pipeline:block",
        "pipeline:respond",
        "config:read",
        "cache:write",
    ];
    let mut permissions = BTreeSet::new();
    for permission in values {
        if !allowed.contains(&permission.as_str()) {
            return Err(format!(
                "plugin '{name}' has unknown middleware permission: {permission}"
            ));
        }
        permissions.insert(permission);
    }
    Ok(permissions)
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

fn spawn_stdin_writer(mut stdin: ChildStdin, request: Vec<u8>) -> JoinHandle<Result<(), String>> {
    std::thread::spawn(move || {
        use std::io::Write as _;
        stdin
            .write_all(&request)
            .map_err(|error| format!("could not write plugin stdin: {error}"))
    })
}

fn spawn_stdout_reader(
    stdout: ChildStdout,
    max_output_bytes: usize,
) -> JoinHandle<Result<Vec<u8>, String>> {
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut stdout = stdout.take(max_output_bytes as u64 + 1);
        let mut output = Vec::new();
        stdout
            .read_to_end(&mut output)
            .map_err(|error| format!("could not read plugin stdout: {error}"))?;
        Ok(output)
    })
}

fn wait_for_child(child: &mut Child, name: &str, timeout: Duration) -> Result<ExitStatus, String> {
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
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not wait for plugin '{name}': {error}"));
            }
        }
    }
}

fn join_stdin(writer: JoinHandle<Result<(), String>>, name: &str) -> Result<(), String> {
    writer
        .join()
        .map_err(|_| format!("plugin '{name}' stdin writer panicked"))?
        .map_err(|error| format!("plugin '{name}' {error}"))
}

fn join_stdout(reader: JoinHandle<Result<Vec<u8>, String>>, name: &str) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| format!("plugin '{name}' stdout reader panicked"))?
        .map_err(|error| format!("plugin '{name}' {error}"))
}

fn apply_plugin_env(
    command: &mut Command,
    id_or_name: &str,
    permissions: &BTreeSet<String>,
) -> Result<(), String> {
    command.env_clear();
    for name in safe_plugin_env_names() {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let id = plugin_id(id_or_name);
    let dirs = plugin_runtime_dirs(&id)?;
    command.env(PLUGIN_NAME_ENV, id);
    command.env(PLUGIN_DATA_DIR_ENV, dirs.data_dir);
    if permissions.contains("cache:write") {
        command.env(PLUGIN_CACHE_DIR_ENV, dirs.cache_dir);
    }
    if permissions.contains("config:read") {
        command.env(PLUGIN_CONFIG_ENV, dirs.config_file);
    }
    Ok(())
}

fn safe_plugin_env_names() -> &'static [&'static str] {
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

fn binary_command(name: &str, binary: &str, args: Vec<String>) -> Result<Vec<String>, String> {
    if binary.is_empty()
        || binary.len() > 128
        || binary.contains('/')
        || binary.contains('\\')
        || !binary.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        || args.iter().any(|argument| argument.contains('\0'))
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

fn plugin_program(program: &str, cwd: &Path, id: &str) -> PathBuf {
    let path = Path::new(program);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    if program.contains('/') || program.contains('\\') {
        return cwd.join(path);
    }
    installed_plugin_program(program, id)
        .or_else(|| sidecar_program(program))
        .unwrap_or_else(|| path.to_path_buf())
}

fn installed_plugin_program(program: &str, id: &str) -> Option<PathBuf> {
    let bin = plugin_runtime_dirs(id).ok()?.data_dir.join("bin");
    command_names(program)
        .into_iter()
        .map(|name| bin.join(name))
        .find(|candidate| candidate.is_file())
}

fn sidecar_program(program: &str) -> Option<PathBuf> {
    let directory = std::env::current_exe().ok()?.parent()?.to_path_buf();
    command_names(program)
        .into_iter()
        .map(|name| directory.join(name))
        .find(|candidate| candidate.is_file())
}

#[cfg(windows)]
fn command_names(name: &str) -> Vec<String> {
    if Path::new(name).extension().is_some() {
        vec![name.to_string()]
    } else {
        vec![format!("{name}.exe"), name.to_string()]
    }
}

#[cfg(not(windows))]
fn command_names(name: &str) -> Vec<String> {
    vec![name.to_string()]
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
    fn parses_all_public_stages() {
        for stage in [
            MiddlewareStage::Ingest,
            MiddlewareStage::Decode,
            MiddlewareStage::Detect,
            MiddlewareStage::Policy,
            MiddlewareStage::Mask,
            MiddlewareStage::ProviderRequest,
            MiddlewareStage::ProviderResponse,
            MiddlewareStage::ToolCall,
            MiddlewareStage::Output,
            MiddlewareStage::FileDiscover,
            MiddlewareStage::FileDecode,
            MiddlewareStage::FileDetect,
            MiddlewareStage::FileTransform,
            MiddlewareStage::Finding,
            MiddlewareStage::Report,
        ] {
            assert_eq!(MiddlewareStage::parse(stage.as_str()), Some(stage));
        }
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
    fn persistent_plugin_handles_multiple_events() {
        let plugin = PluginBinary {
            name: "fixture".to_string(),
            id: "fixture".to_string(),
            path: std::env::current_dir().unwrap().join("plugin.toml"),
            command: persistent_fixture_command(),
            stages: BTreeSet::from([MiddlewareStage::ProviderRequest]),
            permissions: BTreeSet::from(["input:read".to_string(), "payload:write".to_string()]),
            required: true,
            mode: ExecutionMode::Persistent,
            timeout: Duration::from_secs(5),
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_spans: DEFAULT_MAX_SPANS,
            process: Arc::new(Mutex::new(None)),
        };
        let middleware = PluginMiddleware {
            plugins: vec![plugin],
        };
        for sequence in [1, 2] {
            let run = middleware
                .run(
                    MiddlewareStage::ProviderRequest,
                    json!({"sequence": sequence}),
                    None,
                )
                .unwrap();
            assert_eq!(run.payload["sequence"], sequence);
        }
    }

    #[cfg(windows)]
    fn persistent_fixture_command() -> Vec<String> {
        vec![
            "powershell".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            concat!(
                "$input | ForEach-Object { ",
                "$r = $_ | ConvertFrom-Json; ",
                "if ($r.type -eq 'initialize') { ",
                "$o = @{schema='pentect.plugin.v1';id=[long]$r.id;type='initialized'} ",
                "} else { ",
                "$o = @{schema='pentect.plugin.v1';id=[long]$r.id;type='result';action='next';payload=$r.payload} ",
                "}; [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 20)); ",
                "[Console]::Out.Flush() }"
            )
            .to_string(),
        ]
    }

    #[cfg(not(windows))]
    fn persistent_fixture_command() -> Vec<String> {
        vec![
            "sh".to_string(),
            "-c".to_string(),
            concat!(
                "while IFS= read -r line; do ",
                "id=$(printf '%s' \"$line\" | sed -n 's/.*\"id\":\\([0-9][0-9]*\\).*/\\1/p'); ",
                "if printf '%s' \"$line\" | grep -q '\"type\":\"initialize\"'; then ",
                "printf '{\"schema\":\"pentect.plugin.v1\",\"id\":%s,\"type\":\"initialized\"}\\n' \"$id\"; ",
                "else sequence=$(printf '%s' \"$line\" | sed -n 's/.*\"sequence\":\\([0-9][0-9]*\\).*/\\1/p'); ",
                "printf '{\"schema\":\"pentect.plugin.v1\",\"id\":%s,\"type\":\"result\",\"action\":\"next\",\"payload\":{\"sequence\":%s}}\\n' \"$id\" \"$sequence\"; fi; ",
                "done"
            )
            .to_string(),
        ]
    }
}
