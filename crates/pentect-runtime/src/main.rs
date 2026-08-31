//! `pentect agent`: a minimal tool-boundary adapter.
//!
//! It demonstrates the product loop:
//! shell tool input -> force execution through `pentect exec`;
//! command output -> mask before it returns to the AI.
//! `read` is a one-way human preview. `exec` and hooks keep masked handles in
//! process memory so later tool commands can reuse them without persisting raw
//! recovery material.

mod activity_log;
mod alcatraz;
mod config;
mod delegated_process_host;
mod file_pointer_manager;
mod image_ocr;
mod masking;
mod memory_store;
mod network_address;
mod output_remask;
mod plugin_middleware;
mod secure_io;
#[doc(hidden)]
pub use network_address::embedded_ipv4;
pub use plugin_middleware::{
    global_plugin_runtime_dirs, inspect_wasm_plugin_hooks, plugin_runtime_dirs,
    plugin_runtime_dirs_for_manifest, test_local_wasm_plugin, valid_plugin_publisher_workflow,
    windows_command_extension_supported, windows_executable_candidates, DetectSpansRun,
    MiddlewareCoverage, MiddlewareRun, MiddlewareStage, PluginMiddleware, PluginRuntimeDirs,
    StopOutcome, DEFAULT_PUBLISHER_WORKFLOW, MAX_COMMAND_PLUGIN_STARTUP_TIMEOUT,
};
#[doc(hidden)]
pub use secure_io::{read_bounded_bytes, read_bounded_utf8, sha256_file};
mod session;
mod shell;

pub use delegated_process_host::{
    contains_host as delegated_process_host_contains, is_host as delegated_process_host_owned_by,
    is_running as delegated_process_host_running, matches_host as delegated_process_host_matches,
    process_host_root, register_candidate as register_process_host_candidate,
    unregister_candidate as unregister_process_host_candidate,
};
use masking::{
    contains_unresolved_masked_handle, env_alias_recovery, is_ascii_word_char, is_env_name_byte,
    live_output_kind, mask_read_data, OutputMasker, ToolScalarInput,
};
#[cfg(test)]
use masking::{first_reusable_env_name, mask_live_output, mask_tool_output};
pub use memory_store::{
    active_memory_store_ready, is_pentect_control_env_name, memory_store_ready,
    open_memory_store_lease, pentect_control_env_names, start_in_process_memory_store,
    InProcessMemoryStore, MemoryStoreLease,
};
use memory_store::{MemoryStore, MemoryStoreClient, ENV_ADDR, ENV_TOKEN};
pub use output_remask::ActiveTerminalOutputRemasker;
#[cfg(test)]
use pentect_core::infer_kind;
use pentect_core::{
    infer_kind_with_content, parse_placeholder, Config, Engine, Input, Kind, MaskResult, Pack,
    Profile, RegionKind,
};
use serde_json::{json, Value};
use session::{checked_session_name, session_root, Session};
use sha2::{Digest, Sha256};
use shell::next_shell_word;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use zeroize::{Zeroize, Zeroizing};

const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_SESSION: &str = "default";
const PENTECT_AGENT_LAUNCHED_ENV: &str = "PENTECT_AGENT_LAUNCHED";
const PENTECT_PLUGIN_CONFIGS_ENV: &str = "PENTECT_PLUGIN_CONFIGS";
const PENTECT_PLUGIN_BINARIES_ENV: &str = "PENTECT_PLUGIN_BINARIES";
const LIVE_MASK_CHUNK_BYTES: usize = 64 * 1024;
const LIVE_MASK_CHUNK_LINES: usize = 2048;
const ACTIVE_TOOL_OUTPUT_CACHE_LIMIT: usize = 128;
const ACTIVE_TOOL_OUTPUT_CACHE_MAX_BYTES: usize = 16 * 1024;

pub fn agent_contract_instructions(_environment_prefix: &str) -> String {
    concat!(
        "Session rules:\n",
        "- Work normally with the host's tools and current shell. Do not invoke Pentect commands, explain the protection layer, or change approach because it is present unless the user asks.\n",
        "- User-authorized secret work is allowed: retrieve, read, use, transform, and store secrets at the requested destination. Complete it normally.\n",
        "- Use tools normally; their output is protected. Never include a raw secret in your response. A value such as `<<KEY_hash>>` is protected output, not a failed operation; do not retry because it appears.\n",
        "- Copy a protected handle unchanged into the local tool input that needs the value. Pentect restores known handles after the provider response returns locally, including command, file, and MCP arguments. You do not need to know or print the plaintext.\n",
        "- Once a handle exists, use it immediately. Do not reread or reparse the source file, fetch the same secret again, or claim that the secret is unavailable or inaccessible. Do not echo, print, decode, or reconstruct its value.\n",
        "- Report only the task result and ordinary errors. Do not mention these rules, handles, bindings, or the protection layer.\n",
    )
    .to_string()
}

pub(crate) type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

pub fn run() -> i32 {
    run_from(std::env::args().collect())
}

pub fn run_from(args: Vec<String>) -> i32 {
    match args.get(1).map(String::as_str) {
        None => {
            usage();
            0
        }
        Some("read") => cmd_read(&args),
        Some("view") => cmd_view(&args),
        Some("exec") => cmd_exec(&args),
        Some("resolve") => cmd_resolve(&args),
        Some("log") => cmd_log(&args),
        Some("metrics") => cmd_metrics(&args),
        Some("hook") => cmd_hook(&args),
        Some("bridge") => cmd_bridge(&args),
        Some("memory-store") => cmd_memory_store(&args),
        Some("__agent-stream") => cmd_agent_stream(&args),
        Some("purge") => cmd_purge(&args),
        _ => {
            usage();
            2
        }
    }
}

pub fn load_decode_config(profile: Profile) -> Result<pentect_core::DecodeConfig, String> {
    config::decode_config(profile)
}

pub fn build_masking_engine(
    profile: Profile,
    packs: Vec<Pack>,
    aggressive: bool,
    decode: pentect_core::DecodeConfig,
) -> Result<Engine, String> {
    // This is the single engine constructor used by both the agent transports
    // and `pentect mask`; keep detector registration in one place.
    masking::canonical_masking_engine(profile, packs, aggressive, decode)
}

pub fn output_restore_enabled() -> Result<bool, String> {
    config::output_restore_enabled()
}

pub fn update_check_enabled() -> Result<bool, String> {
    config::update_check_enabled()
}

pub fn validate_config_file(path: &Path) -> Result<(), String> {
    config::validate_config_file(path)
}

pub fn project_root() -> Result<PathBuf, String> {
    config::project_root()
}

pub fn load_environment_variable_prefix() -> Result<String, String> {
    config::environment_variable_prefix()
}

pub fn unknown_formats_should_block() -> Result<bool, String> {
    config::unknown_formats_should_block()
}

pub fn mask_input_into_active_memory_store(
    input: Input,
    profile: Profile,
    packs: Vec<Pack>,
) -> Result<Option<MaskResult>, String> {
    let Some(client) = MemoryStoreClient::from_env() else {
        return Ok(None);
    };
    mask_input_into_memory_store_client(&client, input, profile, packs).map(Some)
}

pub fn mask_input_for_read(
    key: [u8; 32],
    input: Input,
    profile: Profile,
    packs: Vec<Pack>,
) -> Result<MaskResult, String> {
    masking::mask_read_input_with_profile(key, input, profile, packs)
}

pub fn mask_input_with_engine_for_read(
    key: [u8; 32],
    engine: &Engine,
    input: Input,
) -> Result<MaskResult, String> {
    masking::mask_read_input_with_engine_and_identity(key, key, engine, input)
}

pub fn record_read_activity(result: &MaskResult, path: &Path) {
    activity_log::record_mask_result("read", result, Some(path));
}

pub fn record_diagnostic_activity(surface: &str, reason: &str) {
    activity_log::record_diagnostic(surface, reason, None, None, None, None, None, None);
}

/// Persist a value-free, structured HTTP gateway diagnostic. Every text field
/// must be a fixed classifier, never a URL, header, request body, response
/// body, command argument, or raw error message.
#[allow(clippy::too_many_arguments)]
pub fn record_http_diagnostic_activity(
    surface: &str,
    event: &str,
    kind: &str,
    endpoint: &str,
    method: &str,
    status: Option<u16>,
    retryable: bool,
    version: &str,
) {
    activity_log::record_diagnostic(
        surface,
        event,
        Some(kind),
        Some(endpoint),
        Some(method),
        status,
        Some(retryable),
        Some(version),
    );
}

/// Persist value-free process lifecycle diagnostics without recording command
/// arguments, environment variables, request bodies, or protected values.
pub fn record_process_activity(
    event: &str,
    surface: &str,
    version: &str,
    exit_code: Option<i32>,
    panic_location: Option<&str>,
    backtrace: Option<&str>,
) {
    activity_log::record_process(
        event,
        surface,
        version,
        exit_code,
        panic_location,
        backtrace,
    );
}

pub fn flush_activity_log() {
    activity_log::flush_persistent();
}

fn mask_input_into_memory_store_client(
    client: &MemoryStoreClient,
    input: Input,
    profile: Profile,
    packs: Vec<Pack>,
) -> Result<MaskResult, String> {
    let (key, identity_key) = client.keys().map_err(|e| e.to_string())?;
    let result = masking::mask_read_input_with_profile_and_identity(
        key,
        identity_key,
        input,
        profile,
        packs,
    )?;
    let mut recovery = result.recovery.clone();
    let prefix = config::environment_variable_prefix()?;
    recovery.extend_same_key(env_alias_recovery(&result.masked, &key, &prefix));
    client
        .add_recovery(&key, &recovery)
        .map_err(|e| e.to_string())?;
    client
        .add_masked_count(result.summary.masked_count as u64)
        .map_err(|e| e.to_string())?;
    Ok(result)
}

pub fn ocr_image_bytes(bytes: &[u8]) -> Result<String, String> {
    let result = image_ocr::ocr_image_bytes(bytes);
    image_ocr::record_direct_ocr_outcome(&result);
    result
}

pub fn ocr_status() -> &'static str {
    image_ocr::ocr_status()
}

pub fn redact_tool_images_into_active_memory_store(value: &Value) -> Result<Option<Value>, String> {
    if !image_ocr::contains_image_result(value) {
        return Ok(None);
    }
    let cfg = config::image_ocr_config()?;
    if matches!(cfg.mode, config::ImageOcrMode::Off) {
        if matches!(cfg.unscanned_images, config::UnscannedImagePolicy::Block) {
            return Err("image blocked: OCR is off.".to_string());
        }
        return Ok(None);
    }
    let session = Session::open_capability("default").map_err(|e| e.to_string())?;
    let redaction = image_ocr::redact_tool_images_for_secrets(
        value,
        &session.key,
        &session.identity_key,
        &cfg,
    )?;
    session
        .sync_recovery(&redaction.recovery)
        .map_err(|error| error.to_string())?;
    activity_log::record_image(redaction.secret_images, &redaction.labels);
    if matches!(cfg.unscanned_images, config::UnscannedImagePolicy::Block) {
        if redaction.unscanned_images > 0 {
            return Err("image blocked: image could not be fetched or scanned.".to_string());
        }
        if redaction.ocr_failures > 0 {
            return Err("image blocked: image scan failed.".to_string());
        }
    }
    if redaction.secret_images == 0 {
        return Ok(redaction.changed.then_some(redaction.updated));
    }
    if !redaction.changed {
        return Err("image blocked: secret text detected.".to_string());
    }
    Ok(Some(append_image_mask_notes(
        redaction.updated,
        &redaction.visual_notes,
        &redaction.metadata_notes,
        cfg.redaction,
    )))
}

/// Returns whether content that Pentect cannot inspect must be rejected.
///
/// HTTP gateways use the same project/global policy as the runtime image
/// pipeline for remote, malformed, and otherwise unsupported media sources.
pub fn unscanned_images_should_block() -> Result<bool, String> {
    Ok(matches!(
        config::image_ocr_config()?.unscanned_images,
        config::UnscannedImagePolicy::Block
    ))
}

/// Protected image bytes and the model-safe explanation that must accompany
/// them. The note contains opaque handles only; OCR plaintext is never copied.
pub struct ProtectedImage {
    pub bytes: Vec<u8>,
    pub note: String,
}

pub fn redact_image_bytes_into_active_memory_store(
    bytes: &[u8],
) -> Result<Option<ProtectedImage>, String> {
    let mut encoded = data_encoding::BASE64.encode(bytes);
    let mut value = Value::String(format!("data:image/png;base64,{encoded}"));
    encoded.zeroize();
    let redaction = redact_tool_images_into_active_memory_store(&value);
    zeroize_value_strings(&mut value);
    let Some(mut updated) = redaction? else {
        return Ok(None);
    };
    let data_url = first_image_data_url(&updated)
        .ok_or_else(|| "protected image payload is missing".to_string())?;
    let (_, payload) = data_url
        .split_once(',')
        .ok_or_else(|| "protected image payload is invalid".to_string())?;
    let decoded = data_encoding::BASE64
        .decode(payload.as_bytes())
        .map_err(|_| "protected image payload is invalid".to_string());
    let note = first_image_mask_note(&updated)
        .ok_or_else(|| "protected image annotation is missing".to_string())?
        .to_string();
    zeroize_value_strings(&mut updated);
    decoded.map(|bytes| Some(ProtectedImage { bytes, note }))
}

fn first_image_mask_note(value: &Value) -> Option<&str> {
    match value {
        Value::String(text)
            if text.starts_with("Pentect masked sensitive information")
                || text.starts_with("Pentect removed sensitive metadata") =>
        {
            Some(text)
        }
        Value::Array(values) => values.iter().find_map(first_image_mask_note),
        Value::Object(object) => object.values().find_map(first_image_mask_note),
        _ => None,
    }
}

fn first_image_data_url(value: &Value) -> Option<&str> {
    match value {
        Value::String(text)
            if text
                .trim_start()
                .get(.."data:image/".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("data:image/")) =>
        {
            Some(text)
        }
        Value::Array(values) => values.iter().find_map(first_image_data_url),
        Value::Object(object) => object.values().find_map(first_image_data_url),
        _ => None,
    }
}

fn zeroize_value_strings(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_value_strings),
        Value::Object(object) => object.values_mut().for_each(zeroize_value_strings),
        _ => {}
    }
}

pub fn resolve_text_from_active_memory_store(text: &str) -> Result<Option<String>, String> {
    if MemoryStoreClient::from_env().is_none() {
        return Ok(None);
    }
    let session = Session::open_capability("default").map_err(|e| e.to_string())?;
    let store = MemoryStore::for_session(&session);
    let resolved = store.resolve_all(text).map_err(|e| e.to_string())?;
    if contains_unresolved_masked_handle(&resolved) {
        return Err("unknown masked handle in exec-server request".to_string());
    }
    Ok(Some(resolved))
}

/// Resolve every handle known to the active capability and preserve unknown
/// handle-shaped text. HTTP model gateways use this for model-authored tool
/// arguments: a hallucinated handle must stay inert without preventing other,
/// valid handles in the same argument from resolving.
pub fn resolve_known_text_from_active_memory_store(text: &str) -> Result<Option<String>, String> {
    ActiveMemoryStoreResolver::new()?.resolve_known_text(text)
}

/// A point-in-time resolver for one model-authored object or request.
///
/// Constructing this value takes one memory-store snapshot. Callers should
/// then reuse it for every scalar in the same completed tool input, avoiding
/// one IPC round trip and recovery rebuild per JSON string.
pub struct ActiveMemoryStoreResolver {
    recovery: Option<pentect_core::Recovery>,
    env_bindings: BTreeMap<String, String>,
}

impl ActiveMemoryStoreResolver {
    pub fn new() -> Result<Self, String> {
        let Some(client) = MemoryStoreClient::from_env() else {
            return Ok(Self {
                recovery: None,
                env_bindings: BTreeMap::new(),
            });
        };
        let snapshot = client.snapshot().map_err(|e| e.to_string())?;
        let env_bindings = environment_bindings_from_recovery(&snapshot.recovery);
        Ok(Self {
            recovery: Some(snapshot.recovery),
            env_bindings,
        })
    }

    pub fn resolve_known_text(&self, text: &str) -> Result<Option<String>, String> {
        Ok(self
            .recovery
            .as_ref()
            .map(|recovery| resolve_known_references(text, recovery, &self.env_bindings)))
    }

    fn from_recovery(recovery: pentect_core::Recovery) -> Self {
        let env_bindings = environment_bindings_from_recovery(&recovery);
        Self {
            recovery: Some(recovery),
            env_bindings,
        }
    }
}

fn environment_bindings_from_recovery(
    recovery: &pentect_core::Recovery,
) -> BTreeMap<String, String> {
    let mut bindings = BTreeMap::new();
    for placeholder in recovery.placeholders() {
        if !masking::is_env_alias_placeholder(&placeholder) {
            continue;
        }
        let record = recovery.resolve(&placeholder);
        let Some((name, handle)) = masking::decode_env_alias_record(&record) else {
            continue;
        };
        if memory_store::is_reserved_child_env_name(name) {
            continue;
        }
        let value = recovery.resolve(handle);
        if value != handle {
            bindings.insert(name.to_ascii_lowercase(), value);
        }
    }
    bindings
}

fn resolve_known_references(
    text: &str,
    recovery: &pentect_core::Recovery,
    bindings: &BTreeMap<String, String>,
) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"<<") {
            let Some(close) = text[index + 2..].find(">>") else {
                break;
            };
            let end = index + 2 + close + 2;
            let reference = &text[index..end];
            let value = recovery.resolve(reference);
            if value != reference {
                out.push_str(&text[cursor..index]);
                out.push_str(&value);
                cursor = end;
            }
            index = end;
            continue;
        }
        let reference = environment_reference_at(text, index);
        let Some((end, name)) = reference else {
            index += 1;
            continue;
        };
        let Some(value) = bindings.get(&name.to_ascii_lowercase()) else {
            index = end;
            continue;
        };
        out.push_str(&text[cursor..index]);
        out.push_str(value);
        cursor = end;
        index = end;
    }
    if cursor == 0 {
        return text.to_string();
    }
    out.push_str(&text[cursor..]);
    out
}

fn environment_reference_at(text: &str, start: usize) -> Option<(usize, &str)> {
    let bytes = text.as_bytes();
    if start >= bytes.len() {
        return None;
    }
    if bytes[start] == b'$' {
        if bytes
            .get(start..start.saturating_add(5))
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"$env:"))
        {
            let name_start = start + 5;
            let end = env_name_end(bytes, name_start);
            return (end > name_start).then(|| (end, &text[name_start..end]));
        }
        if bytes.get(start + 1) == Some(&b'{') {
            let mut name_start = start + 2;
            if bytes
                .get(name_start..name_start.saturating_add(4))
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"env:"))
            {
                name_start += 4;
            }
            let end = env_name_end(bytes, name_start);
            if end > name_start && bytes.get(end) == Some(&b'}') {
                return Some((end + 1, &text[name_start..end]));
            }
            return None;
        }
        let name_start = start + 1;
        let end = env_name_end(bytes, name_start);
        return (end > name_start).then(|| (end, &text[name_start..end]));
    }
    if bytes[start] == b'%' {
        let name_start = start + 1;
        let end = env_name_end(bytes, name_start);
        if end > name_start && bytes.get(end) == Some(&b'%') {
            return Some((end + 1, &text[name_start..end]));
        }
    }
    None
}

fn env_name_end(bytes: &[u8], mut end: usize) -> usize {
    while end < bytes.len() && is_env_name_byte(bytes[end]) {
        end += 1;
    }
    end
}

pub fn preflight_exec_server_process_start_from_active_memory_store(
    argv: &[String],
    env: &[(String, String)],
) -> Result<Option<Vec<(String, String)>>, String> {
    if MemoryStoreClient::from_env().is_none() {
        return Ok(None);
    }
    let session_name = default_session_name()?;
    let session = Session::open_capability(&session_name).map_err(|e| e.to_string())?;
    let store = MemoryStore::for_session(&session);
    let argv_mode = ExecMode::Program(argv.to_vec());
    let opts = ExecOpts {
        session: session_name,
        live: false,
        allow_secret_argv: false,
        secret_stdin: None,
        script_shell: ScriptShell::Native,
        mode: argv_mode,
    };
    prepare_exec_secret_inputs(&store, &opts)?;
    let mut bindings: BTreeMap<String, (String, String)> =
        requested_env_bindings(&store, &opts.mode)?
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), (name, value)))
            .collect();
    for (name, value) in env {
        let resolved = store.resolve_all(value).map_err(|e| e.to_string())?;
        if resolved != *value {
            bindings.insert(name.to_ascii_lowercase(), (name.clone(), resolved));
        }
    }
    Ok(Some(bindings.into_values().collect()))
}

pub struct ActiveToolOutputMasker {
    client: Option<MemoryStoreClient>,
    masker: Option<OutputMasker>,
    reported_masked_count: u64,
    cache: HashMap<[u8; 32], CachedToolOutput>,
    cache_order: VecDeque<[u8; 32]>,
    prompt_cache: HashMap<[u8; 32], CachedToolOutput>,
    prompt_cache_order: VecDeque<[u8; 32]>,
}

struct CachedToolOutput {
    masked: String,
    masked_count: u64,
}

impl ActiveToolOutputMasker {
    pub fn new() -> Result<Self, String> {
        Self::new_with_plugins(PluginMiddleware::from_env()?)
    }

    pub fn new_with_plugins(plugins: PluginMiddleware) -> Result<Self, String> {
        let Some(client) = MemoryStoreClient::from_env() else {
            return Ok(Self {
                client: None,
                masker: None,
                reported_masked_count: 0,
                cache: HashMap::new(),
                cache_order: VecDeque::new(),
                prompt_cache: HashMap::new(),
                prompt_cache_order: VecDeque::new(),
            });
        };
        let session = Session::open_capability("default").map_err(|e| e.to_string())?;
        let store = MemoryStore::for_session(&session);
        Ok(Self {
            client: Some(client),
            masker: Some(OutputMasker::new_shared_with_plugins(store, plugins)?),
            reported_masked_count: 0,
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
            prompt_cache: HashMap::new(),
            prompt_cache_order: VecDeque::new(),
        })
    }

    /// Capture the mappings already owned by this masker without opening a
    /// second memory-store connection. HTTP gateways use this immediately
    /// after masking a request to restore completed local tool inputs.
    pub fn known_text_resolver(&self) -> Result<ActiveMemoryStoreResolver, String> {
        match &self.masker {
            Some(masker) => masker
                .recovery_snapshot()
                .map(ActiveMemoryStoreResolver::from_recovery),
            None => Ok(ActiveMemoryStoreResolver {
                recovery: None,
                env_bindings: BTreeMap::new(),
            }),
        }
    }

    pub fn mask_tool_output(&mut self, text: &str) -> Result<Option<String>, String> {
        self.mask_tool_output_with_plugins(text, true)
    }

    pub fn mask_tool_output_without_plugins(
        &mut self,
        text: &str,
    ) -> Result<Option<String>, String> {
        self.mask_tool_output_with_plugins(text, false)
    }

    fn mask_tool_output_with_plugins(
        &mut self,
        text: &str,
        run_plugins: bool,
    ) -> Result<Option<String>, String> {
        let Some(masker) = &mut self.masker else {
            return Ok(None);
        };
        let cache_key = (text.len() <= ACTIVE_TOOL_OUTPUT_CACHE_MAX_BYTES)
            .then(|| tool_output_cache_key(text, run_plugins));
        if let Some(key) = cache_key {
            if let Some(cached) = self.cache.get(&key) {
                if cached.masked_count > 0 {
                    if let Some(client) = &self.client {
                        client
                            .add_masked_count(cached.masked_count)
                            .map_err(|e| e.to_string())?;
                    }
                }
                return Ok(Some(cached.masked.clone()));
            }
        }
        let masked = if run_plugins {
            masker.mask_tool_output(text)?
        } else {
            masker.mask_tool_output_without_plugins(text)?
        };
        masker.flush_activity();
        let total = masker.masked_count();
        let delta = total.saturating_sub(self.reported_masked_count);
        self.reported_masked_count = total;
        if delta > 0 {
            self.cache.clear();
            self.cache_order.clear();
            self.prompt_cache.clear();
            self.prompt_cache_order.clear();
            if let Some(client) = &self.client {
                client.add_masked_count(delta).map_err(|e| e.to_string())?;
            }
        }
        if let Some(key) = cache_key {
            self.remember(key, &masked, delta);
        }
        Ok(Some(masked))
    }

    /// Return whether tool-output text would be protected, without creating a
    /// handle or changing masking activity/metrics.
    pub fn tool_output_contains_sensitive_text(&self, text: &str) -> Result<Option<bool>, String> {
        self.masker
            .as_ref()
            .map(|masker| masker.tool_output_contains_sensitive_text(text))
            .transpose()
    }

    pub fn mask_prompt_text(&mut self, text: &str) -> Result<Option<String>, String> {
        self.mask_prompt_text_with_plugins(text, true)
    }

    pub fn mask_prompt_text_without_plugins(
        &mut self,
        text: &str,
    ) -> Result<Option<String>, String> {
        self.mask_prompt_text_with_plugins(text, false)
    }

    fn mask_prompt_text_with_plugins(
        &mut self,
        text: &str,
        run_plugins: bool,
    ) -> Result<Option<String>, String> {
        let Some(masker) = &mut self.masker else {
            return Ok(None);
        };
        let cache_key = (text.len() <= ACTIVE_TOOL_OUTPUT_CACHE_MAX_BYTES)
            .then(|| prompt_cache_key(text, run_plugins));
        if let Some(key) = cache_key {
            if let Some(cached) = self.prompt_cache.get(&key) {
                if cached.masked_count > 0 {
                    if let Some(client) = &self.client {
                        client
                            .add_masked_count(cached.masked_count)
                            .map_err(|e| e.to_string())?;
                    }
                }
                return Ok(Some(cached.masked.clone()));
            }
        }
        let masked = if run_plugins {
            masker.mask_prompt_text(text)?
        } else {
            masker.mask_prompt_text_without_plugins(text)?
        };
        masker.flush_activity();
        let total = masker.masked_count();
        let delta = total.saturating_sub(self.reported_masked_count);
        self.reported_masked_count = total;
        if delta > 0 {
            self.cache.clear();
            self.cache_order.clear();
            self.prompt_cache.clear();
            self.prompt_cache_order.clear();
            if let Some(client) = &self.client {
                client.add_masked_count(delta).map_err(|e| e.to_string())?;
            }
        }
        if let Some(key) = cache_key {
            remember_cached_output(
                &mut self.prompt_cache,
                &mut self.prompt_cache_order,
                key,
                &masked,
                delta,
            );
        }
        Ok(Some(masked))
    }

    fn remember(&mut self, key: [u8; 32], masked: &str, masked_count: u64) {
        remember_cached_output(
            &mut self.cache,
            &mut self.cache_order,
            key,
            masked,
            masked_count,
        );
    }
}

fn remember_cached_output(
    cache: &mut HashMap<[u8; 32], CachedToolOutput>,
    order: &mut VecDeque<[u8; 32]>,
    key: [u8; 32],
    masked: &str,
    masked_count: u64,
) {
    if cache.contains_key(&key) {
        return;
    }
    while cache.len() >= ACTIVE_TOOL_OUTPUT_CACHE_LIMIT {
        let Some(oldest) = order.pop_front() else {
            cache.clear();
            break;
        };
        cache.remove(&oldest);
    }
    cache.insert(
        key,
        CachedToolOutput {
            masked: masked.to_string(),
            masked_count,
        },
    );
    order.push_back(key);
}

fn tool_output_cache_key(text: &str, run_plugins: bool) -> [u8; 32] {
    masking_cache_key(b"pentect-tool-output-cache-v1", text, run_plugins)
}

fn prompt_cache_key(text: &str, run_plugins: bool) -> [u8; 32] {
    masking_cache_key(b"pentect-prompt-cache-v1", text, run_plugins)
}

fn masking_cache_key(domain: &[u8], text: &str, run_plugins: bool) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([u8::from(run_plugins)]);
    digest.update(text.as_bytes());
    digest.finalize().into()
}

pub fn mask_tool_output_into_active_memory_store(text: &str) -> Result<Option<String>, String> {
    ActiveToolOutputMasker::new()?.mask_tool_output(text)
}

pub fn mask_prompt_text_into_active_memory_store(text: &str) -> Result<Option<String>, String> {
    if text.is_empty() {
        return Ok(None);
    }
    ActiveToolOutputMasker::new()?.mask_prompt_text(text)
}

fn usage() {
    eprintln!(
        "pentect\n\
         pentect exec \"<command>\"\n\
         pentect view <HANDLE>\n\
         pentect resolve [PATH...]\n\
         pentect log [--json | --path]\n\
         pentect metrics [--json]\n\
         \n\
         exec: masked output\n\
         view: handle\n\
         resolve: write handles\n\
         log: gateway history and live events\n\
         metrics: local value-free protection statistics"
    );
}

fn cmd_log(args: &[String]) -> i32 {
    if args.get(2).map(String::as_str) == Some("--path") && args.len() == 3 {
        println!("{}", activity_log::persistent_log_path().display());
        return 0;
    }
    let json = match args.get(2).map(String::as_str) {
        None => false,
        Some("--json") if args.len() == 3 => true,
        _ => return die("log [--json | --path]"),
    };
    match activity_log::follow(json) {
        Ok(()) => 0,
        Err(error) => die(&error),
    }
}

fn cmd_metrics(args: &[String]) -> i32 {
    let json = match args.get(2).map(String::as_str) {
        None => false,
        Some("--json") if args.len() == 3 => true,
        _ => return die("metrics [--json]"),
    };
    let enabled = match config::metrics_enabled() {
        Ok(enabled) => enabled,
        Err(error) => return die(&error),
    };
    if !enabled {
        if json {
            println!("{{\"enabled\":false}}");
        } else {
            println!("Pentect privacy metrics are disabled (metrics.enabled = false).");
        }
        return 0;
    }
    match activity_log::print_metrics(json) {
        Ok(()) => 0,
        Err(error) => die(&error),
    }
}

fn cmd_read(args: &[String]) -> i32 {
    let opts = match ReadOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let data = match read_input(&opts.path, opts.input_format) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let kind = opts
        .kind
        .unwrap_or_else(|| infer_kind_with_content(&opts.path, &data));
    let source = data.clone();
    let input = Input { kind, data };
    match mask_input_into_active_memory_store(input.clone(), Profile::Strict, Vec::new()) {
        Ok(Some(result)) => {
            register_read_file_pointers(&opts.path, &input.data, &result, opts.input_format);
            activity_log::record_mask_result("read", &result, Some(&opts.path));
            print_read_result(result, opts.emit_meta);
            return 0;
        }
        Ok(None) => {}
        Err(e) => return die(&e),
    }
    let decode = match config::decode_config(Profile::Strict) {
        Ok(config) => config,
        Err(error) => return die(&error),
    };
    let engine = Engine::with_profile_and_decode_config(Profile::Strict, decode);
    let cfg = Config::generate();
    let result = engine.mask(input, &cfg);
    register_read_file_pointers(&opts.path, &source, &result, opts.input_format);
    activity_log::record_mask_result("read", &result, Some(&opts.path));
    print_read_result(result, opts.emit_meta);
    0
}

fn register_read_file_pointers(
    path: &Path,
    source: &str,
    result: &MaskResult,
    input_format: InputFormat,
) -> bool {
    if input_format != InputFormat::Text {
        return false;
    }
    file_pointer_manager::register_file_pointers(path, source, result);
    true
}

fn print_read_result(result: MaskResult, emit_meta: bool) {
    print!("{}", result.masked);
    let _ = std::io::stdout().flush();
    if emit_meta {
        eprintln!(
            "[pentect] masked={}, warned={}",
            result.summary.masked_count,
            result.summary.residual.len()
        );
    }
}

fn cmd_view(args: &[String]) -> i32 {
    if args.len() != 3 {
        return die("view HANDLE");
    }
    let parts = match parse_placeholder(&args[2]) {
        Ok(parts) => parts,
        Err(_) => return die("invalid handle"),
    };
    println!("label: {}", parts.label);
    println!("hash: {}", parts.hash);
    match parts.length_hint.map(|hint| hint.short()).or_else(|| {
        active_handle_length(&args[2])
            .ok()
            .flatten()
            .map(|len| format!("{len} chars"))
    }) {
        Some(length) => println!("length: {length}"),
        None => println!("length: -"),
    }
    0
}

pub fn active_handle_length(handle: &str) -> Result<Option<usize>, String> {
    let Some(client) = MemoryStoreClient::from_env() else {
        return Ok(file_pointer_manager::handle_length(handle));
    };
    let snapshot = client.snapshot().map_err(|e| e.to_string())?;
    Ok(handle_length_from_recovery(&snapshot.recovery, handle)
        .or_else(|| file_pointer_manager::handle_length(handle)))
}

fn handle_length_from_recovery(recovery: &pentect_core::Recovery, handle: &str) -> Option<usize> {
    let mut value = recovery.resolve(handle);
    if value == handle {
        return None;
    }
    let len = value.chars().count();
    value.zeroize();
    Some(len)
}

fn cmd_exec(args: &[String]) -> i32 {
    if matches!(
        args.get(2).map(String::as_str),
        Some("--help" | "-h" | "help")
    ) {
        exec_help();
        return 0;
    }
    let opts = match ExecOpts::parse(args).and_then(prepare_stdin_exec_opts) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let session = match Session::open_capability(&opts.session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let store = MemoryStore::for_session(&session);
    if let Err(e) = prepare_exec_secret_inputs(&store, &opts) {
        return die(&e);
    }
    if opts.live {
        let status = match run_resolved_command_live(&store, &opts) {
            Ok(s) => s,
            Err(e) => return die(&e),
        };
        return exit_code(status);
    }
    let output = match run_resolved_command(&store, &opts) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut masker = match OutputMasker::new_shared(store) {
        Ok(masker) => masker,
        Err(e) => return die(&e),
    };
    let safe_stdout = match masker.mask_tool_output(&stdout) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let safe_stderr = match masker.mask_tool_output(&stderr) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    print!("{safe_stdout}");
    let _ = std::io::stdout().flush();
    eprint!("{safe_stderr}");
    let _ = std::io::stderr().flush();
    exit_code(output.status)
}

fn cmd_resolve(args: &[String]) -> i32 {
    let opts = match ResolveOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let session = match Session::open_capability(&opts.session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let store = MemoryStore::for_session(&session);
    match opts.mode {
        ResolveMode::Files(paths) => {
            for path in &paths {
                if let Err(e) = resolve_path_in_place(&store, path) {
                    return die(&e);
                }
                println!("resolved {}", path.display());
            }
        }
        ResolveMode::Stdin => {
            let input = match read_stdin_text() {
                Ok(s) => s,
                Err(e) => return die(&e),
            };
            let resolved = match resolve_command_text(&store, &input) {
                Ok(s) => s,
                Err(e) => return die(&e),
            };
            if resolved != input {
                activity_log::record_resolve("stdin", None);
            }
            print!("{resolved}");
            let _ = std::io::stdout().flush();
        }
    }
    0
}

fn exec_help() {
    print!(
        "{}",
        concat!(
            "pentect exec \"<command>\"\n",
            "pentect exec --stdin\n",
            "pentect exec --secret-stdin <HANDLE> -- PROGRAM...\n",
            "pentect exec --live \"<command>\"\n\n",
            "COMMAND is a native-shell script; after `--`, PROGRAM is executed directly.\n",
            "exec does not interpret arbitrary text as a file, secret, or handle lookup.\n",
            "stdout/stderr: masked\n",
            "handles: in memory\n",
            "env: $env:KEY or $KEY\n",
            "secret stdin: restored locally, never added to program arguments\n",
        )
    );
}

fn cmd_purge(args: &[String]) -> i32 {
    let opts = match PurgeOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let root = match session_root(&opts.session) {
        Ok(root) => root,
        Err(e) => return die(&e),
    };
    if !root.exists() {
        return 0;
    }
    if let Err(e) = std::fs::remove_dir_all(&root) {
        return die(format!("could not purge session '{}': {e}", root.display()));
    }
    eprintln!("[pentect] purged session state: {}", root.display());
    0
}

fn cmd_memory_store(args: &[String]) -> i32 {
    match args.get(2).map(String::as_str) {
        Some("--serve") if args.len() == 3 => memory_store::serve_memory_store(),
        _ => die("memory-store accepts only `--serve`"),
    }
}

fn cmd_agent_stream(args: &[String]) -> i32 {
    let opts = match AgentStreamOpts::parse(args) {
        Ok(opts) => opts,
        Err(error) => return die(&error),
    };
    if MemoryStoreClient::from_env().is_none() {
        return die("agent stream requires a running Pentect session");
    }
    let session = match Session::open_capability(&opts.session) {
        Ok(session) => session,
        Err(error) => return die(&error),
    };
    let mut masker = match OutputMasker::new_shared(MemoryStore::for_session(&session)) {
        Ok(masker) => masker,
        Err(error) => return die(&error),
    };
    let stream_result = match opts.end_marker.as_deref() {
        Some(marker) => stream_masked_reader_until_marker(
            &mut masker,
            std::io::stdin(),
            opts.target,
            marker.as_bytes(),
        ),
        None => stream_masked_reader(&mut masker, std::io::stdin(), opts.target),
    };
    if let Err(error) = stream_result.and_then(|_| masker.flush()) {
        return die(&error);
    }
    0
}

fn prepare_exec_secret_inputs(store: &MemoryStore, opts: &ExecOpts) -> Result<(), String> {
    if let ExecMode::Shell(command) = &opts.mode {
        let command = resolve_command_text(store, command)?;
        register_local_file_inputs(store, &command)?;
    }
    Ok(())
}

fn cmd_hook(args: &[String]) -> i32 {
    let opts = match HookOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let raw = match read_stdin_text() {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let mut raw_bytes = raw.into_bytes();
    let input: Value = match simd_json::serde::from_slice(&mut raw_bytes) {
        Ok(v) => v,
        Err(e) => return die(format!("hook input must be JSON: {e}")),
    };
    let session_name = match opts.session_name(&input) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let output = match handle_hook_lazy(opts.provider, &session_name, opts.cli, input) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    match serde_json::to_string(&output) {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => die(format!("could not serialize hook output: {e}")),
    }
}

fn cmd_bridge(args: &[String]) -> i32 {
    if args.len() != 2 {
        return die("bridge");
    }
    if !agent_launch_proof_valid() {
        return die("Pentect unavailable.");
    }
    let session = match Session::open_capability(DEFAULT_SESSION) {
        Ok(session) => session,
        Err(_) => return die("Pentect unavailable."),
    };
    let mut prompt_masker = match ActiveToolOutputMasker::new() {
        Ok(masker) => masker,
        Err(_) => return die("Pentect unavailable."),
    };
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    let mut line = Vec::new();
    loop {
        line.clear();
        match read_bridge_line(&mut reader, &mut line) {
            Ok(BridgeLine::Eof) => return 0,
            Ok(BridgeLine::Ready) => {}
            Ok(BridgeLine::Oversized) => return 2,
            Err(_) => return 2,
        }
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        let request = match serde_json::from_slice::<Value>(&line) {
            Ok(request) => request,
            Err(_) => return 2,
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let phase = bridge_request_phase(&request);
        let result = handle_bridge_request(&session, &mut prompt_masker, &request);
        if write_bridge_response(&mut writer, id, phase, result).is_err() {
            return 2;
        }
    }
}

enum BridgeLine {
    Eof,
    Ready,
    Oversized,
}

fn read_bridge_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> std::io::Result<BridgeLine> {
    read_bridge_line_with_limit(reader, line, MAX_INPUT_BYTES)
}

fn read_bridge_line_with_limit(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
    max_bytes: usize,
) -> std::io::Result<BridgeLine> {
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(if line.is_empty() && !oversized {
                BridgeLine::Eof
            } else if oversized {
                BridgeLine::Oversized
            } else {
                BridgeLine::Ready
            });
        }
        let end = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if !oversized {
            if line.len().saturating_add(end) <= max_bytes {
                line.extend_from_slice(&available[..end]);
            } else {
                oversized = true;
                line.clear();
            }
        }
        let complete = available.get(end.saturating_sub(1)) == Some(&b'\n');
        reader.consume(end);
        if complete {
            return Ok(if oversized {
                BridgeLine::Oversized
            } else {
                BridgeLine::Ready
            });
        }
    }
}

fn write_bridge_response(
    writer: &mut impl Write,
    id: Value,
    phase: &str,
    result: Result<Value, String>,
) -> Result<(), String> {
    let executed = phase == "after";
    let response = match result {
        Ok(value) => json!({ "id": id, "ok": true, "value": value }),
        Err(message) => json!({
            "id": id,
            "ok": false,
            "error": {
                "code": if executed { "output_unavailable" } else { "operation_unavailable" },
                "phase": phase,
                "executed": executed,
                "message": message,
            }
        }),
    };
    serde_json::to_writer(&mut *writer, &response).map_err(|_| "bridge unavailable".to_string())?;
    writer
        .write_all(b"\n")
        .and_then(|_| writer.flush())
        .map_err(|_| "bridge unavailable".to_string())
}

fn bridge_request_phase(request: &Value) -> &str {
    match request.get("op").and_then(Value::as_str) {
        Some(phase @ ("session" | "prompt" | "media" | "before" | "after")) => phase,
        _ => "request",
    }
}

fn handle_bridge_request(
    session: &Session,
    prompt_masker: &mut ActiveToolOutputMasker,
    request: &Value,
) -> Result<Value, String> {
    let op = request
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| "invalid bridge request".to_string())?;
    match op {
        "session" => bridge_session_value(),
        "prompt" => {
            let value = request
                .get("value")
                .ok_or_else(|| "invalid bridge request".to_string())?;
            let text = value
                .as_str()
                .ok_or_else(|| "invalid bridge request".to_string())?;
            Ok(Value::String(
                prompt_masker
                    .mask_prompt_text(text)?
                    .unwrap_or_else(|| text.to_string()),
            ))
        }
        "media" => {
            let value = request
                .get("value")
                .ok_or_else(|| "invalid bridge request".to_string())?;
            match claude_image_tool_output(session, value)? {
                Some(ToolTextOutput::Updated(updated)) => Ok(updated),
                Some(ToolTextOutput::Block(reason)) => Err(reason),
                Some(ToolTextOutput::Unchanged) | None => Ok(value.clone()),
            }
        }
        "before" => {
            let value = request
                .get("value")
                .ok_or_else(|| "invalid bridge request".to_string())?;
            let tool_name = request
                .get("tool")
                .and_then(Value::as_str)
                .ok_or_else(|| "invalid bridge request".to_string())?;
            before_tool_updated_input(
                HookProvider::Generic,
                DEFAULT_SESSION,
                session,
                tool_name,
                value,
            )
            .map(|(updated, _)| updated)
        }
        "after" => {
            let value = request
                .get("value")
                .ok_or_else(|| "invalid bridge request".to_string())?;
            let tool_name = request
                .get("tool")
                .and_then(Value::as_str)
                .ok_or_else(|| "invalid bridge request".to_string())?;
            if let Some(tool_input) = request.get("input") {
                repair_masked_write_after_tool(session, tool_name, tool_input)?;
            }
            match mask_tool_text_output(HookProvider::Generic, session, value)? {
                ToolTextOutput::Unchanged => Ok(value.clone()),
                ToolTextOutput::Updated(updated) => Ok(updated),
                ToolTextOutput::Block(reason) => Err(reason),
            }
        }
        _ => Err("invalid bridge request".to_string()),
    }
}

fn bridge_session_value() -> Result<Value, String> {
    if !agent_launch_proof_valid() {
        return Err("bridge unavailable".to_string());
    }
    let environment = bridge_owned_environment(|name| std::env::var(name).ok())?;
    let prefix = config::environment_variable_prefix()?;
    Ok(json!({
        "contract": agent_contract_instructions(&prefix),
        "environment": environment,
    }))
}

fn bridge_owned_environment(
    mut read: impl FnMut(&str) -> Option<String>,
) -> Result<serde_json::Map<String, Value>, String> {
    let mut environment = serde_json::Map::new();
    for name in [ENV_ADDR, ENV_TOKEN, PENTECT_AGENT_LAUNCHED_ENV] {
        let value = read(name).ok_or_else(|| "bridge unavailable".to_string())?;
        if value.is_empty() {
            return Err("bridge unavailable".to_string());
        }
        environment.insert(name.to_string(), Value::String(value));
    }
    for name in [
        "PENTECT_BIN",
        PENTECT_PLUGIN_CONFIGS_ENV,
        PENTECT_PLUGIN_BINARIES_ENV,
    ] {
        if let Some(value) = read(name) {
            if !value.is_empty() {
                environment.insert(name.to_string(), Value::String(value));
            }
        }
    }
    Ok(environment)
}

fn open_hook_session(cli: bool, session_name: &str) -> Result<Session, String> {
    if cli {
        Session::open_capability(session_name)
    } else {
        Session::open(session_name)
    }
    .map_err(|e| e.to_string())
}

fn run_resolved_command(
    store: &MemoryStore,
    opts: &ExecOpts,
) -> Result<std::process::Output, String> {
    match &opts.mode {
        ExecMode::Program(args) => {
            if args.is_empty() {
                return Err("exec requires a program after `--`".to_string());
            }
            let env = requested_env_bindings(store, &opts.mode)?;
            let resolved_args = resolve_command_args(store, args, opts.allow_secret_argv)?;
            let program = &resolved_args[0];
            let command_args = &resolved_args[1..];
            let mut command = Command::new(program);
            command.args(command_args);
            apply_child_env_overlays(&mut command, &env, &opts.session);
            let secret_stdin = resolve_secret_stdin(store, opts)?;
            if let Some(secret) = secret_stdin.as_deref() {
                run_command_with_stdin(command, secret)
            } else {
                command
                    .output()
                    .map_err(|error| command_start_error(&error))
            }
        }
        ExecMode::Shell(command) => {
            let command = resolve_command_text(store, command)?;
            register_local_file_inputs(store, &command)?;
            let env = requested_env_bindings(store, &opts.mode)?;
            run_shell_script(&command, &env, &opts.session, opts.script_shell)
        }
        ExecMode::Stdin => Err("internal error: exec stdin was not prepared".to_string()),
    }
}

fn run_resolved_command_live(store: &MemoryStore, opts: &ExecOpts) -> Result<ExitStatus, String> {
    match &opts.mode {
        ExecMode::Program(args) => {
            if args.is_empty() {
                return Err("exec requires a program after `--`".to_string());
            }
            let env = requested_env_bindings(store, &opts.mode)?;
            let resolved_args = resolve_command_args(store, args, opts.allow_secret_argv)?;
            let program = &resolved_args[0];
            let command_args = &resolved_args[1..];
            let mut command = Command::new(program);
            command.args(command_args);
            apply_child_env_overlays(&mut command, &env, &opts.session);
            let secret_stdin = resolve_secret_stdin(store, opts)?;
            run_live_command(
                command,
                secret_stdin.as_ref().map(|value| value.as_str()),
                store.clone(),
            )
        }
        ExecMode::Shell(command) => {
            let command = resolve_command_text(store, command)?;
            register_local_file_inputs(store, &command)?;
            let env = requested_env_bindings(store, &opts.mode)?;
            let mut shell = shell_script_command(opts.script_shell)?;
            apply_child_env_overlays(&mut shell, &env, &opts.session);
            let command = prepare_shell_script(&command, opts.script_shell);
            run_live_command(shell, Some(&command), store.clone())
        }
        ExecMode::Stdin => Err("internal error: exec stdin was not prepared".to_string()),
    }
}

fn resolve_secret_stdin(
    store: &MemoryStore,
    opts: &ExecOpts,
) -> Result<Option<Zeroizing<String>>, String> {
    let Some(handle) = opts.secret_stdin.as_deref() else {
        return Ok(None);
    };
    let resolved = resolve_command_text(store, handle)?;
    if resolved == handle {
        return Err("secret stdin requires a known handle from the active session".to_string());
    }
    Ok(Some(Zeroizing::new(resolved)))
}

fn run_command_with_stdin(
    mut command: Command,
    stdin_payload: &str,
) -> Result<std::process::Output, String> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| command_start_error(&error))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "could not open command stdin".to_string())?;
    stdin
        .write_all(stdin_payload.as_bytes())
        .map_err(|e| format!("could not write command stdin: {e}"))?;
    drop(stdin);
    child
        .wait_with_output()
        .map_err(|e| format!("could not read command output: {e}"))
}

fn resolve_command_args(
    store: &MemoryStore,
    args: &[String],
    allow_secret_argv: bool,
) -> Result<Vec<String>, String> {
    let mut resolved_args = Vec::with_capacity(args.len());
    for arg in args {
        let mut resolved = resolve_command_text(store, arg)?;
        if resolved != *arg && !allow_secret_argv {
            resolved.zeroize();
            return Err(
                "refusing to place a restored secret in process arguments; prefer target-specific stdin, file-descriptor, or configuration support, or pass --allow-secret-argv after reviewing same-user process visibility (a shell protects the model-facing command only, not child-process arguments)"
                    .to_string(),
            );
        }
        resolved_args.push(resolved);
    }
    Ok(resolved_args)
}

fn resolve_command_text(store: &MemoryStore, text: &str) -> Result<String, String> {
    let resolved = store.resolve_all(text).map_err(|e| e.to_string())?;
    if contains_unresolved_masked_handle(&resolved) {
        return Err(
            "unknown masked handle; use it inside the same running Pentect-launched agent session or re-register it with `pentect exec`"
                .to_string(),
        );
    }
    Ok(resolved)
}

fn resolve_path_in_place(store: &MemoryStore, path: &Path) -> Result<(), String> {
    if path == Path::new("-") {
        return Err("resolve requires a real file path".to_string());
    }
    let Some(path_text) = path.to_str() else {
        return Err("resolve requires a UTF-8 relative path".to_string());
    };
    let path = checked_local_write_path(path_text)?;
    ensure_local_write_path_within_cwd(&path)?;
    let input = read_input(&path, InputFormat::Text)?;
    let resolved = resolve_command_text(store, &input)?;
    if resolved != input {
        std::fs::write(&path, resolved)
            .map_err(|e| format!("could not write '{}': {e}", path.display()))?;
        activity_log::record_resolve("file", Some(&path));
    }
    Ok(())
}

fn apply_child_env_overlays(command: &mut Command, env: &[(String, String)], _session: &str) {
    remove_pentect_control_env(command);
    command.env_remove(ENV_ADDR);
    command.env_remove(ENV_TOKEN);
    command.env_remove("PENTECT_PROCESS_HOST_READ_TOKEN");
    command.env_remove("PENTECT_PROCESS_HOST_WRITE_TOKEN");
    command.env_remove("PENTECT_PROCESS_HOST_ROOT");
    command.env_remove(PENTECT_AGENT_LAUNCHED_ENV);
    apply_env_bindings(command, env);
}

fn remove_pentect_control_env(command: &mut Command) {
    for name in pentect_control_env_names() {
        command.env_remove(name);
    }
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(is_pentect_control_env_name) {
            command.env_remove(name);
        }
    }
}

fn apply_env_bindings(command: &mut Command, env: &[(String, String)]) {
    for (name, value) in env {
        if !is_pentect_control_env_name(name) {
            command.env(name, value);
        }
    }
}

fn requested_env_bindings(
    store: &MemoryStore,
    mode: &ExecMode,
) -> Result<Vec<(String, String)>, String> {
    let available = store.auto_env_bindings().map_err(|e| e.to_string())?;
    if available.is_empty() {
        return Ok(Vec::new());
    }
    let names = referenced_env_names(mode);
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let prefix = config::environment_variable_prefix()?;
    Ok(select_referenced_env_bindings(available, &names, &prefix))
}

fn select_referenced_env_bindings(
    available: Vec<(String, String)>,
    referenced: &BTreeSet<String>,
    prefix: &str,
) -> Vec<(String, String)> {
    let mut selected = Vec::new();
    for (name, value) in available {
        let full_requested = referenced.contains(&name.to_ascii_lowercase());
        let short = name.strip_prefix(prefix).filter(|short| !short.is_empty());
        let short_requested = short
            .is_some_and(|short| short != name && referenced.contains(&short.to_ascii_lowercase()));
        if full_requested {
            selected.push((name.clone(), value.clone()));
        }
        if short_requested {
            selected.push((short.unwrap().to_string(), value));
        }
    }
    selected
}

fn referenced_env_names(mode: &ExecMode) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    match mode {
        ExecMode::Shell(command) => {
            collect_powershell_env_refs(command, &mut names);
            collect_powershell_env_provider_refs(command, &mut names);
            collect_printenv_refs(command, &mut names);
            collect_percent_env_refs(command, &mut names);
            collect_bare_dollar_env_refs(command, &mut names);
        }
        ExecMode::Stdin => {}
        ExecMode::Program(args) => {
            let text = args.join(" ");
            collect_powershell_env_refs(&text, &mut names);
            collect_powershell_env_provider_refs(&text, &mut names);
            collect_printenv_refs(&text, &mut names);
            collect_percent_env_refs(&text, &mut names);
            collect_bare_dollar_env_refs(&text, &mut names);
        }
    }
    names
}

fn collect_powershell_env_refs(text: &str, out: &mut BTreeSet<String>) {
    let lower = text.to_ascii_lowercase();
    let mut offset = 0usize;
    while let Some(index) = lower[offset..].find("$env:") {
        let name_start = offset + index + "$env:".len();
        let mut name_end = name_start;
        let bytes = lower.as_bytes();
        while name_end < bytes.len() && is_env_name_byte(bytes[name_end]) {
            name_end += 1;
        }
        if name_end > name_start {
            out.insert(lower[name_start..name_end].to_string());
        }
        offset = name_end.max(offset + index + "$env:".len());
    }
}

fn collect_powershell_env_provider_refs(text: &str, out: &mut BTreeSet<String>) {
    let lower = text.to_ascii_lowercase();
    let mut offset = 0usize;
    while let Some(index) = lower[offset..].find("env:") {
        let env_start = offset + index;
        let before = lower[..env_start].chars().next_back();
        if before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
            offset = env_start + "env:".len();
            continue;
        }
        let name_start = env_start + "env:".len();
        let mut name_end = name_start;
        let bytes = lower.as_bytes();
        while name_end < bytes.len() && is_env_name_byte(bytes[name_end]) {
            name_end += 1;
        }
        if name_end > name_start {
            out.insert(lower[name_start..name_end].to_string());
        }
        offset = name_end.max(env_start + "env:".len());
    }
}

fn collect_bare_dollar_env_refs(text: &str, out: &mut BTreeSet<String>) {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                if let Some((name, next)) = env_name_after_marker(text, i + 1, '$') {
                    out.insert(name.to_ascii_lowercase());
                    i = next;
                    continue;
                }
            } else if let Some((name, next)) = env_name_after_marker(text, i + 1, '$') {
                if !name.eq_ignore_ascii_case("env") {
                    out.insert(name.to_ascii_lowercase());
                }
                i = next;
                continue;
            }
        }
        i += 1;
    }
}

fn collect_percent_env_refs(text: &str, out: &mut BTreeSet<String>) {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some((name, next)) = env_name_after_marker(text, i + 1, '%') {
                out.insert(name.to_ascii_lowercase());
                i = next;
                continue;
            }
        }
        i += 1;
    }
}

fn collect_printenv_refs(text: &str, out: &mut BTreeSet<String>) {
    let normalized = normalize_policy_text(text);
    let mut offset = 0usize;
    while let Some(index) = normalized[offset..].find("printenv") {
        let word_start = offset + index;
        let word_end = word_start + "printenv".len();
        let before = normalized[..word_start].chars().next_back();
        let after = normalized[word_end..].chars().next();
        if !is_ascii_word_char(before) && !is_ascii_word_char(after) {
            let mut cursor = word_end;
            while let Some((word, _, next)) = next_shell_word(&normalized, cursor) {
                if is_shell_separator_word(&word) {
                    break;
                }
                if !word.starts_with('-') && looks_like_env_name(&word) {
                    out.insert(word.to_ascii_lowercase());
                }
                cursor = next;
            }
        }
        offset = word_end;
    }
}

fn register_local_file_inputs(store: &MemoryStore, script: &str) -> Result<(), String> {
    let paths = local_file_input_paths(script);
    if paths.is_empty() {
        return Ok(());
    }
    let mut masker = OutputMasker::new_shared(store.clone())?;
    for path in paths {
        if !path.is_file() {
            continue;
        }
        let Ok(input) = read_input(&path, InputFormat::Text) else {
            continue;
        };
        let kind = infer_kind_with_content(&path, &input);
        if kind == Kind::Text {
            let _ = masker.mask_tool_output(&input)?;
        } else {
            let _ = masker.mask_text(&input, kind)?;
        }
    }
    Ok(())
}

fn local_file_input_paths(script: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = 0usize;
    while let Some((word, _, next)) = next_shell_word(script, cursor) {
        for candidate in local_file_path_candidates(&word) {
            let path = PathBuf::from(candidate);
            if path.is_file() {
                let key = path.to_string_lossy().to_string();
                if seen.insert(key) {
                    out.push(path);
                }
            }
        }
        cursor = next;
    }
    out
}

fn local_file_path_candidates(word: &str) -> Vec<String> {
    let cleaned = clean_path_word(word);
    if cleaned.is_empty() || looks_like_non_file_reference(&cleaned) {
        return Vec::new();
    }
    let mut out = Vec::new();
    push_file_candidate(&mut out, &cleaned);
    if let Some((_, value)) = cleaned.split_once('=') {
        push_file_candidate(&mut out, value);
    }
    if let Some(value) = cleaned.strip_prefix('@') {
        push_file_candidate(&mut out, value);
    }
    out
}

fn push_file_candidate(out: &mut Vec<String>, value: &str) {
    let candidate = clean_path_word(value);
    if candidate.is_empty() || looks_like_non_file_reference(&candidate) {
        return;
    }
    out.push(candidate);
}

fn clean_path_word(path: &str) -> String {
    path.trim_matches('"')
        .trim_matches('\'')
        .trim_matches(|ch| matches!(ch, ';' | ',' | ')' | ']'))
        .to_string()
}

fn looks_like_non_file_reference(value: &str) -> bool {
    value == "-"
        || value.contains("://")
        || value.starts_with('$')
        || value.starts_with('%')
        || value.contains('*')
        || value.contains('?')
        || value.contains('{')
        || value.contains('}')
}

const POWERSHELL_EXEC_PREAMBLE: &str = concat!(
    "[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);",
    "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);",
    "$OutputEncoding=[Text.UTF8Encoding]::new($false);",
    "trap [System.Management.Automation.CommandNotFoundException] {",
    "[Console]::Error.WriteLine('[pentect] exec could not start command: executable was not found; use `pentect exec -- PROGRAM ARG...` for direct execution');",
    "exit 127",
    "}\n",
);

fn prepare_shell_script(script: &str, script_shell: ScriptShell) -> String {
    let powershell = match script_shell {
        ScriptShell::PowerShell => true,
        ScriptShell::Native => cfg!(windows),
        ScriptShell::Bash => false,
    };
    if powershell {
        format!("{POWERSHELL_EXEC_PREAMBLE}{script}")
    } else {
        script.to_string()
    }
}

fn command_start_error(error: &std::io::Error) -> String {
    let reason = match error.kind() {
        std::io::ErrorKind::NotFound => {
            "executable was not found; `pentect exec --` requires a program name"
        }
        std::io::ErrorKind::PermissionDenied => "permission was denied by the operating system",
        std::io::ErrorKind::InvalidInput => "the operating system rejected the command format",
        _ => "the operating system could not start the process",
    };
    format!("could not start command: {reason}")
}

fn command_shell_start_error(error: &std::io::Error) -> String {
    let reason = match error.kind() {
        std::io::ErrorKind::NotFound => "the native command shell was not found",
        std::io::ErrorKind::PermissionDenied => {
            "permission to start the native command shell was denied"
        }
        _ => "the operating system could not start the native command shell",
    };
    format!("could not start command shell: {reason}")
}

fn run_shell_script(
    script: &str,
    env: &[(String, String)],
    session: &str,
    script_shell: ScriptShell,
) -> Result<std::process::Output, String> {
    let mut command = shell_script_command(script_shell)?;
    apply_child_env_overlays(&mut command, env, session);
    let script = prepare_shell_script(script, script_shell);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| command_shell_start_error(&error))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "could not open shell stdin".to_string())?;
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("could not write shell script to stdin: {e}"))?;
    }
    child
        .wait_with_output()
        .map_err(|e| format!("could not read shell output: {e}"))
}

#[derive(Clone, Copy)]
enum StreamTarget {
    Stdout,
    Stderr,
}

fn run_live_command(
    mut command: Command,
    stdin_payload: Option<&str>,
    store: MemoryStore,
) -> Result<ExitStatus, String> {
    live_status("streaming masked command output");
    if stdin_payload.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| command_start_error(&error))?;
    if let Some(payload) = stdin_payload {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "could not open command stdin".to_string())?;
        stdin
            .write_all(payload.as_bytes())
            .map_err(|e| format!("could not write command stdin: {e}"))?;
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "could not capture command stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "could not capture command stderr".to_string())?;
    let stdout_store = store.clone();
    let stderr_store = store.clone();
    let stdout_thread = std::thread::spawn(move || {
        stream_masked_reader_deferred(stdout_store, stdout, StreamTarget::Stdout)
    });
    let stderr_thread = std::thread::spawn(move || {
        stream_masked_reader_deferred(stderr_store, stderr, StreamTarget::Stderr)
    });
    let status = child
        .wait()
        .map_err(|e| format!("could not wait for command: {e}"))?;
    join_stream_thread(stdout_thread)?;
    join_stream_thread(stderr_thread)?;
    Ok(status)
}

fn stream_masked_reader<R: Read>(
    masker: &mut OutputMasker,
    reader: R,
    target: StreamTarget,
) -> Result<(), String> {
    stream_masked_bufread(masker, BufReader::new(reader), target, None)
}

fn stream_masked_reader_deferred<R: Read>(
    store: MemoryStore,
    reader: R,
    target: StreamTarget,
) -> Result<(), String> {
    let mut reader = BufReader::new(reader);
    let mut first = Vec::new();
    let read = reader
        .read_until(b'\n', &mut first)
        .map_err(|e| format!("could not read command output: {e}"))?;
    if read == 0 {
        return Ok(());
    }
    let mut masker = OutputMasker::new_deferred(store)?;
    stream_masked_reader(
        &mut masker,
        std::io::Cursor::new(first).chain(reader),
        target,
    )?;
    masker.flush()
}

fn stream_masked_reader_until_marker<R: Read>(
    masker: &mut OutputMasker,
    reader: R,
    target: StreamTarget,
    end_marker: &[u8],
) -> Result<(), String> {
    if end_marker.is_empty() {
        return Err("agent stream end marker is invalid".to_string());
    }
    stream_masked_bufread(masker, BufReader::new(reader), target, Some(end_marker))
}

fn stream_masked_bufread<R: BufRead>(
    masker: &mut OutputMasker,
    mut reader: R,
    target: StreamTarget,
    end_marker: Option<&[u8]>,
) -> Result<(), String> {
    let mut buf = Vec::new();
    let mut chunk = String::new();
    let mut chunk_kind: Option<Kind> = None;
    let mut chunk_lines = 0usize;
    loop {
        buf.clear();
        let n = reader
            .read_until(b'\n', &mut buf)
            .map_err(|e| format!("could not read command output: {e}"))?;
        if n == 0 {
            break;
        }
        let marker_position = end_marker.and_then(|marker| {
            buf.windows(marker.len())
                .position(|window| window == marker)
        });
        let visible = marker_position.map_or(buf.as_slice(), |position| &buf[..position]);
        let text = String::from_utf8_lossy(visible);
        if text.is_empty() && marker_position.is_some() {
            break;
        }
        let line_kind = live_output_kind(&text);
        if !chunk.is_empty() && chunk_kind.as_ref() != Some(&line_kind) {
            flush_masked_chunk(masker, target, &mut chunk, chunk_kind.take().unwrap())?;
            chunk_lines = 0;
        }
        chunk_kind = Some(line_kind);
        chunk.push_str(&text);
        chunk_lines += 1;
        if chunk.len() >= LIVE_MASK_CHUNK_BYTES || chunk_lines >= LIVE_MASK_CHUNK_LINES {
            flush_masked_chunk(masker, target, &mut chunk, chunk_kind.take().unwrap())?;
            chunk_lines = 0;
        }
        if marker_position.is_some() {
            break;
        }
    }
    if let Some(kind) = chunk_kind {
        flush_masked_chunk(masker, target, &mut chunk, kind)?;
    }
    Ok(())
}

fn flush_masked_chunk(
    masker: &mut OutputMasker,
    target: StreamTarget,
    chunk: &mut String,
    kind: Kind,
) -> Result<(), String> {
    if chunk.is_empty() {
        return Ok(());
    }
    let masked = masker.mask_text(chunk, kind)?;
    chunk.clear();
    match target {
        StreamTarget::Stdout => {
            print!("{masked}");
            std::io::stdout()
                .flush()
                .map_err(|e| format!("could not flush stdout: {e}"))?;
        }
        StreamTarget::Stderr => {
            eprint!("{masked}");
            std::io::stderr()
                .flush()
                .map_err(|e| format!("could not flush stderr: {e}"))?;
        }
    }
    Ok(())
}

fn join_stream_thread(thread: std::thread::JoinHandle<Result<(), String>>) -> Result<(), String> {
    match thread.join() {
        Ok(result) => result,
        Err(_) => Err("output masking thread panicked".to_string()),
    }
}

fn live_status(message: &str) {
    anstream::eprintln!("\x1b[36;1mpentect live\x1b[0m {message}");
}

fn shell_script_command(script_shell: ScriptShell) -> Result<Command, String> {
    match script_shell {
        ScriptShell::Native => Ok(native_shell_script_command()),
        ScriptShell::Bash => Err(
            "Bash scripts must run inside the host Bash tool through a Pentect hook".to_string(),
        ),
        ScriptShell::PowerShell => Ok(powershell_script_command()),
    }
}

#[cfg(windows)]
fn powershell_script_command() -> Command {
    let mut cmd = Command::new(windows_powershell_path());
    cmd.arg("-NoProfile").arg("-Command").arg("-");
    cmd
}

#[cfg(windows)]
fn windows_powershell_path() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| {
            root.join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe")
        })
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from("powershell"))
}

#[cfg(not(windows))]
fn powershell_script_command() -> Command {
    let mut command = Command::new("pwsh");
    command.arg("-NoProfile").arg("-Command").arg("-");
    command
}

#[cfg(windows)]
fn native_shell_script_command() -> Command {
    powershell_script_command()
}

#[cfg(not(windows))]
fn native_shell_script_command() -> Command {
    let shell = if Path::new("/bin/sh").is_file() {
        PathBuf::from("/bin/sh")
    } else {
        PathBuf::from("sh")
    };
    let mut cmd = Command::new(shell);
    cmd.arg("-s");
    cmd
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookProvider {
    Codex,
    Claude,
    Generic,
}

impl HookProvider {
    fn launch_error(self) -> &'static str {
        match self {
            HookProvider::Codex => "Pentect required; start with `pentect codex`.",
            HookProvider::Claude => "Pentect required; start with `pentect claude`.",
            HookProvider::Generic => "Pentect required; enable the installed integration.",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookPhase {
    BeforeTool,
    AfterTool,
    Other,
}

enum ToolTextOutput {
    Unchanged,
    Updated(Value),
    Block(String),
}

// Hook hosts disagree on casing and envelope names. Keep that compatibility at
// the boundary; detection still walks the returned JSON structure generically.
const HOOK_EVENT_FIELDS: &[&str] = &[
    "hook_event_name",
    "hookEventName",
    "event_name",
    "eventName",
    "event",
];
const HOOK_TOOL_NAME_FIELDS: &[&str] = &["tool_name", "toolName", "name", "tool"];
const HOOK_TOOL_INPUT_FIELDS: &[&str] = &[
    "tool_input",
    "toolInput",
    "tool_arguments",
    "toolArguments",
    "arguments",
    "args",
    "input",
];
const HOOK_TOOL_RESULT_FIELDS: &[&str] = &[
    "tool_response",
    "toolResponse",
    "tool_output",
    "toolOutput",
    "tool_result",
    "toolResult",
    "call_tool_result",
    "callToolResult",
    "mcp_result",
    "mcpResult",
    "mcp_tool_result",
    "mcpToolResult",
    "structured_content",
    "structuredContent",
    "response",
    "result",
    "output",
    "payload",
    "data",
    "body",
    "content",
];
const WRITE_INPUT_FIELDS: &[&str] = &[
    "arguments",
    "args",
    "input",
    "tool_input",
    "toolInput",
    "tool_arguments",
    "toolArguments",
];
const WRITE_PATH_FIELDS: &[&str] = &[
    "file_path",
    "filePath",
    "filepath",
    "path",
    "filename",
    "fileName",
];
const READ_PATH_LIST_FIELDS: &[&str] = &[
    "paths",
    "file_paths",
    "filePaths",
    "filenames",
    "fileNames",
    "files",
];
const WRITE_CONTENT_FIELDS: &[&str] = &[
    "content",
    "file_content",
    "fileContent",
    "text",
    "data",
    "body",
];
const EDIT_OLD_FIELDS: &[&str] = &["old_string", "oldString", "old_text", "oldText"];
const EDIT_NEW_FIELDS: &[&str] = &["new_string", "newString", "new_text", "newText"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InputFormat {
    Text,
    Image,
}

struct ReadOpts {
    input_format: InputFormat,
    kind: Option<Kind>,
    emit_meta: bool,
    path: PathBuf,
}

impl ReadOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut input_format = InputFormat::Text;
        let mut kind = None;
        let mut emit_meta = false;
        let mut path = None;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--input" => {
                    input_format = parse_input_format(&value(args, &mut i, "--input")?)?;
                }
                "--kind" => {
                    kind = Some(parse_kind(&value(args, &mut i, "--kind")?)?);
                }
                "--meta" => {
                    emit_meta = true;
                    i += 1;
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                p => {
                    if path.is_some() {
                        return Err("read accepts exactly one PATH".to_string());
                    }
                    path = Some(PathBuf::from(p));
                    i += 1;
                }
            }
        }
        Ok(Self {
            input_format,
            kind,
            emit_meta,
            path: path.ok_or_else(|| "read requires PATH".to_string())?,
        })
    }
}

struct PurgeOpts {
    session: String,
}

impl PurgeOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let (session, rest) = parse_session_and_rest(args, 2)?;
        if !rest.is_empty() {
            return Err("purge accepts no positional args".to_string());
        }
        Ok(Self { session })
    }
}

struct HookOpts {
    provider: HookProvider,
    session: Option<String>,
    cli: bool,
}

impl HookOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut provider = None;
        let mut session = None;
        let mut cli = false;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--cli" => {
                    cli = true;
                    i += 1;
                }
                "--session" => {
                    session = Some(
                        checked_session_name(&value(args, &mut i, "--session")?)
                            .map_err(|e| e.to_string())?,
                    );
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                value if provider.is_none() => {
                    provider = Some(parse_hook_provider(value)?);
                    i += 1;
                }
                _ => return Err("hook accepts exactly one provider".to_string()),
            }
        }
        Ok(Self {
            provider: provider.ok_or_else(|| {
                "hook requires a provider after --cli: codex or generic".to_string()
            })?,
            session,
            cli,
        })
    }

    fn session_name(&self, input: &Value) -> Result<String, String> {
        if let Some(session) = &self.session {
            return Ok(session.clone());
        }
        let _ = input;
        default_session_name()
    }
}

struct ExecOpts {
    session: String,
    live: bool,
    allow_secret_argv: bool,
    secret_stdin: Option<String>,
    script_shell: ScriptShell,
    mode: ExecMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScriptShell {
    Native,
    Bash,
    PowerShell,
}

impl ScriptShell {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "native" => Ok(Self::Native),
            "bash" => Ok(Self::Bash),
            "powershell" => Ok(Self::PowerShell),
            _ => Err("exec --script-shell requires native, bash, or powershell".to_string()),
        }
    }
}

enum ExecMode {
    Program(Vec<String>),
    Shell(String),
    Stdin,
}

struct ResolveOpts {
    session: String,
    mode: ResolveMode,
}

struct AgentStreamOpts {
    session: String,
    target: StreamTarget,
    end_marker: Option<String>,
}

enum ResolveMode {
    Files(Vec<PathBuf>),
    Stdin,
}

impl AgentStreamOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut session = default_session_name()?;
        let mut target = StreamTarget::Stdout;
        let mut end_marker = None;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--session" => {
                    session = checked_session_name(&value(args, &mut i, "--session")?)
                        .map_err(|error| error.to_string())?;
                }
                "--stderr" => {
                    target = StreamTarget::Stderr;
                    i += 1;
                }
                "--end-marker" => {
                    let marker = value(args, &mut i, "--end-marker")?;
                    if marker.len() < 32
                        || marker.len() > 128
                        || !marker
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    {
                        return Err("agent stream end marker is invalid".to_string());
                    }
                    end_marker = Some(marker);
                }
                flag => return Err(format!("unknown option: {flag}")),
            }
        }
        Ok(Self {
            session,
            target,
            end_marker,
        })
    }
}

impl ResolveOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut session = default_session_name()?;
        let mut paths = Vec::new();
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--session" => {
                    session = checked_session_name(&value(args, &mut i, "--session")?)
                        .map_err(|e| e.to_string())?;
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                path => {
                    paths.push(PathBuf::from(path));
                    i += 1;
                }
            }
        }
        Ok(Self {
            session,
            mode: if paths.is_empty() {
                ResolveMode::Stdin
            } else {
                ResolveMode::Files(paths)
            },
        })
    }
}

impl ExecOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut session = default_session_name()?;
        let mut live = false;
        let mut allow_secret_argv = false;
        let mut secret_stdin = None;
        let mut stdin = false;
        let mut script_shell = ScriptShell::Native;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--session" => {
                    session = value(args, &mut i, "--session")?;
                }
                "--live" => {
                    live = true;
                    i += 1;
                }
                "--allow-secret-argv" => {
                    allow_secret_argv = true;
                    i += 1;
                }
                "--secret-stdin" => {
                    let handle = value(args, &mut i, "--secret-stdin")?;
                    parse_placeholder(&handle).map_err(|_| {
                        "exec --secret-stdin requires exactly one masked handle".to_string()
                    })?;
                    secret_stdin = Some(handle);
                }
                "--stdin" => {
                    stdin = true;
                    i += 1;
                }
                "--script-shell" => {
                    script_shell = ScriptShell::parse(&value(args, &mut i, "--script-shell")?)?;
                }
                "--script-b64" => {
                    if stdin {
                        return Err(
                            "exec --stdin does not accept a base64 script argument".to_string()
                        );
                    }
                    if secret_stdin.is_some() {
                        return Err(
                            "exec --script-b64 cannot be combined with --secret-stdin".to_string()
                        );
                    }
                    let script = decode_script_base64(&value(args, &mut i, "--script-b64")?)?;
                    if i < args.len() {
                        return Err(
                            "exec --script-b64 does not accept trailing arguments".to_string()
                        );
                    }
                    return Ok(Self {
                        session: checked_session_name(&session).map_err(|e| e.to_string())?,
                        live,
                        allow_secret_argv,
                        secret_stdin: None,
                        script_shell,
                        mode: ExecMode::Shell(script),
                    });
                }
                "--shell" => {
                    return Err(
                        "`--shell` was removed; use `pentect exec \"<command>\"`".to_string()
                    );
                }
                "--" => {
                    if stdin {
                        return Err("exec --stdin does not accept a program command".to_string());
                    }
                    let command = args[i + 1..].to_vec();
                    if command.is_empty() {
                        return Err("exec requires a command after `--`".to_string());
                    }
                    return Ok(Self {
                        session: checked_session_name(&session).map_err(|e| e.to_string())?,
                        live,
                        allow_secret_argv,
                        secret_stdin,
                        script_shell: ScriptShell::Native,
                        mode: ExecMode::Program(command),
                    });
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                _ => {
                    if stdin {
                        return Err("exec --stdin does not accept a command argument".to_string());
                    }
                    if secret_stdin.is_some() {
                        return Err("exec --secret-stdin requires a program after `--`".to_string());
                    }
                    return Ok(Self {
                        session: checked_session_name(&session).map_err(|e| e.to_string())?,
                        live,
                        allow_secret_argv,
                        secret_stdin: None,
                        script_shell,
                        mode: ExecMode::Shell(args[i..].join(" ")),
                    });
                }
            }
        }
        if stdin {
            if secret_stdin.is_some() {
                return Err("exec --stdin cannot be combined with --secret-stdin".to_string());
            }
            return Ok(Self {
                session: checked_session_name(&session).map_err(|e| e.to_string())?,
                live,
                allow_secret_argv,
                secret_stdin: None,
                script_shell,
                mode: ExecMode::Stdin,
            });
        }
        Err("exec requires COMMAND, `--stdin`, or `-- PROGRAM...`".to_string())
    }
}

fn prepare_stdin_exec_opts(mut opts: ExecOpts) -> Result<ExecOpts, String> {
    if matches!(opts.mode, ExecMode::Stdin) {
        opts.mode = ExecMode::Shell(read_stdin_text()?);
    }
    Ok(opts)
}

fn decode_script_base64(value: &str) -> Result<String, String> {
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| "exec --script-b64 requires valid base64".to_string())?;
    String::from_utf8(bytes).map_err(|_| "exec --script-b64 requires UTF-8 text".to_string())
}

fn default_session_name() -> Result<String, String> {
    default_directory_session_name()
}

fn default_directory_session_name() -> Result<String, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("could not read current dir: {e}"))?;
    directory_session_name_for(&cwd)
}

fn directory_session_name_for(path: &Path) -> Result<String, String> {
    let identity = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let normalized = identity
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let digest = Sha256::digest(normalized.as_bytes());
    Ok(format!(
        "dir_{}",
        data_encoding::HEXLOWER.encode(&digest[..8])
    ))
}

#[cfg(test)]
fn handle_hook(
    provider: HookProvider,
    session_name: &str,
    session: &Session,
    input: Value,
) -> Result<Value, String> {
    handle_hook_with_launch_requirement(provider, session_name, session, input, false)
}

#[cfg(test)]
fn handle_hook_with_launch_requirement(
    provider: HookProvider,
    session_name: &str,
    session: &Session,
    input: Value,
    require_pentect_launch: bool,
) -> Result<Value, String> {
    match hook_phase(provider, &input) {
        HookPhase::BeforeTool => {
            if let Err(reason) =
                ensure_pentect_agent_launch_required(provider, require_pentect_launch)
            {
                return Ok(before_tool_block_output(provider, &reason));
            }
            let Some(tool_input) = hook_tool_input(&input) else {
                return Ok(json!({}));
            };
            let tool_name = hook_tool_name(&input)
                .and_then(Value::as_str)
                .unwrap_or_default();
            let (updated, changed) = match before_tool_updated_input(
                provider,
                session_name,
                session,
                tool_name,
                tool_input,
            ) {
                Ok(result) => result,
                Err(reason) => return Ok(before_tool_block_output(provider, &reason)),
            };
            if changed {
                Ok(before_tool_output(provider, updated))
            } else {
                Ok(json!({}))
            }
        }
        HookPhase::AfterTool => {
            if let Err(reason) =
                ensure_pentect_agent_launch_required(provider, require_pentect_launch)
            {
                return Ok(after_tool_block_output(provider, &reason));
            }
            let tool_name = hook_tool_name(&input)
                .and_then(Value::as_str)
                .unwrap_or_default();
            if let Some(tool_input) = hook_tool_input(&input) {
                if let Err(reason) = repair_masked_write_after_tool(session, tool_name, tool_input)
                {
                    return Ok(after_tool_block_output(provider, &reason));
                }
            }
            let Some(tool_response) = hook_tool_result(&input) else {
                return Ok(json!({}));
            };
            match mask_tool_text_output(provider, session, tool_response)? {
                ToolTextOutput::Unchanged => Ok(json!({})),
                ToolTextOutput::Updated(updated) => Ok(after_tool_output(provider, updated)),
                ToolTextOutput::Block(reason) => Ok(after_tool_block_output(provider, &reason)),
            }
        }
        HookPhase::Other => Ok(json!({})),
    }
}

fn handle_hook_lazy(
    provider: HookProvider,
    session_name: &str,
    cli: bool,
    input: Value,
) -> Result<Value, String> {
    match hook_phase(provider, &input) {
        HookPhase::BeforeTool => {
            if let Err(reason) = ensure_pentect_agent_launch(provider) {
                return Ok(before_tool_block_output(provider, &reason));
            }
            let Some(tool_input) = hook_tool_input(&input) else {
                return Ok(json!({}));
            };
            let tool_name = hook_tool_name(&input)
                .and_then(Value::as_str)
                .unwrap_or_default();
            let (updated, changed) = match before_tool_updated_input_lazy(
                provider,
                session_name,
                cli,
                tool_name,
                tool_input,
            ) {
                Ok(result) => result,
                Err(reason) => return Ok(before_tool_block_output(provider, &reason)),
            };
            if changed {
                Ok(before_tool_output(provider, updated))
            } else {
                Ok(json!({}))
            }
        }
        HookPhase::AfterTool => {
            if let Err(reason) = ensure_pentect_agent_launch(provider) {
                return Ok(after_tool_block_output(provider, &reason));
            }
            let session = open_hook_session(cli, session_name)?;
            let tool_name = hook_tool_name(&input)
                .and_then(Value::as_str)
                .unwrap_or_default();
            if let Some(tool_input) = hook_tool_input(&input) {
                if let Err(reason) = repair_masked_write_after_tool(&session, tool_name, tool_input)
                {
                    return Ok(after_tool_block_output(provider, &reason));
                }
            }
            let Some(tool_response) = hook_tool_result(&input) else {
                return Ok(json!({}));
            };
            match mask_tool_text_output(provider, &session, tool_response)? {
                ToolTextOutput::Unchanged => Ok(json!({})),
                ToolTextOutput::Updated(updated) => Ok(after_tool_output(provider, updated)),
                ToolTextOutput::Block(reason) => Ok(after_tool_block_output(provider, &reason)),
            }
        }
        HookPhase::Other => Ok(json!({})),
    }
}

fn before_tool_updated_input(
    _provider: HookProvider,
    _session_name: &str,
    session: &Session,
    tool_name: &str,
    tool_input: &Value,
) -> Result<(Value, bool), String> {
    let mut updated = tool_input.clone();
    if is_read_like_tool_name(tool_name) {
        if let Some(updated) = apply_masked_read_before_tool(session, tool_input)? {
            return Ok((updated, true));
        }
    }
    validate_masked_write_before_tool(session, tool_name, tool_input)?;
    if is_shell_tool_name(tool_name) {
        if let Some(command) = updated.get("command").and_then(Value::as_str) {
            if let Some(reason) = pentect_human_only_command_reason(command) {
                return Err(reason);
            }
            let command = canonical_hook_shell_command(command)?;
            if let Some(object) = updated.as_object_mut() {
                object.insert("command".to_string(), Value::String(command));
            }
        }
    }
    resolve_known_value(&MemoryStore::for_session(session), &mut updated)?;
    let changed = updated != *tool_input;
    Ok((updated, changed))
}

fn before_tool_updated_input_lazy(
    _provider: HookProvider,
    session_name: &str,
    cli: bool,
    tool_name: &str,
    tool_input: &Value,
) -> Result<(Value, bool), String> {
    let mut updated = tool_input.clone();
    let read_like = is_read_like_tool_name(tool_name);
    let write_like = is_write_or_edit_like_tool_name(tool_name);
    let has_handle = value_contains_pentect_masked_handle(tool_input);
    let session = if read_like || write_like || has_handle {
        Some(open_hook_session(cli, session_name)?)
    } else {
        None
    };
    if read_like {
        let session = session.as_ref().expect("read tools open a session");
        if let Some(updated) = apply_masked_read_before_tool(session, tool_input)? {
            return Ok((updated, true));
        }
    }
    if write_like {
        let session = session.as_ref().expect("write tools open a session");
        validate_masked_write_before_tool(session, tool_name, tool_input)?;
    }
    if is_shell_tool_name(tool_name) {
        if let Some(command) = updated.get("command").and_then(Value::as_str) {
            if let Some(reason) = pentect_human_only_command_reason(command) {
                return Err(reason);
            }
            let command = canonical_hook_shell_command(command)?;
            if let Some(object) = updated.as_object_mut() {
                object.insert("command".to_string(), Value::String(command));
            }
        }
    }
    if has_handle {
        let session = session.as_ref().expect("handle inputs open a session");
        resolve_known_value(&MemoryStore::for_session(session), &mut updated)?;
    }
    let changed = updated != *tool_input;
    Ok((updated, changed))
}

fn value_contains_pentect_masked_handle(value: &Value) -> bool {
    match value {
        Value::String(text) => contains_pentect_masked_handle(text),
        Value::Array(values) => values.iter().any(value_contains_pentect_masked_handle),
        Value::Object(object) => object.values().any(value_contains_pentect_masked_handle),
        _ => false,
    }
}

fn resolve_known_value(store: &MemoryStore, value: &mut Value) -> Result<(), String> {
    match value {
        Value::String(text) => {
            *text = store.resolve_all(text).map_err(|error| error.to_string())?;
        }
        Value::Array(values) => {
            for value in values {
                resolve_known_value(store, value)?;
            }
        }
        Value::Object(object) => {
            for value in object.values_mut() {
                resolve_known_value(store, value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn ensure_pentect_agent_launch(provider: HookProvider) -> Result<(), String> {
    ensure_pentect_agent_launch_required(provider, config::require_pentect_agent_by_config()?)
}

fn is_shell_tool_name(tool_name: &str) -> bool {
    matches!(
        tool_name.to_ascii_lowercase().as_str(),
        "bash" | "powershell" | "powershell_command" | "shell" | "exec" | "run_command"
    )
}

fn ensure_pentect_agent_launch_required(
    provider: HookProvider,
    required: bool,
) -> Result<(), String> {
    if !required {
        return Ok(());
    }
    if agent_launch_proof_valid() {
        return Ok(());
    }
    Err(provider.launch_error().to_string())
}

fn agent_launch_proof_valid() -> bool {
    let Ok(proof) = std::env::var(PENTECT_AGENT_LAUNCHED_ENV) else {
        return false;
    };
    let Ok(token) = std::env::var(ENV_TOKEN) else {
        return false;
    };
    agent_launch_proof_matches(&proof, &token)
        && memory_store_env_addr_is_loopback()
        && memory_store_accepts_env_token()
}

fn agent_launch_proof_matches(proof: &str, token: &str) -> bool {
    token.len() >= 32 && proof == token
}

fn memory_store_env_addr_is_loopback() -> bool {
    std::env::var(ENV_ADDR)
        .ok()
        .and_then(|addr| addr.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|addr| addr.ip().is_loopback())
}

fn memory_store_accepts_env_token() -> bool {
    MemoryStoreClient::from_env().is_some_and(|client| client.key().is_ok())
}

fn canonical_hook_shell_command(command: &str) -> Result<String, String> {
    let mut command = command.to_string();
    loop {
        if let Some(reason) = pentect_human_only_command_reason(&command) {
            return Err(reason);
        }
        let Some(payload) = extract_pentect_exec_shell_payload(&command) else {
            return Ok(command);
        };
        command = payload;
    }
}

fn apply_masked_read_before_tool(
    session: &Session,
    tool_input: &Value,
) -> Result<Option<Value>, String> {
    let mut replacements = BTreeMap::new();
    for path in read_tool_paths(tool_input) {
        if replacements.contains_key(path) {
            continue;
        }
        let Some(masked_path) = masked_read_copy(session, path)? else {
            continue;
        };
        replacements.insert(path.to_string(), masked_path.to_string_lossy().into_owned());
    }
    if replacements.is_empty() {
        return Ok(None);
    }
    let mut updated = tool_input.clone();
    if rewrite_read_paths(&mut updated, &replacements) {
        Ok(Some(updated))
    } else {
        Err("Read input was not recognized.".to_string())
    }
}

fn masked_read_copy(session: &Session, path_text: &str) -> Result<Option<PathBuf>, String> {
    let path = Path::new(path_text);
    let data = read_input(path, InputFormat::Text)
        .map_err(|_| "read target could not be scanned.".to_string())?;
    let result = mask_read_data(
        session.key,
        session.identity_key,
        data.clone(),
        infer_kind_with_content(path, &data),
    )?;
    if result.summary.masked_count == 0 {
        return Ok(None);
    }
    activity_log::record_mask_result("read", &result, Some(path));
    let mut recovery = result.recovery.clone();
    let prefix = config::environment_variable_prefix()?;
    recovery.extend_same_key(env_alias_recovery(&result.masked, &session.key, &prefix));
    MemoryStore::for_session(session)
        .add_recovery(recovery)
        .map_err(|e| e.to_string())?;
    file_pointer_manager::register_file_pointers(path, &data, &result);

    let masked_path = masked_read_copy_path(path);
    if let Some(parent) = masked_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create '{}': {e}", parent.display()))?;
    }
    std::fs::write(&masked_path, result.masked)
        .map_err(|e| format!("could not write '{}': {e}", masked_path.display()))?;
    Ok(Some(masked_path))
}

fn masked_read_copy_path(original: &Path) -> PathBuf {
    let root = config::project_root().unwrap_or_else(|_| {
        std::env::current_dir()
            .ok()
            .and_then(|cwd| cwd.canonicalize().ok().or(Some(cwd)))
            .unwrap_or_else(|| PathBuf::from("."))
    });
    let display_path = masked_read_display_path(original, &root);
    root.join(".pentect").join("read").join(display_path)
}

fn masked_read_display_path(original: &Path, project_root: &Path) -> PathBuf {
    let absolute = if original.is_absolute() {
        original.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| project_root.to_path_buf())
            .join(original)
    };
    let normalized = absolute.canonicalize().unwrap_or(absolute);
    if let Ok(relative) = normalized.strip_prefix(project_root) {
        return safe_masked_read_path(relative);
    }
    PathBuf::from("_external")
        .join(masked_read_path_hash(&normalized))
        .join(
            normalized
                .file_name()
                .and_then(|name| name.to_str())
                .map(safe_masked_read_component)
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "file.txt".to_string()),
        )
}

fn masked_read_path_hash(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.as_os_str().to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    data_encoding::HEXLOWER.encode(&digest[..6])
}

fn safe_masked_read_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    let mut has_component = false;
    for component in path.components() {
        match component {
            std::path::Component::Normal(value) => {
                let value = safe_masked_read_component(&value.to_string_lossy());
                if !value.is_empty() {
                    out.push(value);
                    has_component = true;
                }
            }
            std::path::Component::ParentDir => {
                out.push("_up");
                has_component = true;
            }
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                out.push("_external");
                has_component = true;
            }
            std::path::Component::CurDir => {}
        }
    }
    if has_component {
        return out;
    }
    PathBuf::from("file.txt")
}

fn safe_masked_read_component(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars().take(80) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

fn rewrite_read_paths(value: &mut Value, replacements: &BTreeMap<String, String>) -> bool {
    let Some(object) = value.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    for field in WRITE_PATH_FIELDS {
        if let Some(path) = object
            .get(*field)
            .and_then(Value::as_str)
            .map(str::to_string)
        {
            if let Some(replacement) = replacements.get(&path) {
                object.insert((*field).to_string(), Value::String(replacement.clone()));
                changed = true;
            }
        }
    }
    for field in READ_PATH_LIST_FIELDS {
        if let Some(paths) = object.get_mut(*field).and_then(Value::as_array_mut) {
            for path in paths {
                let Some(path_text) = path.as_str().map(str::to_string) else {
                    continue;
                };
                if let Some(replacement) = replacements.get(&path_text) {
                    *path = Value::String(replacement.clone());
                    changed = true;
                }
            }
        }
    }
    for field in WRITE_INPUT_FIELDS {
        if let Some(child) = object.get_mut(*field) {
            changed |= rewrite_read_paths(child, replacements);
        }
    }
    changed
}

fn validate_masked_write_before_tool(
    session: &Session,
    tool_name: &str,
    tool_input: &Value,
) -> Result<(), String> {
    if is_write_like_tool_name(tool_name) {
        let Some((path, content)) = write_path_and_content(tool_input) else {
            return Ok(());
        };
        let masked_path = contains_pentect_masked_handle(path);
        let masked_content = contains_pentect_masked_handle(content);
        if !masked_path && !masked_content {
            return Ok(());
        }
        let store = MemoryStore::for_session(session);
        let path = resolved_local_write_path(&store, path, masked_path)?;
        if masked_content {
            let _ = resolve_masked_text(&store, content)?;
        }
        ensure_local_write_path_within_cwd(&path)?;
        return Ok(());
    }
    if is_edit_like_tool_name(tool_name) {
        validate_masked_edit_before_tool(session, tool_input)?;
    }
    Ok(())
}

fn repair_masked_write_after_tool(
    session: &Session,
    tool_name: &str,
    tool_input: &Value,
) -> Result<bool, String> {
    if is_write_like_tool_name(tool_name) {
        let Some((path, content)) = write_path_and_content(tool_input) else {
            return Ok(false);
        };
        if !contains_pentect_masked_handle(content) {
            return Ok(false);
        }
        let (path, resolved) = resolved_write_parts(session, path, content)?;
        ensure_local_write_path_within_cwd(&path)?;
        if !path.is_file() {
            return Ok(false);
        }
        let current = std::fs::read_to_string(&path)
            .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
        if current != content {
            return Ok(false);
        }
        std::fs::write(&path, resolved)
            .map_err(|e| format!("could not repair '{}': {e}", path.display()))?;
        return Ok(true);
    }
    if is_edit_like_tool_name(tool_name) {
        return repair_masked_edit_after_tool(session, tool_input);
    }
    Ok(false)
}

fn resolved_write_parts(
    session: &Session,
    path: &str,
    content: &str,
) -> Result<(PathBuf, String), String> {
    let store = MemoryStore::for_session(session);
    let resolved = resolve_masked_text(&store, content)?;
    let path = resolved_local_write_path(&store, path, contains_pentect_masked_handle(path))?;
    Ok((path, resolved))
}

fn resolved_local_write_path(
    store: &MemoryStore,
    path: &str,
    contains_handle: bool,
) -> Result<PathBuf, String> {
    let resolved = if contains_handle {
        resolve_masked_text(store, path)?
    } else {
        path.to_string()
    };
    checked_local_write_path(&resolved)
}

fn validate_masked_edit_before_tool(session: &Session, tool_input: &Value) -> Result<(), String> {
    let Some((path, edits)) = edit_path_and_texts(tool_input) else {
        return Ok(());
    };
    let masked_path = contains_pentect_masked_handle(path);
    if !masked_path
        && !edits
            .iter()
            .any(|(_, text)| contains_pentect_masked_handle(text))
    {
        return Ok(());
    }
    let store = MemoryStore::for_session(session);
    let path = resolved_local_write_path(&store, path, masked_path)?;
    ensure_local_write_path_within_cwd(&path)?;
    for (kind, text) in edits {
        if matches!(kind, EditTextKind::New) && contains_pentect_masked_handle(text) {
            let _ = resolve_masked_text(&store, text)?;
        }
    }
    Ok(())
}

fn repair_masked_edit_after_tool(session: &Session, tool_input: &Value) -> Result<bool, String> {
    let Some((path, edits)) = edit_path_and_texts(tool_input) else {
        return Ok(false);
    };
    if !edits.iter().any(|(kind, text)| {
        matches!(kind, EditTextKind::New) && contains_pentect_masked_handle(text)
    }) {
        return Ok(false);
    }
    let store = MemoryStore::for_session(session);
    let path = resolved_local_write_path(&store, path, contains_pentect_masked_handle(path))?;
    ensure_local_write_path_within_cwd(&path)?;
    if !path.is_file() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if !contains_pentect_masked_handle(&content) {
        return Ok(false);
    }
    let resolved = resolve_masked_text(&store, &content)?;
    if resolved != content {
        std::fs::write(&path, resolved)
            .map_err(|e| format!("could not repair '{}': {e}", path.display()))?;
    }
    Ok(true)
}

fn resolve_masked_text(store: &MemoryStore, content: &str) -> Result<String, String> {
    let resolved = store.resolve_all(content).map_err(|e| e.to_string())?;
    if contains_pentect_masked_handle(&resolved) {
        return Err(
            "masked handle is unavailable in this running Pentect session; re-read the source and retry."
                .to_string(),
        );
    }
    if resolved == content {
        return Err("masked handle is unavailable in this running Pentect session.".to_string());
    }
    Ok(resolved)
}

pub fn contains_pentect_masked_handle(text: &str) -> bool {
    let mut offset = 0usize;
    while let Some(start_rel) = text[offset..].find("<<") {
        let start = offset + start_rel;
        let Some(end_rel) = text[start + 2..].find(">>") else {
            return false;
        };
        let end = start + 2 + end_rel + 2;
        if parse_placeholder(&text[start..end]).is_ok() {
            return true;
        }
        offset = end;
    }
    false
}

fn is_write_like_tool_name(tool_name: &str) -> bool {
    let normalized = tool_name.to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "write" | "writefile" | "write_file" | "create_file"
    ) || normalized.ends_with("__write_file")
        || normalized.ends_with("_write_file")
}

fn is_edit_like_tool_name(tool_name: &str) -> bool {
    let normalized = tool_name.to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "edit" | "edit_file" | "multiedit" | "multi_edit" | "multi_edit_file"
    ) || normalized.ends_with("__edit_file")
        || normalized.ends_with("_edit_file")
        || normalized.ends_with("__multi_edit_file")
        || normalized.ends_with("_multi_edit_file")
}

fn is_write_or_edit_like_tool_name(tool_name: &str) -> bool {
    is_write_like_tool_name(tool_name) || is_edit_like_tool_name(tool_name)
}

fn write_path_and_content(value: &Value) -> Option<(&str, &str)> {
    for candidate in write_input_candidates(value) {
        if let (Some(path), Some(content)) = (
            string_field(candidate, WRITE_PATH_FIELDS),
            string_field(candidate, WRITE_CONTENT_FIELDS),
        ) {
            return Some((path, content));
        }
    }
    None
}

fn read_tool_paths(value: &Value) -> Vec<&str> {
    let mut paths = Vec::new();
    for candidate in write_input_candidates(value) {
        if let Some(path) = string_field(candidate, WRITE_PATH_FIELDS) {
            paths.push(path);
        }
        for field in READ_PATH_LIST_FIELDS {
            if let Some(items) = candidate.get(*field).and_then(Value::as_array) {
                paths.extend(items.iter().filter_map(Value::as_str));
            }
        }
    }
    paths
}

fn write_input_candidates(value: &Value) -> Vec<&Value> {
    let mut out = vec![value];
    for key in WRITE_INPUT_FIELDS {
        if let Some(candidate) = value.get(key) {
            out.push(candidate);
        }
    }
    out
}

#[derive(Clone, Copy)]
enum EditTextKind {
    Old,
    New,
}

fn edit_path_and_texts(value: &Value) -> Option<(&str, Vec<(EditTextKind, &str)>)> {
    for candidate in write_input_candidates(value) {
        let Some(path) = string_field(candidate, WRITE_PATH_FIELDS) else {
            continue;
        };
        let mut texts = Vec::new();
        push_edit_texts(candidate, &mut texts);
        if !texts.is_empty() {
            return Some((path, texts));
        }
    }
    None
}

fn push_edit_texts<'a>(value: &'a Value, out: &mut Vec<(EditTextKind, &'a str)>) {
    for field in EDIT_OLD_FIELDS {
        if let Some(text) = value.get(*field).and_then(Value::as_str) {
            out.push((EditTextKind::Old, text));
        }
    }
    for field in EDIT_NEW_FIELDS {
        if let Some(text) = value.get(*field).and_then(Value::as_str) {
            out.push((EditTextKind::New, text));
        }
    }
    if let Some(edits) = value.get("edits").and_then(Value::as_array) {
        for edit in edits {
            push_edit_texts(edit, out);
        }
    }
}

fn string_field<'a>(value: &'a Value, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| value.get(*name)?.as_str())
}

fn checked_local_write_path(path: &str) -> Result<PathBuf, String> {
    let path = Path::new(path);
    let mut has_normal_component = false;
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(_) => has_normal_component = true,
            std::path::Component::ParentDir => {
                return Err(
                    "Pentect refused to write masked content outside the current directory"
                        .to_string(),
                );
            }
            std::path::Component::RootDir => {}
            std::path::Component::Prefix(_) if path.is_absolute() => {}
            std::path::Component::Prefix(_) => {
                return Err(
                    "Pentect refused to write masked content outside the current directory"
                        .to_string(),
                );
            }
        }
    }
    if !has_normal_component {
        return Err("Pentect refused to write masked content to an empty path".to_string());
    }
    Ok(path.to_path_buf())
}

fn ensure_local_write_path_within_cwd(path: &Path) -> Result<(), String> {
    let cwd = std::env::current_dir()
        .map_err(|e| format!("could not read current directory: {e}"))?
        .canonicalize()
        .map_err(|e| format!("could not canonicalize current directory: {e}"))?;
    let mut parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    while !parent.exists() {
        let Some(next) = parent.parent() else {
            parent = PathBuf::from(".");
            break;
        };
        if next.as_os_str().is_empty() {
            parent = PathBuf::from(".");
            break;
        }
        parent = next.to_path_buf();
    }
    let parent = parent
        .canonicalize()
        .map_err(|e| format!("could not canonicalize '{}': {e}", parent.display()))?;
    if !parent.starts_with(&cwd) {
        return Err(
            "Pentect refused to write masked content outside the current directory".to_string(),
        );
    }
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err("Pentect refused to write masked content through a symlink".to_string());
    }
    Ok(())
}

fn is_read_like_tool_name(tool_name: &str) -> bool {
    let normalized = tool_name.to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "read"
            | "read_file"
            | "readmanyfiles"
            | "read_many_files"
            | "multiread"
            | "notebookread"
            | "notebook_read"
    ) || normalized.ends_with("__read_file")
        || normalized.ends_with("_read_file")
        || normalized.ends_with("__read_many_files")
        || normalized.ends_with("_read_many_files")
}

fn extract_pentect_exec_shell_payload(command: &str) -> Option<String> {
    let PentectInvocation { subcommand, rest } = parse_pentect_subcommand(command)?;
    if subcommand != PentectSubcommand::Exec {
        return None;
    }
    let mut rest = rest.trim_start();
    loop {
        let (word, _, word_end) = next_shell_word(rest, 0)?;
        match word.as_str() {
            "--session" => {
                let (_, _, value_end) = next_shell_word(rest, word_end)?;
                rest = rest[value_end..].trim_start();
            }
            "--live" => {
                rest = rest[word_end..].trim_start();
            }
            "--script-shell" => {
                let (value, _, value_end) = next_shell_word(rest, word_end)?;
                ScriptShell::parse(&value).ok()?;
                rest = rest[value_end..].trim_start();
            }
            "--stdin" => return None,
            "--script-b64" => {
                let (payload, _, payload_end) = next_shell_word(rest, word_end)?;
                if !rest[payload_end..].trim().is_empty() {
                    return None;
                }
                return decode_script_base64(&payload).ok();
            }
            "--shell" => {
                return Some(unquote_wrapped_shell_arg(rest[word_end..].trim_start()));
            }
            "--" => {
                let payload = rest[word_end..].trim_start();
                if payload.is_empty() {
                    return None;
                }
                return Some(unquote_wrapped_shell_arg(payload));
            }
            _ => return Some(unquote_wrapped_shell_arg(rest)),
        }
    }
}

pub fn display_command_without_pentect_exec_wrapper(command: &str) -> Option<String> {
    extract_pentect_exec_shell_payload(command)
}

fn pentect_human_only_command_reason(command: &str) -> Option<String> {
    let invocation = parse_pentect_subcommand(command)?;
    match invocation.subcommand {
        PentectSubcommand::Exec | PentectSubcommand::Read | PentectSubcommand::Resolve => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PentectSubcommand {
    Exec,
    Read,
    Resolve,
}

struct PentectInvocation<'a> {
    subcommand: PentectSubcommand,
    rest: &'a str,
}

fn parse_pentect_subcommand(command: &str) -> Option<PentectInvocation<'_>> {
    let mut cursor = 0usize;
    let (first, _, first_end) = next_shell_word(command, cursor)?;
    cursor = first_end;
    let first = if first == "&" {
        let (word, _, end) = next_shell_word(command, cursor)?;
        cursor = end;
        word
    } else {
        first
    };
    if !is_pentect_command(&first) {
        return None;
    }
    let (mut subcommand, _, mut end) = next_shell_word(command, cursor)?;
    if subcommand.eq_ignore_ascii_case("agent") {
        let (word, _, word_end) = next_shell_word(command, end)?;
        subcommand = word;
        end = word_end;
    }
    let subcommand = match subcommand.to_ascii_lowercase().as_str() {
        "exec" => PentectSubcommand::Exec,
        "read" => PentectSubcommand::Read,
        "resolve" => PentectSubcommand::Resolve,
        _ => return None,
    };
    Some(PentectInvocation {
        subcommand,
        rest: &command[end..],
    })
}

fn is_pentect_command(command: &str) -> bool {
    let normalized = command.replace('\\', "/");
    let command = normalized.trim_start_matches("./");
    let command = command.to_ascii_lowercase();
    command == "pentect"
        || command == "pentect.exe"
        || command.ends_with("/pentect")
        || command.ends_with("/pentect.exe")
}

fn unquote_wrapped_shell_arg(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'' {
            return value[1..value.len() - 1].replace("''", "'");
        }
        if bytes[0] == b'"' && bytes[value.len() - 1] == b'"' {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

fn hook_phase(provider: HookProvider, input: &Value) -> HookPhase {
    let event = hook_event_name(input).unwrap_or_default();
    match provider {
        HookProvider::Codex | HookProvider::Claude | HookProvider::Generic => match event {
            "PreToolUse" => HookPhase::BeforeTool,
            "PostToolUse" => HookPhase::AfterTool,
            _ => HookPhase::Other,
        },
    }
}

fn hook_event_name(input: &Value) -> Option<&str> {
    hook_field(input, HOOK_EVENT_FIELDS).and_then(Value::as_str)
}

fn hook_field<'a>(input: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| input.get(*name))
}

fn hook_tool_name(input: &Value) -> Option<&Value> {
    hook_field(input, HOOK_TOOL_NAME_FIELDS)
}

fn hook_tool_input(input: &Value) -> Option<&Value> {
    hook_field(input, HOOK_TOOL_INPUT_FIELDS)
}

fn hook_tool_result(input: &Value) -> Option<&Value> {
    hook_field(input, HOOK_TOOL_RESULT_FIELDS)
}

fn before_tool_output(provider: HookProvider, updated_input: Value) -> Value {
    match provider {
        HookProvider::Codex | HookProvider::Claude | HookProvider::Generic => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": updated_input
            }
        }),
    }
}

fn before_tool_block_output(provider: HookProvider, reason: &str) -> Value {
    match provider {
        HookProvider::Codex | HookProvider::Claude | HookProvider::Generic => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason
            }
        }),
    }
}

fn after_tool_output(provider: HookProvider, updated_output: Value) -> Value {
    match provider {
        HookProvider::Claude | HookProvider::Generic => json!({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": updated_output
            }
        }),
        HookProvider::Codex => json!({
            "decision": "block",
            "reason": format!(
                "Tool completed. Protected output:\n{}",
                stringify_tool_output(&updated_output)
            )
        }),
    }
}

fn after_tool_block_output(_provider: HookProvider, reason: &str) -> Value {
    json!({
        "decision": "block",
        "reason": format!(
            "Tool completed, but its output was unavailable. Check side effects before retrying.\n{reason}"
        )
    })
}

fn mask_tool_text_output(
    provider: HookProvider,
    session: &Session,
    tool_response: &Value,
) -> Result<ToolTextOutput, String> {
    let mut output = tool_response.clone();
    let mut image_changed = false;
    if provider == HookProvider::Claude {
        match claude_image_tool_output(session, tool_response)? {
            Some(ToolTextOutput::Updated(updated)) => {
                output = updated;
                image_changed = true;
            }
            Some(ToolTextOutput::Block(reason)) => return Ok(ToolTextOutput::Block(reason)),
            Some(ToolTextOutput::Unchanged) | None => {}
        }
    } else if let Some(reason) = image_tool_result_block_reason(session, tool_response)? {
        return Ok(ToolTextOutput::Block(reason));
    }
    if let Some(reason) = unsupported_tool_result_reason(&output) {
        return Ok(ToolTextOutput::Block(reason));
    }
    let store = MemoryStore::for_session(session);
    let mut masker = OutputMasker::new_deferred(store)?;
    let (updated, changed) = mask_tool_json(&output, &mut masker)?;
    masker.flush()?;
    if changed || image_changed {
        Ok(ToolTextOutput::Updated(updated))
    } else {
        Ok(ToolTextOutput::Unchanged)
    }
}

fn claude_image_tool_output(
    session: &Session,
    value: &Value,
) -> Result<Option<ToolTextOutput>, String> {
    if !image_ocr::contains_image_result(value) {
        return Ok(None);
    }
    let cfg = config::image_ocr_config()?;
    if matches!(cfg.mode, config::ImageOcrMode::Off) {
        return Ok(
            matches!(cfg.unscanned_images, config::UnscannedImagePolicy::Block).then_some(
                ToolTextOutput::Block("image blocked: OCR is off.".to_string()),
            ),
        );
    }
    let redaction = image_ocr::redact_tool_images_for_secrets(
        value,
        &session.key,
        &session.identity_key,
        &cfg,
    )?;
    session
        .sync_recovery(&redaction.recovery)
        .map_err(|error| error.to_string())?;
    activity_log::record_image(redaction.secret_images, &redaction.labels);
    if matches!(cfg.unscanned_images, config::UnscannedImagePolicy::Block) {
        if redaction.unscanned_images > 0 {
            return Ok(Some(ToolTextOutput::Block(
                "image blocked: image could not be fetched or scanned.".to_string(),
            )));
        }
        if redaction.ocr_failures > 0 {
            return Ok(Some(ToolTextOutput::Block(
                "image blocked: image scan failed.".to_string(),
            )));
        }
    }
    if redaction.secret_images > 0 {
        if !redaction.changed {
            return Ok(Some(ToolTextOutput::Block(
                "image blocked: secret text detected.".to_string(),
            )));
        }
        let updated = append_image_mask_notes(
            redaction.updated,
            &redaction.visual_notes,
            &redaction.metadata_notes,
            cfg.redaction,
        );
        return Ok(Some(ToolTextOutput::Updated(updated)));
    }
    if matches!(cfg.unscanned_images, config::UnscannedImagePolicy::Allow) {
        return Ok(None);
    }
    Ok(None)
}

fn append_image_mask_notes(
    mut value: Value,
    visual_notes: &[String],
    metadata_notes: &[String],
    style: config::ImageRedactionStyle,
) -> Value {
    if visual_notes.is_empty() && metadata_notes.is_empty() {
        return value;
    }
    let mut sections = Vec::new();
    if !visual_notes.is_empty() {
        let explanation = match style {
            config::ImageRedactionStyle::Black => {
                "Pentect masked sensitive information in this image with black boxes."
            }
            config::ImageRedactionStyle::Blur => {
                "Pentect masked sensitive information in this image by blurring those regions."
            }
        };
        sections.push(format!(
            "{explanation}\nMasked regions:\n{}",
            visual_notes.join("\n")
        ));
    }
    if !metadata_notes.is_empty() {
        sections.push(format!(
            "Pentect removed sensitive metadata from this image.\nProtected values:\n{}",
            metadata_notes.join("\n")
        ));
    }
    let text = sections.join("\n");
    if append_text_block_to_content(&mut value, &text) {
        return value;
    }
    match value {
        Value::Object(mut map) => {
            map.insert("pentect_image_masks".to_string(), Value::String(text));
            Value::Object(map)
        }
        other => json!({
            "content": [
                other,
                {
                    "type": "text",
                    "text": text
                }
            ]
        }),
    }
}

fn append_text_block_to_content(value: &mut Value, text: &str) -> bool {
    match value {
        Value::Array(items) => {
            for item in items {
                if append_text_block_to_content(item, text) {
                    return true;
                }
            }
            false
        }
        Value::Object(map) => {
            if let Some(content) = map.get_mut("content").and_then(Value::as_array_mut) {
                content.push(json!({
                    "type": "text",
                    "text": text
                }));
                return true;
            }
            for item in map.values_mut() {
                if append_text_block_to_content(item, text) {
                    return true;
                }
            }
            false
        }
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => false,
    }
}

fn image_tool_result_block_reason(
    session: &Session,
    value: &Value,
) -> Result<Option<String>, String> {
    if !image_ocr::contains_image_result(value) {
        return Ok(None);
    }
    let cfg = config::image_ocr_config()?;
    if matches!(cfg.mode, config::ImageOcrMode::Off) {
        if matches!(cfg.unscanned_images, config::UnscannedImagePolicy::Block) {
            record_image_block(image_ocr::count_image_results(value));
            return Ok(Some("image blocked: OCR is off.".to_string()));
        }
        return Ok(None);
    }
    let inspection = image_ocr::inspect_tool_images_for_secrets(value, &session.key, &cfg)?;
    if inspection.secret_images > 0 {
        activity_log::record_summary(
            "detect",
            "image",
            inspection.secret_images as u64,
            BTreeMap::new(),
            None,
        );
        record_image_block(inspection.secret_images);
        return Ok(Some("image blocked: secret text detected.".to_string()));
    }
    if matches!(cfg.unscanned_images, config::UnscannedImagePolicy::Allow) {
        return Ok(None);
    }
    if inspection.unscanned_images > 0 {
        record_image_block(inspection.unscanned_images);
        return Ok(Some(
            "image blocked: image could not be fetched or scanned.".to_string(),
        ));
    }
    if inspection.ocr_failures > 0 {
        record_image_block(inspection.ocr_failures);
        return Ok(Some("image blocked: image scan failed.".to_string()));
    }
    Ok(None)
}

fn record_image_block(images: usize) {
    activity_log::record_summary("block", "image", 1, BTreeMap::new(), None);
    activity_log::record_summary("block-image", "image", images as u64, BTreeMap::new(), None);
}

fn unsupported_tool_result_reason(value: &Value) -> Option<String> {
    if contains_unsupported_media_result(value) {
        return Some("Media output unavailable because it could not be inspected.".to_string());
    }
    None
}

fn contains_unsupported_media_result(value: &Value) -> bool {
    match value {
        Value::String(text) => looks_like_media_reference(text),
        Value::Number(_) | Value::Bool(_) | Value::Null => false,
        Value::Array(items) => items.iter().any(contains_unsupported_media_result),
        Value::Object(map) => map.iter().any(|(key, item)| {
            let key = normalized_json_key(key);
            key_marks_media_value(&key, item)
                || string_media_field(&key, item)
                || contains_unsupported_media_result(item)
        }),
    }
}

fn normalized_json_key(key: &str) -> String {
    key.chars()
        .filter(|c| *c != '_' && *c != '-' && !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

fn key_marks_media_value(key: &str, value: &Value) -> bool {
    matches!(key, "audio" | "video" | "media" | "binary" | "blob") && !empty_json_value(value)
}

fn string_media_field(key: &str, value: &Value) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    match key {
        "type" | "kind" => matches!(normalized_json_key(text).as_str(), "audio" | "video"),
        "mimetype" | "mediatype" | "contenttype" => is_unsupported_media_mime(text),
        "url" | "uri" | "src" | "href" | "dataurl" => looks_like_media_reference(text),
        _ => false,
    }
}

fn looks_like_media_reference(text: &str) -> bool {
    let value = text.trim().to_ascii_lowercase();
    value.starts_with("data:audio/")
        || value.starts_with("data:video/")
        || value.starts_with("data:application/pdf")
}

fn is_unsupported_media_mime(text: &str) -> bool {
    let value = text.trim().to_ascii_lowercase();
    value.starts_with("audio/") || value.starts_with("video/") || value == "application/pdf"
}

fn empty_json_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.trim().is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        Value::Bool(false) => true,
        Value::Bool(true) | Value::Number(_) => false,
    }
}

fn mask_tool_json(value: &Value, masker: &mut OutputMasker) -> Result<(Value, bool), String> {
    let mut scalars = Vec::new();
    collect_tool_json_scalars(value, None, None, &[], &mut scalars);
    let masked = masker.mask_tool_result_scalars(&scalars)?;
    let mut cursor = 0usize;
    let out = rebuild_masked_tool_json(value, &masked, &mut cursor)?;
    if cursor != masked.len() {
        return Err("internal error: unused batched tool-result masks".to_string());
    }
    Ok((out.clone(), out != *value))
}

fn collect_tool_json_scalars(
    value: &Value,
    key: Option<&str>,
    path: Option<&str>,
    hints: &[String],
    out: &mut Vec<ToolScalarInput>,
) {
    match value {
        Value::String(text) => {
            if !image_ocr::skip_text_masking_for_image_payload(text) {
                out.push(ToolScalarInput {
                    text: text.clone(),
                    region_kind: RegionKind::JsonValue,
                    key: key.map(str::to_string),
                    path: path.map(str::to_string),
                    hints: hints.to_vec(),
                });
            }
        }
        Value::Number(_) | Value::Bool(_) => {
            out.push(ToolScalarInput {
                text: value.to_string(),
                region_kind: RegionKind::JsonValue,
                key: key.map(str::to_string),
                path: path.map(str::to_string),
                hints: hints.to_vec(),
            });
        }
        Value::Null => {}
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let child_path = path_with_segment(path, &index.to_string());
                collect_tool_json_scalars(item, key, Some(&child_path), hints, out);
            }
        }
        Value::Object(map) => {
            let image_object = image_ocr::contains_image_result(value);
            for (object_key, item) in map {
                let child_path = path_with_segment(path, object_key);
                out.push(ToolScalarInput {
                    text: object_key.clone(),
                    region_kind: RegionKind::JsonKey,
                    key: None,
                    path: Some(child_path.clone()),
                    hints: Vec::new(),
                });
                let child_hints = sibling_context_hints(map, object_key);
                if !(image_object
                    && item.as_str().is_some_and(|text| {
                        image_ocr::skip_text_masking_for_image_field(object_key, text)
                    }))
                {
                    collect_tool_json_scalars(
                        item,
                        Some(object_key),
                        Some(&child_path),
                        &child_hints,
                        out,
                    );
                }
            }
        }
    }
}

fn rebuild_masked_tool_json(
    value: &Value,
    masked: &[String],
    cursor: &mut usize,
) -> Result<Value, String> {
    match value {
        Value::String(text) if image_ocr::skip_text_masking_for_image_payload(text) => {
            Ok(value.clone())
        }
        Value::String(_) => {
            let out = take_masked(masked, cursor)?;
            Ok(Value::String(out))
        }
        Value::Number(_) | Value::Bool(_) => {
            let raw = value.to_string();
            let out = take_masked(masked, cursor)?;
            if out == raw {
                Ok(value.clone())
            } else {
                Ok(Value::String(out))
            }
        }
        Value::Null => Ok(Value::Null),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(rebuild_masked_tool_json(item, masked, cursor)?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(map) => {
            let image_object = image_ocr::contains_image_result(value);
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, item) in map {
                let masked_key = take_masked(masked, cursor)?;
                let item = if image_object
                    && item
                        .as_str()
                        .is_some_and(|text| image_ocr::skip_text_masking_for_image_field(key, text))
                {
                    item.clone()
                } else {
                    rebuild_masked_tool_json(item, masked, cursor)?
                };
                out.insert(masked_key, item);
            }
            Ok(Value::Object(out))
        }
    }
}

fn take_masked(masked: &[String], cursor: &mut usize) -> Result<String, String> {
    let Some(value) = masked.get(*cursor) else {
        return Err("internal error: missing batched tool-result mask".to_string());
    };
    *cursor += 1;
    Ok(value.clone())
}

fn sibling_context_hints(map: &serde_json::Map<String, Value>, object_key: &str) -> Vec<String> {
    if !object_key.eq_ignore_ascii_case("value") {
        return Vec::new();
    }
    ["label", "name", "ariaLabel", "placeholder", "title"]
        .iter()
        .filter_map(|key| map.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn path_with_segment(parent: Option<&str>, segment: &str) -> String {
    match parent {
        Some(parent) if !parent.is_empty() => format!("{parent}.{segment}"),
        _ => segment.to_string(),
    }
}

fn stringify_tool_output(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        _ => serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
    }
}

#[cfg(test)]
fn unix_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn read_input(path: &Path, format: InputFormat) -> Result<String, String> {
    let bytes = read_bytes(path)?;
    match format {
        InputFormat::Text => String::from_utf8(bytes)
            .map_err(|_| format!("input '{}' is not UTF-8 text", path.display())),
        InputFormat::Image => image_ocr::ocr_image_bytes(&bytes),
    }
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    if path == Path::new("-") {
        let mut buf = Vec::new();
        std::io::stdin()
            .take((MAX_INPUT_BYTES + 1) as u64)
            .read_to_end(&mut buf)
            .map_err(|e| format!("could not read stdin: {e}"))?;
        if buf.len() > MAX_INPUT_BYTES {
            return Err(format!("input exceeds {MAX_INPUT_BYTES} bytes"));
        }
        return Ok(buf);
    }
    let metadata =
        std::fs::metadata(path).map_err(|e| format!("could not stat '{}': {e}", path.display()))?;
    if metadata.len() > MAX_INPUT_BYTES as u64 {
        return Err(format!(
            "input '{}' exceeds {MAX_INPUT_BYTES} bytes",
            path.display()
        ));
    }
    std::fs::read(path).map_err(|e| format!("could not read '{}': {e}", path.display()))
}

fn read_stdin_text() -> Result<String, String> {
    let mut buf = Vec::new();
    std::io::stdin()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("could not read stdin: {e}"))?;
    if buf.len() > MAX_INPUT_BYTES {
        return Err(format!("input exceeds {MAX_INPUT_BYTES} bytes"));
    }
    let mut text = String::from_utf8(buf).map_err(|_| "stdin is not UTF-8 text".to_string())?;
    if text.starts_with('\u{feff}') {
        text = text.trim_start_matches('\u{feff}').to_string();
    }
    Ok(text)
}

fn normalize_policy_text(text: &str) -> String {
    text.to_ascii_lowercase().replace('\\', "/")
}

fn is_shell_separator_word(word: &str) -> bool {
    matches!(word, "|" | ";" | "&&" | "||") || word.starts_with('<') || word.starts_with('>')
}

fn looks_like_env_name(name: &str) -> bool {
    !name.is_empty() && !name.as_bytes()[0].is_ascii_digit() && name.bytes().all(is_env_name_byte)
}

fn env_name_after_marker(text: &str, start: usize, marker: char) -> Option<(&str, usize)> {
    let bytes = text.as_bytes();
    if start >= bytes.len() {
        return None;
    }

    if marker == '$' && bytes[start] == b'{' {
        let name_start = start + 1;
        let mut end = name_start;
        while end < bytes.len() && is_env_name_byte(bytes[end]) {
            end += 1;
        }
        if end > name_start && end < bytes.len() && bytes[end] == b'}' {
            return Some((&text[name_start..end], end + 1));
        }
        return None;
    }

    let mut end = start;
    while end < bytes.len() && is_env_name_byte(bytes[end]) {
        end += 1;
    }
    if end == start {
        return None;
    }
    if marker == '%' && (end >= bytes.len() || bytes[end] != b'%') {
        return None;
    }
    let next = if marker == '%' { end + 1 } else { end };
    Some((&text[start..end], next))
}

fn parse_kind(value: &str) -> Result<Kind, String> {
    match value {
        "text" => Ok(Kind::Text),
        "json" => Ok(Kind::Json),
        "ndjson" | "jsonl" => Ok(Kind::Ndjson),
        "env" => Ok(Kind::Env),
        "har" => Ok(Kind::Har),
        "structured" | "config" => Ok(Kind::Other("structured".to_string())),
        "secret" | "secret-file" => Ok(Kind::Other("secret-file:SECRET".to_string())),
        other => Err(format!("unknown kind: {other}")),
    }
}

fn parse_hook_provider(value: &str) -> Result<HookProvider, String> {
    match value {
        "codex" => Ok(HookProvider::Codex),
        "claude" => Err(
            "Claude hook mode was replaced by the HTTP gateway; start with `pentect claude`"
                .to_string(),
        ),
        "generic" | "external" | "update" => Ok(HookProvider::Generic),
        other => Err(format!("unknown hook provider: {other}")),
    }
}

fn parse_input_format(value: &str) -> Result<InputFormat, String> {
    match value {
        "text" => Ok(InputFormat::Text),
        "image" | "ocr" => Ok(InputFormat::Image),
        other => Err(format!("unknown input format: {other}")),
    }
}

fn parse_session_and_rest(args: &[String], start: usize) -> Result<(String, Vec<String>), String> {
    let mut session = default_session_name()?;
    let mut rest = Vec::new();
    let mut i = start;
    while i < args.len() {
        match args[i].as_str() {
            "--session" => session = value(args, &mut i, "--session")?,
            flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
            arg => {
                rest.push(arg.to_string());
                i += 1;
            }
        }
    }
    Ok((
        checked_session_name(&session).map_err(|e| e.to_string())?,
        rest,
    ))
}

fn value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    let Some(value) = args.get(*i + 1) else {
        return Err(format!("{flag} requires a value"));
    };
    *i += 2;
    Ok(value.clone())
}

fn die(msg: impl std::fmt::Display) -> i32 {
    eprintln!("[pentect] {msg}");
    2
}

#[cfg(test)]
mod tests;
