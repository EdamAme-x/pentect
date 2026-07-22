//! `pentect agent`: a minimal tool-boundary adapter.
//!
//! It demonstrates the product loop:
//! shell tool input -> force execution through `pentect exec`;
//! command output -> mask before it returns to the AI.
//! `read` is a one-way human preview. `exec` and hooks keep masked handles in
//! process memory so later tool commands can reuse them without persisting raw
//! recovery material.

mod activity_log;
mod config;
mod delegated_process_host;
mod file_pointer_manager;
mod image_ocr;
mod masking;
mod memory_store;
mod output_remask;
mod plugin_adapter;
mod session;
mod shell;

pub use activity_log::record_scan as record_scan_activity;
pub use delegated_process_host::{
    contains_host as delegated_process_host_contains, is_host as delegated_process_host_owned_by,
    is_running as delegated_process_host_running, matches_host as delegated_process_host_matches,
    persistent_candidate_is_running as persistent_process_host_running, process_host_root,
    register_candidate as register_process_host_candidate,
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
use pentect_core::{
    infer_kind, parse_placeholder, Config, Engine, Input, Kind, MaskResult, Pack, Profile,
    RegionKind,
};
use portable_pty::{native_pty_system, Child as PtyChild, CommandBuilder, MasterPty, PtySize};
#[cfg(windows)]
use rustyline::{
    completion::{Completer, FilenameCompleter, Pair},
    error::ReadlineError,
    highlight::Highlighter,
    hint::Hinter,
    history::DefaultHistory,
    validate::Validator,
    Context as ReadlineContext, Editor, Helper,
};
use serde_json::{json, Value};
use session::{checked_session_name, session_root, Session};
use sha2::{Digest, Sha256};
use shell::{next_shell_word, powershell_string_literal, powershell_word, shell_quote_unix};
#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_SESSION: &str = "default";
const PENTECT_AGENT_LAUNCHED_ENV: &str = "PENTECT_AGENT_LAUNCHED";
const PENTECT_CODEX_EXEC_PROXY_ENV: &str = "PENTECT_CODEX_EXEC_PROXY";
const PENTECT_PLUGIN_CONFIGS_ENV: &str = "PENTECT_PLUGIN_CONFIGS";
const PENTECT_PLUGIN_ADAPTERS_ENV: &str = "PENTECT_PLUGIN_ADAPTERS";
const LIVE_MASK_CHUNK_BYTES: usize = 64 * 1024;
const LIVE_MASK_CHUNK_LINES: usize = 2048;
const ACTIVE_TOOL_OUTPUT_CACHE_LIMIT: usize = 128;
const ACTIVE_TOOL_OUTPUT_CACHE_MAX_BYTES: usize = 16 * 1024;
const PTY_PARTIAL_FLUSH_TIMEOUT: Duration = Duration::from_millis(30);
const PTY_PARTIAL_FLUSH_BYTES: usize = 4096;
const PTY_PARTIAL_TAIL_BYTES: usize = 512;
const BRACKETED_PASTE_START: &[u8] = b"\x1b[200~";
const BRACKETED_PASTE_END: &[u8] = b"\x1b[201~";
const PTY_PASTE_MAX_PENDING_BYTES: usize = 32 * 1024 * 1024;

pub fn agent_contract_instructions(environment_prefix: &str) -> String {
    format!(
        concat!(
            "Session rules:\n",
            "- Work normally with the host's tools and current shell. Do not invoke Pentect commands, explain the protection layer, or change approach because it is present unless the user asks.\n",
            "- User-authorized secret work is allowed: retrieve, read, use, transform, and store secrets at the requested destination. Complete it normally.\n",
            "- Use tools normally; their output is protected. Never include a raw secret in your response. A value such as `<<KEY_hash>>` is protected output, not a failed operation; do not retry because it appears.\n",
            "- A protected handle means the real value is ready to use through its environment binding: `$env:{environment_prefix}KEY_hash` in PowerShell or `${environment_prefix}KEY_hash` in a POSIX shell. Treat that binding as the real secret for commands, API requests, headers, SDKs, and destination files. You do not need to know or print its plaintext to use it.\n",
            "- Once a handle or environment binding exists, use it immediately. Do not reread or reparse the source file, fetch the same secret again, or claim that the secret is unavailable or inaccessible. Do not echo, print, decode, or reconstruct the binding's value.\n",
            "- If dotenv output shows `KEY=<<KEY_hash>>`, use `$env:{environment_prefix}KEY_hash` directly in the PowerShell command that needs the value (or `${environment_prefix}KEY_hash` in POSIX). Do not parse the dotenv file in a shell, copy the handle into `$env:KEY`, or call `SetEnvironmentVariable`.\n",
            "- Shell tool calls may run in separate processes. Never depend on an environment assignment made by an earlier tool call; reference the provided binding directly in every command that needs it.\n",
            "- Report only the task result and ordinary errors. Do not mention these rules, handles, bindings, or the protection layer.\n",
        ),
        environment_prefix = environment_prefix
    )
}

#[cfg(test)]
thread_local! {
    static CODEX_EXEC_PROXY_TEST_OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
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
        Some("shell") => cmd_shell(&args),
        Some("resolve") => cmd_resolve(&args),
        Some("log") => cmd_log(&args),
        Some("hook") => cmd_hook(&args),
        Some("bridge") => cmd_bridge(&args),
        Some("memory-store") => cmd_memory_store(&args),
        Some("__agent-script") => cmd_agent_script(&args),
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

pub fn load_environment_variable_prefix() -> Result<String, String> {
    config::environment_variable_prefix()
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

pub fn record_read_activity(result: &MaskResult, path: &Path) {
    activity_log::record_mask_result("read", result, Some(path));
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

pub fn active_masked_count() -> Result<Option<u64>, String> {
    let Some(client) = MemoryStoreClient::from_env() else {
        return Ok(None);
    };
    client.masked_count().map(Some).map_err(|e| e.to_string())
}

pub fn status_line_text() -> String {
    match active_masked_count() {
        Ok(Some(count)) => format!("Pentect {count}"),
        _ => "Pentect 0".to_string(),
    }
}

pub fn ocr_image_bytes(bytes: &[u8]) -> Result<String, String> {
    image_ocr::ocr_image_bytes(bytes)
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
        return Ok(None);
    }
    let session = Session::open_capability("default").map_err(|e| e.to_string())?;
    let redaction = image_ocr::redact_tool_images_for_secrets(value, &session.key, &cfg)?;
    activity_log::record_image(redaction.secret_images, &redaction.notes);
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
        &redaction.notes,
    )))
}

pub fn redact_image_bytes_into_active_memory_store(
    bytes: &[u8],
) -> Result<Option<Vec<u8>>, String> {
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
    zeroize_value_strings(&mut updated);
    decoded.map(Some)
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
}

struct CachedToolOutput {
    masked: String,
    masked_count: u64,
}

impl ActiveToolOutputMasker {
    pub fn new() -> Result<Self, String> {
        let Some(client) = MemoryStoreClient::from_env() else {
            return Ok(Self {
                client: None,
                masker: None,
                reported_masked_count: 0,
                cache: HashMap::new(),
                cache_order: VecDeque::new(),
            });
        };
        let session = Session::open_capability("default").map_err(|e| e.to_string())?;
        let store = MemoryStore::for_session(&session);
        Ok(Self {
            client: Some(client),
            masker: Some(OutputMasker::new_shared(store)?),
            reported_masked_count: 0,
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
        })
    }

    pub fn mask_tool_output(&mut self, text: &str) -> Result<Option<String>, String> {
        let Some(masker) = &mut self.masker else {
            return Ok(None);
        };
        let cache_key =
            (text.len() <= ACTIVE_TOOL_OUTPUT_CACHE_MAX_BYTES).then(|| tool_output_cache_key(text));
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
        let masked = masker.mask_tool_output(text)?;
        masker.flush_activity();
        let total = masker.masked_count();
        let delta = total.saturating_sub(self.reported_masked_count);
        self.reported_masked_count = total;
        if delta > 0 {
            self.cache.clear();
            self.cache_order.clear();
            if let Some(client) = &self.client {
                client.add_masked_count(delta).map_err(|e| e.to_string())?;
            }
        }
        if let Some(key) = cache_key {
            self.remember(key, &masked, delta);
        }
        Ok(Some(masked))
    }

    pub fn mask_prompt_text(&mut self, text: &str) -> Result<Option<String>, String> {
        let Some(masker) = &mut self.masker else {
            return Ok(None);
        };
        let masked = masker.mask_prompt_text(text)?;
        masker.flush_activity();
        let total = masker.masked_count();
        let delta = total.saturating_sub(self.reported_masked_count);
        self.reported_masked_count = total;
        if delta > 0 {
            self.cache.clear();
            self.cache_order.clear();
            if let Some(client) = &self.client {
                client.add_masked_count(delta).map_err(|e| e.to_string())?;
            }
        }
        Ok(Some(masked))
    }

    fn remember(&mut self, key: [u8; 32], masked: &str, masked_count: u64) {
        if self.cache.contains_key(&key) {
            return;
        }
        while self.cache.len() >= ACTIVE_TOOL_OUTPUT_CACHE_LIMIT {
            let Some(oldest) = self.cache_order.pop_front() else {
                self.cache.clear();
                break;
            };
            self.cache.remove(&oldest);
        }
        self.cache.insert(
            key,
            CachedToolOutput {
                masked: masked.to_string(),
                masked_count,
            },
        );
        self.cache_order.push_back(key);
    }
}

fn tool_output_cache_key(text: &str) -> [u8; 32] {
    let digest = Sha256::digest(text.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
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
         pentect shell\n\
         pentect view <HANDLE>\n\
         pentect resolve [PATH...]\n\
         pentect log [--json]\n\
         \n\
         exec: masked output\n\
         shell: masked shell\n\
         view: handle\n\
         resolve: write handles\n\
         log: live events"
    );
}

fn cmd_log(args: &[String]) -> i32 {
    let json = match args.get(2).map(String::as_str) {
        None => false,
        Some("--json") if args.len() == 3 => true,
        _ => return die("log [--json]"),
    };
    match activity_log::follow(json) {
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
    let kind = opts.kind.unwrap_or_else(|| infer_kind(&opts.path));
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

fn cmd_shell(args: &[String]) -> i32 {
    if matches!(
        args.get(2).map(String::as_str),
        Some("--help" | "-h" | "help")
    ) {
        shell_help();
        return 0;
    }
    let opts = match ShellOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let session = match Session::open_capability(&opts.session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let store = MemoryStore::for_session(&session);
    match run_masked_shell(store, &opts) {
        Ok(code) => code,
        Err(e) => die(&e),
    }
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
            "pentect exec --live \"<command>\"\n\n",
            "stdout/stderr: masked\n",
            "handles: in memory\n",
            "env: $env:KEY or $KEY\n",
        )
    );
}

fn shell_help() {
    print!(
        "{}",
        concat!(
            "pentect shell\n",
            "pentect shell -- PROGRAM [ARG...]\n\n",
            "stdout/stderr: masked\n",
            "stdin: hidden\n",
            "codex/claude: pentect wrapped\n",
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

fn cmd_agent_script(args: &[String]) -> i32 {
    let opts = match AgentScriptOpts::parse(args) {
        Ok(opts) => opts,
        Err(error) => return die(&error),
    };
    let Some(client) = MemoryStoreClient::from_env() else {
        return die("agent script requires a running Pentect session");
    };
    let mut rendered = match take_rendered_agent_script(&client, &opts) {
        Ok(rendered) => rendered,
        Err(error) => return die(&error),
    };
    print!("{}", rendered.as_str());
    let result = std::io::stdout().flush();
    rendered.zeroize();
    match result {
        Ok(()) => 0,
        Err(error) => die(format!("could not write agent script: {error}")),
    }
}

fn take_rendered_agent_script(
    client: &MemoryStoreClient,
    opts: &AgentScriptOpts,
) -> Result<Zeroizing<String>, String> {
    let (shell, masked_script) = match client.take_agent_script(&opts.id) {
        Ok(pending) => pending,
        Err(error) => return Err(error.to_string()),
    };
    let session = match Session::open_capability(&opts.session) {
        Ok(session) => session,
        Err(error) => return Err(error.to_string()),
    };
    let store = MemoryStore::for_session(&session);
    let mode = ExecMode::Shell(masked_script.to_string());
    let mut resolved = resolve_command_text(&store, masked_script.as_str())?;
    if let Err(error) = register_local_file_inputs(&store, &resolved) {
        resolved.zeroize();
        return Err(error);
    }
    let mut env = match requested_env_bindings(&store, &mode) {
        Ok(env) => env,
        Err(error) => {
            resolved.zeroize();
            return Err(error);
        }
    };
    let rendered = match render_agent_script(&shell, &env, &resolved) {
        Ok(rendered) => rendered,
        Err(error) => {
            resolved.zeroize();
            zeroize_env_bindings(&mut env);
            return Err(error);
        }
    };
    resolved.zeroize();
    zeroize_env_bindings(&mut env);
    Ok(Zeroizing::new(rendered))
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

fn render_agent_script(
    shell: &str,
    env: &[(String, String)],
    resolved: &str,
) -> Result<String, String> {
    let mut rendered = String::new();
    match shell {
        "bash" => {
            for (name, value) in env {
                if !looks_like_env_name(name) || is_pentect_control_env_name(name) {
                    continue;
                }
                rendered.push_str("export ");
                rendered.push_str(name);
                rendered.push('=');
                rendered.push_str(&shell_quote_unix(value));
                rendered.push('\n');
            }
        }
        "powershell" => {
            for (name, value) in env {
                if !looks_like_env_name(name) || is_pentect_control_env_name(name) {
                    continue;
                }
                rendered.push_str("$env:");
                rendered.push_str(name);
                rendered.push_str(" = ");
                rendered.push_str(&powershell_string_literal(value));
                rendered.push('\n');
            }
        }
        _ => return Err("agent script shell is invalid".to_string()),
    }
    rendered.push_str(resolved);
    Ok(rendered)
}

fn zeroize_env_bindings(env: &mut [(String, String)]) {
    for (_, value) in env {
        value.zeroize();
    }
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
            match mask_tool_text_output(HookProvider::Claude, session, value)? {
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
        PENTECT_PLUGIN_ADAPTERS_ENV,
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
            let resolved_args = resolve_command_args(store, args)?;
            let program = &resolved_args[0];
            let command_args = &resolved_args[1..];
            let mut command = Command::new(program);
            command.args(command_args);
            apply_child_env_overlays(&mut command, &env, &opts.session);
            command
                .output()
                .map_err(|e| format!("could not execute command: {e}"))
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
            let resolved_args = resolve_command_args(store, args)?;
            let program = &resolved_args[0];
            let command_args = &resolved_args[1..];
            let mut command = Command::new(program);
            command.args(command_args);
            apply_child_env_overlays(&mut command, &env, &opts.session);
            run_live_command(command, None, store.clone())
        }
        ExecMode::Shell(command) => {
            let command = resolve_command_text(store, command)?;
            register_local_file_inputs(store, &command)?;
            let env = requested_env_bindings(store, &opts.mode)?;
            let mut shell = shell_script_command(opts.script_shell)?;
            apply_child_env_overlays(&mut shell, &env, &opts.session);
            run_live_command(shell, Some(&command), store.clone())
        }
        ExecMode::Stdin => Err("internal error: exec stdin was not prepared".to_string()),
    }
}

fn resolve_command_args(store: &MemoryStore, args: &[String]) -> Result<Vec<String>, String> {
    args.iter()
        .map(|arg| resolve_command_text(store, arg))
        .collect()
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
        let kind = infer_kind(&path);
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

fn run_shell_script(
    script: &str,
    env: &[(String, String)],
    session: &str,
    script_shell: ScriptShell,
) -> Result<std::process::Output, String> {
    let mut command = shell_script_command(script_shell)?;
    apply_child_env_overlays(&mut command, env, session);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not execute shell command: {e}"))?;
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
    stdin_script: Option<&str>,
    store: MemoryStore,
) -> Result<ExitStatus, String> {
    live_status("streaming masked command output");
    if stdin_script.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("could not execute command: {e}"))?;
    if let Some(script) = stdin_script {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "could not open command stdin".to_string())?;
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("could not write shell script to stdin: {e}"))?;
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

fn run_masked_shell(store: MemoryStore, opts: &ShellOpts) -> Result<i32, String> {
    let shim = ShellShimDir::install()?;
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        #[cfg(windows)]
        if opts.program.is_none() {
            return run_masked_windows_powershell(store, opts, &shim);
        }
        run_masked_shell_pty(store, opts, &shim)
    } else {
        run_masked_shell_pipe(store, opts, &shim)
    }
}

#[cfg(windows)]
const WINDOWS_SHELL_HOST_SCRIPT: &str = concat!(
    "$marker=$env:PENTECT_SHELL_COMMAND_MARKER;",
    "$drain=$env:PENTECT_SHELL_DRAIN_MARKER;",
    "while (($line=[Console]::In.ReadLine()) -ne $null) {",
    "try {",
    "$text=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($line));",
    "if (-not [String]::IsNullOrWhiteSpace($text)) { Invoke-Expression $text *>&1 | Out-String -Stream | ForEach-Object { [Console]::Out.WriteLine($_) } }",
    "} catch {",
    "$message=$_ | Out-String;[Console]::Out.WriteLine($message)",
    "};",
    "[Console]::Out.WriteLine($marker+'DRAIN');[Console]::Out.Flush();",
    "while (($pending=[Console]::In.ReadLine()) -ne $null -and $pending -ne $drain) {}",
    "$cwd=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Location).Path));",
    "[Console]::Out.WriteLine($marker+$cwd);[Console]::Out.Flush()",
    "}"
);

#[cfg(windows)]
fn run_masked_windows_powershell(
    store: MemoryStore,
    opts: &ShellOpts,
    shim: &ShellShimDir,
) -> Result<i32, String> {
    let marker = windows_shell_marker()?;
    let drain_marker = windows_shell_marker()?;
    let mut command = Command::new(windows_powershell_path());
    command
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(WINDOWS_SHELL_HOST_SCRIPT);
    apply_child_env_overlays(&mut command, &[], &opts.session);
    apply_active_memory_store_env(&mut command);
    command.env("PENTECT_SHELL_COMMAND_MARKER", &marker);
    command.env("PENTECT_SHELL_DRAIN_MARKER", &drain_marker);
    shim.apply_to_command(&mut command);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("could not start PowerShell: {e}"))?;
    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "could not open PowerShell stdin".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "could not capture PowerShell stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "could not capture PowerShell stderr".to_string())?;
    let (completion_tx, completion_rx) = mpsc::channel();
    let stdout_store = store.clone();
    let stdout_marker = marker.clone();
    let stdout_thread = std::thread::spawn(move || {
        stream_windows_shell_stdout(stdout_store, stdout, &stdout_marker, completion_tx)
    });
    let stderr_store = store.clone();
    let stderr_thread = std::thread::spawn(move || {
        stream_masked_reader_deferred(stderr_store, stderr, StreamTarget::Stderr)
    });
    masking::prewarm_tool_boundary_engine();
    let status = pump_windows_shell_input(
        &mut child,
        &mut child_stdin,
        store,
        &completion_rx,
        &drain_marker,
    )?;
    drop(child_stdin);
    join_stream_thread(stdout_thread)?;
    join_stream_thread(stderr_thread)?;
    Ok(exit_code(status))
}

#[cfg(windows)]
fn windows_shell_marker() -> Result<String, String> {
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|e| format!("could not create shell protocol marker: {e}"))?;
    Ok(format!(
        "__PENTECT_COMMAND_DONE_{}__",
        data_encoding::HEXLOWER.encode(&random)
    ))
}

#[cfg(windows)]
fn stream_windows_shell_stdout(
    store: MemoryStore,
    stdout: std::process::ChildStdout,
    marker: &str,
    completion_tx: mpsc::Sender<WindowsShellCompletion>,
) -> Result<(), String> {
    let mut reader = BufReader::new(stdout);
    let mut masker = None;
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|e| format!("could not read PowerShell output: {e}"))?;
        if read == 0 {
            break;
        }
        if let Some(start) = line.find(marker) {
            let prefix = &line[..start];
            if !prefix.is_empty() {
                let mut chunk = prefix.to_string();
                flush_masked_chunk(
                    deferred_masker(&mut masker, &store)?,
                    StreamTarget::Stdout,
                    &mut chunk,
                    live_output_kind(prefix),
                )?;
            }
            // Publish handles and their environment aliases before the input
            // loop exposes the next prompt. Deferred output otherwise keeps a
            // freshly printed dotenv handle unusable until the shell exits.
            if let Some(masker) = &mut masker {
                masker.flush()?;
            }
            let encoded = line[start + marker.len()..].trim_end_matches(['\r', '\n']);
            if encoded == "DRAIN" {
                if completion_tx
                    .send(WindowsShellCompletion::DrainInput)
                    .is_err()
                {
                    break;
                }
                continue;
            }
            let cwd = data_encoding::BASE64
                .decode(encoded.as_bytes())
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .ok_or_else(|| "PowerShell returned an invalid working directory".to_string())?;
            if completion_tx
                .send(WindowsShellCompletion::Complete(cwd))
                .is_err()
            {
                break;
            }
            continue;
        }
        let kind = live_output_kind(&line);
        flush_masked_chunk(
            deferred_masker(&mut masker, &store)?,
            StreamTarget::Stdout,
            &mut line,
            kind,
        )?;
    }
    if let Some(masker) = &mut masker {
        masker.flush()?;
    }
    Ok(())
}

#[cfg(windows)]
enum WindowsShellCompletion {
    DrainInput,
    Complete(String),
}

#[cfg(windows)]
fn pump_windows_shell_input(
    child: &mut std::process::Child,
    child_stdin: &mut std::process::ChildStdin,
    store: MemoryStore,
    completion_rx: &mpsc::Receiver<WindowsShellCompletion>,
    drain_marker: &str,
) -> Result<ExitStatus, String> {
    normalize_windows_shell_console_input_mode()?;
    let display = WindowsShellDisplay::new(store.clone())?;
    let mut editor = Editor::<WindowsShellDisplay, DefaultHistory>::new()
        .map_err(|e| format!("could not initialize shell input: {e}"))?;
    editor.set_helper(Some(display));
    let history_path = windows_shell_history_path()?;
    if let Some(parent) = history_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create shell history directory: {e}"))?;
    }
    load_windows_powershell_history(&mut editor);
    if history_path.exists() {
        let _ = editor.load_history(&history_path);
    }
    let mut protector = ShellInputProtector::new(store)?;
    let mut cwd = std::env::current_dir()
        .map_err(|e| format!("could not read current directory: {e}"))?
        .to_string_lossy()
        .into_owned();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("could not poll PowerShell: {e}"))?
        {
            return Ok(status);
        }
        let prompt = format!("PS {}> ", compact_windows_shell_cwd(&cwd));
        let mut raw = match editor.readline(&prompt) {
            Ok(line) => line,
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => {
                child
                    .kill()
                    .map_err(|e| format!("could not stop PowerShell: {e}"))?;
                return child
                    .wait()
                    .map_err(|e| format!("could not wait for PowerShell: {e}"));
            }
            Err(e) => return Err(format!("could not read shell input: {e}")),
        };
        if raw.trim().is_empty() {
            raw.zeroize();
            continue;
        }
        if let Some(agent_args) = windows_shell_interactive_agent_args(&raw) {
            let mut history_probe = protector.prepare_paste(&raw)?;
            if windows_shell_history_is_safe(&raw, history_probe.changed) {
                remember_windows_shell_history(&mut editor, &history_path, &raw);
            }
            history_probe.child.zeroize();
            history_probe.injected_prefix.zeroize();
            let result = run_windows_shell_interactive_agent(&agent_args, &cwd);
            raw.zeroize();
            result?;
            continue;
        }
        let mut protected = protector.prepare_paste(&raw)?;
        if windows_shell_history_is_safe(&raw, protected.changed) {
            remember_windows_shell_history(&mut editor, &history_path, &raw);
        }
        raw.zeroize();
        let mut encoded = data_encoding::BASE64.encode(protected.child.as_bytes());
        child_stdin
            .write_all(encoded.as_bytes())
            .and_then(|_| child_stdin.write_all(b"\n"))
            .and_then(|_| child_stdin.flush())
            .map_err(|e| format!("could not write PowerShell input: {e}"))?;
        encoded.zeroize();
        protected.child.zeroize();
        protected.injected_prefix.zeroize();
        match wait_for_windows_shell_completion_without_terminal_input(
            child,
            child_stdin,
            completion_rx,
            drain_marker,
        )? {
            Some(next_cwd) => {
                cwd.zeroize();
                cwd = next_cwd;
            }
            None => {
                return child
                    .wait()
                    .map_err(|e| format!("could not wait for PowerShell: {e}"));
            }
        }
    }
}

#[cfg(windows)]
fn windows_shell_history_path() -> Result<PathBuf, String> {
    Ok(process_host_root()?.join("shell-history.txt"))
}

#[cfg(windows)]
fn windows_powershell_history_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|root| {
        PathBuf::from(root)
            .join("Microsoft")
            .join("Windows")
            .join("PowerShell")
            .join("PSReadLine")
            .join("ConsoleHost_history.txt")
    })
}

#[cfg(windows)]
fn load_windows_powershell_history(editor: &mut Editor<WindowsShellDisplay, DefaultHistory>) {
    const IMPORT_LIMIT: usize = 100;
    let Some(path) = windows_powershell_history_path() else {
        return;
    };
    let Ok(contents) = std::fs::read_to_string(path) else {
        return;
    };
    let mut recent = contents
        .lines()
        .rev()
        .take(IMPORT_LIMIT)
        .collect::<Vec<_>>();
    recent.reverse();
    for command in recent {
        if windows_shell_history_is_safe(command, false) {
            let _ = editor.add_history_entry(command);
        }
    }
}

#[cfg(windows)]
fn remember_windows_shell_history(
    editor: &mut Editor<WindowsShellDisplay, DefaultHistory>,
    path: &Path,
    command: &str,
) {
    if command.trim().is_empty() {
        return;
    }
    if editor.add_history_entry(command).is_ok() {
        let _ = editor.save_history(path);
    }
}

#[cfg(windows)]
fn windows_shell_history_is_safe(command: &str, protected: bool) -> bool {
    !protected
        && likely_shell_secret_range(command).is_none()
        && !contains_unresolved_masked_handle(command)
        && !command.to_ascii_lowercase().contains("pentect_")
}

#[cfg(all(windows, test))]
fn is_windows_shell_interactive_agent_command(command: &str) -> bool {
    windows_shell_interactive_agent_args(command).is_some()
}

#[cfg(windows)]
fn windows_shell_interactive_agent_args(command: &str) -> Option<Vec<String>> {
    let trimmed = command.trim();
    if trimmed.is_empty() || trimmed.contains([';', '|', '&', '\r', '\n']) {
        return None;
    }
    let (program, _, mut cursor) = next_shell_word(trimmed, 0)?;
    if !matches!(
        program.to_ascii_lowercase().as_str(),
        "codex" | "claude" | "opencode"
    ) {
        return None;
    }
    let mut args = vec![program.to_ascii_lowercase()];
    while let Some((arg, _, next)) = next_shell_word(trimmed, cursor) {
        args.push(arg);
        cursor = next;
    }
    Some(args)
}

#[cfg(windows)]
fn run_windows_shell_interactive_agent(args: &[String], cwd: &str) -> Result<(), String> {
    let executable =
        std::env::current_exe().map_err(|e| format!("could not locate pentect executable: {e}"))?;
    let mut command = Command::new(executable);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command
        .status()
        .map_err(|e| format!("could not start interactive agent: {e}"))?;
    Ok(())
}

#[cfg(windows)]
struct WindowsShellDisplay {
    completer: FilenameCompleter,
}

#[cfg(windows)]
impl WindowsShellDisplay {
    fn new(_store: MemoryStore) -> Result<Self, String> {
        Ok(Self {
            completer: FilenameCompleter::new(),
        })
    }
}

#[cfg(windows)]
impl Completer for WindowsShellDisplay {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &ReadlineContext<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        self.completer.complete(line, pos, ctx)
    }
}

#[cfg(windows)]
impl Hinter for WindowsShellDisplay {
    type Hint = String;
}

#[cfg(windows)]
impl Validator for WindowsShellDisplay {}

#[cfg(windows)]
impl Helper for WindowsShellDisplay {}

#[cfg(windows)]
impl Highlighter for WindowsShellDisplay {
    fn highlight<'line>(&self, line: &'line str, _pos: usize) -> std::borrow::Cow<'line, str> {
        provisional_shell_secret_display(line)
            .map(std::borrow::Cow::Owned)
            .unwrap_or(std::borrow::Cow::Borrowed(line))
    }

    fn highlight_char(
        &self,
        _line: &str,
        _pos: usize,
        _kind: rustyline::highlight::CmdKind,
    ) -> bool {
        true
    }
}

#[cfg(windows)]
fn provisional_shell_secret_display(raw: &str) -> Option<String> {
    let (start, end) = likely_shell_secret_range(raw)?;
    let mut display = raw.to_string();
    display.replace_range(start..end, &"•".repeat(raw[start..end].chars().count()));
    Some(display)
}

fn likely_shell_secret_range(text: &str) -> Option<(usize, usize)> {
    let range = masking::first_shell_input_secret_range(text)?;
    Some((range.start, range.end))
}

#[cfg(windows)]
fn normalize_windows_shell_console_input_mode() -> Result<(), String> {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, STD_INPUT_HANDLE,
    };

    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut current = 0;
    if unsafe { GetConsoleMode(handle, &mut current) } == 0 {
        return Ok(());
    }
    let sane = windows_shell_sane_input_mode(current);
    if sane != current && unsafe { SetConsoleMode(handle, sane) } == 0 {
        return Err("could not restore the Windows console input mode".to_string());
    }
    Ok(())
}

#[cfg(windows)]
fn windows_shell_sane_input_mode(current: u32) -> u32 {
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_EXTENDED_FLAGS, ENABLE_LINE_INPUT, ENABLE_MOUSE_INPUT,
        ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
    };

    (current & !(ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_MOUSE_INPUT))
        | ENABLE_PROCESSED_INPUT
        | ENABLE_LINE_INPUT
        | ENABLE_ECHO_INPUT
        | ENABLE_EXTENDED_FLAGS
}

#[cfg(windows)]
fn wait_for_windows_shell_completion_without_terminal_input(
    child: &mut std::process::Child,
    child_stdin: &mut std::process::ChildStdin,
    completion_rx: &mpsc::Receiver<WindowsShellCompletion>,
    drain_marker: &str,
) -> Result<Option<String>, String> {
    loop {
        match completion_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(WindowsShellCompletion::DrainInput) => {
                child_stdin
                    .write_all(drain_marker.as_bytes())
                    .and_then(|_| child_stdin.write_all(b"\r\n"))
                    .and_then(|_| child_stdin.flush())
                    .map_err(|e| format!("could not drain PowerShell input: {e}"))?;
            }
            Ok(WindowsShellCompletion::Complete(cwd)) => return Ok(Some(cwd)),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if child
                    .try_wait()
                    .map_err(|e| format!("could not poll PowerShell: {e}"))?
                    .is_some()
                {
                    return Ok(None);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(None),
        }
    }
}

#[cfg(any())]
fn pump_windows_shell_input_legacy(
    child: &mut std::process::Child,
    child_stdin: &mut std::process::ChildStdin,
    store: MemoryStore,
    completion_rx: &mpsc::Receiver<WindowsShellCompletion>,
    drain_marker: &str,
) -> Result<ExitStatus, String> {
    let _raw = RawModeGuard::enable()?;
    let _paste = BracketedPasteGuard::enable()?;
    let mut protector = ShellInputProtector::new(store)?;
    let mut cwd = std::env::current_dir()
        .map_err(|e| format!("could not read current directory: {e}"))?
        .to_string_lossy()
        .into_owned();
    let mut line = WindowsShellLine::default();
    print_windows_shell_prompt(&cwd)?;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("could not poll PowerShell: {e}"))?
        {
            line.clear();
            return Ok(status);
        }
        if !crossterm::event::poll(Duration::from_millis(50))
            .map_err(|e| format!("could not read terminal input: {e}"))?
        {
            continue;
        }
        match crossterm::event::read().map_err(|e| format!("could not read terminal input: {e}"))? {
            crossterm::event::Event::Key(event)
                if matches!(
                    event.kind,
                    crossterm::event::KeyEventKind::Press | crossterm::event::KeyEventKind::Repeat
                ) =>
            {
                use crossterm::event::{KeyCode, KeyModifiers};
                match event.code {
                    KeyCode::Char('c') if event.modifiers.contains(KeyModifiers::CONTROL) => {
                        line.clear();
                        print!("^C\r\n");
                        print_windows_shell_prompt(&cwd)?;
                    }
                    KeyCode::Char('l') if event.modifiers.contains(KeyModifiers::CONTROL) => {
                        crossterm::execute!(
                            std::io::stdout(),
                            crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
                            crossterm::cursor::MoveTo(0, 0)
                        )
                        .map_err(|e| format!("could not clear shell display: {e}"))?;
                        print_windows_shell_prompt(&cwd)?;
                        print!("{}", line.visible());
                        std::io::stdout()
                            .flush()
                            .map_err(|e| format!("could not render shell input: {e}"))?;
                    }
                    KeyCode::Char('d')
                        if event.modifiers.contains(KeyModifiers::CONTROL)
                            && line.units.is_empty() =>
                    {
                        child
                            .kill()
                            .map_err(|e| format!("could not stop PowerShell: {e}"))?;
                        return child
                            .wait()
                            .map_err(|e| format!("could not wait for PowerShell: {e}"));
                    }
                    KeyCode::Enter | KeyCode::Char('\r') | KeyCode::Char('\n') => {
                        let mut raw = line.raw();
                        print!("\r\n");
                        std::io::stdout()
                            .flush()
                            .map_err(|e| format!("could not render shell input: {e}"))?;
                        let mut paste = protector.prepare_paste(&raw)?;
                        raw.zeroize();
                        let mut child_command = line.take_injected_prefixes();
                        child_command.push_str(&paste.child);
                        line.clear();
                        let mut encoded = data_encoding::BASE64.encode(child_command.as_bytes());
                        child_stdin
                            .write_all(encoded.as_bytes())
                            .and_then(|_| child_stdin.write_all(b"\n"))
                            .and_then(|_| child_stdin.flush())
                            .map_err(|e| format!("could not write PowerShell input: {e}"))?;
                        encoded.zeroize();
                        child_command.zeroize();
                        paste.child.zeroize();
                        paste.injected_prefix.zeroize();
                        match wait_for_windows_shell_completion(
                            child,
                            child_stdin,
                            completion_rx,
                            drain_marker,
                        )? {
                            Some(next_cwd) => {
                                cwd.zeroize();
                                cwd = next_cwd;
                                print_windows_shell_prompt(&cwd)?;
                            }
                            None => {
                                return child
                                    .wait()
                                    .map_err(|e| format!("could not wait for PowerShell: {e}"));
                            }
                        }
                    }
                    KeyCode::Char(ch) => {
                        let mut encoded = [0u8; 4];
                        let text = ch.encode_utf8(&mut encoded);
                        line.push_typed(text);
                        print!("{text}");
                        std::io::stdout()
                            .flush()
                            .map_err(|e| format!("could not render shell input: {e}"))?;
                    }
                    KeyCode::Backspace => {
                        if let Some(width) = line.backspace() {
                            for _ in 0..width {
                                print!("\x08 \x08");
                            }
                            std::io::stdout()
                                .flush()
                                .map_err(|e| format!("could not render shell input: {e}"))?;
                        }
                    }
                    _ => {}
                }
            }
            crossterm::event::Event::Paste(mut text) => {
                let paste = protector.prepare_paste(&text)?;
                let visible = single_line_shell_display(&paste.visible);
                line.push_paste(
                    std::mem::take(&mut text),
                    visible.clone(),
                    paste.injected_prefix,
                );
                print!("{visible}");
                std::io::stdout()
                    .flush()
                    .map_err(|e| format!("could not render pasted input: {e}"))?;
            }
            _ => {}
        }
    }
}

#[cfg(any())]
fn wait_for_windows_shell_completion_legacy(
    child: &mut std::process::Child,
    child_stdin: &mut std::process::ChildStdin,
    completion_rx: &mpsc::Receiver<WindowsShellCompletion>,
    drain_marker: &str,
) -> Result<Option<String>, String> {
    let mut input = WindowsRunningInput::default();
    loop {
        match completion_rx.try_recv() {
            Ok(WindowsShellCompletion::DrainInput) => {
                input.clear();
                child_stdin
                    .write_all(b"\r\n")
                    .and_then(|_| child_stdin.write_all(drain_marker.as_bytes()))
                    .and_then(|_| child_stdin.write_all(b"\r\n"))
                    .and_then(|_| child_stdin.flush())
                    .map_err(|e| format!("could not drain PowerShell input: {e}"))?;
            }
            Ok(WindowsShellCompletion::Complete(cwd)) => return Ok(Some(cwd)),
            Err(mpsc::TryRecvError::Empty) => {
                if child
                    .try_wait()
                    .map_err(|e| format!("could not poll PowerShell: {e}"))?
                    .is_some()
                {
                    return Ok(None);
                }
            }
            Err(mpsc::TryRecvError::Disconnected) => return Ok(None),
        }
        if crossterm::event::poll(Duration::from_millis(50))
            .map_err(|e| format!("could not read terminal input: {e}"))?
        {
            let event = crossterm::event::read()
                .map_err(|e| format!("could not read terminal input: {e}"))?;
            forward_windows_running_input(event, child_stdin, &mut input)?;
        }
    }
}

#[cfg(any())]
#[derive(Default)]
struct WindowsRunningInput {
    pending: String,
}

#[cfg(any())]
impl WindowsRunningInput {
    fn clear(&mut self) {
        self.pending.zeroize();
        self.pending.clear();
    }

    fn submit(&mut self, child_stdin: &mut dyn Write) -> Result<(), String> {
        child_stdin
            .write_all(self.pending.as_bytes())
            .and_then(|_| child_stdin.write_all(b"\r\n"))
            .and_then(|_| child_stdin.flush())
            .map_err(|e| format!("could not write PowerShell input: {e}"))?;
        self.clear();
        Ok(())
    }

    fn paste(&mut self, text: &str, child_stdin: &mut dyn Write) -> Result<(), String> {
        let mut chars = text.chars().peekable();
        while let Some(ch) = chars.next() {
            if matches!(ch, '\r' | '\n') {
                if ch == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                self.submit(child_stdin)?;
            } else {
                self.pending.push(ch);
            }
        }
        Ok(())
    }
}

#[cfg(any())]
fn forward_windows_running_input(
    event: crossterm::event::Event,
    child_stdin: &mut dyn Write,
    input: &mut WindowsRunningInput,
) -> Result<(), String> {
    use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};

    match event {
        Event::Paste(text) => input.paste(&text, child_stdin),
        Event::Key(event) if matches!(event.kind, KeyEventKind::Press | KeyEventKind::Repeat) => {
            match event.code {
                KeyCode::Char('c') if event.modifiers.contains(KeyModifiers::CONTROL) => {
                    input.clear();
                    child_stdin
                        .write_all(&[0x03])
                        .and_then(|_| child_stdin.flush())
                        .map_err(|e| format!("could not write PowerShell input: {e}"))
                }
                KeyCode::Char(ch) => {
                    input.pending.push(ch);
                    Ok(())
                }
                KeyCode::Enter => input.submit(child_stdin),
                KeyCode::Backspace => {
                    input.pending.pop();
                    Ok(())
                }
                KeyCode::Tab => {
                    input.pending.push('\t');
                    Ok(())
                }
                _ => Ok(()),
            }
        }
        _ => Ok(()),
    }
}

#[cfg(any())]
fn print_windows_shell_prompt(cwd: &str) -> Result<(), String> {
    let display = compact_windows_shell_cwd(cwd);
    print!("PS {display}> ");
    std::io::stdout()
        .flush()
        .map_err(|e| format!("could not render shell prompt: {e}"))
}

#[cfg(windows)]
fn compact_windows_shell_cwd(cwd: &str) -> String {
    let Some(home) = std::env::var_os("USERPROFILE") else {
        return cwd.to_string();
    };
    compact_windows_shell_cwd_with_home(cwd, &home.to_string_lossy())
}

#[cfg(windows)]
fn compact_windows_shell_cwd_with_home(cwd: &str, home: &str) -> String {
    if cwd.eq_ignore_ascii_case(home) {
        return "~".to_string();
    }
    cwd.get(home.len()..)
        .filter(|tail| {
            cwd[..home.len()].eq_ignore_ascii_case(home)
                && (tail.starts_with('\\') || tail.starts_with('/'))
        })
        .map(|tail| format!("~{tail}"))
        .unwrap_or_else(|| cwd.to_string())
}

#[cfg(any())]
fn single_line_shell_display(text: &str) -> String {
    text.replace("\r\n", " ↵ ").replace(['\r', '\n'], " ↵ ")
}

#[cfg(any())]
struct BracketedPasteGuard;

#[cfg(any())]
impl BracketedPasteGuard {
    fn enable() -> Result<Self, String> {
        crossterm::execute!(std::io::stdout(), crossterm::event::EnableBracketedPaste)
            .map_err(|e| format!("could not enable protected paste: {e}"))?;
        Ok(Self)
    }
}

#[cfg(any())]
impl Drop for BracketedPasteGuard {
    fn drop(&mut self) {
        let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableBracketedPaste);
    }
}

fn run_masked_shell_pipe(
    store: MemoryStore,
    opts: &ShellOpts,
    shim: &ShellShimDir,
) -> Result<i32, String> {
    let mut command = match &opts.program {
        Some(program) => shell_program_command(program)?,
        None => interactive_shell_pipe_command(),
    };
    apply_child_env_overlays(&mut command, &[], &opts.session);
    apply_active_memory_store_env(&mut command);
    shim.apply_to_command(&mut command);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("could not start shell: {e}"))?;
    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "could not open shell stdin".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "could not capture shell stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "could not capture shell stderr".to_string())?;
    let stdout_store = store.clone();
    let stderr_store = store.clone();
    let stdout_thread = std::thread::spawn(move || {
        stream_masked_reader_deferred(stdout_store, stdout, StreamTarget::Stdout)
    });
    let stderr_thread = std::thread::spawn(move || {
        stream_masked_reader_deferred(stderr_store, stderr, StreamTarget::Stderr)
    });
    let status = if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        pump_masked_terminal_stdin(&mut child, child_stdin, store.clone())?
    } else {
        pump_plain_stdin_until_exit(&mut child, child_stdin)?
    };
    join_stream_thread(stdout_thread)?;
    join_stream_thread(stderr_thread)?;
    Ok(exit_code(status))
}

fn run_masked_shell_pty(
    store: MemoryStore,
    opts: &ShellOpts,
    shim: &ShellShimDir,
) -> Result<i32, String> {
    let shell = match &opts.program {
        Some(program) => shell_program_argv(program)?,
        None => interactive_shell_pty_program(),
    };
    let pty_system = native_pty_system();
    let (cols, rows) = current_pty_size();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("could not start pty: {e}"))?;
    let mut command = CommandBuilder::new(&shell.command);
    command.args(&shell.args);
    let cwd = std::env::current_dir().map_err(|e| format!("could not read current dir: {e}"))?;
    command.cwd(cwd.as_os_str());
    apply_shell_env_builder(&mut command, &opts.session, shim);
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|e| format!("could not start shell: {e}"))?;
    drop(pair.slave);
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("could not capture shell output: {e}"))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|e| format!("could not open shell input: {e}"))?;
    let writer = Arc::new(Mutex::new(writer));
    let suppressor = PtyEchoSuppressor::default();
    let output_store = store.clone();
    let output_suppressor = suppressor.clone();
    let terminal_responder = writer.clone();
    let output_thread = std::thread::spawn(move || {
        let mut masker = OutputMasker::new_deferred(output_store)?;
        stream_masked_pty_reader(&mut masker, reader, output_suppressor, terminal_responder)?;
        masker.flush()
    });
    let status = pump_masked_pty_terminal_stdin(
        child.as_mut(),
        writer,
        store,
        suppressor,
        pair.master.as_ref(),
        (cols, rows),
    )?;
    drop(pair.master);
    join_stream_thread(output_thread)?;
    Ok(pty_exit_code(status))
}

fn current_pty_size() -> (u16, u16) {
    select_pty_size(
        observed_terminal_size(),
        pty_dimension_from_env("COLUMNS"),
        pty_dimension_from_env("LINES"),
    )
}

fn observed_terminal_size() -> Option<(u16, u16)> {
    crossterm::terminal::size()
        .ok()
        .filter(|(cols, rows)| *cols >= 2 && *rows >= 2)
}

fn select_pty_size(
    terminal: Option<(u16, u16)>,
    env_cols: Option<u16>,
    env_rows: Option<u16>,
) -> (u16, u16) {
    let terminal = terminal.filter(|(cols, rows)| *cols >= 2 && *rows >= 2);
    let cols = terminal.map(|size| size.0).or(env_cols).unwrap_or(120);
    let rows = terminal.map(|size| size.1).or(env_rows).unwrap_or(30);
    (cols, rows)
}

fn pty_dimension_from_env(name: &str) -> Option<u16> {
    std::env::var(name)
        .ok()?
        .parse::<u16>()
        .ok()
        .filter(|value| *value >= 2)
}

fn shell_program_command(program: &[String]) -> Result<Command, String> {
    let Some((command, args)) = program.split_first() else {
        return Err("shell requires PROGRAM after `--`".to_string());
    };
    let mut cmd = Command::new(command);
    cmd.args(args);
    Ok(cmd)
}

struct ShellProgram {
    command: OsString,
    args: Vec<OsString>,
}

fn shell_program_argv(program: &[String]) -> Result<ShellProgram, String> {
    let Some((command, args)) = program.split_first() else {
        return Err("shell requires PROGRAM after `--`".to_string());
    };
    Ok(ShellProgram {
        command: OsString::from(command),
        args: args.iter().map(OsString::from).collect(),
    })
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

#[cfg(windows)]
fn interactive_shell_pipe_command() -> Command {
    let shell = windows_powershell_path();
    let mut cmd = Command::new(shell);
    cmd.arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-Command")
        .arg("-");
    cmd
}

#[cfg(windows)]
fn interactive_shell_pty_program() -> ShellProgram {
    ShellProgram {
        command: windows_powershell_path().into_os_string(),
        args: vec![
            OsString::from("-NoLogo"),
            OsString::from("-NoProfile"),
            OsString::from("-NoExit"),
            OsString::from("-Command"),
            OsString::from("try { Set-PSReadLineOption -HistorySaveStyle SaveNothing } catch {}"),
        ],
    }
}

#[cfg(not(windows))]
fn interactive_shell_path() -> PathBuf {
    std::env::var_os("SHELL")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| {
            Path::new("/bin/sh")
                .is_file()
                .then(|| PathBuf::from("/bin/sh"))
        })
        .unwrap_or_else(|| PathBuf::from("sh"))
}

#[cfg(not(windows))]
fn interactive_shell_pipe_command() -> Command {
    let shell = interactive_shell_path();
    let mut cmd = Command::new(shell);
    cmd.arg("-i");
    cmd
}

#[cfg(not(windows))]
fn interactive_shell_pty_program() -> ShellProgram {
    let shell = std::env::var_os("SHELL")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| {
            Path::new("/bin/sh")
                .is_file()
                .then(|| PathBuf::from("/bin/sh"))
        })
        .unwrap_or_else(|| PathBuf::from("sh"));
    ShellProgram {
        command: shell.into_os_string(),
        args: vec![OsString::from("-i")],
    }
}

fn pump_plain_stdin_until_exit(
    child: &mut std::process::Child,
    mut child_stdin: std::process::ChildStdin,
) -> Result<ExitStatus, String> {
    let stdin_thread = std::thread::spawn(move || -> Result<(), String> {
        let mut input = std::io::stdin().lock();
        std::io::copy(&mut input, &mut child_stdin)
            .map(|_| ())
            .map_err(|e| format!("could not write shell stdin: {e}"))
    });
    let status = child
        .wait()
        .map_err(|e| format!("could not wait for shell: {e}"))?;
    match stdin_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("shell stdin thread panicked".to_string()),
    }
    Ok(status)
}

fn pump_masked_terminal_stdin(
    child: &mut std::process::Child,
    mut child_stdin: std::process::ChildStdin,
    store: MemoryStore,
) -> Result<ExitStatus, String> {
    let _raw = RawModeGuard::enable()?;
    let mut line_stars = 0usize;
    let mut protector = ShellInputProtector::new(store)?;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("could not poll shell: {e}"))?
        {
            return Ok(status);
        }
        if !crossterm::event::poll(Duration::from_millis(50))
            .map_err(|e| format!("could not read terminal input: {e}"))?
        {
            continue;
        }
        match crossterm::event::read().map_err(|e| format!("could not read terminal input: {e}"))? {
            crossterm::event::Event::Key(event) => {
                if !forward_masked_key(event, &mut child_stdin, &mut line_stars)? {
                    drop(child_stdin);
                    return child
                        .wait()
                        .map_err(|e| format!("could not wait for shell: {e}"));
                }
            }
            crossterm::event::Event::Paste(text) => {
                forward_masked_text(
                    &text,
                    &mut child_stdin,
                    &mut line_stars,
                    &mut protector,
                    ShellInputEcho::Masked,
                    None,
                )?;
            }
            _ => {}
        }
    }
}

fn pump_masked_pty_terminal_stdin(
    child: &mut dyn PtyChild,
    child_stdin: Arc<Mutex<Box<dyn Write + Send>>>,
    store: MemoryStore,
    suppressor: PtyEchoSuppressor,
    master: &dyn MasterPty,
    mut pty_size: (u16, u16),
) -> Result<portable_pty::ExitStatus, String> {
    let _raw = RawModeGuard::enable()?;
    let mut protector = ShellInputProtector::new(store)?;
    let (input_tx, input_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        let mut buf = [0u8; 8192];
        loop {
            match input.read(&mut buf) {
                Ok(0) => {
                    let _ = input_tx.send(Vec::new());
                    break;
                }
                Ok(n) => {
                    if input_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = input_tx.send(Vec::new());
                    break;
                }
            }
        }
    });
    loop {
        sync_pty_size(master, &mut pty_size);
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("could not poll shell: {e}"))?
        {
            return Ok(status);
        }
        match input_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(bytes) if bytes.is_empty() => {
                with_pty_writer(&child_stdin, |writer| {
                    flush_pty_input(writer, &mut protector, &suppressor)
                })?;
                drop(child_stdin);
                return child
                    .wait()
                    .map_err(|e| format!("could not wait for shell: {e}"));
            }
            Ok(bytes) => {
                with_pty_writer(&child_stdin, |writer| {
                    forward_pty_input_bytes(&bytes, writer, &mut protector, &suppressor)
                })?;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                with_pty_writer(&child_stdin, |writer| {
                    flush_pty_input(writer, &mut protector, &suppressor)
                })?;
                drop(child_stdin);
                return child
                    .wait()
                    .map_err(|e| format!("could not wait for shell: {e}"));
            }
        }
    }
}

fn sync_pty_size(master: &dyn MasterPty, current: &mut (u16, u16)) {
    let Some(next) = observed_terminal_size() else {
        return;
    };
    if next == *current {
        return;
    }
    if master
        .resize(PtySize {
            rows: next.1,
            cols: next.0,
            pixel_width: 0,
            pixel_height: 0,
        })
        .is_ok()
    {
        *current = next;
    }
}

fn with_pty_writer<T>(
    writer: &Arc<Mutex<Box<dyn Write + Send>>>,
    action: impl FnOnce(&mut dyn Write) -> Result<T, String>,
) -> Result<T, String> {
    let mut writer = writer
        .lock()
        .map_err(|_| "shell input lock failed".to_string())?;
    action(writer.as_mut())
}

fn forward_masked_key(
    event: crossterm::event::KeyEvent,
    child_stdin: &mut dyn Write,
    line_stars: &mut usize,
) -> Result<bool, String> {
    if !matches!(
        event.kind,
        crossterm::event::KeyEventKind::Press | crossterm::event::KeyEventKind::Repeat
    ) {
        return Ok(true);
    }
    match event.code {
        crossterm::event::KeyCode::Char('c')
            if event
                .modifiers
                .contains(crossterm::event::KeyModifiers::CONTROL) =>
        {
            child_stdin
                .write_all(&[0x03])
                .map_err(|e| format!("could not write shell stdin: {e}"))?;
            print!("\r\n");
            *line_stars = 0;
        }
        crossterm::event::KeyCode::Char('d')
            if event
                .modifiers
                .contains(crossterm::event::KeyModifiers::CONTROL) =>
        {
            return Ok(false);
        }
        crossterm::event::KeyCode::Char(ch) => {
            let mut buf = [0u8; 4];
            let text = ch.encode_utf8(&mut buf);
            child_stdin
                .write_all(text.as_bytes())
                .map_err(|e| format!("could not write shell stdin: {e}"))?;
            echo_masked_input(1)?;
            *line_stars += 1;
        }
        crossterm::event::KeyCode::Enter => {
            if cfg!(windows) {
                child_stdin
                    .write_all(b"\r\n")
                    .map_err(|e| format!("could not write shell stdin: {e}"))?;
            } else {
                child_stdin
                    .write_all(b"\n")
                    .map_err(|e| format!("could not write shell stdin: {e}"))?;
            }
            print!("\r\n");
            std::io::stdout()
                .flush()
                .map_err(|e| format!("could not flush terminal input: {e}"))?;
            *line_stars = 0;
        }
        crossterm::event::KeyCode::Backspace => {
            child_stdin
                .write_all(&[0x08])
                .map_err(|e| format!("could not write shell stdin: {e}"))?;
            if *line_stars > 0 {
                print!("\x08 \x08");
                std::io::stdout()
                    .flush()
                    .map_err(|e| format!("could not flush terminal input: {e}"))?;
                *line_stars -= 1;
            }
        }
        crossterm::event::KeyCode::Tab => {
            child_stdin
                .write_all(b"\t")
                .map_err(|e| format!("could not write shell stdin: {e}"))?;
            echo_masked_input(1)?;
            *line_stars += 1;
        }
        crossterm::event::KeyCode::Esc => {
            child_stdin
                .write_all(&[0x1b])
                .map_err(|e| format!("could not write shell stdin: {e}"))?;
            echo_masked_input(1)?;
            *line_stars += 1;
        }
        _ => {}
    }
    child_stdin
        .flush()
        .map_err(|e| format!("could not flush shell stdin: {e}"))?;
    Ok(true)
}

fn forward_pty_input_bytes(
    bytes: &[u8],
    child_stdin: &mut dyn Write,
    protector: &mut ShellInputProtector,
    suppressor: &PtyEchoSuppressor,
) -> Result<(), String> {
    protector.pty_pending.extend_from_slice(bytes);
    if protector.pty_pending.len() > PTY_PASTE_MAX_PENDING_BYTES {
        return Err("pasted input is too large".to_string());
    }
    loop {
        if protector.in_bracketed_paste {
            let Some(end) = find_input_bytes(&protector.pty_pending, BRACKETED_PASTE_END) else {
                return Ok(());
            };
            let mut content: Vec<u8> = protector.pty_pending.drain(..end).collect();
            let text = match std::str::from_utf8(&content) {
                Ok(text) => text,
                Err(_) => {
                    content.zeroize();
                    return Err("pasted input must be UTF-8 text".to_string());
                }
            };
            let mut line_stars = 0usize;
            forward_masked_text(
                text,
                child_stdin,
                &mut line_stars,
                protector,
                ShellInputEcho::Native,
                Some(suppressor),
            )?;
            content.zeroize();
            protector.pty_pending.drain(..BRACKETED_PASTE_END.len());
            child_stdin
                .write_all(BRACKETED_PASTE_END)
                .map_err(|e| format!("could not write shell stdin: {e}"))?;
            protector.in_bracketed_paste = false;
            continue;
        }

        if let Some(start) = find_input_bytes(&protector.pty_pending, BRACKETED_PASTE_START) {
            let mut before: Vec<u8> = protector.pty_pending.drain(..start).collect();
            forward_pty_plain_bytes(&before, child_stdin, protector, suppressor)?;
            before.zeroize();
            protector.pty_pending.drain(..BRACKETED_PASTE_START.len());
            child_stdin
                .write_all(BRACKETED_PASTE_START)
                .map_err(|e| format!("could not write shell stdin: {e}"))?;
            protector.in_bracketed_paste = true;
            continue;
        }

        let keep = partial_input_prefix_len(&protector.pty_pending, BRACKETED_PASTE_START);
        let emit_len = protector.pty_pending.len().saturating_sub(keep);
        if emit_len > 0 {
            let mut plain: Vec<u8> = protector.pty_pending.drain(..emit_len).collect();
            forward_pty_plain_bytes(&plain, child_stdin, protector, suppressor)?;
            plain.zeroize();
        }
        child_stdin
            .flush()
            .map_err(|e| format!("could not flush shell stdin: {e}"))?;
        return Ok(());
    }
}

fn forward_pty_plain_bytes(
    bytes: &[u8],
    child_stdin: &mut dyn Write,
    protector: &mut ShellInputProtector,
    suppressor: &PtyEchoSuppressor,
) -> Result<(), String> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if should_protect_pty_input_text(text) {
            let mut line_stars = 0usize;
            return forward_masked_text(
                text,
                child_stdin,
                &mut line_stars,
                protector,
                ShellInputEcho::Native,
                Some(suppressor),
            );
        }
    }
    child_stdin
        .write_all(bytes)
        .map_err(|e| format!("could not write shell stdin: {e}"))
}

fn flush_pty_input(
    child_stdin: &mut dyn Write,
    protector: &mut ShellInputProtector,
    suppressor: &PtyEchoSuppressor,
) -> Result<(), String> {
    if protector.pty_pending.is_empty() {
        return Ok(());
    }
    let mut pending = std::mem::take(&mut protector.pty_pending);
    if protector.in_bracketed_paste {
        let text = match std::str::from_utf8(&pending) {
            Ok(text) => text,
            Err(_) => {
                pending.zeroize();
                return Err("pasted input must be UTF-8 text".to_string());
            }
        };
        let mut line_stars = 0usize;
        forward_masked_text(
            text,
            child_stdin,
            &mut line_stars,
            protector,
            ShellInputEcho::Native,
            Some(suppressor),
        )?;
    } else {
        forward_pty_plain_bytes(&pending, child_stdin, protector, suppressor)?;
    }
    pending.zeroize();
    protector.in_bracketed_paste = false;
    child_stdin
        .flush()
        .map_err(|e| format!("could not flush shell stdin: {e}"))
}

fn find_input_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn partial_input_prefix_len(bytes: &[u8], prefix: &[u8]) -> usize {
    let max = bytes.len().min(prefix.len().saturating_sub(1));
    (1..=max)
        .rev()
        .find(|len| bytes[bytes.len() - len..] == prefix[..*len])
        .unwrap_or(0)
}

fn should_protect_pty_input_text(text: &str) -> bool {
    text.len() >= 16 && !text.contains('\x1b')
}

#[derive(Clone, Copy)]
enum ShellInputEcho {
    Masked,
    Native,
}

fn forward_masked_text(
    text: &str,
    child_stdin: &mut dyn Write,
    line_stars: &mut usize,
    protector: &mut ShellInputProtector,
    echo: ShellInputEcho,
    suppressor: Option<&PtyEchoSuppressor>,
) -> Result<(), String> {
    let paste = protector.prepare_paste(text)?;
    if let Some(suppressor) = suppressor {
        suppressor.push(paste.injected_prefix);
    }
    child_stdin
        .write_all(paste.child.as_bytes())
        .map_err(|e| format!("could not write shell stdin: {e}"))?;
    match echo {
        ShellInputEcho::Masked if paste.changed => {
            echo_visible_input(&paste.visible)?;
            *line_stars = trailing_line_width(&paste.visible);
        }
        ShellInputEcho::Masked => {
            echo_masked_text(&paste.visible, line_stars)?;
        }
        ShellInputEcho::Native => {}
    }
    child_stdin
        .flush()
        .map_err(|e| format!("could not flush shell stdin: {e}"))
}

fn echo_masked_text(text: &str, line_stars: &mut usize) -> Result<(), String> {
    let mut stars = 0usize;
    for ch in text.chars() {
        if matches!(ch, '\r' | '\n') {
            if stars > 0 {
                echo_masked_input(stars)?;
                stars = 0;
            }
            eprint!("\r\n");
            *line_stars = 0;
        } else {
            stars += 1;
            *line_stars += 1;
        }
    }
    if stars > 0 {
        echo_masked_input(stars)?;
    }
    Ok(())
}

fn echo_visible_input(text: &str) -> Result<(), String> {
    for ch in text.chars() {
        if matches!(ch, '\r' | '\n') {
            eprint!("\r\n");
        } else {
            eprint!("{ch}");
        }
    }
    std::io::stderr()
        .flush()
        .map_err(|e| format!("could not flush terminal input: {e}"))
}

fn echo_masked_input(count: usize) -> Result<(), String> {
    for _ in 0..count {
        eprint!("*");
    }
    std::io::stderr()
        .flush()
        .map_err(|e| format!("could not flush terminal input: {e}"))
}

fn trailing_line_width(text: &str) -> usize {
    text.rsplit(['\r', '\n'])
        .next()
        .unwrap_or("")
        .chars()
        .count()
}

#[derive(Clone, Default)]
struct PtyEchoSuppressor {
    entries: Arc<Mutex<VecDeque<String>>>,
}

impl PtyEchoSuppressor {
    fn push(&self, text: String) {
        if text.is_empty() {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        while entries.len() >= 32 {
            if let Some(mut old) = entries.pop_front() {
                old.zeroize();
            }
        }
        entries.push_back(text);
    }

    fn scrub(&self, text: &mut String) {
        if text.is_empty() {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let mut index = 0;
        while index < entries.len() {
            let found = {
                let entry = &entries[index];
                let mut found = false;
                while let Some(start) = text.find(entry.as_str()) {
                    let end = start + entry.len();
                    text.replace_range(start..end, "");
                    found = true;
                }
                found
            };
            if found {
                if let Some(mut removed) = entries.remove(index) {
                    removed.zeroize();
                }
            } else {
                index += 1;
            }
        }
    }
}

struct ProtectedPaste {
    child: String,
    visible: String,
    changed: bool,
    injected_prefix: String,
}

struct ShellInputProtector {
    masker: Option<OutputMasker>,
    store: MemoryStore,
    syntax: ShellSyntax,
    environment_prefix: String,
    defined_env: BTreeSet<String>,
    pty_pending: Vec<u8>,
    in_bracketed_paste: bool,
}

impl ShellInputProtector {
    fn new(store: MemoryStore) -> Result<Self, String> {
        Ok(Self {
            masker: None,
            store,
            syntax: ShellSyntax::current(),
            environment_prefix: config::environment_variable_prefix()?,
            defined_env: BTreeSet::new(),
            pty_pending: Vec::new(),
            in_bracketed_paste: false,
        })
    }

    fn prepare_paste(&mut self, text: &str) -> Result<ProtectedPaste, String> {
        let referenced = referenced_env_names_in_text(text);
        let available = self.store.auto_env_bindings().map_err(|e| e.to_string())?;
        if stale_env_handle(&referenced, &available, &self.environment_prefix) {
            return Ok(ProtectedPaste {
                child: self.syntax.stale_handle_error(),
                visible: text.to_string(),
                changed: true,
                injected_prefix: String::new(),
            });
        }
        let selected =
            select_referenced_env_bindings(available, &referenced, &self.environment_prefix);
        if self.masker.is_none() {
            self.masker = Some(OutputMasker::new_shell_input(self.store.clone())?);
        }
        let masker = self.masker.as_mut().expect("masker was initialized");
        let masked = masker.mask_text(text, live_output_kind(text))?;
        let (mut visible, mut bindings) = replace_masked_handles_with_env_refs(
            &masked,
            &self.store,
            self.syntax,
            &self.environment_prefix,
        )?;
        restore_safe_shell_literals(text, &mut visible, &mut bindings, self.syntax);
        if bindings.len() == 1 {
            if let Some((start, end)) = likely_shell_secret_range(text) {
                bindings[0].value.zeroize();
                bindings[0].value.push_str(&text[start..end]);
                let env_ref = self.syntax.env_ref(&bindings[0].name);
                visible.clear();
                visible.push_str(&text[..start]);
                visible.push_str(&env_ref);
                visible.push_str(&text[end..]);
            }
        }
        let replaced_secret = !bindings.is_empty();
        let command_text = if replaced_secret { &visible } else { text };
        let mut child = String::new();
        let mut injected_prefix = String::new();
        for mut binding in bindings {
            if self.defined_env.insert(binding.name.clone()) {
                let assignment = self.syntax.env_assignment(&binding.name, &binding.value);
                injected_prefix.push_str(&assignment);
                child.push_str(&assignment);
            }
            binding.value.zeroize();
        }
        for (name, mut value) in selected {
            if self.defined_env.insert(name.clone()) {
                let assignment = self.syntax.env_assignment(&name, &value);
                injected_prefix.push_str(&assignment);
                child.push_str(&assignment);
            }
            value.zeroize();
        }
        child.push_str(command_text);
        Ok(ProtectedPaste {
            child,
            visible: command_text.to_string(),
            changed: replaced_secret || !injected_prefix.is_empty(),
            injected_prefix,
        })
    }
}

fn stale_env_handle(
    referenced: &BTreeSet<String>,
    available: &[(String, String)],
    prefix: &str,
) -> bool {
    let mut current = BTreeSet::new();
    let mut labels = BTreeSet::new();
    for (name, _) in available {
        let Some((label, hash)) = env_handle_name_parts(name, prefix) else {
            continue;
        };
        labels.insert(label.clone());
        current.insert(format!("{label}_{hash}"));
    }
    referenced.iter().any(|name| {
        env_handle_name_parts(name, prefix).is_some_and(|(label, hash)| {
            labels.contains(&label) && !current.contains(&format!("{label}_{hash}"))
        })
    })
}

fn env_handle_name_parts(name: &str, prefix: &str) -> Option<(String, String)> {
    let lower = name.to_ascii_lowercase();
    let prefix = prefix.to_ascii_lowercase();
    let core = lower.strip_prefix(&prefix).unwrap_or(&lower);
    let (label, hash) = core.rsplit_once('_')?;
    if label.is_empty()
        || hash.len() != 16
        || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return None;
    }
    Some((label.to_string(), hash.to_string()))
}

fn restore_safe_shell_literals(
    original: &str,
    visible: &mut String,
    bindings: &mut Vec<ShellEnvBinding>,
    syntax: ShellSyntax,
) {
    let mut index = 0usize;
    while index < bindings.len() {
        let value = bindings[index].value.as_str();
        let is_existing_env_ref = !referenced_env_names_in_text(value).is_empty();
        let is_public_url = (value.starts_with("https://") || value.starts_with("http://"))
            && !value.chars().any(|ch| matches!(ch, '@' | '?' | '#'));
        if original.contains(value) && (is_existing_env_ref || is_public_url) {
            let binding = bindings.remove(index);
            *visible = visible.replace(&syntax.env_ref(&binding.name), &binding.value);
        } else {
            index += 1;
        }
    }
}

fn referenced_env_names_in_text(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    collect_powershell_env_refs(text, &mut names);
    collect_powershell_env_provider_refs(text, &mut names);
    collect_printenv_refs(text, &mut names);
    collect_percent_env_refs(text, &mut names);
    collect_bare_dollar_env_refs(text, &mut names);
    names
}

#[derive(Clone, Copy)]
enum ShellSyntax {
    PowerShell,
    Posix,
}

impl ShellSyntax {
    fn current() -> Self {
        if cfg!(windows) {
            Self::PowerShell
        } else {
            Self::Posix
        }
    }

    fn env_ref(self, name: &str) -> String {
        match self {
            Self::PowerShell => format!("$env:{name}"),
            Self::Posix => format!("${{{name}}}"),
        }
    }

    fn env_assignment(self, name: &str, value: &str) -> String {
        match self {
            Self::PowerShell => {
                format!("$env:{name}={}; ", powershell_string_literal(value))
            }
            Self::Posix => format!("export {name}={}; ", shell_quote_unix(value)),
        }
    }

    fn stale_handle_error(self) -> String {
        const MESSAGE: &str =
            "Pentect: stale environment handle; run cat .env again and use the new handle.";
        match self {
            Self::PowerShell => format!("Write-Error {}", powershell_string_literal(MESSAGE)),
            Self::Posix => format!("printf '%s\\n' {} >&2", shell_quote_unix(MESSAGE)),
        }
    }
}

struct ShellEnvBinding {
    name: String,
    value: String,
}

fn masked_handles_in_text(text: &str) -> Vec<String> {
    let mut handles = Vec::new();
    let mut cursor = 0;
    while let Some(relative_start) = text[cursor..].find("<<") {
        let start = cursor + relative_start;
        let Some(relative_end) = text[start + 2..].find(">>") else {
            break;
        };
        let end = start + 2 + relative_end + 2;
        let candidate = &text[start..end];
        if parse_placeholder(candidate).is_ok() && !handles.iter().any(|item| item == candidate) {
            handles.push(candidate.to_string());
        }
        cursor = end;
    }
    handles
}

fn replace_masked_handles_with_env_refs(
    masked: &str,
    store: &MemoryStore,
    syntax: ShellSyntax,
    environment_prefix: &str,
) -> Result<(String, Vec<ShellEnvBinding>), String> {
    let handles = masked_handles_in_text(masked);
    if handles.is_empty() {
        return Ok((masked.to_string(), Vec::new()));
    }
    let mut out = masked.to_string();
    let mut bindings = Vec::new();
    for handle in handles {
        let Ok(parts) = parse_placeholder(&handle) else {
            continue;
        };
        let name = format!("{environment_prefix}{}_{}", parts.label, parts.hash);
        let mut value = store.resolve_all(&handle).map_err(|e| e.to_string())?;
        if value == handle {
            value.zeroize();
            continue;
        }
        out = out.replace(&handle, &syntax.env_ref(&name));
        bindings.push(ShellEnvBinding { name, value });
    }
    Ok((out, bindings))
}

fn apply_active_memory_store_env(command: &mut Command) {
    if !active_memory_store_ready() {
        return;
    }
    let (Some(addr), Some(token)) = (std::env::var_os(ENV_ADDR), std::env::var_os(ENV_TOKEN))
    else {
        return;
    };
    if addr.is_empty() || token.is_empty() {
        return;
    }
    command.env(ENV_ADDR, addr);
    command.env(ENV_TOKEN, &token);
    command.env(PENTECT_AGENT_LAUNCHED_ENV, token);
}

fn apply_shell_env_builder(command: &mut CommandBuilder, _session: &str, shim: &ShellShimDir) {
    for name in pentect_control_env_names() {
        command.env_remove(name);
    }
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(is_pentect_control_env_name) {
            command.env_remove(name);
        }
    }
    command.env_remove(ENV_ADDR);
    command.env_remove(ENV_TOKEN);
    command.env_remove("PENTECT_PROCESS_HOST_ROOT");
    command.env_remove(PENTECT_AGENT_LAUNCHED_ENV);
    if active_memory_store_ready() {
        let (Some(addr), Some(token)) = (std::env::var_os(ENV_ADDR), std::env::var_os(ENV_TOKEN))
        else {
            shim.apply_to_builder(command);
            return;
        };
        if !addr.is_empty() && !token.is_empty() {
            command.env(ENV_ADDR, addr);
            command.env(ENV_TOKEN, &token);
            command.env(PENTECT_AGENT_LAUNCHED_ENV, token);
        }
    }
    shim.apply_to_builder(command);
}

struct RawModeGuard {
    #[cfg(windows)]
    previous: Option<(*mut std::ffi::c_void, u32)>,
}

impl RawModeGuard {
    fn enable() -> Result<Self, String> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Console::{
                GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
                ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT, STD_INPUT_HANDLE,
            };

            let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
            let mut previous = 0;
            if unsafe { GetConsoleMode(handle, &mut previous) } == 0 {
                return Ok(Self { previous: None });
            }
            let mode = (previous
                & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
                | ENABLE_VIRTUAL_TERMINAL_INPUT;
            if unsafe { SetConsoleMode(handle, mode) } == 0 {
                return Err("could not enter raw terminal mode".to_string());
            }
            Ok(Self {
                previous: Some((handle, previous)),
            })
        }
        #[cfg(not(windows))]
        {
            crossterm::terminal::enable_raw_mode()
                .map_err(|e| format!("could not enter raw terminal mode: {e}"))?;
            Ok(Self {})
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some((handle, mode)) = self.previous {
            unsafe {
                let _ = windows_sys::Win32::System::Console::SetConsoleMode(handle, mode);
            }
        }
        #[cfg(not(windows))]
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

struct ShellShimDir {
    path: PathBuf,
    pentect: PathBuf,
}

impl ShellShimDir {
    fn install() -> Result<Self, String> {
        let exe = std::env::current_exe()
            .map_err(|e| format!("could not locate pentect executable: {e}"))?;
        let path = create_shell_shim_dir()?;
        Self::install_at(path, &exe)
    }

    fn install_at(path: PathBuf, pentect: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("could not create shell shim dir '{}': {e}", path.display()))?;
        write_tool_shim(&path, "codex")?;
        write_tool_shim(&path, "claude")?;
        let shim = Self {
            path,
            pentect: pentect.to_path_buf(),
        };
        Ok(shim)
    }

    fn apply_to_command(&self, command: &mut Command) {
        command.env("PENTECT_SHELL_BIN", &self.pentect);
        command.env("PENTECT_SHELL", "1");
        command.env(path_env_key(), prepended_path_value(&self.path));
    }

    fn apply_to_builder(&self, command: &mut CommandBuilder) {
        command.env("PENTECT_SHELL_BIN", &self.pentect);
        command.env("PENTECT_SHELL", "1");
        command.env(path_env_key(), prepended_path_value(&self.path));
    }
}

impl Drop for ShellShimDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn create_shell_shim_dir() -> Result<PathBuf, String> {
    let base = std::env::temp_dir();
    for _ in 0..16 {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| format!("could not generate shell shim name: {e}"))?;
        let name = format!("pentect-shell-{}", data_encoding::HEXLOWER.encode(&bytes));
        let path = base.join(name);
        match std::fs::create_dir(&path) {
            Ok(()) => {
                secure_shell_shim_dir_permissions(&path)?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "could not create shell shim dir '{}': {e}",
                    path.display()
                ));
            }
        }
    }
    Err("could not allocate shell shim dir".to_string())
}

#[cfg(unix)]
fn secure_shell_shim_dir_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .map_err(|e| format!("could not stat shell shim dir '{}': {e}", path.display()))?
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
        .map_err(|e| format!("could not chmod shell shim dir '{}': {e}", path.display()))
}

#[cfg(not(unix))]
fn secure_shell_shim_dir_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn write_tool_shim(dir: &Path, tool: &str) -> Result<(), String> {
    let path = dir.join(format!("{tool}.cmd"));
    let content = format!("@echo off\r\n\"%PENTECT_SHELL_BIN%\" {tool} %*\r\n");
    std::fs::write(&path, content)
        .map_err(|e| format!("could not write shell shim '{}': {e}", path.display()))
}

#[cfg(not(windows))]
fn write_tool_shim(dir: &Path, tool: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let path = dir.join(tool);
    let content = format!("#!/bin/sh\nexec \"$PENTECT_SHELL_BIN\" {tool} \"$@\"\n");
    std::fs::write(&path, content)
        .map_err(|e| format!("could not write shell shim '{}': {e}", path.display()))?;
    let mut permissions = std::fs::metadata(&path)
        .map_err(|e| format!("could not stat shell shim '{}': {e}", path.display()))?
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions)
        .map_err(|e| format!("could not chmod shell shim '{}': {e}", path.display()))
}

fn prepended_path_value(path: &Path) -> OsString {
    let mut value = std::ffi::OsString::from(path.as_os_str());
    if let Some(existing) = std::env::var_os("PATH") {
        value.push(if cfg!(windows) { ";" } else { ":" });
        value.push(existing);
    }
    value
}

fn path_env_key() -> &'static str {
    if cfg!(windows) {
        "Path"
    } else {
        "PATH"
    }
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

fn deferred_masker<'a>(
    masker: &'a mut Option<OutputMasker>,
    store: &MemoryStore,
) -> Result<&'a mut OutputMasker, String> {
    if masker.is_none() {
        *masker = Some(OutputMasker::new_deferred(store.clone())?);
    }
    Ok(masker.as_mut().expect("masker was initialized"))
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

enum PtyReadEvent {
    Data(Vec<u8>),
    Eof,
    Error(String),
}

fn stream_masked_pty_reader(
    masker: &mut OutputMasker,
    mut reader: Box<dyn Read + Send>,
    suppressor: PtyEchoSuppressor,
    terminal_responder: Arc<Mutex<Box<dyn Write + Send>>>,
) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let reader_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.send(PtyReadEvent::Eof);
                    break;
                }
                Ok(n) => {
                    if tx.send(PtyReadEvent::Data(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(PtyReadEvent::Error(format!(
                        "could not read shell output: {e}"
                    )));
                    break;
                }
            }
        }
    });
    let mut pending = String::new();
    let mut read_error = None;
    loop {
        match rx.recv_timeout(PTY_PARTIAL_FLUSH_TIMEOUT) {
            Ok(PtyReadEvent::Data(bytes)) => {
                pending.push_str(&String::from_utf8_lossy(&bytes));
                respond_to_terminal_queries(&mut pending, &terminal_responder)?;
                flush_pty_complete_lines(masker, &suppressor, &mut pending)?;
                flush_pty_large_prefix(masker, &suppressor, &mut pending)?;
            }
            Ok(PtyReadEvent::Eof) => break,
            Ok(PtyReadEvent::Error(e)) => {
                read_error = Some(e);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if should_flush_pty_partial(&pending) {
                    flush_pty_text(masker, &suppressor, &mut pending)?;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if !pending.is_empty() {
        flush_pty_text(masker, &suppressor, &mut pending)?;
    }
    match reader_thread.join() {
        Ok(()) => {}
        Err(_) => return Err("pty output reader thread panicked".to_string()),
    }
    if let Some(e) = read_error {
        return Err(e);
    }
    Ok(())
}

fn respond_to_terminal_queries(
    pending: &mut String,
    writer: &Arc<Mutex<Box<dyn Write + Send>>>,
) -> Result<(), String> {
    while let Some(start) = pending.find("\x1b[6n") {
        pending.replace_range(start..start + 4, "");
        with_pty_writer(writer, |writer| {
            writer
                .write_all(b"\x1b[1;1R")
                .and_then(|_| writer.flush())
                .map_err(|e| format!("could not answer shell terminal query: {e}"))
        })?;
    }
    while let Some(start) = pending.find("\x1b[5n") {
        pending.replace_range(start..start + 4, "");
        with_pty_writer(writer, |writer| {
            writer
                .write_all(b"\x1b[0n")
                .and_then(|_| writer.flush())
                .map_err(|e| format!("could not answer shell terminal query: {e}"))
        })?;
    }
    Ok(())
}

fn flush_pty_complete_lines(
    masker: &mut OutputMasker,
    suppressor: &PtyEchoSuppressor,
    pending: &mut String,
) -> Result<(), String> {
    while let Some(index) = pending.find('\n') {
        let mut line: String = pending.drain(..=index).collect();
        flush_pty_text(masker, suppressor, &mut line)?;
    }
    Ok(())
}

fn flush_pty_large_prefix(
    masker: &mut OutputMasker,
    suppressor: &PtyEchoSuppressor,
    pending: &mut String,
) -> Result<(), String> {
    if pending.len() <= PTY_PARTIAL_FLUSH_BYTES {
        return Ok(());
    }
    let mut split = pending.len().saturating_sub(PTY_PARTIAL_TAIL_BYTES);
    while split > 0 && !pending.is_char_boundary(split) {
        split -= 1;
    }
    if split == 0 {
        return Ok(());
    }
    let mut prefix: String = pending.drain(..split).collect();
    flush_pty_text(masker, suppressor, &mut prefix)
}

fn should_flush_pty_partial(pending: &str) -> bool {
    !pending.is_empty()
        && !is_terminal_query_prefix(pending.as_bytes())
        && (pending.contains('\x1b')
            || pending.len() >= 256
            || pending.ends_with("> ")
            || pending.ends_with("$ ")
            || pending.ends_with("# ")
            || pending.ends_with(": ")
            || pending.ends_with("? "))
}

fn is_terminal_query_prefix(pending: &[u8]) -> bool {
    [b"\x1b[5n".as_slice(), b"\x1b[6n".as_slice()]
        .iter()
        .any(|query| pending.len() < query.len() && query.starts_with(pending))
}

fn flush_pty_text(
    masker: &mut OutputMasker,
    suppressor: &PtyEchoSuppressor,
    chunk: &mut String,
) -> Result<(), String> {
    suppressor.scrub(chunk);
    if chunk.is_empty() {
        return Ok(());
    }
    let kind = live_output_kind(chunk);
    flush_masked_chunk(masker, StreamTarget::Stdout, chunk, kind)
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
    let shell = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| {
            root.join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe")
        })
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from("powershell"));
    let mut cmd = Command::new(shell);
    cmd.arg("-NoProfile").arg("-Command").arg("-");
    cmd
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

fn pty_exit_code(status: portable_pty::ExitStatus) -> i32 {
    i32::try_from(status.exit_code()).unwrap_or(1)
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
                "hook requires a provider after --cli: codex, claude, or generic".to_string()
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

    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Bash => "bash",
            Self::PowerShell => "powershell",
        }
    }
}

#[derive(Debug)]
struct ShellOpts {
    session: String,
    program: Option<Vec<String>>,
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

struct AgentScriptOpts {
    session: String,
    id: String,
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

impl AgentScriptOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut session = default_session_name()?;
        let mut id = None;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--session" => {
                    session = checked_session_name(&value(args, &mut i, "--session")?)
                        .map_err(|error| error.to_string())?;
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                value if id.is_none() => {
                    id = Some(value.to_string());
                    i += 1;
                }
                value => return Err(format!("unexpected agent script argument: {value}")),
            }
        }
        Ok(Self {
            session,
            id: id.ok_or_else(|| "agent script requires an id".to_string())?,
        })
    }
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

impl ShellOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut session = default_session_name()?;
        let mut program = None;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--session" => {
                    session = checked_session_name(&value(args, &mut i, "--session")?)
                        .map_err(|e| e.to_string())?;
                }
                "--" => {
                    let command = args[i + 1..].to_vec();
                    if command.is_empty() {
                        return Err("shell requires PROGRAM after `--`".to_string());
                    }
                    program = Some(command);
                    break;
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                value => {
                    return Err(format!(
                        "unknown argument: {value}; use `pentect shell -- PROGRAM [ARG...]`"
                    ));
                }
            }
        }
        Ok(Self { session, program })
    }
}

impl ExecOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut session = default_session_name()?;
        let mut live = false;
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
                    let script = decode_script_base64(&value(args, &mut i, "--script-b64")?)?;
                    if i < args.len() {
                        return Err(
                            "exec --script-b64 does not accept trailing arguments".to_string()
                        );
                    }
                    return Ok(Self {
                        session: checked_session_name(&session).map_err(|e| e.to_string())?,
                        live,
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
                        script_shell: ScriptShell::Native,
                        mode: ExecMode::Program(command),
                    });
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                _ => {
                    if stdin {
                        return Err("exec --stdin does not accept a command argument".to_string());
                    }
                    return Ok(Self {
                        session: checked_session_name(&session).map_err(|e| e.to_string())?,
                        live,
                        script_shell,
                        mode: ExecMode::Shell(args[i..].join(" ")),
                    });
                }
            }
        }
        if stdin {
            return Ok(Self {
                session: checked_session_name(&session).map_err(|e| e.to_string())?,
                live,
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
            if codex_exec_proxy_owns_shell_output(provider, tool_name) {
                return Ok(json!({}));
            }
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
            if codex_exec_proxy_owns_shell_output(provider, tool_name) {
                return Ok(json!({}));
            }
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
    provider: HookProvider,
    session_name: &str,
    session: &Session,
    tool_name: &str,
    tool_input: &Value,
) -> Result<(Value, bool), String> {
    if is_read_like_tool_name(tool_name) {
        if let Some(updated) = apply_masked_read_before_tool(session, tool_input)? {
            return Ok((updated, true));
        }
    }
    if is_edit_like_tool_name(tool_name) {
        if let Some(updated) = apply_masked_old_edit_before_tool(session, tool_input)? {
            return Ok((updated, true));
        }
    }
    validate_masked_write_before_tool(session, tool_name, tool_input)?;
    if is_shell_tool_name(tool_name) {
        if let Some(command) = tool_input.get("command").and_then(Value::as_str) {
            if let Some(reason) = pentect_human_only_command_reason(command) {
                return Err(reason);
            }
            if codex_exec_proxy_should_own_shell_tool(provider) {
                return Ok((tool_input.clone(), false));
            }
            let command = canonical_hook_shell_command(command)?;
            let mut updated = tool_input.clone();
            if let Some(object) = updated.as_object_mut() {
                object.insert(
                    "command".to_string(),
                    Value::String(wrap_shell_command(
                        provider,
                        session_name,
                        tool_name,
                        &command,
                    )?),
                );
                return Ok((updated, true));
            }
        }
    }
    Ok((tool_input.clone(), false))
}

fn before_tool_updated_input_lazy(
    provider: HookProvider,
    session_name: &str,
    cli: bool,
    tool_name: &str,
    tool_input: &Value,
) -> Result<(Value, bool), String> {
    if is_read_like_tool_name(tool_name) {
        let session = open_hook_session(cli, session_name)?;
        if let Some(updated) = apply_masked_read_before_tool(&session, tool_input)? {
            return Ok((updated, true));
        }
    }
    if is_write_or_edit_like_tool_name(tool_name) {
        let session = open_hook_session(cli, session_name)?;
        if is_edit_like_tool_name(tool_name) {
            if let Some(updated) = apply_masked_old_edit_before_tool(&session, tool_input)? {
                return Ok((updated, true));
            }
        }
        validate_masked_write_before_tool(&session, tool_name, tool_input)?;
    }
    if is_shell_tool_name(tool_name) {
        if let Some(command) = tool_input.get("command").and_then(Value::as_str) {
            if let Some(reason) = pentect_human_only_command_reason(command) {
                return Err(reason);
            }
            if codex_exec_proxy_should_own_shell_tool(provider) {
                return Ok((tool_input.clone(), false));
            }
            let command = canonical_hook_shell_command(command)?;
            let mut updated = tool_input.clone();
            if let Some(object) = updated.as_object_mut() {
                object.insert(
                    "command".to_string(),
                    Value::String(wrap_shell_command(
                        provider,
                        session_name,
                        tool_name,
                        &command,
                    )?),
                );
                return Ok((updated, true));
            }
        }
    }
    Ok((tool_input.clone(), false))
}

fn ensure_pentect_agent_launch(provider: HookProvider) -> Result<(), String> {
    ensure_pentect_agent_launch_required(provider, config::require_pentect_agent_by_config()?)
}

fn codex_exec_proxy_enabled() -> bool {
    #[cfg(test)]
    if let Some(value) = CODEX_EXEC_PROXY_TEST_OVERRIDE.with(Cell::get) {
        return value;
    }
    std::env::var(PENTECT_CODEX_EXEC_PROXY_ENV).is_ok_and(|value| value == "1")
}

fn codex_app_server_proxy_active() -> bool {
    std::env::var("PENTECT_CODEX_APP_SERVER_PROXY").is_ok_and(|value| value == "1")
}

fn codex_exec_proxy_should_own_shell_tool(provider: HookProvider) -> bool {
    provider == HookProvider::Codex
        && codex_exec_proxy_enabled()
        && !codex_app_server_proxy_active()
}

#[cfg(test)]
fn set_codex_exec_proxy_test_override(value: Option<bool>) -> Option<bool> {
    CODEX_EXEC_PROXY_TEST_OVERRIDE.with(|cell| {
        let previous = cell.get();
        cell.set(value);
        previous
    })
}

fn codex_exec_proxy_owns_shell_output(provider: HookProvider, tool_name: &str) -> bool {
    codex_exec_proxy_should_own_shell_tool(provider) && is_shell_tool_name(tool_name)
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
        infer_kind(path),
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
    let display_path = masked_read_display_path(original);
    PathBuf::from(".pentect").join("read").join(display_path)
}

fn masked_read_display_path(original: &Path) -> PathBuf {
    if original.is_absolute() {
        if let Ok(cwd) = std::env::current_dir() {
            if let Ok(relative) = original.strip_prefix(cwd) {
                return safe_masked_read_path(relative);
            }
        }
        return PathBuf::from("_external")
            .join(masked_read_path_hash(original))
            .join(
                original
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(safe_masked_read_component)
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| "file.txt".to_string()),
            );
    }
    safe_masked_read_path(original)
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
        if !contains_pentect_masked_handle(content) {
            return Ok(());
        }
        let (path, _) = resolved_write_parts(session, path, content)?;
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
    let path = checked_local_write_path(path)?;
    Ok((path, resolved))
}

fn validate_masked_edit_before_tool(session: &Session, tool_input: &Value) -> Result<(), String> {
    let Some((path, edits)) = edit_path_and_texts(tool_input) else {
        return Ok(());
    };
    if !edits
        .iter()
        .any(|(_, text)| contains_pentect_masked_handle(text))
    {
        return Ok(());
    }
    let path = checked_local_write_path(path)?;
    ensure_local_write_path_within_cwd(&path)?;
    let store = MemoryStore::for_session(session);
    for (kind, text) in edits {
        if matches!(kind, EditTextKind::New) && contains_pentect_masked_handle(text) {
            let _ = resolve_masked_text(&store, text)?;
        }
    }
    Ok(())
}

fn apply_masked_old_edit_before_tool(
    session: &Session,
    tool_input: &Value,
) -> Result<Option<Value>, String> {
    let Some((path_text, edits)) = edit_path_and_replacements(tool_input) else {
        return Ok(None);
    };
    if !edits
        .iter()
        .any(|edit| contains_pentect_masked_handle(edit.old))
    {
        return Ok(None);
    }
    let path = checked_local_write_path(path_text)?;
    ensure_local_write_path_within_cwd(&path)?;
    let store = MemoryStore::for_session(session);
    let mut content = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    for edit in edits {
        let old = resolve_masked_text_if_needed(&store, edit.old)?;
        let new = resolve_masked_text_if_needed(&store, edit.new)?;
        if old.is_empty() {
            return Err("masked edit needs non-empty old text.".to_string());
        }
        if !content.contains(&old) {
            return Err("masked edit target was not found; re-read the file.".to_string());
        }
        content = content.replacen(&old, &new, 1);
    }
    let anchor = safe_noop_edit_anchor(&content, &session.key)
        .ok_or_else(|| "masked edit has no safe no-op anchor; use Write.".to_string())?;
    let updated = noop_edit_input(tool_input, &anchor)?;
    std::fs::write(&path, content)
        .map_err(|e| format!("could not edit '{}': {e}", path.display()))?;
    Ok(Some(updated))
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
    let path = checked_local_write_path(path)?;
    ensure_local_write_path_within_cwd(&path)?;
    if !path.is_file() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if !contains_pentect_masked_handle(&content) {
        return Ok(false);
    }
    let store = MemoryStore::for_session(session);
    let resolved = resolve_masked_text(&store, &content)?;
    if resolved != content {
        std::fs::write(&path, resolved)
            .map_err(|e| format!("could not repair '{}': {e}", path.display()))?;
    }
    Ok(true)
}

fn resolve_masked_text_if_needed(store: &MemoryStore, content: &str) -> Result<String, String> {
    if contains_pentect_masked_handle(content) {
        resolve_masked_text(store, content)
    } else {
        Ok(content.to_string())
    }
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

fn contains_pentect_masked_handle(text: &str) -> bool {
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

struct EditReplacement<'a> {
    old: &'a str,
    new: &'a str,
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

fn edit_path_and_replacements(value: &Value) -> Option<(&str, Vec<EditReplacement<'_>>)> {
    for candidate in write_input_candidates(value) {
        let Some(path) = string_field(candidate, WRITE_PATH_FIELDS) else {
            continue;
        };
        let mut edits = Vec::new();
        push_edit_replacements(candidate, &mut edits);
        if !edits.is_empty() {
            return Some((path, edits));
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

fn push_edit_replacements<'a>(value: &'a Value, out: &mut Vec<EditReplacement<'a>>) {
    if let (Some(old), Some(new)) = (
        string_field(value, EDIT_OLD_FIELDS),
        string_field(value, EDIT_NEW_FIELDS),
    ) {
        out.push(EditReplacement { old, new });
    }
    if let Some(edits) = value.get("edits").and_then(Value::as_array) {
        for edit in edits {
            push_edit_replacements(edit, out);
        }
    }
}

fn noop_edit_input(value: &Value, anchor: &str) -> Result<Value, String> {
    let mut updated = value.clone();
    let Some(candidate) = edit_candidate_object_mut(&mut updated) else {
        return Err("masked edit input was not recognized.".to_string());
    };
    if candidate.get("edits").is_some() {
        candidate.insert(
            "edits".to_string(),
            json!([{ "old_string": anchor, "new_string": anchor }]),
        );
        return Ok(updated);
    }
    let old_field = existing_field_name(candidate, EDIT_OLD_FIELDS).unwrap_or("old_string");
    let new_field = existing_field_name(candidate, EDIT_NEW_FIELDS).unwrap_or("new_string");
    candidate.insert(old_field.to_string(), Value::String(anchor.to_string()));
    candidate.insert(new_field.to_string(), Value::String(anchor.to_string()));
    Ok(updated)
}

fn edit_candidate_object_mut(value: &mut Value) -> Option<&mut serde_json::Map<String, Value>> {
    if direct_edit_candidate(value) {
        return value.as_object_mut();
    }
    let field = WRITE_INPUT_FIELDS
        .iter()
        .copied()
        .find(|field| value.get(*field).is_some_and(direct_edit_candidate))?;
    value.get_mut(field)?.as_object_mut()
}

fn direct_edit_candidate(value: &Value) -> bool {
    string_field(value, WRITE_PATH_FIELDS).is_some() && edit_path_and_replacements(value).is_some()
}

fn existing_field_name<'a>(
    object: &serde_json::Map<String, Value>,
    names: &'a [&'a str],
) -> Option<&'a str> {
    names
        .iter()
        .copied()
        .find(|name| object.contains_key(*name))
}

fn safe_noop_edit_anchor(content: &str, key: &[u8; 32]) -> Option<String> {
    content
        .split_inclusive('\n')
        .find(|candidate| safe_noop_edit_anchor_candidate(candidate, key))
        .map(str::to_string)
}

fn safe_noop_edit_anchor_candidate(candidate: &str, key: &[u8; 32]) -> bool {
    let text = candidate.trim();
    if text.is_empty() || candidate.len() > 512 || contains_pentect_masked_handle(candidate) {
        return false;
    }
    let Ok(decode) = config::decode_config(Profile::Strict) else {
        return false;
    };
    let result = Engine::with_profile_and_decode_config(Profile::Strict, decode).mask(
        Input {
            kind: Kind::Text,
            data: candidate.to_string(),
        },
        &Config::new(*key),
    );
    result.summary.masked_count == 0
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

fn wrap_shell_command(
    provider: HookProvider,
    session_name: &str,
    tool_name: &str,
    masked_command: &str,
) -> Result<String, String> {
    let shell = script_shell_for_tool(tool_name);
    if matches!(provider, HookProvider::Claude | HookProvider::Generic)
        && matches!(shell, ScriptShell::Bash | ScriptShell::PowerShell)
    {
        if let Some(client) = MemoryStoreClient::from_env() {
            let id = client
                .put_agent_script(shell.as_str(), masked_command)
                .map_err(|error| error.to_string())?;
            return same_shell_agent_wrapper(shell, session_name, &id);
        }
    }
    let mut args = vec!["exec".to_string()];
    add_non_default_session(&mut args, session_name);
    args.push("--script-shell".to_string());
    args.push(shell.as_str().to_string());
    args.push("--script-b64".to_string());
    args.push(data_encoding::BASE64URL_NOPAD.encode(masked_command.as_bytes()));
    Ok(visible_pentect_command(&args))
}

fn same_shell_agent_wrapper(
    shell: ScriptShell,
    session_name: &str,
    id: &str,
) -> Result<String, String> {
    let suffix = id
        .get(..12)
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| "agent script id is invalid".to_string())?;
    let mut script_args = vec!["__agent-script".to_string(), id.to_string()];
    let end_marker = format!("__PENTECT_STREAM_END_{id}__");
    let mut stream_args = vec![
        "__agent-stream".to_string(),
        "--end-marker".to_string(),
        end_marker.clone(),
    ];
    add_non_default_session(&mut script_args, session_name);
    add_non_default_session(&mut stream_args, session_name);
    match shell {
        ScriptShell::Bash => Ok(bash_same_shell_wrapper(
            suffix,
            &end_marker,
            &target_shell_pentect_command(shell, &script_args),
            &target_shell_pentect_command(shell, &stream_args),
        )),
        ScriptShell::PowerShell => Ok(powershell_same_shell_wrapper(
            suffix,
            &powershell_agent_script_fetch(suffix, id),
        )),
        ScriptShell::Native => Err("same-shell wrapper requires a known shell".to_string()),
    }
}

fn target_shell_pentect_command(shell: ScriptShell, args: &[String]) -> String {
    let quote = match shell {
        ScriptShell::Bash => shell_quote_unix,
        ScriptShell::PowerShell | ScriptShell::Native => powershell_word,
    };
    let mut command = match shell {
        ScriptShell::Bash => String::from("\"${PENTECT_BIN}\""),
        ScriptShell::PowerShell | ScriptShell::Native => String::from("$env:PENTECT_BIN"),
    };
    for arg in args {
        command.push(' ');
        command.push_str(&quote(arg));
    }
    command
}

fn bash_same_shell_wrapper(
    suffix: &str,
    end_marker: &str,
    script_command: &str,
    stream_command: &str,
) -> String {
    let status = format!("_pentect_status_{suffix}");
    let stream_status = format!("_pentect_stream_status_{suffix}");
    let pipe_status = format!("_pentect_pipe_status_{suffix}");
    let script = format!("_pentect_script_{suffix}");
    format!(
        "(set +x; {script}=\"$({script_command} 2>&1)\"; {status}=$?; if [ \"${status}\" -ne 0 ]; then printf '%s\\n' \"${script}\" | {stream_command}; unset {script}; exit \"${status}\"; fi; {{ eval \"${script}\"; {status}=$?; printf '%s\\n' {marker}; exit \"${status}\"; }} 2>&1 | {stream_command}; {pipe_status}=(\"${{PIPESTATUS[@]}}\"); unset {script}; {status}=\"${{{pipe_status}[0]}}\"; {stream_status}=\"${{{pipe_status}[1]}}\"; if [ \"${status}\" -eq 0 ] && [ \"${stream_status}\" -ne 0 ]; then {status}=${stream_status}; fi; exit \"${status}\")",
        marker = shell_quote_unix(end_marker),
    )
}

fn powershell_same_shell_wrapper(suffix: &str, script_command: &str) -> String {
    let script = format!("__pentect_script_{suffix}");
    let status = format!("__pentect_status_{suffix}");
    let success = format!("__pentect_success_{suffix}");
    let native_status = format!("__pentect_native_status_{suffix}");
    format!(
        "${script} = (& {script_command} | Out-String); ${status} = 0; try {{ $global:LASTEXITCODE = 0; Invoke-Expression ${script}; ${success} = $?; ${native_status} = $LASTEXITCODE; if (${native_status} -is [int] -and ${native_status} -ne 0) {{ ${status} = ${native_status} }} elseif (-not ${success}) {{ ${status} = 1 }} }} catch {{ Write-Error -ErrorRecord $_; ${status} = 1 }}; ${script} = $null; if (${status} -ne 0) {{ exit ${status} }}"
    )
}

fn powershell_agent_script_fetch(suffix: &str, id: &str) -> String {
    format!(
        "{{ ${client} = [System.Net.Sockets.TcpClient]::new(); ${reader} = $null; ${writer} = $null; try {{ ${address} = $env:PENTECT_MEMORY_STORE_ADDR -split ':', 2; if (${address}.Count -ne 2) {{ throw 'session unavailable' }}; ${client}.Connect(${address}[0], [int]${address}[1]); ${stream} = ${client}.GetStream(); ${writer} = [System.IO.StreamWriter]::new(${stream}, [System.Text.UTF8Encoding]::new($false), 1024, $true); ${reader} = [System.IO.StreamReader]::new(${stream}, [System.Text.Encoding]::UTF8, $false, 1024, $true); ${writer}.NewLine = \"`n\"; ${writer}.WriteLine(\"$env:PENTECT_MEMORY_STORE_TOKEN`tSCRIPT_RENDER`t{id}\"); ${writer}.Flush(); ${response} = ${reader}.ReadLine(); ${fields} = ${response} -split \"`t\", 2; if (${fields}.Count -ne 2 -or ${fields}[0] -ne 'OK') {{ throw 'script unavailable' }}; ${decoded} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${fields}[1])); ${separator} = ${decoded}.IndexOf([char]0); if (${separator} -lt 0) {{ throw 'script unavailable' }}; ${decoded}.Substring(${separator} + 1) }} finally {{ if (${reader}) {{ ${reader}.Dispose() }}; if (${writer}) {{ ${writer}.Dispose() }}; ${client}.Dispose(); ${response} = $null; ${fields} = $null; ${decoded} = $null }} }}",
        client = format!("__pentect_client_{suffix}"),
        reader = format!("__pentect_reader_{suffix}"),
        writer = format!("__pentect_writer_{suffix}"),
        address = format!("__pentect_address_{suffix}"),
        stream = format!("__pentect_network_{suffix}"),
        response = format!("__pentect_response_{suffix}"),
        fields = format!("__pentect_fields_{suffix}"),
        decoded = format!("__pentect_decoded_{suffix}"),
        separator = format!("__pentect_separator_{suffix}"),
    )
}

fn script_shell_for_tool(tool_name: &str) -> ScriptShell {
    match tool_name.to_ascii_lowercase().as_str() {
        "bash" => ScriptShell::Bash,
        "powershell" => ScriptShell::PowerShell,
        _ => ScriptShell::Native,
    }
}

fn visible_pentect_command(args: &[String]) -> String {
    let quote = if cfg!(windows) {
        powershell_word
    } else {
        shell_quote_unix
    };
    let mut out = String::from("pentect");
    if !args.is_empty() {
        out.push(' ');
        out.push_str(
            &args
                .iter()
                .map(|arg| quote(arg))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    out
}

fn add_non_default_session(words: &mut Vec<String>, session_name: &str) {
    if should_emit_session_arg(session_name) {
        words.push("--session".to_string());
        words.push(session_name.to_string());
    }
}

fn should_emit_session_arg(session_name: &str) -> bool {
    session_name != DEFAULT_SESSION
        && !default_session_name().is_ok_and(|default| default == session_name)
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
    let redaction = image_ocr::redact_tool_images_for_secrets(value, &session.key, &cfg)?;
    activity_log::record_image(redaction.secret_images, &redaction.notes);
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
        let updated = append_image_mask_notes(redaction.updated, &redaction.notes);
        return Ok(Some(ToolTextOutput::Updated(updated)));
    }
    if matches!(cfg.unscanned_images, config::UnscannedImagePolicy::Allow) {
        return Ok(None);
    }
    Ok(None)
}

fn append_image_mask_notes(mut value: Value, notes: &[String]) -> Value {
    if notes.is_empty() {
        return value;
    }
    let text = format!("Masked regions\n{}", notes.join("\n"));
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
        return Ok(
            matches!(cfg.unscanned_images, config::UnscannedImagePolicy::Block)
                .then_some("image blocked: OCR is off.".to_string()),
        );
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
        return Ok(Some("image blocked: secret text detected.".to_string()));
    }
    if matches!(cfg.unscanned_images, config::UnscannedImagePolicy::Allow) {
        return Ok(None);
    }
    if inspection.unscanned_images > 0 {
        return Ok(Some(
            "image blocked: image could not be fetched or scanned.".to_string(),
        ));
    }
    if inspection.ocr_failures > 0 {
        return Ok(Some("image blocked: image scan failed.".to_string()));
    }
    Ok(None)
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
        other => Err(format!("unknown kind: {other}")),
    }
}

fn parse_hook_provider(value: &str) -> Result<HookProvider, String> {
    match value {
        "codex" => Ok(HookProvider::Codex),
        "claude" => Ok(HookProvider::Claude),
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
