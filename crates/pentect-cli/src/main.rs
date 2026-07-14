//! Pentect CLI: local secret masking boundary for AI agents.

mod agent_integrations;
mod app_server_proxy;
mod doctor;
mod eval;
mod exec_proxy;
mod extensions;
mod extensions_cmd;
mod input;
mod scan;
mod terminal;

use input::{decode_utf8_text, ImageOcrInput, InputAdapter, TextInput};
use pentect_core::{
    infer_kind, load_pack, parse_placeholder, Config, Engine, Input, Kind, Pack, Profile,
};
use portable_pty::{native_pty_system, Child as PtyChild, CommandBuilder, MasterPty, PtySize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use zeroize::Zeroize;

pub(crate) type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

/// Refuse oversized input rather than emit partially-masked output (a masked
/// head plus a raw tail would leak the tail).
const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const PENTECT_CONTRACT_INSTRUCTIONS: &str = concat!(
    "Pentect agent contract:\n",
    "- Use normal shell commands. Pentect routes stdout/stderr through its protected runner and masks tool results.\n",
    "- You may read, fetch, transform, store, sync, and use user-authorized secrets. Pentect is the safety layer; raw secret values must not reach chat.\n",
    "- Prefer one normal shell command for secret work, e.g. `cat .env`, service CLIs, or a command that reads a source and writes the exact requested destination.\n",
    "- Masked handles like `<<NAME_hash>>` work only in this running Pentect-launched session. Use `$env:NAME`/`$env:PENTECT_NAME_hash` on PowerShell or `$NAME`/`$PENTECT_NAME_hash` on Unix.\n",
    "- `pentect view '<handle>'` shows only label, hash, and length. Use handles or generated env vars instead of printing raw values.\n",
    "- Use the current shell syntax. On PowerShell use PowerShell commands and `$env:NAME`; on Unix use POSIX commands and `$NAME`.\n",
    "- MCP, browser, plugin, and connector tools may retrieve and use user-authorized secrets. Pentect masks tool text output when the host supports replacement; otherwise it stops unsafe output.\n",
    "- Default builds check image output with OS OCR on Windows/macOS and bundled OCR on Linux.\n",
    "- For user-requested storage, write only to the exact requested local file, credential store, service, authenticated account, or destination; print only non-secret verification.\n",
    "- Do not disclose raw secrets in chat, logs, screenshots, encodings, chunks, prefixes/suffixes, third-party destinations, public locations, or unrelated persistent services.\n",
);
const PENTECT_BIN_ENV: &str = "PENTECT_BIN";
const PENTECT_AGENT_LAUNCHED_ENV: &str = "PENTECT_AGENT_LAUNCHED";
const PENTECT_MEMORY_STORE_ADDR_ENV: &str = "PENTECT_MEMORY_STORE_ADDR";
const PENTECT_MEMORY_STORE_TOKEN_ENV: &str = "PENTECT_MEMORY_STORE_TOKEN";
const PENTECT_PROCESS_HOST_ROOT_ENV: &str = "PENTECT_PROCESS_HOST_ROOT";
const PENTECT_PROCESS_HOST_READ_TOKEN_ENV: &str = "PENTECT_PROCESS_HOST_READ_TOKEN";
const PENTECT_PROCESS_HOST_WRITE_TOKEN_ENV: &str = "PENTECT_PROCESS_HOST_WRITE_TOKEN";
const PENTECT_STATUS_LINE_ENV: &str = "PENTECT_STATUS_LINE";
const PENTECT_DIR: &str = ".pentect";
const PENTECT_CONFIG_FILE: &str = "config.toml";
const MEMORY_STORE_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const ISSUE_NEW_URL: &str = "https://github.com/EdamAme-x/pentect/issues/new";
const CODEX_ENVIRONMENT_OVERLAY_MARKER: &[u8] = b"# pentect-managed-environments\n";
const PROMPT_PASTE_START: &[u8] = b"\x1b[200~";
const PROMPT_PASTE_END: &[u8] = b"\x1b[201~";
const PROMPT_INPUT_POLL: Duration = Duration::from_millis(50);
const PROMPT_INPUT_MAX_PENDING_BYTES: usize = 1024 * 1024;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if is_memory_store_server(&args) || !supports_process_host(&args) {
        dispatch(args);
        return;
    }
    let pentect = std::env::var_os(PENTECT_BIN_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(default_pentect_path);
    let process_host_root = process_host_root().unwrap_or_else(|error| die_with_issue(error));
    let _process_host_root_env = EnvVarGuard::set_optional([(
        PENTECT_PROCESS_HOST_ROOT_ENV,
        Some(process_host_root.clone().into_os_string()),
    )]);
    let process_host = MemoryStoreGuard::start(&pentect, false)
        .unwrap_or_else(|error| die_with_issue(error))
        .unwrap_or_else(|| die_with_issue("could not start process host candidate"));
    let _process_host_env = memory_store_parent_env_guard(&pentect, &process_host);
    dispatch(args);
}

fn dispatch(args: Vec<String>) {
    match args.get(1).map(String::as_str) {
        None => usage(),
        Some("help" | "--help" | "-h") => cmd_help(),
        Some("mask") => cmd_mask(&args),
        Some("read") => cmd_read(&args),
        Some("view") => cmd_view(&args),
        Some("statusline") => cmd_statusline(&args),
        Some("up") => cmd_up(&args),
        Some("doctor") => doctor::cmd_doctor(&args),
        Some("extensions") => extensions_cmd::cmd_extensions(&args),
        Some("eval") => eval::cmd_eval(&args),
        Some("scan") => scan::cmd_scan(&args),
        Some(
            "exec" | "shell" | "resolve" | "log" | "hook" | "bridge" | "memory-store" | "purge",
        ) => cmd_agent_from(1, &args),
        Some("agent") => cmd_agent_from(2, &args),
        Some("codex") => cmd_agent_tool(AgentTool::Codex, &args),
        Some("claude") => cmd_agent_tool(AgentTool::Claude, &args),
        Some("opencode") => cmd_agent_tool(AgentTool::OpenCode, &args),
        Some("pi") => cmd_agent_tool(AgentTool::Pi, &args),
        _ => usage(),
    }
}

fn is_memory_store_server(args: &[String]) -> bool {
    matches!(
        (
            args.get(1).map(String::as_str),
            args.get(2).map(String::as_str)
        ),
        (Some("memory-store"), _) | (Some("agent"), Some("memory-store"))
    )
}

/// A process-host candidate needs enough lifetime to serve other processes.
/// One-shot inspection commands would only add startup cost and disappear
/// before a useful handoff can occur.
fn supports_process_host(args: &[String]) -> bool {
    matches!(
        (
            args.get(1).map(String::as_str),
            args.get(2).map(String::as_str),
        ),
        (Some("codex" | "claude" | "opencode" | "pi"), _)
            | (Some("exec" | "shell" | "log" | "bridge"), _)
            | (Some("agent"), Some("exec" | "shell" | "log" | "bridge"))
    )
}

fn usage() {
    eprintln!(
        "pentect\n\
         pentect codex|claude|opencode|pi\n\
         pentect exec \"<command>\"\n\
         pentect shell\n\
         pentect up\n\
         pentect doctor\n\
         pentect extensions list|inspect|test [NAME]\n\
         pentect eval [--json]\n\
         pentect scan [--binary skip|text] [--exclude PATTERN|~GROUP|!PATTERN] [--gitignore] [PATH...]\n\
         pentect view <HANDLE>\n\
         pentect statusline\n\
         pentect resolve [PATH...]\n\
         pentect log [--json]\n\
         pentect help\n\
         \n\
         exec: masked output\n\
         shell: masked shell\n\
         up: process host\n\
         doctor: readiness\n\
         eval: metrics\n\
         scan: secrets\n\
         view: handle\n\
         statusline: count\n\
         resolve: write handles\n\
         log: live events"
    );
}

fn cmd_help() {
    print!("{}", help_text());
}

fn help_text() -> &'static str {
    concat!(
        "pentect protects AI tool boundaries.\n\n",
        "Use:\n",
        "  pentect\n",
        "  pentect codex|claude|opencode|pi [--extensions NAME|PATH.toml]\n",
        "  pentect exec \"<command>\"\n\n",
        "  pentect shell\n\n",
        "  pentect up\n\n",
        "  pentect doctor [--json]\n",
        "  pentect extensions list|inspect|test [NAME|PATH] [--json]\n",
        "  pentect eval [--json]\n\n",
        "  pentect scan [--binary skip|text] [--exclude PATTERN|~GROUP|!PATTERN] [--gitignore] [PATH...]\n\n",
        "  pentect view '<HANDLE>'\n\n",
        "  pentect statusline\n\n",
        "  pentect log [--json]\n\n",
        "exec: masked stdout/stderr\n",
        "shell: masked shell\n",
        "up: process host\n",
        "read: masked file preview\n",
        "view: handle\n",
        "statusline: masked count\n",
        "log: live events\n",
        "resolve: write handles\n",
        "scan: CredSweeper + core; binary skip(default)|text(lossy); narrow with --exclude, --gitignore, .pentectignore\n",
        "groups: ~vcs ~deps ~build ~cache ~pentect ~heavy ~all; ! restores\n",
        "doctor: readiness\n",
        "extensions: list, inspect, test\n",
        "eval: precision, recall\n",
    )
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("[pentect] {msg}");
    std::process::exit(2);
}

fn die_with_issue(msg: impl std::fmt::Display) -> ! {
    eprintln!("[pentect] {msg}");
    eprintln!("[pentect] report: {}", issue_report_url());
    std::process::exit(2);
}

fn issue_report_url() -> String {
    let body = concat!(
        "## What happened\n\n",
        "<what did you run?>\n\n",
        "## Error\n\n",
        "```text\n",
        "<paste Pentect error output here>\n",
        "```\n\n",
        "## Environment\n\n",
        "- OS:\n",
        "- Pentect version or commit:\n",
        "- Terminal:\n\n",
        "Do not paste raw secrets, API keys, tokens, cookies, or private files.\n",
    );
    format!(
        "{ISSUE_NEW_URL}?title={}&body={}",
        url_query_encode("Pentect error"),
        url_query_encode(body)
    )
}

fn url_query_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn cmd_agent_from(start: usize, args: &[String]) {
    let (forward_args, explicit_extensions) = match extensions::strip_from_args(&args[start..]) {
        Ok(parsed) => parsed,
        Err(e) => die(&e),
    };
    let active_extensions = match extensions::active_from_specs(explicit_extensions, true) {
        Ok(active) => active,
        Err(e) => die(&e),
    };
    if let Some(value) = match active_extensions.config_env_value() {
        Ok(value) => value,
        Err(e) => die(&e),
    } {
        std::env::set_var(extensions::CONFIGS_ENV, value);
    }
    if let Some(value) = match active_extensions.adapter_env_value() {
        Ok(value) => value,
        Err(e) => die(&e),
    } {
        std::env::set_var(extensions::ADAPTERS_ENV, value);
    }
    let mut agent_args = Vec::with_capacity(forward_args.len() + 1);
    agent_args.push(
        args.first()
            .cloned()
            .unwrap_or_else(|| "pentect".to_string()),
    );
    agent_args.extend(forward_args);
    let shell_store = if agent_args
        .get(1)
        .is_some_and(|arg| matches!(arg.as_str(), "shell" | "log"))
    {
        let pentect = std::env::var_os(PENTECT_BIN_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(default_pentect_path);
        Some(start_memory_store(&pentect).unwrap_or_else(|e| die_with_issue(e)))
    } else {
        None
    };
    let _shell_store_env = shell_store.as_ref().map(|store| {
        EnvVarGuard::set_optional([
            (
                PENTECT_MEMORY_STORE_ADDR_ENV,
                Some(OsString::from(store.addr.as_str())),
            ),
            (
                PENTECT_MEMORY_STORE_TOKEN_ENV,
                Some(OsString::from(store.token.as_str())),
            ),
            (
                PENTECT_PROCESS_HOST_READ_TOKEN_ENV,
                Some(OsString::from(store.process_host_read_token.as_str())),
            ),
            (
                PENTECT_PROCESS_HOST_WRITE_TOKEN_ENV,
                Some(OsString::from(store.process_host_write_token.as_str())),
            ),
            (
                PENTECT_PROCESS_HOST_ROOT_ENV,
                Some(store.process_host_root.clone().into_os_string()),
            ),
            (
                PENTECT_AGENT_LAUNCHED_ENV,
                Some(OsString::from(store.token.as_str())),
            ),
        ])
    });
    let code = pentect_agent::run_from(agent_args);
    drop(_shell_store_env);
    drop(shell_store);
    std::process::exit(code);
}

fn cmd_agent_tool(tool: AgentTool, args: &[String]) {
    let opts = match AgentToolOpts::parse(tool, args) {
        Ok(o) => o,
        Err(e) => die(&e),
    };
    let pentect = opts.pentect.clone().unwrap_or_else(default_pentect_path);
    if !pentect.exists() && pentect.components().count() > 1 {
        die(format!(
            "pentect not found at '{}'; run `cargo build -p pentect-cli --release` or pass --pentect PATH",
            pentect.display()
        ));
    }
    let status = match tool {
        AgentTool::Codex => run_codex(&opts, &pentect),
        AgentTool::Claude => run_claude(&opts, &pentect),
        AgentTool::OpenCode => run_bridge_agent(&opts, &pentect, tool),
        AgentTool::Pi => run_bridge_agent(&opts, &pentect, tool),
    }
    .unwrap_or_else(|e| die_with_issue(&e));
    let code = status.code().unwrap_or(1);
    std::process::exit(code);
}

fn start_memory_store(pentect: &Path) -> Result<MemoryStoreGuard, String> {
    MemoryStoreGuard::start(pentect, false)?
        .ok_or_else(|| "could not start Pentect memory store".to_string())
}

fn cmd_up(args: &[String]) {
    if args.len() != 2 {
        die("up");
    }
    let root = process_host_root().unwrap_or_else(|error| die_with_issue(error));
    if pentect_agent::persistent_process_host_running(&root) {
        return;
    }
    let pentect = std::env::var_os(PENTECT_BIN_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(default_pentect_path);
    if let Some(host) =
        MemoryStoreGuard::start(&pentect, true).unwrap_or_else(|error| die_with_issue(error))
    {
        host.detach();
    }
}

fn agent_tool_extensions(opts: &AgentToolOpts) -> Result<extensions::ActiveExtensions, String> {
    extensions::active_from_specs(opts.extensions.clone(), true).map_err(|e| e.to_string())
}

fn blocked_headless_codex_error() -> String {
    "headless Codex may skip hooks. Use interactive `pentect codex` for protected tool use."
        .to_string()
}

/// Read stdin as bytes (no panic on binary), cap the size, then delegate
/// interpretation to the injected input adapter.
fn read_stdin_capped(reader: &dyn InputAdapter) -> Result<String, String> {
    let mut buf = Vec::new();
    std::io::stdin()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("could not read stdin: {e}"))?;
    if buf.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "input exceeds {MAX_INPUT_BYTES} bytes; refusing to mask partially"
        ));
    }
    reader.read(buf)
}

fn cmd_mask(args: &[String]) {
    if let Err(e) = validate_mask_args(args) {
        die(&e);
    }
    let kind = match arg_value(args, "--kind").as_deref() {
        Some(name) => match parse_kind(name) {
            Ok(k) => k,
            Err(e) => die(&e),
        },
        None => Kind::Text,
    };
    let profile: Profile = match arg_value(args, "--profile").as_deref() {
        Some(name) => match name.parse() {
            Ok(p) => p,
            Err(e) => die(&e),
        },
        None => Profile::Strict,
    };
    let aggressive = has_flag(args, "--aggressive");
    let packs = match load_packs(args) {
        Ok(p) => p,
        Err(e) => die(&e),
    };
    let reader = match input_adapter(args) {
        Ok(r) => r,
        Err(e) => die(&e),
    };
    let data = match read_stdin_capped(reader.as_ref()) {
        Ok(s) => s,
        Err(e) => die(&e),
    };

    // Fresh per-run key: mask-only, so the recovery map is not retained and a
    // reproducible key isn't needed (resolve/restore is unavailable by design).
    let kind_label = format!("{kind:?}");
    let engine = match build_engine(profile, aggressive, packs) {
        Ok(engine) => engine,
        Err(error) => die(error),
    };
    let cfg = Config::generate();
    let result = engine.mask(Input { kind, data }, &cfg);

    print!("{}", result.masked);
    let _ = std::io::stdout().flush();
    eprintln!(
        "[pentect] profile={profile:?} masked {} value(s), {} warned.",
        result.summary.masked_count,
        result.summary.residual.len()
    );
    if result.summary.parser_fallback {
        eprintln!("[pentect] note: --kind {kind_label} failed to parse; masked as plaintext (key context lost, structure not guaranteed).");
    }
    if !result.summary.collisions.is_empty() {
        eprintln!(
            "[pentect] WARNING: {} placeholder collision(s) — resolve/restore may be wrong for the colliding value(s).",
            result.summary.collisions.len()
        );
    }
}

fn validate_mask_args(args: &[String]) -> Result<(), String> {
    let mut i = 2usize;
    while i < args.len() {
        match args[i].as_str() {
            "--kind" | "--profile" | "--input" | "--pack" | "--pack-dir" | "--extensions" => {
                let Some(value) = args.get(i + 1) else {
                    return Err(format!("{} requires a value", args[i]));
                };
                if value.starts_with("--") {
                    return Err(format!("{} requires a value", args[i]));
                }
                if args[i] == "--kind" {
                    parse_kind(value)?;
                }
                if args[i] == "--profile" {
                    value.parse::<Profile>()?;
                }
                if args[i] == "--extensions" {
                    extensions::parse_extension_value(value).map_err(|e| e.to_string())?;
                }
                i += 2;
            }
            "--aggressive" => {
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(format!("unknown option: {flag}"));
            }
            value => {
                return Err(format!("unexpected argument for mask: {value}"));
            }
        }
    }
    Ok(())
}

fn cmd_read(args: &[String]) {
    let opts = match ReadOpts::parse(args) {
        Ok(o) => o,
        Err(e) => die(&e),
    };
    let data = match read_input(&opts.path, opts.input_format) {
        Ok(s) => s,
        Err(e) => die(&e),
    };
    let kind = opts.kind.unwrap_or_else(|| infer_kind(&opts.path));
    let active_extensions = match extensions::active_from_specs(opts.extensions.clone(), true) {
        Ok(active) => active,
        Err(e) => die(&e),
    };
    let packs = match extensions::load_config_packs_from_active(&active_extensions) {
        Ok(packs) => packs,
        Err(e) => die(&e),
    };
    let config_env = match active_extensions.config_env_value() {
        Ok(value) => value,
        Err(e) => die(&e),
    };
    let adapter_env = match active_extensions.adapter_env_value() {
        Ok(value) => value,
        Err(e) => die(&e),
    };
    let _extension_env = EnvVarGuard::set_optional([
        (extensions::CONFIGS_ENV, config_env),
        (extensions::ADAPTERS_ENV, adapter_env),
    ]);
    let input = Input { kind, data };
    match pentect_agent::mask_input_into_active_memory_store(
        input.clone(),
        opts.profile,
        packs.clone(),
    ) {
        Ok(Some(result)) => {
            pentect_agent::record_read_activity(&result, &opts.path);
            print_read_result(result, opts.emit_meta);
            return;
        }
        Ok(None) => {}
        Err(e) => die(&e),
    }
    let cfg = Config::generate();
    let result = match pentect_agent::mask_input_for_read(cfg.key, input, opts.profile, packs) {
        Ok(result) => result,
        Err(e) => die(&e),
    };
    pentect_agent::record_read_activity(&result, &opts.path);
    print_read_result(result, opts.emit_meta);
}

fn print_read_result(result: pentect_core::MaskResult, emit_meta: bool) {
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

fn cmd_view(args: &[String]) {
    if args.len() != 3 {
        die("view HANDLE");
    }
    let parts = match parse_placeholder(&args[2]) {
        Ok(parts) => parts,
        Err(_) => die("invalid handle"),
    };
    println!("label: {}", parts.label);
    println!("hash: {}", parts.hash);
    match parts.length_hint.map(|hint| hint.short()).or_else(|| {
        pentect_agent::active_handle_length(&args[2])
            .ok()
            .flatten()
            .map(|len| format!("{len} chars"))
    }) {
        Some(length) => println!("length: {length}"),
        None => println!("length: -"),
    }
}

fn cmd_statusline(args: &[String]) {
    if args.len() != 2 {
        die("statusline");
    }
    println!("{}", pentect_agent::status_line_text());
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentTool {
    Codex,
    Claude,
    OpenCode,
    Pi,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadInputFormat {
    Text,
    Pdf,
    Image,
}

struct ReadOpts {
    input_format: ReadInputFormat,
    kind: Option<Kind>,
    profile: Profile,
    emit_meta: bool,
    extensions: Vec<String>,
    path: PathBuf,
}

impl ReadOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut input_format = ReadInputFormat::Text;
        let mut kind = None;
        let mut profile = Profile::Strict;
        let mut emit_meta = false;
        let mut extensions = Vec::new();
        let mut path = None;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--input" => {
                    input_format =
                        parse_read_input_format(&required_value(args, &mut i, "--input")?)?;
                }
                "--kind" => {
                    kind = Some(parse_kind(&required_value(args, &mut i, "--kind")?)?);
                }
                "--profile" => {
                    profile = required_value(args, &mut i, "--profile")?.parse()?;
                }
                "--meta" => {
                    emit_meta = true;
                    i += 1;
                }
                "--extensions" => {
                    for spec in extensions::parse_extension_value(&required_value(
                        args,
                        &mut i,
                        "--extensions",
                    )?)
                    .map_err(|e| e.to_string())?
                    {
                        if !extensions.iter().any(|existing| existing == &spec) {
                            extensions.push(spec);
                        }
                    }
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
            profile,
            emit_meta,
            extensions,
            path: path.ok_or_else(|| "read requires PATH".to_string())?,
        })
    }
}

impl AgentTool {
    fn name(self) -> &'static str {
        match self {
            AgentTool::Codex => "codex",
            AgentTool::Claude => "claude",
            AgentTool::OpenCode => "opencode",
            AgentTool::Pi => "pi",
        }
    }

    fn env_var(self) -> &'static str {
        match self {
            AgentTool::Codex => "PENTECT_CODEX",
            AgentTool::Claude => "PENTECT_CLAUDE",
            AgentTool::OpenCode => "PENTECT_OPENCODE",
            AgentTool::Pi => "PENTECT_PI",
        }
    }

    fn default_command(self) -> &'static str {
        self.name()
    }

    fn path_flag(self) -> &'static str {
        match self {
            AgentTool::Codex => "--codex",
            AgentTool::Claude => "--claude",
            AgentTool::OpenCode => "--opencode",
            AgentTool::Pi => "--pi",
        }
    }
}

#[derive(Debug)]
struct AgentToolOpts {
    session: Option<String>,
    pentect: Option<PathBuf>,
    command: PathBuf,
    extensions: Vec<String>,
    dry_run: bool,
    allow_unverified_hooks: bool,
    codex_app_server_proxy_disabled: bool,
    tool_args: Vec<String>,
}

impl AgentToolOpts {
    fn parse(tool: AgentTool, args: &[String]) -> Result<Self, String> {
        let mut session = None;
        let mut pentect = None;
        let mut command = std::env::var_os(tool.env_var())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(tool.default_command()));
        let mut extensions = Vec::new();
        let mut dry_run = false;
        let mut allow_unverified_hooks = false;
        let mut codex_app_server_proxy_disabled = false;
        let mut tool_args = Vec::new();
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--" => {
                    tool_args.extend(args[i + 1..].iter().cloned());
                    break;
                }
                "--session" => {
                    session = Some(checked_agent_session_name(&required_value(
                        args,
                        &mut i,
                        "--session",
                    )?)?);
                }
                "--pentect" => {
                    pentect = Some(PathBuf::from(required_value(args, &mut i, "--pentect")?));
                }
                "--tool" => {
                    command = PathBuf::from(required_value(args, &mut i, "--tool")?);
                }
                flag if flag == tool.path_flag() => {
                    command = PathBuf::from(required_value(args, &mut i, flag)?);
                }
                "--extensions" => {
                    for name in extensions::parse_extension_value(&required_value(
                        args,
                        &mut i,
                        "--extensions",
                    )?)
                    .map_err(|e| e.to_string())?
                    {
                        if !extensions.iter().any(|existing| existing == &name) {
                            extensions.push(name);
                        }
                    }
                }
                "--dry-run" => {
                    dry_run = true;
                    i += 1;
                }
                "--allow-unverified-hooks" => {
                    allow_unverified_hooks = true;
                    i += 1;
                }
                "--no-app-server-proxy" if tool == AgentTool::Codex => {
                    codex_app_server_proxy_disabled = true;
                    i += 1;
                }
                "--prompt-proxy" | "--no-prompt-proxy" => {
                    return Err(
                        "prompt proxy is currently disabled/TODO; Pentect now protects tool boundaries via agent hooks only"
                            .to_string(),
                    );
                }
                _ => {
                    tool_args.extend(args[i..].iter().cloned());
                    break;
                }
            }
        }
        Ok(Self {
            session,
            pentect: pentect.or_else(|| std::env::var_os(PENTECT_BIN_ENV).map(PathBuf::from)),
            command,
            extensions,
            dry_run,
            allow_unverified_hooks,
            codex_app_server_proxy_disabled,
            tool_args,
        })
    }
}

fn run_codex(opts: &AgentToolOpts, pentect: &Path) -> Result<std::process::ExitStatus, String> {
    let configs = codex_hook_config_args(pentect, opts.session.as_deref())?;
    let status_line_enabled = status_line_enabled_by_config()?;
    if opts.dry_run {
        if codex_uses_unverified_headless_hook_path(&opts.tool_args) {
            eprintln!(
                "[pentect] note: headless Codex may skip hooks; use interactive `pentect codex` for protected tool use."
            );
        }
        print_dry_run(&opts.command, &codex_args(&configs, &opts.tool_args));
        return Ok(success_status());
    }
    if codex_uses_unverified_headless_hook_path(&opts.tool_args) && !opts.allow_unverified_hooks {
        return Err(blocked_headless_codex_error());
    }
    let active_extensions = agent_tool_extensions(opts)?;
    let mut cmd = Command::new(&opts.command);
    apply_extension_env(&mut cmd, &active_extensions)?;
    let memory_store = start_memory_store(pentect)?;
    let _parent_env = agent_parent_env_guard(
        pentect,
        &memory_store,
        status_line_enabled,
        &active_extensions,
    )?;
    let exec_proxy = if codex_unified_exec_proxy_enabled(&opts.tool_args) {
        Some(exec_proxy::ExecProxyGuard::start(&opts.command)?)
    } else {
        None
    };
    let _exec_proxy_env = exec_proxy.as_ref().map(|exec_proxy| {
        EnvVarGuard::set_optional([
            (
                "CODEX_EXEC_SERVER_URL",
                Some(OsString::from(exec_proxy.url())),
            ),
            (
                exec_proxy::PENTECT_CODEX_EXEC_PROXY_ENV,
                Some(OsString::from("1")),
            ),
        ])
    });
    apply_pentect_env(&mut cmd, pentect, Some(memory_store.token.as_str()));
    apply_memory_store_env(&mut cmd, Some(&memory_store));
    apply_status_line_env(&mut cmd, status_line_enabled);
    if let Some(exec_proxy) = &exec_proxy {
        cmd.env("CODEX_EXEC_SERVER_URL", exec_proxy.url());
        cmd.env(exec_proxy::PENTECT_CODEX_EXEC_PROXY_ENV, "1");
    }
    let _codex_environment_overlay = exec_proxy
        .as_ref()
        .map(|exec_proxy| CodexEnvironmentOverlayGuard::install(exec_proxy.url()))
        .transpose()?;
    let codex_args =
        if codex_app_server_proxy_enabled(&opts.tool_args, opts.codex_app_server_proxy_disabled)? {
            let _app_server_proxy_env = EnvVarGuard::set_optional([(
                app_server_proxy::PENTECT_CODEX_APP_SERVER_PROXY_ENV,
                Some(OsString::from("1")),
            )]);
            cmd.env(app_server_proxy::PENTECT_CODEX_APP_SERVER_PROXY_ENV, "1");
            let proxy = app_server_proxy::AppServerProxyGuard::start(
                &opts.command,
                codex_app_server_args(&configs, &opts.tool_args),
            )?;
            let args = codex_args_with_remote(&configs, &opts.tool_args, Some(proxy.url()));
            cmd.args(args);
            return run_interactive_command_with_guard(cmd, &opts.command, proxy);
        } else {
            codex_args(&configs, &opts.tool_args)
        };
    cmd.args(codex_args);
    run_interactive_command(cmd, &opts.command)
}

fn run_claude(opts: &AgentToolOpts, pentect: &Path) -> Result<std::process::ExitStatus, String> {
    let settings = claude_settings_json(pentect, opts.session.as_deref());
    let args = claude_args(&settings, &opts.tool_args);
    if opts.dry_run {
        print_dry_run(&opts.command, &args);
        return Ok(success_status());
    }
    let active_extensions = agent_tool_extensions(opts)?;
    let mut cmd = Command::new(&opts.command);
    apply_extension_env(&mut cmd, &active_extensions)?;
    let memory_store = start_memory_store(pentect)?;
    let status_line_enabled = status_line_enabled_by_config()?;
    let _parent_env = agent_parent_env_guard(
        pentect,
        &memory_store,
        status_line_enabled,
        &active_extensions,
    )?;
    apply_pentect_env(&mut cmd, pentect, Some(memory_store.token.as_str()));
    apply_memory_store_env(&mut cmd, Some(&memory_store));
    apply_status_line_env(&mut cmd, status_line_enabled);
    cmd.args(&args);
    run_interactive_command(cmd, &opts.command)
}

fn run_bridge_agent(
    opts: &AgentToolOpts,
    pentect: &Path,
    tool: AgentTool,
) -> Result<std::process::ExitStatus, String> {
    use agent_integrations::{IntegrationKind, TempAgentIntegration};

    let kind = match tool {
        AgentTool::OpenCode => IntegrationKind::OpenCode,
        AgentTool::Pi => IntegrationKind::Pi,
        AgentTool::Codex | AgentTool::Claude => {
            return Err("unsupported bridge agent".to_string());
        }
    };
    let integration = TempAgentIntegration::create(kind)?;
    let mut args = Vec::new();
    if tool == AgentTool::Pi {
        args.push("--extension".to_string());
        args.push(integration.path().to_string_lossy().into_owned());
    }
    args.extend(opts.tool_args.iter().cloned());
    if opts.dry_run {
        print_dry_run(&opts.command, &args);
        return Ok(success_status());
    }

    let active_extensions = agent_tool_extensions(opts)?;
    let memory_store = start_memory_store(pentect)?;
    let status_line_enabled = status_line_enabled_by_config()?;
    let _parent_env = agent_parent_env_guard(
        pentect,
        &memory_store,
        status_line_enabled,
        &active_extensions,
    )?;
    let mut cmd = Command::new(&opts.command);
    apply_extension_env(&mut cmd, &active_extensions)?;
    apply_pentect_env(&mut cmd, pentect, Some(memory_store.token.as_str()));
    apply_memory_store_env(&mut cmd, Some(&memory_store));
    apply_status_line_env(&mut cmd, status_line_enabled);
    cmd.env("PENTECT_AGENT_CONTRACT", PENTECT_CONTRACT_INSTRUCTIONS);
    if tool == AgentTool::OpenCode {
        let existing = std::env::var("OPENCODE_CONFIG_CONTENT").ok();
        let config = agent_integrations::opencode_config_with_plugin(
            existing.as_deref(),
            integration.path(),
        )?;
        cmd.env("OPENCODE_CONFIG_CONTENT", config);
    }
    cmd.args(args);
    run_interactive_command_with_guard(cmd, &opts.command, (integration, memory_store))
}

fn run_interactive_command(
    mut cmd: Command,
    display: &Path,
) -> Result<std::process::ExitStatus, String> {
    run_interactive_command_inner(&mut cmd, display)
}

fn run_interactive_command_with_guard<G>(
    mut cmd: Command,
    display: &Path,
    _guard: G,
) -> Result<std::process::ExitStatus, String> {
    run_interactive_command_inner(&mut cmd, display)
}

fn run_interactive_command_inner(
    cmd: &mut Command,
    display: &Path,
) -> Result<std::process::ExitStatus, String> {
    let mut terminal_guard = terminal::TuiSessionGuard::enter();
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        let status = run_interactive_command_pty(cmd, display, &mut terminal_guard);
        return status;
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            terminal_guard.restore_without_prompt();
            return Err(format!("could not start '{}': {e}", display.display()));
        }
    };
    // Set this after spawn so child TUIs still receive Ctrl+C; the parent
    // stays alive long enough to restore terminal state after the child exits.
    let ctrl_c_guard = terminal::IgnoreCtrlCGuard::new();
    let status = match child.wait() {
        Ok(status) => status,
        Err(e) => {
            drop(ctrl_c_guard);
            terminal_guard.restore_after_tui();
            return Err(format!("could not wait for '{}': {e}", display.display()));
        }
    };
    drop(ctrl_c_guard);
    terminal_guard.restore_after_tui();
    Ok(status)
}

fn run_interactive_command_pty(
    cmd: &Command,
    display: &Path,
    terminal_guard: &mut terminal::TuiSessionGuard,
) -> Result<std::process::ExitStatus, String> {
    let pty_system = native_pty_system();
    let (cols, rows) = current_pty_size();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("could not start pty for '{}': {e}", display.display()))?;
    let command = command_builder_from_process_command(cmd)?;
    let mut child = match pair.slave.spawn_command(command) {
        Ok(child) => child,
        Err(e) => {
            terminal_guard.restore_without_prompt();
            return Err(format!("could not start '{}': {e}", display.display()));
        }
    };
    drop(pair.slave);
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("could not capture '{}': {e}", display.display()))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|e| format!("could not open '{}': {e}", display.display()))?;
    let output_thread = thread::spawn(move || proxy_pty_output(reader));
    let ctrl_c_guard = terminal::IgnoreCtrlCGuard::new();
    let status =
        pump_prompt_guarded_pty_input(child.as_mut(), writer, pair.master.as_ref(), (cols, rows));
    drop(ctrl_c_guard);
    drop(pair.master);
    match output_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            terminal_guard.restore_after_tui();
            return Err(e);
        }
        Err(_) => {
            terminal_guard.restore_after_tui();
            return Err("pty output thread panicked".to_string());
        }
    }
    let status = match status {
        Ok(status) => status,
        Err(e) => {
            terminal_guard.restore_after_tui();
            return Err(e);
        }
    };
    terminal_guard.restore_after_tui();
    Ok(exit_status_from_code(status.exit_code()))
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

fn command_builder_from_process_command(cmd: &Command) -> Result<CommandBuilder, String> {
    let mut command = CommandBuilder::new(cmd.get_program());
    command.args(cmd.get_args());
    let cwd = match cmd.get_current_dir() {
        Some(cwd) => cwd.to_path_buf(),
        None => std::env::current_dir().map_err(|e| format!("could not read current dir: {e}"))?,
    };
    command.cwd(cwd.as_os_str());
    for (name, value) in cmd.get_envs() {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        }
    }
    Ok(command)
}

fn proxy_pty_output(mut reader: Box<dyn Read + Send>) -> Result<(), String> {
    let mut out = std::io::stdout().lock();
    let mut buf = [0u8; 8192];
    let mut remasker = pentect_agent::ActiveTerminalOutputRemasker::new()?;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("could not read pty output: {e}"))?;
        if n == 0 {
            break;
        }
        let remasked = remasker.push(&buf[..n])?;
        buf[..n].zeroize();
        out.write_all(&remasked)
            .map_err(|e| format!("could not write pty output: {e}"))?;
        out.flush()
            .map_err(|e| format!("could not flush pty output: {e}"))?;
    }
    let tail = remasker.finish()?;
    out.write_all(&tail)
        .map_err(|e| format!("could not write pty output tail: {e}"))?;
    out.flush()
        .map_err(|e| format!("could not flush pty output tail: {e}"))?;
    Ok(())
}

fn pump_prompt_guarded_pty_input(
    child: &mut dyn PtyChild,
    mut child_stdin: Box<dyn Write + Send>,
    master: &dyn MasterPty,
    mut pty_size: (u16, u16),
) -> Result<portable_pty::ExitStatus, String> {
    let _raw = RawModeGuard::enable()?;
    let mut protector = PromptInputProtector::default();
    let (input_tx, input_rx) = mpsc::channel();
    thread::spawn(move || {
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
            .map_err(|e| format!("could not poll agent: {e}"))?
        {
            return Ok(status);
        }
        match input_rx.recv_timeout(PROMPT_INPUT_POLL) {
            Ok(bytes) if bytes.is_empty() => {
                let tail = protector.flush()?;
                if !tail.is_empty() {
                    child_stdin
                        .write_all(&tail)
                        .map_err(|e| format!("could not write agent input: {e}"))?;
                }
                drop(child_stdin);
                return child
                    .wait()
                    .map_err(|e| format!("could not wait for agent: {e}"));
            }
            Ok(bytes) => {
                let rewritten = protector.rewrite_bytes(&bytes)?;
                if !rewritten.is_empty() {
                    child_stdin
                        .write_all(&rewritten)
                        .map_err(|e| format!("could not write agent input: {e}"))?;
                    child_stdin
                        .flush()
                        .map_err(|e| format!("could not flush agent input: {e}"))?;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let tail = protector.flush()?;
                if !tail.is_empty() {
                    child_stdin
                        .write_all(&tail)
                        .map_err(|e| format!("could not write agent input: {e}"))?;
                }
                drop(child_stdin);
                return child
                    .wait()
                    .map_err(|e| format!("could not wait for agent: {e}"));
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

#[derive(Default)]
struct PromptInputProtector {
    state: PromptInputState,
    #[cfg(windows)]
    win32: Win32PromptInputState,
}

impl PromptInputProtector {
    fn rewrite_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut mask = |text: &str| pentect_agent::mask_prompt_text_into_active_memory_store(text);
        #[cfg(windows)]
        {
            rewrite_win32_prompt_input_bytes_with(
                &mut self.state,
                &mut self.win32,
                bytes,
                &mut mask,
            )
        }
        #[cfg(not(windows))]
        {
            rewrite_prompt_input_bytes_with(&mut self.state, bytes, &mut mask)
        }
    }

    fn flush(&mut self) -> Result<Vec<u8>, String> {
        let mut mask = |text: &str| pentect_agent::mask_prompt_text_into_active_memory_store(text);
        #[cfg(windows)]
        {
            flush_win32_prompt_input_with(&mut self.state, &mut self.win32, &mut mask)
        }
        #[cfg(not(windows))]
        {
            flush_prompt_input_with(&mut self.state, &mut mask)
        }
    }
}

#[derive(Default)]
struct PromptInputState {
    pending: Vec<u8>,
    in_bracketed_paste: bool,
}

#[cfg(windows)]
#[derive(Default)]
struct Win32PromptInputState {
    decode_pending: Vec<u8>,
}

#[cfg(windows)]
enum Win32InputRecord {
    Text(Vec<u16>),
    KeyUp,
    NonText,
}

#[cfg(windows)]
fn rewrite_win32_prompt_input_bytes_with<F>(
    normal: &mut PromptInputState,
    state: &mut Win32PromptInputState,
    bytes: &[u8],
    mask: &mut F,
) -> Result<Vec<u8>, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    state.decode_pending.extend_from_slice(bytes);
    let mut out = Vec::with_capacity(bytes.len());
    loop {
        let Some(start) = find_bytes(&state.decode_pending, b"\x1b[") else {
            let keep = partial_suffix_prefix_len(&state.decode_pending, b"\x1b[");
            let emit_len = state.decode_pending.len().saturating_sub(keep);
            if emit_len > 0 {
                let mut raw: Vec<u8> = state.decode_pending.drain(..emit_len).collect();
                out.extend(rewrite_prompt_input_bytes_with(normal, &raw, mask)?);
                raw.zeroize();
            }
            break;
        };
        if start > 0 {
            let mut raw: Vec<u8> = state.decode_pending.drain(..start).collect();
            out.extend(rewrite_prompt_input_bytes_with(normal, &raw, mask)?);
            raw.zeroize();
            continue;
        }
        let Some(final_offset) = state
            .decode_pending
            .iter()
            .enumerate()
            .skip(2)
            .find_map(|(index, byte)| (b'@'..=b'~').contains(byte).then_some(index))
        else {
            break;
        };
        let mut sequence: Vec<u8> = state.decode_pending.drain(..=final_offset).collect();
        match parse_win32_input_record(&sequence) {
            Some(Win32InputRecord::Text(units)) => match String::from_utf16(&units) {
                Ok(mut text) => {
                    out.extend(rewrite_prompt_input_bytes_with(
                        normal,
                        text.as_bytes(),
                        mask,
                    )?);
                    text.zeroize();
                }
                Err(_) => out.extend_from_slice(&sequence),
            },
            Some(Win32InputRecord::KeyUp) => {}
            Some(Win32InputRecord::NonText) => out.extend_from_slice(&sequence),
            None => out.extend(rewrite_prompt_input_bytes_with(normal, &sequence, mask)?),
        }
        sequence.zeroize();
    }
    if state.decode_pending.len() > PROMPT_INPUT_MAX_PENDING_BYTES {
        state.decode_pending.zeroize();
        state.decode_pending.clear();
        return Err("terminal input sequence exceeds 1 MiB".to_string());
    }
    Ok(out)
}

#[cfg(windows)]
fn parse_win32_input_record(sequence: &[u8]) -> Option<Win32InputRecord> {
    let body = sequence.strip_prefix(b"\x1b[")?.strip_suffix(b"_")?;
    let text = std::str::from_utf8(body).ok()?;
    let fields = text
        .split(';')
        .map(|field| field.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>()?;
    if fields.len() != 6 {
        return None;
    }
    let unicode = u16::try_from(*fields.get(2)?).ok()?;
    let key_down = *fields.get(3)?;
    let repeat = usize::try_from(*fields.get(5)?).ok()?;
    if repeat > 1024 {
        return None;
    }
    if key_down == 0 {
        return Some(Win32InputRecord::KeyUp);
    }
    if unicode == 0 {
        return Some(Win32InputRecord::NonText);
    }
    Some(Win32InputRecord::Text(vec![unicode; repeat.max(1)]))
}

#[cfg(windows)]
#[cfg(test)]
fn encode_win32_unicode_input(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len().saturating_mul(40));
    for unit in text.encode_utf16() {
        out.extend_from_slice(format!("\x1b[0;0;{unit};1;0;1_").as_bytes());
        out.extend_from_slice(format!("\x1b[0;0;{unit};0;0;1_").as_bytes());
    }
    out
}

#[cfg(windows)]
fn flush_win32_prompt_input_with<F>(
    normal: &mut PromptInputState,
    state: &mut Win32PromptInputState,
    mask: &mut F,
) -> Result<Vec<u8>, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    let mut out = Vec::new();
    if !state.decode_pending.is_empty() {
        let mut raw = std::mem::take(&mut state.decode_pending);
        out.extend(rewrite_prompt_input_bytes_with(normal, &raw, mask)?);
        raw.zeroize();
    }
    out.extend(flush_prompt_input_with(normal, mask)?);
    Ok(out)
}

fn rewrite_prompt_input_bytes_with<F>(
    state: &mut PromptInputState,
    bytes: &[u8],
    mask: &mut F,
) -> Result<Vec<u8>, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    state.pending.extend_from_slice(bytes);
    let mut out = Vec::with_capacity(bytes.len());
    loop {
        if state.in_bracketed_paste {
            if let Some(end) = find_bytes(&state.pending, PROMPT_PASTE_END) {
                let mut content: Vec<u8> = state.pending.drain(..end).collect();
                out.extend(rewrite_prompt_plain_bytes_with(&content, true, mask)?);
                content.zeroize();
                state.pending.drain(..PROMPT_PASTE_END.len());
                out.extend_from_slice(PROMPT_PASTE_END);
                state.in_bracketed_paste = false;
                continue;
            }
            if state.pending.len() > PROMPT_INPUT_MAX_PENDING_BYTES {
                let mut content = std::mem::take(&mut state.pending);
                out.extend(rewrite_prompt_plain_bytes_with(&content, true, mask)?);
                content.zeroize();
                state.in_bracketed_paste = false;
            }
            break;
        }

        if let Some(start) = find_bytes(&state.pending, PROMPT_PASTE_START) {
            let mut before: Vec<u8> = state.pending.drain(..start).collect();
            out.extend(rewrite_prompt_plain_bytes_with(&before, false, mask)?);
            before.zeroize();
            state.pending.drain(..PROMPT_PASTE_START.len());
            out.extend_from_slice(PROMPT_PASTE_START);
            state.in_bracketed_paste = true;
            continue;
        }

        let keep = partial_suffix_prefix_len(&state.pending, PROMPT_PASTE_START);
        let emit_len = state.pending.len().saturating_sub(keep);
        if emit_len > 0 {
            let mut plain: Vec<u8> = state.pending.drain(..emit_len).collect();
            out.extend(rewrite_prompt_plain_bytes_with(&plain, false, mask)?);
            plain.zeroize();
        }
        break;
    }
    Ok(out)
}

fn flush_prompt_input_with<F>(state: &mut PromptInputState, mask: &mut F) -> Result<Vec<u8>, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    if state.pending.is_empty() {
        return Ok(Vec::new());
    }
    let mut pending = std::mem::take(&mut state.pending);
    let out = rewrite_prompt_plain_bytes_with(&pending, state.in_bracketed_paste, mask)?;
    pending.zeroize();
    state.in_bracketed_paste = false;
    Ok(out)
}

fn rewrite_prompt_plain_bytes_with<F>(
    bytes: &[u8],
    force_scan: bool,
    mask: &mut F,
) -> Result<Vec<u8>, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Ok(bytes.to_vec());
    };
    if !force_scan && !should_scan_prompt_input_text(text) {
        return Ok(bytes.to_vec());
    }
    match mask(text)? {
        Some(masked) if masked != text => Ok(masked.into_bytes()),
        _ => Ok(bytes.to_vec()),
    }
}

fn should_scan_prompt_input_text(text: &str) -> bool {
    text.len() >= 32 && !text.contains('\x1b')
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn partial_suffix_prefix_len(bytes: &[u8], prefix: &[u8]) -> usize {
    let max = bytes.len().min(prefix.len().saturating_sub(1));
    (1..=max)
        .rev()
        .find(|len| bytes[bytes.len() - len..] == prefix[..*len])
        .unwrap_or(0)
}

struct MemoryStoreGuard {
    child: Option<Child>,
    lease: Option<pentect_agent::MemoryStoreLease>,
    addr: String,
    token: String,
    process_host_read_token: String,
    process_host_write_token: String,
    process_host_root: PathBuf,
    process_host_candidate: Option<PathBuf>,
}

impl MemoryStoreGuard {
    fn start(pentect: &Path, persistent: bool) -> Result<Option<Self>, String> {
        if !persistent {
            if let (
                Some(addr),
                Some(token),
                Some(process_host_read_token),
                Some(process_host_write_token),
                Some(process_host_root),
            ) = (
                std::env::var_os(PENTECT_MEMORY_STORE_ADDR_ENV),
                std::env::var_os(PENTECT_MEMORY_STORE_TOKEN_ENV),
                std::env::var_os(PENTECT_PROCESS_HOST_READ_TOKEN_ENV),
                std::env::var_os(PENTECT_PROCESS_HOST_WRITE_TOKEN_ENV),
                std::env::var_os(PENTECT_PROCESS_HOST_ROOT_ENV),
            ) {
                let addr = addr.to_string_lossy().to_string();
                let token = token.to_string_lossy().to_string();
                let process_host_read_token = process_host_read_token.to_string_lossy().to_string();
                let process_host_write_token =
                    process_host_write_token.to_string_lossy().to_string();
                if !addr.is_empty()
                    && !token.is_empty()
                    && !process_host_read_token.is_empty()
                    && !process_host_write_token.is_empty()
                    && !process_host_root.is_empty()
                {
                    return Ok(Some(Self {
                        child: None,
                        lease: None,
                        addr,
                        token,
                        process_host_read_token,
                        process_host_write_token,
                        process_host_root: PathBuf::from(process_host_root),
                        process_host_candidate: None,
                    }));
                }
            }
        }
        let mut command = Command::new(pentect);
        command
            .arg("agent")
            .arg("memory-store")
            .arg("--serve")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if persistent {
            configure_persistent_child(&mut command);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("could not start Pentect memory store: {e}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "could not capture Pentect memory store startup".to_string())?;
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout)
                .read_line(&mut line)
                .map_err(|e| format!("could not read Pentect memory store startup: {e}"))
                .and_then(|_| {
                    if line.trim().is_empty() {
                        Err("Pentect memory store exited before startup".to_string())
                    } else {
                        Ok(line)
                    }
                });
            let _ = tx.send(result);
        });
        let line = match rx.recv_timeout(MEMORY_STORE_STARTUP_TIMEOUT) {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Pentect memory store did not start within 5 seconds".to_string());
            }
        };
        let (addr, token, process_host_read_token, process_host_write_token) =
            match parse_memory_store_startup(&line) {
                Ok(parsed) => parsed,
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e);
                }
            };
        let lease = if persistent {
            None
        } else {
            match pentect_agent::open_memory_store_lease(&addr, &token) {
                Ok(lease) => Some(lease),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error.to_string());
                }
            }
        };
        let process_host_root = process_host_root()?;
        let process_host_candidate = match pentect_agent::register_process_host_candidate(
            &process_host_root,
            &addr,
            &process_host_read_token,
            &process_host_write_token,
            child.id(),
            persistent,
        ) {
            Ok(Some(path)) => path,
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(None);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        Ok(Some(Self {
            child: Some(child),
            lease,
            addr,
            token,
            process_host_read_token,
            process_host_write_token,
            process_host_root,
            process_host_candidate: Some(process_host_candidate),
        }))
    }

    fn detach(mut self) {
        self.lease.take();
        self.child.take();
        self.process_host_candidate.take();
    }
}

impl Drop for MemoryStoreGuard {
    fn drop(&mut self) {
        if let Some(path) = self.process_host_candidate.take() {
            pentect_agent::unregister_process_host_candidate(&path);
        }
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.token.zeroize();
        self.process_host_read_token.zeroize();
        self.process_host_write_token.zeroize();
    }
}

#[cfg(windows)]
fn configure_persistent_child(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
}

fn process_host_root() -> Result<PathBuf, String> {
    if let Some(root) = std::env::var_os(PENTECT_PROCESS_HOST_ROOT_ENV).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(root));
    }
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .or_else(|| {
                std::env::var_os("USERPROFILE").map(|home| {
                    PathBuf::from(home)
                        .join("AppData")
                        .join("Local")
                        .into_os_string()
                })
            })
            .map(PathBuf::from)
            .map(|root| root.join("pentect"))
            .ok_or_else(|| "could not locate local application data".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join("Library").join("Caches").join("pentect"))
            .ok_or_else(|| "could not locate the user cache directory".to_string())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(root) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(root).join("pentect"));
        }
        if let Some(root) = std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(root).join("pentect"));
        }
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".cache").join("pentect"))
            .ok_or_else(|| "could not locate the user cache directory".to_string())
    }
}

#[cfg(unix)]
fn configure_persistent_child(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

fn apply_pentect_env(cmd: &mut Command, pentect: &Path, launch_proof: Option<&str>) {
    cmd.env(PENTECT_BIN_ENV, pentect);
    if let Some(launch_proof) = launch_proof.filter(|value| !value.is_empty()) {
        cmd.env(PENTECT_AGENT_LAUNCHED_ENV, launch_proof);
    } else {
        cmd.env_remove(PENTECT_AGENT_LAUNCHED_ENV);
    }
}

fn apply_memory_store_env(cmd: &mut Command, memory_store: Option<&MemoryStoreGuard>) {
    let Some(memory_store) = memory_store else {
        return;
    };
    cmd.env(PENTECT_MEMORY_STORE_ADDR_ENV, &memory_store.addr);
    cmd.env(PENTECT_MEMORY_STORE_TOKEN_ENV, &memory_store.token);
    cmd.env(
        PENTECT_PROCESS_HOST_READ_TOKEN_ENV,
        &memory_store.process_host_read_token,
    );
    cmd.env(
        PENTECT_PROCESS_HOST_WRITE_TOKEN_ENV,
        &memory_store.process_host_write_token,
    );
    cmd.env(
        PENTECT_PROCESS_HOST_ROOT_ENV,
        &memory_store.process_host_root,
    );
}

fn apply_status_line_env(cmd: &mut Command, enabled: bool) {
    cmd.env(PENTECT_STATUS_LINE_ENV, if enabled { "1" } else { "0" });
}

fn memory_store_parent_env_guard(pentect: &Path, memory_store: &MemoryStoreGuard) -> EnvVarGuard {
    EnvVarGuard::set_optional([
        (
            PENTECT_MEMORY_STORE_ADDR_ENV,
            Some(OsString::from(memory_store.addr.as_str())),
        ),
        (
            PENTECT_MEMORY_STORE_TOKEN_ENV,
            Some(OsString::from(memory_store.token.as_str())),
        ),
        (
            PENTECT_PROCESS_HOST_READ_TOKEN_ENV,
            Some(OsString::from(
                memory_store.process_host_read_token.as_str(),
            )),
        ),
        (
            PENTECT_PROCESS_HOST_WRITE_TOKEN_ENV,
            Some(OsString::from(
                memory_store.process_host_write_token.as_str(),
            )),
        ),
        (
            PENTECT_PROCESS_HOST_ROOT_ENV,
            Some(memory_store.process_host_root.clone().into_os_string()),
        ),
        (PENTECT_BIN_ENV, Some(pentect.as_os_str().to_os_string())),
        (
            PENTECT_AGENT_LAUNCHED_ENV,
            Some(OsString::from(memory_store.token.as_str())),
        ),
    ])
}

fn agent_parent_env_guard(
    pentect: &Path,
    memory_store: &MemoryStoreGuard,
    status_line_enabled: bool,
    active_extensions: &extensions::ActiveExtensions,
) -> Result<EnvVarGuard, String> {
    let config_env = active_extensions
        .config_env_value()
        .map_err(|e| e.to_string())?;
    let adapter_env = active_extensions
        .adapter_env_value()
        .map_err(|e| e.to_string())?;
    Ok(EnvVarGuard::set_optional([
        (
            PENTECT_MEMORY_STORE_ADDR_ENV,
            Some(OsString::from(memory_store.addr.as_str())),
        ),
        (
            PENTECT_MEMORY_STORE_TOKEN_ENV,
            Some(OsString::from(memory_store.token.as_str())),
        ),
        (
            PENTECT_PROCESS_HOST_READ_TOKEN_ENV,
            Some(OsString::from(
                memory_store.process_host_read_token.as_str(),
            )),
        ),
        (
            PENTECT_PROCESS_HOST_WRITE_TOKEN_ENV,
            Some(OsString::from(
                memory_store.process_host_write_token.as_str(),
            )),
        ),
        (
            PENTECT_PROCESS_HOST_ROOT_ENV,
            Some(memory_store.process_host_root.clone().into_os_string()),
        ),
        (PENTECT_BIN_ENV, Some(pentect.as_os_str().to_os_string())),
        (
            PENTECT_AGENT_LAUNCHED_ENV,
            Some(OsString::from(memory_store.token.as_str())),
        ),
        (
            PENTECT_STATUS_LINE_ENV,
            Some(OsString::from(if status_line_enabled { "1" } else { "0" })),
        ),
        (extensions::CONFIGS_ENV, config_env),
        (extensions::ADAPTERS_ENV, adapter_env),
    ]))
}

fn status_line_enabled_by_config() -> Result<bool, String> {
    let path = Path::new(PENTECT_DIR).join(PENTECT_CONFIG_FILE);
    if !path.exists() {
        return Ok(true);
    }
    let src = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if src.trim().is_empty() {
        return Ok(true);
    }
    let value = src
        .parse::<toml::Value>()
        .map_err(|e| format!("could not parse '{}': {e}", path.display()))?;
    Ok(status_line_config_value(&value)?.unwrap_or(true))
}

fn status_line_config_value(value: &toml::Value) -> Result<Option<bool>, String> {
    if let Some(raw) = value.get("status_line") {
        return status_line_config_bool(raw, "status_line").map(Some);
    }
    let Some(raw) = value.get("agent") else {
        return Ok(None);
    };
    let Some(table) = raw.as_table() else {
        return Err("agent config must be a table".to_string());
    };
    if let Some(raw) = table.get("status_line") {
        return status_line_config_bool(raw, "agent.status_line").map(Some);
    }
    Ok(None)
}

fn status_line_config_bool(value: &toml::Value, field: &str) -> Result<bool, String> {
    if let Some(value) = value.as_bool() {
        return Ok(value);
    }
    if let Some(value) = value.as_str() {
        return match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(format!("config {field} must be boolean-like")),
        };
    }
    Err(format!("config {field} must be a boolean"))
}

fn parse_memory_store_startup(line: &str) -> Result<(String, String, String, String), String> {
    let startup: Value = serde_json::from_str(line)
        .map_err(|e| format!("Pentect memory store startup was not JSON: {e}"))?;
    let addr = startup
        .get("addr")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Pentect memory store startup did not include addr".to_string())?
        .to_string();
    let token = startup
        .get("token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Pentect memory store startup did not include token".to_string())?
        .to_string();
    let process_host_read_token = startup
        .get("process_host_read_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "Pentect memory store startup did not include process_host_read_token".to_string()
        })?
        .to_string();
    let process_host_write_token = startup
        .get("process_host_write_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "Pentect memory store startup did not include process_host_write_token".to_string()
        })?
        .to_string();
    Ok((
        addr,
        token,
        process_host_read_token,
        process_host_write_token,
    ))
}

struct EnvVarGuard {
    previous: Vec<(&'static str, Option<OsString>)>,
}

impl EnvVarGuard {
    fn set_optional<const N: usize>(pairs: [(&'static str, Option<OsString>); N]) -> Self {
        let mut previous = Vec::with_capacity(N);
        for (name, value) in pairs {
            previous.push((name, std::env::var_os(name)));
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        Self { previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (name, value) in self.previous.drain(..).rev() {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

struct CodexEnvironmentOverlayGuard {
    path: PathBuf,
    backup_path: PathBuf,
    previous: Option<Vec<u8>>,
}

impl CodexEnvironmentOverlayGuard {
    fn install(exec_proxy_url: &str) -> Result<Self, String> {
        let codex_home = codex_home_dir()?;
        std::fs::create_dir_all(&codex_home).map_err(|e| {
            format!(
                "could not create Codex home '{}': {e}",
                codex_home.display()
            )
        })?;
        let path = codex_home.join("environments.toml");
        let backup_path = codex_home.join("environments.toml.pentect.bak");
        recover_stale_codex_environment_overlay(&path, &backup_path)?;
        let previous = match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(format!(
                    "could not read Codex environments '{}': {e}",
                    path.display()
                ));
            }
        };
        match previous.as_ref() {
            Some(previous) => std::fs::write(&backup_path, previous).map_err(|e| {
                format!(
                    "could not write Codex environments backup '{}': {e}",
                    backup_path.display()
                )
            })?,
            None => {
                let _ = std::fs::remove_file(&backup_path);
            }
        }
        std::fs::write(&path, codex_environments_toml(exec_proxy_url)).map_err(|e| {
            format!(
                "could not write Codex environments '{}': {e}",
                path.display()
            )
        })?;
        Ok(Self {
            path,
            backup_path,
            previous,
        })
    }
}

impl Drop for CodexEnvironmentOverlayGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(previous) => {
                let _ = std::fs::write(&self.path, previous);
            }
            None => {
                let _ = std::fs::remove_file(&self.path);
            }
        }
        let _ = std::fs::remove_file(&self.backup_path);
    }
}

fn recover_stale_codex_environment_overlay(path: &Path, backup_path: &Path) -> Result<(), String> {
    let current = match std::fs::read(path) {
        Ok(current) => current,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "could not inspect Codex environments '{}': {e}",
                path.display()
            ));
        }
    };
    if !current.starts_with(CODEX_ENVIRONMENT_OVERLAY_MARKER) {
        return Ok(());
    }
    match std::fs::read(backup_path) {
        Ok(previous) => {
            std::fs::write(path, previous).map_err(|e| {
                format!(
                    "could not restore Codex environments '{}': {e}",
                    path.display()
                )
            })?;
            let _ = std::fs::remove_file(backup_path);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::remove_file(path).map_err(|e| {
                format!(
                    "could not remove stale Codex environments '{}': {e}",
                    path.display()
                )
            })?;
        }
        Err(e) => {
            return Err(format!(
                "could not read Codex environments backup '{}': {e}",
                backup_path.display()
            ));
        }
    }
    Ok(())
}

fn codex_home_dir() -> Result<PathBuf, String> {
    if let Some(value) = std::env::var_os("CODEX_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(value));
    }
    if cfg!(windows) {
        if let Some(profile) = std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
            return Ok(PathBuf::from(profile).join(".codex"));
        }
        if let (Some(drive), Some(path)) =
            (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH"))
        {
            let mut home = PathBuf::from(drive);
            home.push(path);
            return Ok(home.join(".codex"));
        }
    }
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(".codex"))
        .ok_or_else(|| "could not resolve Codex home".to_string())
}

fn codex_environments_toml(exec_proxy_url: &str) -> String {
    format!(
        "{}default = \"pentect\"\ninclude_local = true\n\n[[environments]]\nid = \"pentect\"\nurl = {}\n",
        String::from_utf8_lossy(CODEX_ENVIRONMENT_OVERLAY_MARKER),
        toml_string(exec_proxy_url)
    )
}

fn apply_extension_env(
    cmd: &mut Command,
    active: &extensions::ActiveExtensions,
) -> Result<(), String> {
    if let Some(value) = active.config_env_value().map_err(|e| e.to_string())? {
        cmd.env(extensions::CONFIGS_ENV, value);
    }
    if let Some(value) = active.adapter_env_value().map_err(|e| e.to_string())? {
        cmd.env(extensions::ADAPTERS_ENV, value);
    }
    Ok(())
}

fn codex_args(configs: &[String], tool_args: &[String]) -> Vec<String> {
    codex_args_with_remote(configs, tool_args, None)
}

fn codex_args_with_remote(
    configs: &[String],
    tool_args: &[String],
    remote: Option<&str>,
) -> Vec<String> {
    let mut args = Vec::with_capacity(configs.len() * 2 + 5 + tool_args.len());
    if !codex_args_disable_unified_exec(tool_args) && !codex_args_enable_unified_exec(tool_args) {
        args.push("--enable".to_string());
        args.push("unified_exec".to_string());
    }
    for config in configs {
        args.push("--config".to_string());
        args.push(config.clone());
    }
    args.push("--config".to_string());
    args.push(format!(
        "developer_instructions={}",
        toml_string(PENTECT_CONTRACT_INSTRUCTIONS)
    ));
    if let Some(remote) = remote {
        args.push("--remote".to_string());
        args.push(remote.to_string());
    }
    args.extend(tool_args.iter().cloned());
    args
}

fn codex_app_server_args(configs: &[String], tool_args: &[String]) -> Vec<String> {
    let mut args = Vec::with_capacity(configs.len() * 2 + 5);
    if !codex_args_disable_unified_exec(tool_args) && !codex_args_enable_unified_exec(tool_args) {
        args.push("--enable".to_string());
        args.push("unified_exec".to_string());
    }
    for config in configs {
        args.push("--config".to_string());
        args.push(config.clone());
    }
    args.push("--config".to_string());
    args.push(format!(
        "developer_instructions={}",
        toml_string(PENTECT_CONTRACT_INSTRUCTIONS)
    ));
    for (flag, value) in codex_root_config_args(tool_args) {
        args.push(flag);
        if let Some(value) = value {
            args.push(value);
        }
    }
    args
}

fn codex_root_config_args(args: &[String]) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            break;
        }
        match arg {
            "-c" | "--config" | "--enable" | "--disable" => {
                if let Some(value) = args.get(i + 1) {
                    out.push((arg.to_string(), Some(value.clone())));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--strict-config" => {
                out.push((arg.to_string(), None));
                i += 1;
            }
            _ if arg.starts_with("--config=")
                || arg.starts_with("--enable=")
                || arg.starts_with("--disable=") =>
            {
                out.push((arg.to_string(), None));
                i += 1;
            }
            _ if arg.starts_with('-') => {
                i += if codex_long_option_takes_value(arg) || codex_short_option_takes_value(arg) {
                    2
                } else {
                    1
                };
            }
            _ => {
                break;
            }
        }
    }
    out
}

fn codex_args_enable_unified_exec(args: &[String]) -> bool {
    codex_args_feature_value(args, "--enable", "unified_exec")
}

fn codex_args_disable_unified_exec(args: &[String]) -> bool {
    codex_args_feature_value(args, "--disable", "unified_exec")
}

fn codex_unified_exec_proxy_enabled(args: &[String]) -> bool {
    !codex_args_disable_unified_exec(args)
}

fn codex_app_server_proxy_enabled(args: &[String], disabled: bool) -> Result<bool, String> {
    if disabled {
        return Ok(false);
    }
    if codex_metadata_only_args(args) {
        return Ok(false);
    }
    if codex_args_remote_value(args).is_some() {
        return Err(
            "`pentect codex` owns Codex --remote; remove --remote or pass --no-app-server-proxy"
                .to_string(),
        );
    }
    let path = Path::new(PENTECT_DIR).join(PENTECT_CONFIG_FILE);
    if !path.exists() {
        return Ok(true);
    }
    let src = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if src.trim().is_empty() {
        return Ok(true);
    }
    let value = src
        .parse::<toml::Value>()
        .map_err(|e| format!("could not parse '{}': {e}", path.display()))?;
    Ok(codex_app_server_proxy_config_value(&value)?.unwrap_or(true))
}

fn codex_app_server_proxy_config_value(value: &toml::Value) -> Result<Option<bool>, String> {
    let Some(raw) = value.get("agent") else {
        return Ok(None);
    };
    let Some(table) = raw.as_table() else {
        return Err("agent config must be a table".to_string());
    };
    if let Some(raw) = table.get("codex_app_server_proxy") {
        return status_line_config_bool(raw, "agent.codex_app_server_proxy").map(Some);
    }
    Ok(None)
}

fn codex_args_remote_value(args: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            return None;
        }
        if arg == "--remote" {
            return args.get(i + 1).map(String::as_str);
        }
        if let Some(value) = arg.strip_prefix("--remote=") {
            return Some(value);
        }
        i += if codex_long_option_takes_value(arg) || codex_short_option_takes_value(arg) {
            2
        } else {
            1
        };
    }
    None
}

fn codex_metadata_only_args(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h" | "--version" | "-V"))
        || matches!(codex_first_positional(args), Some("help"))
}

fn codex_args_feature_value(args: &[String], flag: &str, feature: &str) -> bool {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == flag {
            if args.get(i + 1).is_some_and(|value| value == feature) {
                return true;
            }
            i += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
            if value == feature {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn claude_args(settings: &str, tool_args: &[String]) -> Vec<String> {
    let mut args = vec![
        "--settings".to_string(),
        settings.to_string(),
        "--append-system-prompt".to_string(),
        PENTECT_CONTRACT_INSTRUCTIONS.to_string(),
    ];
    args.extend(tool_args.iter().cloned());
    args
}

fn codex_hook_config_args(agent: &Path, session: Option<&str>) -> Result<Vec<String>, String> {
    let command = hook_command(agent, "codex", session);
    let windows = hook_command_windows(agent, "codex", session);
    let hooks = codex_hooks_inline_table(&command, &windows)?;
    Ok(vec![
        "features.hooks=true".to_string(),
        format!("hooks={hooks}"),
    ])
}

fn codex_hooks_inline_table(command: &str, windows: &str) -> Result<String, String> {
    const MATCHER: &str = "*";
    const TIMEOUT: u64 = 30;
    let pre_hash = codex_command_hook_hash("pre_tool_use", MATCHER, command, windows, TIMEOUT)?;
    let post_hash = codex_command_hook_hash("post_tool_use", MATCHER, command, windows, TIMEOUT)?;
    let pre_key = codex_session_flags_hook_key("pre_tool_use", 0, 0);
    let post_key = codex_session_flags_hook_key("post_tool_use", 0, 0);
    let hook = format!(
        "{{matcher={},hooks=[{{type=\"command\",command={},commandWindows={},timeout={TIMEOUT}}}]}}",
        toml_string(MATCHER),
        toml_string(command),
        toml_string(windows)
    );
    Ok(format!(
        "{{PreToolUse=[{hook}],PostToolUse=[{hook}],state={{{}={{trusted_hash={}}},{}={{trusted_hash={}}}}}}}",
        toml_string(&pre_key),
        toml_string(&pre_hash),
        toml_string(&post_key),
        toml_string(&post_hash)
    ))
}

fn codex_session_flags_hook_key(
    event_label: &str,
    group_index: usize,
    handler_index: usize,
) -> String {
    format!(
        "{}:{event_label}:{group_index}:{handler_index}",
        codex_session_flags_config_path()
    )
}

fn codex_session_flags_config_path() -> &'static str {
    if cfg!(windows) {
        r"C:\<session-flags>\config.toml"
    } else {
        "/<session-flags>/config.toml"
    }
}

#[derive(serde::Serialize)]
struct CodexNormalizedHookIdentity<'a> {
    event_name: &'a str,
    #[serde(flatten)]
    group: CodexMatcherGroup<'a>,
}

#[derive(Clone, serde::Serialize)]
struct CodexMatcherGroup<'a> {
    matcher: Option<&'a str>,
    hooks: Vec<CodexHookHandlerConfig<'a>>,
}

#[derive(Clone, serde::Serialize)]
#[serde(tag = "type")]
enum CodexHookHandlerConfig<'a> {
    #[serde(rename = "command")]
    Command {
        command: &'a str,
        #[serde(rename = "commandWindows", skip_serializing_if = "Option::is_none")]
        command_windows: Option<&'a str>,
        #[serde(rename = "timeout", skip_serializing_if = "Option::is_none")]
        timeout_sec: Option<u64>,
        #[serde(rename = "async")]
        r#async: bool,
        #[serde(rename = "statusMessage", skip_serializing_if = "Option::is_none")]
        status_message: Option<&'a str>,
    },
}

fn codex_command_hook_hash(
    event_label: &str,
    matcher: &str,
    command: &str,
    windows: &str,
    timeout_sec: u64,
) -> Result<String, String> {
    let platform_command = if cfg!(windows) { windows } else { command };
    let identity = CodexNormalizedHookIdentity {
        event_name: event_label,
        group: CodexMatcherGroup {
            matcher: Some(matcher),
            hooks: vec![CodexHookHandlerConfig::Command {
                command: platform_command,
                command_windows: None,
                timeout_sec: Some(timeout_sec),
                r#async: false,
                status_message: None,
            }],
        },
    };
    let value = toml::Value::try_from(identity)
        .map_err(|e| format!("could not build Codex hook trust identity: {e}"))?;
    version_for_toml_value(&value)
}

fn version_for_toml_value(value: &toml::Value) -> Result<String, String> {
    let json = serde_json::to_value(value)
        .map_err(|e| format!("could not serialize Codex hook trust identity: {e}"))?;
    let canonical = canonical_json_value(&json);
    let serialized = serde_json::to_vec(&canonical)
        .map_err(|e| format!("could not encode Codex hook trust identity: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(serialized);
    let hash = hasher.finalize();
    let hex = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("sha256:{hex}"))
}

fn canonical_json_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            for key in keys {
                if let Some(value) = map.get(key) {
                    sorted.insert(key.clone(), canonical_json_value(value));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_json_value).collect()),
        other => other.clone(),
    }
}

fn codex_uses_unverified_headless_hook_path(tool_args: &[String]) -> bool {
    if tool_args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h" | "--version" | "-V"))
    {
        return false;
    }
    matches!(
        codex_first_positional(tool_args),
        Some("exec" | "e" | "review")
    )
}

fn codex_first_positional(args: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            return args.get(i + 1).map(String::as_str);
        }
        if arg.starts_with("--") {
            i += if codex_long_option_takes_value(arg) {
                2
            } else {
                1
            };
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            i += if codex_short_option_takes_value(arg) {
                2
            } else {
                1
            };
            continue;
        }
        return Some(arg);
    }
    None
}

fn codex_long_option_takes_value(arg: &str) -> bool {
    if arg.contains('=') {
        return false;
    }
    matches!(
        arg,
        "--model"
            | "--config"
            | "--profile"
            | "--sandbox"
            | "--ask-for-approval"
            | "--cd"
            | "--add-dir"
            | "--enable"
            | "--disable"
            | "--remote"
            | "--remote-auth-token-env"
            | "--image"
            | "--local-provider"
            | "--output-last-message"
            | "--color"
    )
}

fn codex_short_option_takes_value(arg: &str) -> bool {
    matches!(arg, "-m" | "-c" | "-p" | "-s" | "-C" | "-o")
}

fn claude_settings_json(agent: &Path, session: Option<&str>) -> String {
    let words = hook_words(agent, "claude", session);
    let command = words[0].clone();
    let args = words[1..].to_vec();
    json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": "*",
                "hooks": [{
                    "type": "command",
                    "command": command.clone(),
                    "args": args.clone(),
                    "timeout": 30
                }]
            }],
            "PostToolUse": [{
                "matcher": "*",
                "hooks": [{
                    "type": "command",
                    "command": command.clone(),
                    "args": args.clone(),
                    "timeout": 30
                }]
            }]
        }
    })
    .to_string()
}

#[cfg(not(windows))]
fn hook_command_unix(agent: &Path, provider: &str, session: Option<&str>) -> String {
    hook_words(agent, provider, session)
        .iter()
        .map(|word| shell_quote_unix(word))
        .collect::<Vec<_>>()
        .join(" ")
}

fn hook_command_windows(agent: &Path, provider: &str, session: Option<&str>) -> String {
    let words = hook_words(agent, provider, session);
    let command = words
        .iter()
        .map(|word| cmd_quote(word))
        .collect::<Vec<_>>()
        .join(" ");
    format!("cmd /D /S /C {command}")
}

#[cfg(windows)]
fn hook_command(agent: &Path, provider: &str, session: Option<&str>) -> String {
    hook_command_windows(agent, provider, session)
}

#[cfg(not(windows))]
fn hook_command(agent: &Path, provider: &str, session: Option<&str>) -> String {
    hook_command_unix(agent, provider, session)
}

fn cmd_quote(value: &str) -> String {
    if !value.is_empty()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b'\\' | b':')
        })
    {
        return value.to_string();
    }
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn hook_words(agent: &Path, provider: &str, session: Option<&str>) -> Vec<String> {
    let agent = agent_command_path(agent);
    let mut words = vec![
        agent.to_string_lossy().into_owned(),
        "hook".to_string(),
        "--cli".to_string(),
        provider.to_string(),
    ];
    add_explicit_session(&mut words, session);
    words
}

fn add_explicit_session(words: &mut Vec<String>, session: Option<&str>) {
    let Some(session) = session else {
        return;
    };
    words.push("--session".to_string());
    words.push(session.to_string());
}

fn agent_command_path(agent: &Path) -> PathBuf {
    if agent.is_absolute() {
        return agent.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(agent))
        .unwrap_or_else(|_| agent.to_path_buf())
}

fn default_pentect_path() -> PathBuf {
    let exe_name = if cfg!(windows) {
        "pentect.exe"
    } else {
        "pentect"
    };
    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            candidates.push(dir.join(exe_name));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("target").join("debug").join(exe_name));
        candidates.push(cwd.join("target").join("release").join(exe_name));
    }
    candidates
        .into_iter()
        .find(|path| path.exists())
        .unwrap_or_else(|| PathBuf::from(exe_name))
}

fn print_dry_run(command: &Path, args: &[String]) {
    print!("{}", shell_quote_display(&command.to_string_lossy()));
    for arg in args {
        print!(" {}", shell_quote_display(arg));
    }
    println!();
}

fn success_status() -> std::process::ExitStatus {
    exit_status_from_code(0)
}

fn exit_status_from_code(code: u32) -> std::process::ExitStatus {
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code)
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw((code as i32) << 8)
    }
}

fn shell_quote_display(value: &str) -> String {
    if cfg!(windows) {
        shell_quote_windows(value)
    } else {
        shell_quote_unix(value)
    }
}

fn shell_quote_unix(value: &str) -> String {
    if is_simple_shell_word(value) {
        return value.to_string();
    }
    if value.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn shell_quote_windows(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

fn is_simple_shell_word(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn checked_agent_session_name(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("session name must not be empty".to_string());
    }
    if matches!(name, "." | "..") {
        return Err("session name must not be a dot path segment".to_string());
    }
    if name.chars().any(|c| {
        c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    }) {
        return Err("session name must be a simple file-name segment".to_string());
    }
    Ok(name.to_string())
}

fn input_adapter(args: &[String]) -> Result<Box<dyn InputAdapter>, String> {
    match arg_value(args, "--input").as_deref() {
        Some("pdf") => pdf_input_adapter(),
        Some("image" | "ocr") => Ok(Box::new(ImageOcrInput)),
        Some("text") | None => Ok(Box::new(TextInput)),
        Some(other) => Err(format!("unknown --input: {other}")),
    }
}

fn parse_read_input_format(value: &str) -> Result<ReadInputFormat, String> {
    match value {
        "text" => Ok(ReadInputFormat::Text),
        "pdf" => Ok(ReadInputFormat::Pdf),
        "image" | "ocr" => Ok(ReadInputFormat::Image),
        other => Err(format!("unknown --input: {other}")),
    }
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

fn read_input(path: &Path, format: ReadInputFormat) -> Result<String, String> {
    let bytes = read_bytes(path)?;
    match format {
        ReadInputFormat::Text => decode_utf8_text(
            bytes,
            format!("input '{}' is not UTF-8 text", path.display()),
        ),
        ReadInputFormat::Pdf => pdf_text(&bytes),
        ReadInputFormat::Image => pentect_agent::ocr_image_bytes(&bytes),
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

#[cfg(feature = "pdf")]
fn pdf_text(bytes: &[u8]) -> Result<String, String> {
    let text = pdf_extract::extract_text_from_mem(bytes)
        .map_err(|e| format!("could not extract PDF text: {e}"))?;
    if text.trim().is_empty() {
        return Err(
            "PDF contains no extractable text; scanned/image-only PDFs need OCR".to_string(),
        );
    }
    Ok(text)
}

#[cfg(not(feature = "pdf"))]
fn pdf_text(_bytes: &[u8]) -> Result<String, String> {
    Err("PDF input requires a build with `--features pdf`".to_string())
}

#[cfg(feature = "pdf")]
fn pdf_input_adapter() -> Result<Box<dyn InputAdapter>, String> {
    Ok(Box::new(input::PdfTextInput))
}

#[cfg(not(feature = "pdf"))]
fn pdf_input_adapter() -> Result<Box<dyn InputAdapter>, String> {
    Err("PDF input requires a build with `--features pdf`".to_string())
}

/// `--aggressive` disables the benign-shape guard, so even UUIDs/hashes get
/// masked. Output is then mostly unusable for reasoning, but still reversible.
fn build_engine(profile: Profile, aggressive: bool, packs: Vec<Pack>) -> Result<Engine, String> {
    if aggressive {
        eprintln!("[pentect] WARNING: --aggressive disables benign-shape guards; output likely unusable for reasoning.");
    }
    let decode = pentect_agent::load_decode_config(profile)?;
    Ok(Engine::with_profile_and_packs_and_decode_config(
        profile, packs, aggressive, decode,
    ))
}

/// Load each `--pack FILE` as a TOML rule pack. Reading a config file is input,
/// not secret persistence. Errors are reported with the file name so a pack
/// author can see exactly what to fix.
fn load_packs(args: &[String]) -> Result<Vec<Pack>, String> {
    let mut packs = Vec::new();
    for path in pack_paths(args)? {
        let display = path.display();
        let src = std::fs::read_to_string(&path)
            .map_err(|e| format!("could not read pack '{display}': {e}"))?;
        let pack = load_pack(&src).map_err(|e| format!("pack '{display}' is invalid: {e}"))?;
        packs.push(pack);
    }
    packs.extend(extensions::load_config_packs_from_args(args, true).map_err(|e| e.to_string())?);
    Ok(packs)
}

fn pack_paths(args: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut paths: Vec<PathBuf> = arg_values(args, "--pack")
        .into_iter()
        .map(PathBuf::from)
        .collect();
    for dir in arg_values(args, "--pack-dir") {
        paths.extend(toml_files_in_dir(Path::new(&dir))?);
    }
    Ok(paths)
}

fn toml_files_in_dir(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)
        .map_err(|e| format!("could not read pack directory '{}': {e}", dir.display()))?
    {
        let path = entry
            .map_err(|e| format!("could not read pack directory '{}': {e}", dir.display()))?
            .path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// All values following each occurrence of `flag` (so `--pack` can repeat).
fn arg_values(args: &[String], flag: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| a.as_str() == flag)
        .filter_map(|(i, _)| args.get(i + 1).cloned())
        .collect()
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn required_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    let Some(value) = args.get(*i + 1) else {
        return Err(format!("{flag} requires a value"));
    };
    *i += 2;
    Ok(value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pty_size_tracks_the_real_terminal_before_fallbacks() {
        assert_eq!(
            select_pty_size(Some((180, 52)), Some(100), Some(24)),
            (180, 52)
        );
        assert_eq!(select_pty_size(None, Some(100), Some(24)), (100, 24));
        assert_eq!(select_pty_size(Some((0, 0)), None, None), (120, 30));
    }

    #[test]
    fn read_parse_infers_dotenv_and_defaults_to_strict() {
        let args = vec!["pentect".into(), "read".into(), r".\.env".into()];
        let opts = ReadOpts::parse(&args).unwrap();
        assert_eq!(opts.profile, Profile::Strict);
        assert_eq!(infer_kind(&opts.path), Kind::Env);
        assert!(!opts.emit_meta);

        let args = vec![
            "pentect".into(),
            "read".into(),
            "--meta".into(),
            "--kind".into(),
            "env".into(),
            r".\.env".into(),
        ];
        let opts = ReadOpts::parse(&args).unwrap();
        assert_eq!(opts.kind, Some(Kind::Env));
        assert!(opts.emit_meta);

        let args = vec![
            "pentect".into(),
            "read".into(),
            "--persist".into(),
            r".\.env".into(),
        ];
        let err = match ReadOpts::parse(&args) {
            Ok(_) => panic!("expected --persist to be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("unknown option"), "{err}");
    }

    #[test]
    fn mask_rejects_unknown_kind_and_accepts_profile_modes() {
        let args = vec![
            "pentect".into(),
            "mask".into(),
            "--kind".into(),
            "yaml".into(),
        ];
        assert!(validate_mask_args(&args)
            .unwrap_err()
            .contains("unknown kind"));

        let args = vec![
            "pentect".into(),
            "mask".into(),
            "--profile".into(),
            "extra".into(),
        ];
        assert!(validate_mask_args(&args)
            .unwrap_err()
            .contains("unknown profile"));

        let args = vec![
            "pentect".into(),
            "mask".into(),
            "--profile".into(),
            "balanced".into(),
            "--aggressive".into(),
        ];
        assert!(validate_mask_args(&args).is_ok());
    }

    #[test]
    fn mask_accepts_extension_names() {
        let args = vec![
            "pentect".into(),
            "mask".into(),
            "--extensions".into(),
            "openai-privacy-filter,local.rules".into(),
        ];
        assert!(validate_mask_args(&args).is_ok());
    }

    #[test]
    fn pack_dir_expands_toml_files_in_stable_order() {
        let root =
            std::env::temp_dir().join(format!("pentect-pack-dir-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("b.toml"), "").unwrap();
        std::fs::write(root.join("a.toml"), "").unwrap();
        std::fs::write(root.join("skip.txt"), "").unwrap();

        let args = vec![
            "pentect".to_string(),
            "mask".to_string(),
            "--pack-dir".to_string(),
            root.display().to_string(),
        ];
        let paths = pack_paths(&args).unwrap();
        assert_eq!(
            paths,
            vec![root.join("a.toml"), root.join("b.toml")],
            "{paths:?}"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn agent_tool_parse_accepts_unverified_hook_escape_hatch() {
        let args = vec![
            "pentect".to_string(),
            "codex".to_string(),
            "--allow-unverified-hooks".to_string(),
            "--".to_string(),
            "exec".to_string(),
            "do something".to_string(),
        ];
        let opts = AgentToolOpts::parse(AgentTool::Codex, &args).unwrap();
        assert!(opts.allow_unverified_hooks);
        assert_eq!(opts.tool_args, vec!["exec", "do something"]);
    }

    #[test]
    fn agent_tool_parse_consumes_codex_app_server_proxy_toggle() {
        let args = vec![
            "pentect".to_string(),
            "codex".to_string(),
            "--no-app-server-proxy".to_string(),
            "hello".to_string(),
        ];
        let opts = AgentToolOpts::parse(AgentTool::Codex, &args).unwrap();
        assert!(opts.codex_app_server_proxy_disabled);
        assert_eq!(opts.tool_args, vec!["hello"]);
    }

    #[test]
    fn agent_tool_parse_consumes_extensions_before_tool_args() {
        let args = vec![
            "pentect".to_string(),
            "codex".to_string(),
            "--extensions".to_string(),
            "openai-privacy-filter,local.rules".to_string(),
            "--".to_string(),
            "hello".to_string(),
        ];
        let opts = AgentToolOpts::parse(AgentTool::Codex, &args).unwrap();
        assert_eq!(
            opts.extensions,
            vec![
                "openai-privacy-filter".to_string(),
                "local.rules".to_string()
            ]
        );
        assert_eq!(opts.tool_args, vec!["hello"]);
    }

    #[test]
    fn agent_tool_parse_rejects_prompt_proxy_for_all_agents() {
        for tool in [
            AgentTool::Codex,
            AgentTool::Claude,
            AgentTool::OpenCode,
            AgentTool::Pi,
        ] {
            let args = vec![
                "pentect".to_string(),
                tool.name().to_string(),
                "--prompt-proxy".to_string(),
            ];
            let err = AgentToolOpts::parse(tool, &args).unwrap_err();
            assert!(err.contains("disabled/TODO"), "{tool:?}: {err}");
        }
    }

    #[test]
    fn bridge_agents_have_distinct_commands_and_path_flags() {
        assert_eq!(AgentTool::OpenCode.env_var(), "PENTECT_OPENCODE");
        assert_eq!(AgentTool::OpenCode.path_flag(), "--opencode");
        assert_eq!(AgentTool::Pi.env_var(), "PENTECT_PI");
        assert_eq!(AgentTool::Pi.path_flag(), "--pi");
    }

    #[test]
    fn codex_metadata_commands_do_not_need_verified_hooks() {
        assert!(!codex_uses_unverified_headless_hook_path(&[
            "--version".to_string()
        ]));
        assert!(!codex_uses_unverified_headless_hook_path(&[
            "--help".to_string()
        ]));
        assert!(!codex_uses_unverified_headless_hook_path(&[
            "help".to_string()
        ]));
    }

    #[test]
    fn help_text_is_compact() {
        let help = help_text();
        assert!(help.contains("pentect exec"), "{help}");
        assert!(help.contains("pentect shell"), "{help}");
        assert!(!help.contains("agent exec"), "{help}");
        assert!(!help.contains("bench"), "{help}");
        assert!(help.contains("doctor: readiness"), "{help}");
        assert!(help.contains("extensions: list, inspect, test"), "{help}");
        assert!(help.contains("eval: precision, recall"), "{help}");
        assert!(help.contains("scan: CredSweeper + core"), "{help}");
        assert!(help.contains("statusline: masked count"), "{help}");
        assert!(!help.contains("pentect purge"), "{help}");
        assert!(!help.contains("authenticated browser/API/MCP"), "{help}");
    }

    #[test]
    fn issue_report_url_prefills_safe_template() {
        let url = issue_report_url();
        assert!(url.starts_with("https://github.com/EdamAme-x/pentect/issues/new?"));
        assert!(url.contains("title=Pentect%20error"), "{url}");
        assert!(url.contains("body="), "{url}");
        assert!(url.contains("Do%20not%20paste%20raw%20secrets"), "{url}");
        assert!(!url.contains("<paste Pentect error output here>"), "{url}");
    }

    #[test]
    fn agent_session_names_reject_dot_segments() {
        assert!(checked_agent_session_name(".").is_err());
        assert!(checked_agent_session_name("..").is_err());
        assert!(checked_agent_session_name("../x").is_err());
        assert_eq!(checked_agent_session_name("demo").unwrap(), "demo");
    }

    #[test]
    fn hook_words_use_pentect_hook_subcommand() {
        let pentect = absolute_pentect_fixture_path();
        let words = hook_words(&pentect, "codex", Some("demo"));
        assert_eq!(words[0], pentect.to_string_lossy().as_ref());
        assert_eq!(
            words[1..].to_vec(),
            vec![
                "hook".to_string(),
                "--cli".to_string(),
                "codex".to_string(),
                "--session".to_string(),
                "demo".to_string()
            ]
        );
    }

    fn absolute_pentect_fixture_path() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\repo\target\debug\pentect.exe")
        } else {
            PathBuf::from("/repo/target/debug/pentect")
        }
    }

    #[test]
    fn hook_words_use_pentect_path_without_session() {
        let pentect = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("debug")
            .join(if cfg!(windows) {
                "pentect.exe"
            } else {
                "pentect"
            });
        let words = hook_words(&pentect, "codex", None);
        assert_eq!(words[0], pentect.to_string_lossy().as_ref());
        assert_eq!(
            words[1..].to_vec(),
            vec!["hook".to_string(), "--cli".to_string(), "codex".to_string()]
        );
    }

    #[test]
    fn launched_agent_tools_export_pentect_path_for_hooks() {
        let pentect = Path::new(r"C:\repo\target\debug\pentect.exe");
        let launch_proof = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut cmd = Command::new("codex");
        apply_pentect_env(&mut cmd, pentect, Some(launch_proof));
        let actual = cmd
            .get_envs()
            .find(|(key, _)| *key == std::ffi::OsStr::new(PENTECT_BIN_ENV))
            .and_then(|(_, value)| value)
            .unwrap();
        assert_eq!(actual, pentect.as_os_str());
        let launched = cmd
            .get_envs()
            .find(|(key, _)| *key == std::ffi::OsStr::new(PENTECT_AGENT_LAUNCHED_ENV))
            .and_then(|(_, value)| value)
            .unwrap();
        assert_eq!(launched, std::ffi::OsStr::new(launch_proof));
    }

    #[test]
    fn status_line_config_defaults_on_and_accepts_agent_toggle() {
        let empty = ""
            .parse::<toml::Value>()
            .unwrap_or(toml::Value::Table(Default::default()));
        assert_eq!(status_line_config_value(&empty).unwrap(), None);

        let value = "[agent]\nstatus_line = false"
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(status_line_config_value(&value).unwrap(), Some(false));

        let value = "status_line = \"on\"".parse::<toml::Value>().unwrap();
        assert_eq!(status_line_config_value(&value).unwrap(), Some(true));
    }

    #[test]
    fn memory_store_startup_requires_process_host_tokens() {
        let parsed = parse_memory_store_startup(
            r#"{"addr":"127.0.0.1:1234","token":"memory","process_host_read_token":"read","process_host_write_token":"write"}"#,
        )
        .unwrap();
        assert_eq!(
            parsed,
            (
                "127.0.0.1:1234".to_string(),
                "memory".to_string(),
                "read".to_string(),
                "write".to_string(),
            )
        );
        assert!(
            parse_memory_store_startup(r#"{"addr":"127.0.0.1:1234","token":"write"}"#).is_err()
        );
    }

    #[test]
    fn status_line_env_is_compact() {
        let mut cmd = Command::new("codex");
        apply_status_line_env(&mut cmd, true);
        let enabled = cmd
            .get_envs()
            .find(|(key, _)| *key == std::ffi::OsStr::new(PENTECT_STATUS_LINE_ENV))
            .and_then(|(_, value)| value)
            .unwrap();
        assert_eq!(enabled, std::ffi::OsStr::new("1"));

        apply_status_line_env(&mut cmd, false);
        let disabled = cmd
            .get_envs()
            .find(|(key, _)| *key == std::ffi::OsStr::new(PENTECT_STATUS_LINE_ENV))
            .and_then(|(_, value)| value)
            .unwrap();
        assert_eq!(disabled, std::ffi::OsStr::new("0"));
    }

    #[test]
    fn codex_args_place_remote_before_prompt() {
        let args = codex_args_with_remote(
            &["features.hooks=true".to_string()],
            &["hello".to_string()],
            Some("ws://127.0.0.1:12345"),
        );
        let remote = args.iter().position(|arg| arg == "--remote").unwrap();
        let prompt = args.iter().position(|arg| arg == "hello").unwrap();
        assert!(remote < prompt, "{args:?}");
        assert_eq!(args[remote + 1], "ws://127.0.0.1:12345");
    }

    #[test]
    fn codex_remote_scan_skips_short_option_values() {
        assert_eq!(
            codex_args_remote_value(&["-m".to_string(), "--remote".to_string()]),
            None
        );
        assert_eq!(
            codex_args_remote_value(&[
                "-m".to_string(),
                "gpt-5.5".to_string(),
                "--remote".to_string(),
                "ws://127.0.0.1:12345".to_string()
            ]),
            Some("ws://127.0.0.1:12345")
        );
    }

    #[test]
    fn codex_app_server_args_keep_pentect_and_root_config_only() {
        let args = codex_app_server_args(
            &["features.hooks=true".to_string()],
            &[
                "-m".to_string(),
                "gpt-5.3-codex".to_string(),
                "--config".to_string(),
                "model_reasoning_effort=\"high\"".to_string(),
                "hello".to_string(),
            ],
        );
        assert!(args.contains(&"--enable".to_string()), "{args:?}");
        assert!(args.contains(&"unified_exec".to_string()), "{args:?}");
        assert!(
            args.contains(&"features.hooks=true".to_string()),
            "{args:?}"
        );
        assert!(
            args.contains(&"model_reasoning_effort=\"high\"".to_string()),
            "{args:?}"
        );
        assert!(!args.contains(&"-m".to_string()), "{args:?}");
        assert!(!args.contains(&"hello".to_string()), "{args:?}");
    }

    #[test]
    fn codex_app_server_proxy_config_defaults_and_can_disable() {
        let empty = ""
            .parse::<toml::Value>()
            .unwrap_or(toml::Value::Table(Default::default()));
        assert_eq!(codex_app_server_proxy_config_value(&empty).unwrap(), None);

        let value = "[agent]\ncodex_app_server_proxy = false"
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(
            codex_app_server_proxy_config_value(&value).unwrap(),
            Some(false)
        );
    }

    #[test]
    fn codex_environments_toml_keeps_local_available() {
        let rendered = codex_environments_toml("ws://127.0.0.1:12345/pentect");
        assert!(rendered.contains("default = \"pentect\""), "{rendered}");
        assert!(rendered.contains("include_local = true"), "{rendered}");
        assert!(rendered.contains("id = \"pentect\""), "{rendered}");
        assert!(
            rendered.contains("url = \"ws://127.0.0.1:12345/pentect\""),
            "{rendered}"
        );
    }

    #[test]
    fn codex_environment_overlay_restores_existing_file() {
        let root = std::env::temp_dir().join(format!(
            "pentect-codex-env-overlay-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("environments.toml");
        std::fs::write(&path, b"default = \"local\"\n").unwrap();
        let _env = EnvVarGuard::set_optional([("CODEX_HOME", Some(root.clone().into_os_string()))]);
        {
            let _guard =
                CodexEnvironmentOverlayGuard::install("ws://127.0.0.1:12345/pentect").unwrap();
            let current = std::fs::read_to_string(&path).unwrap();
            assert!(current.contains("default = \"pentect\""), "{current}");
        }
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "default = \"local\"\n"
        );
        assert!(!root.join("environments.toml.pentect.bak").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_environment_overlay_recovers_stale_file() {
        let root = std::env::temp_dir().join(format!(
            "pentect-codex-env-overlay-stale-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("environments.toml");
        let backup_path = root.join("environments.toml.pentect.bak");
        std::fs::write(&path, codex_environments_toml("ws://127.0.0.1:1")).unwrap();
        std::fs::write(&backup_path, b"default = \"local\"\n").unwrap();
        recover_stale_codex_environment_overlay(&path, &backup_path).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "default = \"local\"\n"
        );
        assert!(!backup_path.exists());
        std::fs::write(&path, codex_environments_toml("ws://127.0.0.1:1")).unwrap();
        recover_stale_codex_environment_overlay(&path, &backup_path).unwrap();
        assert!(!path.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_args_inject_model_visible_pentect_contract() {
        let args = codex_args(&["features.hooks=true".to_string()], &["hello".to_string()]);
        let rendered = args.join("\n");
        assert!(!args.contains(&"--dangerously-bypass-hook-trust".to_string()));
        assert!(rendered.contains("developer_instructions="), "{rendered}");
        assert!(rendered.contains("Pentect agent contract"), "{rendered}");
        assert!(rendered.contains("Use normal shell commands"), "{rendered}");
        assert!(rendered.contains("--enable\nunified_exec"), "{rendered}");
        assert!(rendered.contains("protected runner"), "{rendered}");
        assert!(rendered.contains("tool results"), "{rendered}");
        assert!(rendered.contains("Masked handles"), "{rendered}");
        assert!(rendered.contains("$env:NAME"), "{rendered}");
        assert!(rendered.contains("user-authorized secrets"), "{rendered}");
        assert!(
            rendered.contains("Pentect is the safety layer"),
            "{rendered}"
        );
        assert!(rendered.contains("PENTECT_"), "{rendered}");
        assert!(rendered.contains("pentect view"), "{rendered}");
        assert!(!rendered.contains("pentect read"), "{rendered}");
        assert!(rendered.contains("PowerShell"), "{rendered}");
        assert!(
            rendered.contains("MCP, browser, plugin, and connector"),
            "{rendered}"
        );
        assert!(rendered.contains("tool text output"), "{rendered}");
        assert!(rendered.contains("user-requested storage"), "{rendered}");
        assert!(rendered.contains("exact requested"), "{rendered}");
        assert!(rendered.contains("local file"), "{rendered}");
        assert!(rendered.contains("service CLIs"), "{rendered}");
        assert!(!rendered.contains("pentect resolve"), "{rendered}");
        assert!(
            rendered.contains("Do not disclose raw secrets"),
            "{rendered}"
        );
        assert!(rendered.contains("encodings"), "{rendered}");
        assert!(rendered.contains("third-party destinations"), "{rendered}");
        assert!(
            !rendered.contains("pentect exec \\\"pentect exec"),
            "{rendered}"
        );
    }

    #[test]
    fn codex_hook_config_trusts_pentect_hooks_for_this_session() {
        let pentect = absolute_pentect_fixture_path();
        let configs = codex_hook_config_args(&pentect, None).unwrap();
        let rendered = configs.join("\n");
        assert!(rendered.contains("features.hooks=true"), "{rendered}");
        assert!(rendered.contains("hooks={"), "{rendered}");
        assert!(rendered.contains("PreToolUse"), "{rendered}");
        assert!(rendered.contains("PostToolUse"), "{rendered}");
        assert!(rendered.contains("state={"), "{rendered}");
        assert!(rendered.contains("<session-flags>"), "{rendered}");
        assert!(rendered.contains(":pre_tool_use:0:0"), "{rendered}");
        assert!(rendered.contains(":post_tool_use:0:0"), "{rendered}");
        assert!(rendered.contains("trusted_hash=\"sha256:"), "{rendered}");
        assert!(!rendered.contains("statusMessage"), "{rendered}");
        assert!(
            !rendered.contains("dangerously-bypass-hook-trust"),
            "{rendered}"
        );
    }

    #[test]
    fn codex_hook_hash_uses_platform_command_only() {
        let command = "pentect hook --cli codex";
        let windows = "cmd /D /S /C pentect hook --cli codex";
        let selected = if cfg!(windows) { windows } else { command };
        let expected = version_for_toml_value(
            &toml::Value::try_from(CodexNormalizedHookIdentity {
                event_name: "pre_tool_use",
                group: CodexMatcherGroup {
                    matcher: Some("*"),
                    hooks: vec![CodexHookHandlerConfig::Command {
                        command: selected,
                        command_windows: None,
                        timeout_sec: Some(30),
                        r#async: false,
                        status_message: None,
                    }],
                },
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            codex_command_hook_hash("pre_tool_use", "*", command, windows, 30).unwrap(),
            expected
        );
    }

    #[test]
    fn codex_args_respects_explicit_unified_exec_disable() {
        let tool_args = vec![
            "--disable".to_string(),
            "unified_exec".to_string(),
            "exec".to_string(),
            "hello".to_string(),
        ];
        let args = codex_args(&[], &tool_args);
        let rendered = args.join("\n");
        assert!(!codex_unified_exec_proxy_enabled(&tool_args));
        assert!(!rendered.contains("--enable\nunified_exec"), "{rendered}");
        assert!(rendered.contains("--disable\nunified_exec"), "{rendered}");
    }

    #[test]
    fn claude_args_inject_model_visible_pentect_contract() {
        let args = claude_args("{}", &["hello".to_string()]);
        let rendered = args.join("\n");
        assert!(rendered.contains("--append-system-prompt"), "{rendered}");
        assert!(rendered.contains("Pentect agent contract"), "{rendered}");
        assert!(rendered.contains("Use normal shell commands"), "{rendered}");
        assert!(rendered.contains("protected runner"), "{rendered}");
        assert!(rendered.contains("tool results"), "{rendered}");
        assert!(rendered.contains("$env:NAME"), "{rendered}");
        assert!(rendered.contains("user-authorized secrets"), "{rendered}");
        assert!(
            rendered.contains("Pentect is the safety layer"),
            "{rendered}"
        );
        assert!(rendered.contains("PENTECT_"), "{rendered}");
        assert!(rendered.contains("pentect view"), "{rendered}");
        assert!(!rendered.contains("pentect read"), "{rendered}");
        assert!(rendered.contains("PowerShell"), "{rendered}");
        assert!(
            rendered.contains("MCP, browser, plugin, and connector"),
            "{rendered}"
        );
        assert!(rendered.contains("tool text output"), "{rendered}");
        assert!(rendered.contains("user-requested storage"), "{rendered}");
        assert!(rendered.contains("exact requested"), "{rendered}");
        assert!(rendered.contains("local file"), "{rendered}");
        assert!(rendered.contains("service CLIs"), "{rendered}");
        assert!(!rendered.contains("pentect resolve"), "{rendered}");
        assert!(
            rendered.contains("Do not disclose raw secrets"),
            "{rendered}"
        );
        assert!(rendered.contains("encodings"), "{rendered}");
        assert!(rendered.contains("third-party destinations"), "{rendered}");
        assert!(
            !rendered.contains("pentect exec \"pentect exec"),
            "{rendered}"
        );
    }

    #[test]
    fn codex_interactive_invocations_do_not_need_headless_hook_guard() {
        assert!(!codex_uses_unverified_headless_hook_path(&Vec::new()));
        assert!(!codex_uses_unverified_headless_hook_path(&[
            "review this".to_string()
        ]));
        assert!(!codex_uses_unverified_headless_hook_path(&[
            "--model".to_string(),
            "gpt-5.5".to_string(),
            "Run a command".to_string()
        ]));
    }

    #[test]
    fn codex_headless_commands_need_verified_hooks() {
        assert!(codex_uses_unverified_headless_hook_path(&[
            "exec".to_string()
        ]));
        assert!(codex_uses_unverified_headless_hook_path(&["e".to_string()]));
        assert!(codex_uses_unverified_headless_hook_path(&[
            "review".to_string()
        ]));
        assert!(codex_uses_unverified_headless_hook_path(&[
            "--model".to_string(),
            "gpt-5.5".to_string(),
            "exec".to_string()
        ]));
        assert!(codex_uses_unverified_headless_hook_path(&[
            "--".to_string(),
            "exec".to_string()
        ]));
        assert!(codex_uses_unverified_headless_hook_path(&[
            "--enable".to_string(),
            "foo".to_string(),
            "exec".to_string()
        ]));
    }

    #[test]
    fn prompt_input_rewrites_bracketed_paste_payload() {
        let mut state = PromptInputState::default();
        let mut mask = |text: &str| {
            Ok(Some(text.replace(
                "sk-ABCDEFGHIJKLMNOPQRSTUVWX",
                "<<OPENAI_API_KEY_demo>>",
            )))
        };
        let out = rewrite_prompt_input_bytes_with(
            &mut state,
            b"\x1b[200~OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\x1b[201~",
            &mut mask,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("\x1b[200~"), "{text:?}");
        assert!(text.ends_with("\x1b[201~"), "{text:?}");
        assert!(!text.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"), "{text}");
        assert!(text.contains("<<OPENAI_API_KEY_demo>>"), "{text}");
    }

    #[test]
    fn prompt_input_rewrites_split_bracketed_paste() {
        let mut state = PromptInputState::default();
        let mut mask = |text: &str| Ok(Some(text.replace("secret-value", "<<TOKEN_demo>>")));
        let first = rewrite_prompt_input_bytes_with(&mut state, b"\x1b[20", &mut mask).unwrap();
        assert!(first.is_empty(), "{first:?}");
        let second =
            rewrite_prompt_input_bytes_with(&mut state, b"0~token=secret-", &mut mask).unwrap();
        assert_eq!(second, b"\x1b[200~");
        let third =
            rewrite_prompt_input_bytes_with(&mut state, b"value\x1b[201~", &mut mask).unwrap();
        assert_eq!(
            String::from_utf8(third).unwrap(),
            "token=<<TOKEN_demo>>\x1b[201~"
        );
    }

    #[cfg(windows)]
    #[test]
    fn prompt_input_rewrites_win32_encoded_bracketed_paste() {
        let raw = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX";
        let mut encoded = encode_win32_unicode_input("\x1b[200~");
        encoded.extend(encode_win32_unicode_input(raw));
        encoded.extend(encode_win32_unicode_input("\x1b[201~"));
        let split = encoded.len() / 2;
        let mut normal = PromptInputState::default();
        let mut win32 = Win32PromptInputState::default();
        let mut mask = |text: &str| {
            Ok(Some(text.replace(
                "sk-ABCDEFGHIJKLMNOPQRSTUVWX",
                "<<OPENAI_API_KEY_demo>>",
            )))
        };
        let mut out = rewrite_win32_prompt_input_bytes_with(
            &mut normal,
            &mut win32,
            &encoded[..split],
            &mut mask,
        )
        .unwrap();
        out.extend(
            rewrite_win32_prompt_input_bytes_with(
                &mut normal,
                &mut win32,
                &encoded[split..],
                &mut mask,
            )
            .unwrap(),
        );
        let decoded = String::from_utf8_lossy(&out);
        assert!(
            !decoded.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
            "{decoded}"
        );
        assert!(decoded.contains("<<OPENAI_API_KEY_demo>>"), "{decoded}");
        assert!(decoded.starts_with("\x1b[200~"), "{decoded:?}");
        assert!(decoded.contains("\x1b[201~"), "{decoded:?}");
    }

    #[cfg(windows)]
    #[test]
    fn prompt_input_preserves_non_win32_terminal_responses() {
        let mut normal = PromptInputState::default();
        let mut win32 = Win32PromptInputState::default();
        let mut mask = |_: &str| Ok(Some("masked".to_string()));
        let out =
            rewrite_win32_prompt_input_bytes_with(&mut normal, &mut win32, b"\x1b[2;1R", &mut mask)
                .unwrap();
        assert_eq!(out, b"\x1b[2;1R");
    }

    #[cfg(windows)]
    #[test]
    fn prompt_input_decodes_win32_text_and_enter_without_dropping_repeats() {
        let encoded = encode_win32_unicode_input("tools\r");
        let mut normal = PromptInputState::default();
        let mut win32 = Win32PromptInputState::default();
        let mut mask = |_: &str| Ok(None);
        let out =
            rewrite_win32_prompt_input_bytes_with(&mut normal, &mut win32, &encoded, &mut mask)
                .unwrap();
        assert_eq!(out, b"tools\r");
    }

    #[test]
    fn prompt_input_keeps_escape_sequences_raw() {
        let mut state = PromptInputState::default();
        let mut called = false;
        let mut mask = |_: &str| {
            called = true;
            Ok(Some("masked".to_string()))
        };
        let out = rewrite_prompt_input_bytes_with(&mut state, b"\x1b[A", &mut mask).unwrap();
        assert_eq!(out, b"\x1b[A");
        assert!(!called);
    }

    #[test]
    fn only_session_commands_support_process_host_handoff() {
        for command in [
            "exec", "shell", "log", "bridge", "codex", "claude", "opencode", "pi",
        ] {
            let args = vec!["pentect".to_string(), command.to_string()];
            assert!(supports_process_host(&args), "{command}");
        }
        for command in [
            "help",
            "read",
            "view",
            "statusline",
            "doctor",
            "extensions",
            "eval",
            "scan",
            "resolve",
            "up",
        ] {
            let args = vec!["pentect".to_string(), command.to_string()];
            assert!(!supports_process_host(&args), "{command}");
        }
        assert!(supports_process_host(&[
            "pentect".to_string(),
            "agent".to_string(),
            "shell".to_string(),
        ]));
        assert!(!supports_process_host(&[
            "pentect".to_string(),
            "agent".to_string(),
            "hook".to_string(),
        ]));
    }
}
