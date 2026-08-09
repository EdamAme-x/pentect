//! Pentect CLI: local secret masking boundary for AI agents.

mod app_launcher;
mod claude_app_proxy;
mod claude_http_proxy;
mod client_descriptor;
mod cloud_code_http_proxy;
mod codex_app;
mod default_launch;
mod doctor;
mod http_files;
mod input;
mod installation;
mod openai_clients;
mod openai_http_proxy;
mod plugins;
mod plugins_cmd;
mod remote_content;
mod uninstall;
mod update;
mod upstream;

use input::{decode_utf8_text, ImageOcrInput, InputAdapter, TextInput};
use pentect_core::{
    infer_kind_with_content, load_pack, parse_placeholder, Config, Engine, Input, Kind, Pack,
    Profile,
};
use serde_json::Value;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use zeroize::Zeroize;

pub(crate) type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

#[cfg(windows)]
pub(crate) fn windows_system_executable(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| OsString::from(r"C:\Windows")))
        .join("System32")
        .join(name)
}

#[cfg(test)]
pub(crate) static TEST_PROCESS_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Refuse oversized input rather than emit partially-masked output (a masked
/// head plus a raw tail would leak the tail).
const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const PENTECT_BIN_ENV: &str = "PENTECT_BIN";
const PENTECT_AGENT_LAUNCHED_ENV: &str = "PENTECT_AGENT_LAUNCHED";
const PENTECT_MEMORY_STORE_ADDR_ENV: &str = "PENTECT_MEMORY_STORE_ADDR";
const PENTECT_MEMORY_STORE_TOKEN_ENV: &str = "PENTECT_MEMORY_STORE_TOKEN";
const MEMORY_STORE_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const ISSUE_NEW_URL: &str = "https://github.com/EdamAme-x/pentect/issues/new";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandAudience {
    Public,
    Advanced,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CommandSpec {
    name: &'static str,
    usage: &'static str,
    summary: &'static str,
    audience: CommandAudience,
}

const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "help",
        usage: "pentect help",
        summary: "Show this help",
        audience: CommandAudience::Public,
    },
    CommandSpec {
        name: "version",
        usage: "pentect version",
        summary: "Print the installed version",
        audience: CommandAudience::Public,
    },
    CommandSpec {
        name: "update",
        usage: "pentect update [VERSION] [--check | --force]",
        summary: "Install a verified release",
        audience: CommandAudience::Public,
    },
    CommandSpec {
        name: "uninstall",
        usage: "pentect uninstall",
        summary: "Remove Pentect and keep project data",
        audience: CommandAudience::Public,
    },
    CommandSpec {
        name: "doctor",
        usage: "pentect doctor [--json | --fix [--yes]]",
        summary: "Check readiness and offer safe repairs",
        audience: CommandAudience::Public,
    },
    CommandSpec {
        name: "plugins",
        usage: "pentect plugins <COMMAND>",
        summary: "Build, install, configure, and update plugins",
        audience: CommandAudience::Public,
    },
    CommandSpec {
        name: "mask",
        usage: "< input pentect mask",
        summary: "Mask UTF-8 text from standard input",
        audience: CommandAudience::Public,
    },
    CommandSpec {
        name: "read",
        usage: "pentect read PATH",
        summary: "Mask a file with filename-aware metadata",
        audience: CommandAudience::Public,
    },
    CommandSpec {
        name: "exec",
        usage: "pentect exec [--] COMMAND [ARG...]",
        summary: "Restore handles locally and mask command output",
        audience: CommandAudience::Public,
    },
    CommandSpec {
        name: "view",
        usage: "pentect view '<HANDLE>'",
        summary: "Show safe handle metadata",
        audience: CommandAudience::Public,
    },
    CommandSpec {
        name: "log",
        usage: "pentect log [--json]",
        summary: "Follow local protection events",
        audience: CommandAudience::Public,
    },
    CommandSpec {
        name: "resolve",
        usage: "pentect resolve [PATH...]",
        summary: "Write real values for known handles",
        audience: CommandAudience::Advanced,
    },
    CommandSpec {
        name: "__apply-update",
        usage: "",
        summary: "",
        audience: CommandAudience::Internal,
    },
    CommandSpec {
        name: "hook",
        usage: "",
        summary: "",
        audience: CommandAudience::Internal,
    },
    CommandSpec {
        name: "bridge",
        usage: "",
        summary: "",
        audience: CommandAudience::Internal,
    },
    CommandSpec {
        name: "memory-store",
        usage: "",
        summary: "",
        audience: CommandAudience::Internal,
    },
    CommandSpec {
        name: "purge",
        usage: "",
        summary: "",
        audience: CommandAudience::Internal,
    },
    CommandSpec {
        name: "__agent-script",
        usage: "",
        summary: "",
        audience: CommandAudience::Internal,
    },
    CommandSpec {
        name: "__agent-stream",
        usage: "",
        summary: "",
        audience: CommandAudience::Internal,
    },
    CommandSpec {
        name: "agent",
        usage: "",
        summary: "",
        audience: CommandAudience::Internal,
    },
    CommandSpec {
        name: "claude-app",
        usage: "",
        summary: "",
        audience: CommandAudience::Internal,
    },
    CommandSpec {
        name: "codex-app",
        usage: "",
        summary: "",
        audience: CommandAudience::Internal,
    },
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = catch_cli_exit(|| run(args)) {
        std::process::exit(code);
    }
}

fn run(args: Vec<String>) -> Option<i32> {
    let inherited_env_is_trusted = pentect_agent::active_memory_store_ready();
    if is_memory_store_server(&args) || !supports_process_host(&args) {
        return dispatch(args, inherited_env_is_trusted);
    }
    let pentect = default_pentect_path();
    let process_host =
        MemoryStoreGuard::start(&pentect).unwrap_or_else(|error| die_with_issue(error));
    let _process_host_env = memory_store_parent_env_guard(&pentect, &process_host);
    let exit_code = dispatch(args, inherited_env_is_trusted);
    drop(_process_host_env);
    drop(process_host);
    exit_code
}

fn catch_cli_exit(operation: impl FnOnce() -> Option<i32>) -> Option<i32> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(code) => code,
        Err(payload) => match payload.downcast::<CliExit>() {
            Ok(exit) => {
                eprintln!("[pentect] {}", exit.message);
                if exit.report_issue {
                    eprintln!("[pentect] report: {}", issue_report_url());
                }
                Some(2)
            }
            Err(payload) => std::panic::resume_unwind(payload),
        },
    }
}

fn dispatch(args: Vec<String>, inherited_env_is_trusted: bool) -> Option<i32> {
    match args.get(1).map(String::as_str) {
        None => usage(),
        Some("help" | "--help" | "-h") => cmd_help(),
        Some("version" | "--version" | "-V") => update::cmd_version(),
        Some("update") => update::cmd_update(&args),
        Some("uninstall") => uninstall::cmd_uninstall(&args),
        Some("__apply-update") => return Some(update::cmd_apply_update(&args)),
        Some("mask") => cmd_mask(&args),
        Some("read") => cmd_read(&args),
        Some("view") => cmd_view(&args),
        Some("doctor") => doctor::cmd_doctor(&args),
        Some("plugins") => plugins_cmd::cmd_plugins(&args),
        Some(
            "exec" | "resolve" | "log" | "hook" | "bridge" | "memory-store" | "purge"
            | "__agent-script" | "__agent-stream",
        ) => return Some(cmd_agent_from(1, &args, inherited_env_is_trusted)),
        Some("agent") => return Some(cmd_agent_from(2, &args, inherited_env_is_trusted)),
        Some("codex") if args.get(2).is_some_and(|arg| arg == "app") => {
            return Some(cmd_codex_app(&args));
        }
        Some("claude") if args.get(2).is_some_and(|arg| arg == "app") => {
            return Some(cmd_claude_app(&args));
        }
        Some("claude-app") => return Some(cmd_claude_app(&args)),
        Some("codex-app") => return Some(cmd_codex_app(&args)),
        Some(command) => match AgentTool::from_command(command) {
            Some(tool) => return Some(cmd_agent_tool(tool, &args)),
            None => {
                usage();
                return Some(2);
            }
        },
    }
    None
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
        (Some("exec" | "log" | "bridge"), _) | (Some("agent"), Some("exec" | "log" | "bridge"))
    )
}

fn usage() {
    eprint!("{}", help_text());
}

fn cmd_help() {
    print!("{}", help_text());
}

fn help_text() -> String {
    let mut help = String::from("pentect protects sensitive data in AI workflows.\n\nClients:\n");
    for tool in AgentTool::ALL {
        let descriptor = tool.descriptor();
        help.push_str(&format!(
            "  pentect {:<13} Launch {} and pass normal client arguments through\n",
            descriptor.name, descriptor.default_command
        ));
    }
    help.push_str(
        "  pentect codex app     Launch Codex App for this protected session\n  pentect claude app    Launch Claude Desktop for this protected session\n\nCommands:\n",
    );
    append_help_commands(&mut help, CommandAudience::Public);
    help.push_str("\nAdvanced:\n");
    append_help_commands(&mut help, CommandAudience::Advanced);
    help.push_str(
        "\nClient arguments are forwarded as written; `--` is optional.\n\
         Use --upstream URL, --upstream-header-env HEADER=ENV_NAME, or --plugins SOURCE before client arguments.\n\
         Codex and Claude support --set-default and --unset-default.\n\
         App commands support --install-launcher, --remove-launcher, --app PATH, and --check.\n",
    );
    help
}

fn append_help_commands(help: &mut String, audience: CommandAudience) {
    for command in COMMANDS
        .iter()
        .filter(|command| command.audience == audience)
    {
        help.push_str(&format!("  {:<54} {}\n", command.usage, command.summary));
    }
}

#[cfg(test)]
fn command_names(audience: CommandAudience) -> Vec<&'static str> {
    let mut names = COMMANDS
        .iter()
        .filter(|command| command.audience == audience)
        .map(|command| command.name)
        .collect::<Vec<_>>();
    if audience == CommandAudience::Public {
        names.extend(AgentTool::ALL.map(AgentTool::name));
    }
    names.sort_unstable();
    names
}

#[derive(Debug)]
struct CliExit {
    message: String,
    report_issue: bool,
}

fn die(msg: impl std::fmt::Display) -> ! {
    std::panic::resume_unwind(Box::new(CliExit {
        message: msg.to_string(),
        report_issue: false,
    }))
}

fn die_with_issue(msg: impl std::fmt::Display) -> ! {
    std::panic::resume_unwind(Box::new(CliExit {
        message: msg.to_string(),
        report_issue: true,
    }))
}

fn issue_report_url() -> String {
    format!(
        "{ISSUE_NEW_URL}?title={}",
        url_query_encode("Pentect error")
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

fn cmd_agent_from(start: usize, args: &[String], inherited_env_is_trusted: bool) -> i32 {
    let (forward_args, explicit_plugins) = match plugins::strip_from_args(&args[start..]) {
        Ok(parsed) => parsed,
        Err(e) => die(&e),
    };
    let active_plugins = match plugins::active_from_specs(explicit_plugins, true) {
        Ok(active) => active,
        Err(e) => die(&e),
    };
    let config_env = match active_plugins.config_env_value() {
        Ok(value) => value,
        Err(e) => die(&e),
    }
    .or_else(|| {
        inherited_env_is_trusted
            .then(|| std::env::var_os(plugins::CONFIGS_ENV))
            .flatten()
    });
    let binary_env = match active_plugins.binary_env_value() {
        Ok(value) => value,
        Err(e) => die(&e),
    }
    .or_else(|| {
        inherited_env_is_trusted
            .then(|| std::env::var_os(plugins::BINARIES_ENV))
            .flatten()
    });
    let plugin_env = EnvVarGuard::set_optional([
        (plugins::CONFIGS_ENV, config_env),
        (plugins::BINARIES_ENV, binary_env),
    ]);
    let mut agent_args = Vec::with_capacity(forward_args.len() + 1);
    agent_args.push(
        args.first()
            .cloned()
            .unwrap_or_else(|| "pentect".to_string()),
    );
    agent_args.extend(forward_args);
    let log_store = if agent_args.get(1).is_some_and(|arg| arg == "log") {
        let pentect = default_pentect_path();
        Some(start_memory_store(&pentect).unwrap_or_else(|e| die_with_issue(e)))
    } else {
        None
    };
    let _log_store_env = log_store.as_ref().map(|store| {
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
                PENTECT_AGENT_LAUNCHED_ENV,
                Some(OsString::from(store.token.as_str())),
            ),
        ])
    });
    let code = pentect_agent::run_from(agent_args);
    drop(_log_store_env);
    drop(log_store);
    drop(plugin_env);
    code
}

fn cmd_agent_tool(tool: AgentTool, args: &[String]) -> i32 {
    if default_launch::run_if_requested(tool.name(), &args[2..])
        .unwrap_or_else(|error| die(error))
        .is_some()
    {
        return 0;
    }
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
        AgentTool::OpenCode | AgentTool::Pi | AgentTool::Aider => {
            openai_clients::run(tool, &opts, &pentect)
        }
        AgentTool::Antigravity => run_antigravity(&opts, &pentect),
    }
    .unwrap_or_else(|e| die_with_issue(&e));
    status.code().unwrap_or(1)
}

fn cmd_claude_app(args: &[String]) -> i32 {
    if app_launcher::run_if_requested("claude", args)
        .unwrap_or_else(|error| die(error))
        .is_some()
    {
        return 0;
    }
    if claude_app_proxy::check_mode(args).unwrap_or_else(|error| die(error)) {
        return claude_app_proxy::cmd_claude_app(args);
    }
    let _plugin_env = app_plugin_env_guard(args).unwrap_or_else(|error| die(error));
    let pentect = default_pentect_path();
    let memory_store = match start_memory_store(&pentect) {
        Ok(store) => store,
        Err(error) => die_with_issue(error),
    };
    let _parent_env = memory_store_parent_env_guard(&pentect, &memory_store);
    let code = claude_app_proxy::cmd_claude_app(args);
    drop(_parent_env);
    drop(memory_store);
    code
}

fn cmd_codex_app(args: &[String]) -> i32 {
    if app_launcher::run_if_requested("codex", args)
        .unwrap_or_else(|error| die(error))
        .is_some()
    {
        return 0;
    }
    if codex_app::check_mode(args).unwrap_or_else(|error| die(error)) {
        return codex_app::cmd_codex_app(args);
    }
    let _plugin_env = app_plugin_env_guard(args).unwrap_or_else(|error| die(error));
    let pentect = default_pentect_path();
    let memory_store = match start_memory_store(&pentect) {
        Ok(store) => store,
        Err(error) => die_with_issue(error),
    };
    let _parent_env = memory_store_parent_env_guard(&pentect, &memory_store);
    let code = codex_app::cmd_codex_app(args);
    drop(_parent_env);
    drop(memory_store);
    code
}

fn app_plugin_env_guard(args: &[String]) -> Result<EnvVarGuard, String> {
    let explicit = plugins::collect_from_args(args).map_err(|error| error.to_string())?;
    let active = plugins::active_from_specs(explicit, true).map_err(|error| error.to_string())?;
    Ok(EnvVarGuard::set_optional([
        (
            plugins::CONFIGS_ENV,
            active
                .config_env_value()
                .map_err(|error| error.to_string())?,
        ),
        (
            plugins::BINARIES_ENV,
            active
                .binary_env_value()
                .map_err(|error| error.to_string())?,
        ),
    ]))
}

fn start_memory_store(pentect: &Path) -> Result<MemoryStoreGuard, String> {
    MemoryStoreGuard::start(pentect)
}

fn agent_tool_plugins(opts: &AgentToolOpts) -> Result<plugins::ActivePlugins, String> {
    plugins::active_from_specs(opts.plugins.clone(), true).map_err(|e| e.to_string())
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
    let explicit_kind = match arg_value(args, "--kind").as_deref() {
        Some(name) => match parse_kind(name) {
            Ok(kind) => Some(kind),
            Err(e) => die(&e),
        },
        None => None,
    };
    let profile: Profile = match arg_value(args, "--profile").as_deref() {
        Some(name) => match name.parse() {
            Ok(p) => p,
            Err(e) => die(&e),
        },
        None => Profile::Strict,
    };
    let aggressive = has_flag(args, "--aggressive");
    let explicit_plugins = match plugins::collect_from_args(args) {
        Ok(specs) => specs,
        Err(error) => die(error),
    };
    let active_plugins = match plugins::active_from_specs(explicit_plugins, true) {
        Ok(active) => active,
        Err(error) => die(error),
    };
    let _plugin_env = EnvVarGuard::set_optional([
        (
            plugins::CONFIGS_ENV,
            active_plugins
                .config_env_value()
                .unwrap_or_else(|error| die(error)),
        ),
        (
            plugins::BINARIES_ENV,
            active_plugins
                .binary_env_value()
                .unwrap_or_else(|error| die(error)),
        ),
    ]);
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
    let inferred_kind = explicit_kind.is_none();
    let kind =
        explicit_kind.unwrap_or_else(|| infer_kind_with_content(Path::new("stdin"), data.as_str()));

    // Fresh per-run key: mask-only, so the recovery map is not retained and a
    // reproducible key isn't needed (resolve/restore is unavailable by design).
    let kind_label = format!("{kind:?}");
    let engine = match build_engine(profile, aggressive, packs) {
        Ok(engine) => engine,
        Err(error) => die(error),
    };
    let cfg = Config::generate();
    let result = match pentect_agent::mask_input_with_engine_for_read(
        cfg.key,
        &engine,
        Input { kind, data },
    ) {
        Ok(result) => result,
        Err(error) => die(error),
    };

    print!("{}", result.masked);
    let _ = std::io::stdout().flush();
    eprintln!(
        "[pentect] profile={profile:?} masked {} value(s), {} warned.",
        result.summary.masked_count,
        result.summary.residual.len()
    );
    if result.summary.parser_fallback {
        let source = if inferred_kind {
            "inferred kind"
        } else {
            "--kind"
        };
        eprintln!("[pentect] note: {source} {kind_label} failed to parse; masked as plaintext (key context lost, structure not guaranteed).");
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
            "--kind" | "--profile" | "--input" | "--pack" | "--pack-dir" | "--plugins" => {
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
                if args[i] == "--plugins" {
                    plugins::parse_plugin_value(value).map_err(|e| e.to_string())?;
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
    let kind = opts
        .kind
        .unwrap_or_else(|| infer_kind_with_content(&opts.path, &data));
    let active_plugins = match plugins::active_from_specs(opts.plugins.clone(), true) {
        Ok(active) => active,
        Err(e) => die(&e),
    };
    let packs = match plugins::load_config_packs_from_active(&active_plugins) {
        Ok(packs) => packs,
        Err(e) => die(&e),
    };
    let config_env = match active_plugins.config_env_value() {
        Ok(value) => value,
        Err(e) => die(&e),
    };
    let binary_env = match active_plugins.binary_env_value() {
        Ok(value) => value,
        Err(e) => die(&e),
    };
    let _plugin_env = EnvVarGuard::set_optional([
        (plugins::CONFIGS_ENV, config_env),
        (plugins::BINARIES_ENV, binary_env),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentTool {
    Codex,
    Claude,
    OpenCode,
    Pi,
    Antigravity,
    Aider,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadInputFormat {
    Text,
    Image,
}

struct ReadOpts {
    input_format: ReadInputFormat,
    kind: Option<Kind>,
    profile: Profile,
    emit_meta: bool,
    plugins: Vec<String>,
    path: PathBuf,
}

impl ReadOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut input_format = ReadInputFormat::Text;
        let mut kind = None;
        let mut profile = Profile::Strict;
        let mut emit_meta = false;
        let mut plugins = Vec::new();
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
                "--plugins" => {
                    for spec in
                        plugins::parse_plugin_value(&required_value(args, &mut i, "--plugins")?)
                            .map_err(|e| e.to_string())?
                    {
                        if !plugins.iter().any(|existing| existing == &spec) {
                            plugins.push(spec);
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
            plugins,
            path: path.ok_or_else(|| "read requires PATH".to_string())?,
        })
    }
}

impl AgentTool {
    const ALL: [Self; 6] = [
        Self::Codex,
        Self::Claude,
        Self::OpenCode,
        Self::Pi,
        Self::Antigravity,
        Self::Aider,
    ];

    fn from_command(command: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| {
            let descriptor = tool.descriptor();
            command == descriptor.name || descriptor.aliases.contains(&command)
        })
    }

    fn descriptor(self) -> &'static client_descriptor::ClientDescriptor {
        match self {
            AgentTool::Codex => &client_descriptor::CODEX,
            AgentTool::Claude => &client_descriptor::CLAUDE,
            AgentTool::OpenCode => &client_descriptor::OPENCODE,
            AgentTool::Pi => &client_descriptor::PI,
            AgentTool::Antigravity => &client_descriptor::ANTIGRAVITY,
            AgentTool::Aider => &client_descriptor::AIDER,
        }
    }

    fn name(self) -> &'static str {
        self.descriptor().name
    }

    fn default_command(self) -> &'static str {
        self.descriptor().default_command
    }

    fn path_flag(self) -> &'static str {
        self.descriptor().path_flag
    }
}

#[derive(Debug)]
struct AgentToolOpts {
    pentect: Option<PathBuf>,
    command: PathBuf,
    plugins: Vec<String>,
    dry_run: bool,
    anthropic_upstream: Option<String>,
    openai_upstream: Option<String>,
    cloud_code_upstream: Option<String>,
    model: Option<String>,
    api: Option<String>,
    upstream_header_env: Vec<String>,
    tool_args: Vec<String>,
}

impl AgentToolOpts {
    fn parse(tool: AgentTool, args: &[String]) -> Result<Self, String> {
        let mut pentect = None;
        let mut command = PathBuf::from(tool.default_command());
        let mut plugins = Vec::new();
        let mut dry_run = false;
        let mut anthropic_upstream = None;
        let mut openai_upstream = None;
        let mut cloud_code_upstream = None;
        let mut model = None;
        let mut api = None;
        let mut upstream_header_env = Vec::new();
        let mut tool_args = Vec::new();
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--" => {
                    tool_args.extend(args[i + 1..].iter().cloned());
                    break;
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
                "--plugins" => {
                    for name in
                        plugins::parse_plugin_value(&required_value(args, &mut i, "--plugins")?)
                            .map_err(|e| e.to_string())?
                    {
                        if !plugins.iter().any(|existing| existing == &name) {
                            plugins.push(name);
                        }
                    }
                }
                "--dry-run" => {
                    dry_run = true;
                    i += 1;
                }
                "--no-app-server-proxy" if tool == AgentTool::Codex => {
                    return Err(
                        "Codex app-server interception was removed; HTTP protection is automatic"
                            .to_string(),
                    );
                }
                "--upstream" if tool == AgentTool::Claude => {
                    anthropic_upstream = Some(required_value(args, &mut i, "--upstream")?);
                }
                "--upstream"
                    if tool.descriptor().protocol == client_descriptor::Protocol::OpenAi =>
                {
                    openai_upstream = Some(required_value(args, &mut i, "--upstream")?);
                }
                "--upstream" if tool == AgentTool::Antigravity => {
                    cloud_code_upstream = Some(required_value(args, &mut i, "--upstream")?);
                }
                "--model" | "-m" if tool.descriptor().accepts_model => {
                    model = Some(required_value(args, &mut i, "--model")?);
                }
                "--api" if tool.descriptor().accepts_api => {
                    api = Some(required_value(args, &mut i, "--api")?);
                }
                "--upstream-header-env" => {
                    upstream_header_env.push(required_value(
                        args,
                        &mut i,
                        "--upstream-header-env",
                    )?);
                }
                "--prompt-proxy" | "--no-prompt-proxy" => {
                    return Err("prompt protection is automatic".to_string());
                }
                _ => {
                    tool_args.extend(args[i..].iter().cloned());
                    break;
                }
            }
        }
        Ok(Self {
            pentect,
            command,
            plugins,
            dry_run,
            anthropic_upstream,
            openai_upstream,
            cloud_code_upstream,
            model,
            api,
            upstream_header_env,
            tool_args,
        })
    }
}

fn run_codex(opts: &AgentToolOpts, pentect: &Path) -> Result<std::process::ExitStatus, String> {
    let routing = codex_effective_routing(opts)?;
    let mut args = opts.tool_args.clone();
    if opts.dry_run {
        args.extend(routing.gateway_args("<pentect-gateway>"));
        print_dry_run(&opts.command, &args);
        return Ok(success_status());
    }

    let active_plugins = agent_tool_plugins(opts)?;
    let memory_store = start_memory_store(pentect)?;
    let _parent_env = agent_parent_env_guard(pentect, &memory_store, &active_plugins)?;
    let http_proxy = openai_http_proxy::OpenAiHttpProxyGuard::start_with_header_env(
        routing.upstream.clone(),
        &opts.upstream_header_env,
    )?;
    // These overrides are appended so a caller-supplied routing override
    // cannot bypass the local gateway. Codex accepts global config flags after
    // its subcommand and uses the last value for duplicate keys.
    args.extend(routing.gateway_args(http_proxy.base_url()));

    let mut cmd = Command::new(&opts.command);
    clear_pentect_control_env(&mut cmd);
    upstream::hide_header_source_env(&mut cmd, &opts.upstream_header_env);
    apply_plugin_env(&mut cmd, &active_plugins)?;
    apply_pentect_env(&mut cmd, pentect, Some(memory_store.token.as_str()))?;
    apply_memory_store_env(&mut cmd, Some(&memory_store));
    cmd.args(args);
    run_native_command_with_guards(cmd, &opts.command, (http_proxy, memory_store))
}

fn run_claude(opts: &AgentToolOpts, pentect: &Path) -> Result<std::process::ExitStatus, String> {
    let args = opts.tool_args.clone();
    if opts.dry_run {
        print_dry_run(&opts.command, &args);
        return Ok(success_status());
    }
    let caller_settings = ClaudeCallerSettings::from_args(&args)?;
    reject_unsupported_claude_provider(&caller_settings)?;
    preflight_managed_claude_routing()?;
    let upstream = claude_effective_upstream(opts, &caller_settings)?;
    let enable_tool_search = is_official_anthropic_upstream(&upstream)
        && caller_settings.env_string("ENABLE_TOOL_SEARCH")?.is_none()
        && std::env::var_os("ENABLE_TOOL_SEARCH").is_none();

    let active_plugins = agent_tool_plugins(opts)?;
    let memory_store = start_memory_store(pentect)?;
    let _parent_env = agent_parent_env_guard(pentect, &memory_store, &active_plugins)?;
    let mut cmd = Command::new(&opts.command);
    clear_pentect_control_env(&mut cmd);
    upstream::hide_header_source_env(&mut cmd, &opts.upstream_header_env);
    apply_plugin_env(&mut cmd, &active_plugins)?;
    apply_pentect_env(&mut cmd, pentect, Some(memory_store.token.as_str()))?;
    apply_memory_store_env(&mut cmd, Some(&memory_store));
    let http_proxy = claude_http_proxy::ClaudeHttpProxyGuard::start_with_header_env(
        upstream,
        &opts.upstream_header_env,
    )?;
    cmd.env("ANTHROPIC_BASE_URL", http_proxy.base_url());
    // Claude Code reapplies settings.env after process start. Put the local
    // route in the CLI settings layer as well, while preserving a caller's
    // existing --settings payload. The provider-managed-host switch is not
    // used here because it also disables normal Claude subscription auth.
    let gateway_settings =
        caller_settings.with_gateway(&args, http_proxy.base_url(), enable_tool_search)?;
    cmd.args(gateway_settings.args());
    run_native_command_with_guards(cmd, &opts.command, (http_proxy, gateway_settings))
}

fn run_antigravity(
    opts: &AgentToolOpts,
    pentect: &Path,
) -> Result<std::process::ExitStatus, String> {
    const DEFAULT_UPSTREAM: &str = "https://daily-cloudcode-pa.googleapis.com";
    let upstream = opts
        .cloud_code_upstream
        .clone()
        .or_else(|| {
            std::env::var("CLOUD_CODE_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| DEFAULT_UPSTREAM.to_string());
    if opts.dry_run {
        print_dry_run(&opts.command, &opts.tool_args);
        return Ok(success_status());
    }

    let active_plugins = agent_tool_plugins(opts)?;
    let memory_store = start_memory_store(pentect)?;
    let _parent_env = agent_parent_env_guard(pentect, &memory_store, &active_plugins)?;
    let proxy = cloud_code_http_proxy::CloudCodeHttpProxyGuard::start_with_header_env(
        upstream,
        &opts.upstream_header_env,
    )?;
    let mut command = Command::new(&opts.command);
    clear_pentect_control_env(&mut command);
    upstream::hide_header_source_env(&mut command, &opts.upstream_header_env);
    apply_plugin_env(&mut command, &active_plugins)?;
    apply_pentect_env(&mut command, pentect, Some(memory_store.token.as_str()))?;
    apply_memory_store_env(&mut command, Some(&memory_store));
    command.env("CLOUD_CODE_URL", proxy.base_url());
    command.args(&opts.tool_args);
    run_native_command_with_guards(command, &opts.command, (proxy, memory_store))
}

const CLAUDE_CLOUD_PROVIDER_FLAGS: &[&str] = &[
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_USE_MANTLE",
];

#[derive(Debug)]
struct ClaudeCallerSettings {
    value: serde_json::Value,
    effective_env: serde_json::Map<String, serde_json::Value>,
    settings_at: Option<usize>,
    inline: bool,
    source_path: Option<PathBuf>,
}

impl ClaudeCallerSettings {
    fn from_args(args: &[String]) -> Result<Self, String> {
        let mut settings_at = None;
        let mut inline = false;
        for (index, arg) in args.iter().enumerate() {
            if arg == "--settings" {
                if settings_at.is_some() {
                    return Err(
                        "Claude accepts only one --settings value through Pentect".to_string()
                    );
                }
                settings_at = Some(index);
            } else if arg.starts_with("--settings=") {
                if settings_at.is_some() {
                    return Err(
                        "Claude accepts only one --settings value through Pentect".to_string()
                    );
                }
                settings_at = Some(index);
                inline = true;
            }
        }

        let (value, source_path) = if let Some(index) = settings_at {
            let raw = if inline {
                args[index]
                    .split_once('=')
                    .map(|(_, value)| value)
                    .unwrap_or_default()
                    .to_string()
            } else {
                args.get(index + 1)
                    .cloned()
                    .ok_or_else(|| "--settings requires a value".to_string())?
            };
            read_claude_settings_value(&raw)?
        } else {
            (serde_json::json!({}), None)
        };
        if !value.is_object() {
            return Err("Claude --settings must contain a JSON object".to_string());
        }
        let mut effective_env = load_claude_nonmanaged_env()?;
        if let Some(env) = value.get("env") {
            let env = env
                .as_object()
                .ok_or_else(|| "Claude --settings env must be a JSON object".to_string())?;
            for (name, value) in env {
                effective_env.insert(name.clone(), value.clone());
            }
        }
        Ok(Self {
            value,
            effective_env,
            settings_at,
            inline,
            source_path,
        })
    }

    fn env_string(&self, name: &str) -> Result<Option<&str>, String> {
        let Some(value) = self.effective_env.get(name) else {
            return Ok(None);
        };
        value
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("Claude --settings env.{name} must be a string"))
    }

    fn with_gateway(
        &self,
        args: &[String],
        base_url: &str,
        enable_tool_search: bool,
    ) -> Result<ClaudeGatewaySettings, String> {
        let mut settings = self.value.clone();
        let object = settings
            .as_object_mut()
            .ok_or_else(|| "Claude --settings must contain a JSON object".to_string())?;
        let env = object
            .entry("env")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .ok_or_else(|| "Claude --settings env must be a JSON object".to_string())?;
        env.insert(
            "ANTHROPIC_BASE_URL".to_string(),
            serde_json::Value::String(base_url.to_string()),
        );
        if enable_tool_search {
            env.insert(
                "ENABLE_TOOL_SEARCH".to_string(),
                serde_json::Value::String("true".to_string()),
            );
        }

        let directory = self
            .source_path
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .map(Ok)
            .unwrap_or_else(|| {
                std::env::current_dir().map_err(|error| {
                    format!("could not locate the working directory for Claude settings: {error}")
                })
            })?;
        let file = ClaudeSettingsFile::create(&directory, &settings)?;
        let path = file.path().to_string_lossy().into_owned();
        let mut out = args.to_vec();
        if let Some(index) = self.settings_at {
            if self.inline {
                out[index] = format!("--settings={path}");
            } else {
                out[index + 1] = path;
            }
        } else {
            out.insert(0, path);
            out.insert(0, "--settings".to_string());
        }
        Ok(ClaudeGatewaySettings {
            args: out,
            _file: file,
        })
    }
}

#[derive(Debug)]
struct ClaudeGatewaySettings {
    args: Vec<String>,
    _file: ClaudeSettingsFile,
}

impl ClaudeGatewaySettings {
    fn args(&self) -> &[String] {
        &self.args
    }
}

#[derive(Debug)]
struct ClaudeSettingsFile {
    path: PathBuf,
}

impl ClaudeSettingsFile {
    fn create(directory: &Path, settings: &serde_json::Value) -> Result<Self, String> {
        cleanup_stale_claude_settings_files(directory);
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| format!("OS CSPRNG unavailable for Claude settings: {error}"))?;
        let name = format!(
            ".pentect-claude-settings-{}-{}.json",
            std::process::id(),
            data_encoding::HEXLOWER.encode(&nonce)
        );
        let path = directory.join(name);
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|error| {
            format!(
                "could not create protected Claude settings beside the caller settings ({}): {error}",
                path.display()
            )
        })?;
        if let Err(error) = restrict_sensitive_file(&path) {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        if let Err(error) = serde_json::to_writer(&mut file, settings) {
            let _ = std::fs::remove_file(&path);
            return Err(format!(
                "could not encode protected Claude settings: {error}"
            ));
        }
        if let Err(error) = file.flush() {
            let _ = std::fs::remove_file(&path);
            return Err(format!(
                "could not flush protected Claude settings: {error}"
            ));
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(windows)]
fn restrict_sensitive_file(path: &Path) -> Result<(), String> {
    let identity = Command::new("whoami.exe")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| format!("could not resolve the Windows account for ACL setup: {error}"))?;
    if !identity.status.success() {
        return Err("could not resolve the Windows account for ACL setup".to_string());
    }
    let identity = String::from_utf8(identity.stdout)
        .map_err(|_| "Windows account name is not UTF-8".to_string())?;
    let identity = identity.trim();
    if identity.is_empty() {
        return Err("Windows account name is empty".to_string());
    }
    let grant = format!("{identity}:(F)");
    let status = Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("could not restrict Claude settings ACL: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("could not restrict Claude settings ACL".to_string())
    }
}

#[cfg(not(windows))]
fn restrict_sensitive_file(_: &Path) -> Result<(), String> {
    Ok(())
}

fn cleanup_stale_claude_settings_files(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut candidates = Vec::new();
    for path in entries.filter_map(|entry| entry.ok().map(|entry| entry.path())) {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(stem) = name
            .strip_prefix(".pentect-claude-settings-")
            .and_then(|rest| rest.strip_suffix(".json"))
        else {
            continue;
        };
        // Builds before PID ownership used a single 128-bit hex nonce. No
        // current process creates that shape, so it is always crash residue.
        if stem.len() == 32 && stem.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            let _ = std::fs::remove_file(path);
            continue;
        }
        let Some(owner) = stem
            .split_once('-')
            .map(|(owner, _)| owner)
            .and_then(|owner| owner.parse::<u32>().ok())
        else {
            continue;
        };
        if owner != std::process::id() {
            candidates.push((path, sysinfo::Pid::from_u32(owner)));
        }
    }
    if candidates.is_empty() {
        return;
    }
    let pids = candidates.iter().map(|(_, pid)| *pid).collect::<Vec<_>>();
    let mut system = sysinfo::System::new();
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&pids),
        true,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    for (path, pid) in candidates {
        if system.process(pid).is_none() {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl Drop for ClaudeSettingsFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn read_claude_settings_value(raw: &str) -> Result<(serde_json::Value, Option<PathBuf>), String> {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        return serde_json::from_str(trimmed)
            .map(|value| (value, None))
            .map_err(|error| format!("Claude --settings JSON is invalid: {error}"));
    }
    let path = PathBuf::from(trimmed);
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("could not read Claude --settings file {trimmed}: {error}"))?;
    serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map(|value| (value, Some(path)))
        .map_err(|error| format!("Claude --settings file is invalid JSON: {error}"))
}

fn claude_effective_upstream(
    opts: &AgentToolOpts,
    settings: &ClaudeCallerSettings,
) -> Result<String, String> {
    if let Some(explicit) = opts
        .anthropic_upstream
        .clone()
        .or_else(|| nonempty_env("PENTECT_ANTHROPIC_UPSTREAM"))
    {
        return Ok(explicit);
    }
    // Claude settings override the inherited environment. An empty setting
    // explicitly unsets the provider override rather than revealing a lower
    // layer, so route to the official endpoint in that case.
    if let Some(configured) = settings.env_string("ANTHROPIC_BASE_URL")? {
        return Ok(if configured.trim().is_empty() {
            "https://api.anthropic.com".to_string()
        } else {
            configured.to_string()
        });
    }
    Ok(nonempty_env("ANTHROPIC_BASE_URL")
        .unwrap_or_else(|| "https://api.anthropic.com".to_string()))
}

fn load_claude_nonmanaged_env() -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let cwd = std::env::current_dir()
        .map_err(|error| format!("could not locate the Claude working directory: {error}"))?;
    let project = find_project_root(&cwd);
    let config_dir = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| home_directory().map(|home| home.join(".claude")));
    let mut env = serde_json::Map::new();
    if let Some(config_dir) = config_dir {
        merge_claude_env_file(&mut env, &config_dir.join("settings.json"))?;
    }
    merge_claude_env_file(&mut env, &project.join(".claude/settings.json"))?;
    // Claude Code still reads a legacy local file in the launch directory,
    // while the repository-root file wins when both exist.
    if cwd != project {
        merge_claude_env_file(&mut env, &cwd.join(".claude/settings.local.json"))?;
    }
    merge_claude_env_file(&mut env, &project.join(".claude/settings.local.json"))?;
    Ok(env)
}

fn merge_claude_env_file(
    target: &mut serde_json::Map<String, serde_json::Value>,
    path: &Path,
) -> Result<(), String> {
    if !path.is_file() {
        return Ok(());
    }
    let settings = read_json_file(path)?;
    let Some(env) = settings.get("env") else {
        return Ok(());
    };
    let env = env.as_object().ok_or_else(|| {
        format!(
            "Claude settings {} env must be a JSON object",
            path.display()
        )
    })?;
    for (name, value) in env {
        target.insert(name.clone(), value.clone());
    }
    Ok(())
}

fn find_project_root(cwd: &Path) -> PathBuf {
    cwd.ancestors()
        .find(|path| path.join(".git").exists())
        .unwrap_or(cwd)
        .to_path_buf()
}

fn home_directory() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

fn reject_unsupported_claude_provider(settings: &ClaudeCallerSettings) -> Result<(), String> {
    for name in CLAUDE_CLOUD_PROVIDER_FLAGS {
        let configured = settings
            .env_string(name)?
            .map(cloud_provider_enabled)
            .unwrap_or_else(|| {
                std::env::var(name).is_ok_and(|value| cloud_provider_enabled(&value))
            });
        if configured {
            return Err(format!(
                "{name} cannot be routed through the Pentect Anthropic HTTP proxy; unset it or use Claude Code without `pentect claude`"
            ));
        }
    }
    Ok(())
}

fn preflight_managed_claude_routing() -> Result<(), String> {
    if let Some(settings) = managed_claude_settings()? {
        reject_managed_routing_value(&settings)?;
    }
    Ok(())
}

fn reject_managed_routing_value(settings: &serde_json::Value) -> Result<(), String> {
    if settings.get("policyHelper").is_some() {
        return Err(
            "Claude managed settings use policyHelper, so Pentect cannot verify that API traffic will stay on its HTTP proxy; run Claude without `pentect claude` or remove the managed provider override"
                .to_string(),
        );
    }
    let Some(env) = settings.get("env") else {
        return Ok(());
    };
    let env = env
        .as_object()
        .ok_or_else(|| "Claude managed settings env must be a JSON object".to_string())?;
    if env
        .get("ANTHROPIC_BASE_URL")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        return Err(
            "Claude managed settings override ANTHROPIC_BASE_URL and would bypass Pentect's HTTP proxy; use Claude without `pentect claude` or ask the administrator to remove that override"
                .to_string(),
        );
    }
    for name in CLAUDE_CLOUD_PROVIDER_FLAGS {
        if env
            .get(*name)
            .and_then(serde_json::Value::as_str)
            .is_some_and(cloud_provider_enabled)
        {
            return Err(format!(
                "Claude managed settings enable {name}, which cannot be routed through Pentect's Anthropic HTTP proxy"
            ));
        }
    }
    Ok(())
}

fn managed_claude_settings() -> Result<Option<serde_json::Value>, String> {
    let directory = if cfg!(windows) {
        let Some(program_files) = std::env::var_os("ProgramFiles") else {
            return Ok(None);
        };
        PathBuf::from(program_files).join("ClaudeCode")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/ClaudeCode")
    } else {
        PathBuf::from("/etc/claude-code")
    };
    let file_settings = read_file_managed_claude_settings(&directory)?;

    #[cfg(windows)]
    {
        if file_settings
            .as_ref()
            .is_some_and(|settings| settings.get("policyHelper").is_some())
        {
            return Ok(file_settings);
        }
        if let Some(settings) = read_windows_claude_policy("HKLM\\SOFTWARE\\Policies\\ClaudeCode")?
        {
            return Ok(Some(settings));
        }
        if file_settings.is_some() {
            return Ok(file_settings);
        }
        return read_windows_claude_policy("HKCU\\SOFTWARE\\Policies\\ClaudeCode");
    }
    #[allow(unreachable_code)]
    Ok(file_settings)
}

fn read_file_managed_claude_settings(
    directory: &Path,
) -> Result<Option<serde_json::Value>, String> {
    let mut merged = serde_json::json!({});
    let mut found = false;
    let base = directory.join("managed-settings.json");
    if base.is_file() {
        merge_json_object(&mut merged, &read_json_file(&base)?)?;
        found = true;
    }
    let drop_in = directory.join("managed-settings.d");
    if drop_in.is_dir() {
        let mut paths = std::fs::read_dir(&drop_in)
            .map_err(|error| format!("could not inspect {}: {error}", drop_in.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension().and_then(|value| value.to_str()) == Some("json")
                    && !path
                        .file_name()
                        .and_then(|value| value.to_str())
                        .is_some_and(|value| value.starts_with('.'))
            })
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            merge_json_object(&mut merged, &read_json_file(&path)?)?;
            found = true;
        }
    }
    Ok(found.then_some(merged))
}

fn read_json_file(path: &Path) -> Result<serde_json::Value, String> {
    let bytes = std::fs::read(path).map_err(|error| {
        format!(
            "could not read Claude managed settings {}: {error}",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "Claude managed settings {} contain invalid JSON: {error}",
            path.display()
        )
    })
}

fn merge_json_object(
    target: &mut serde_json::Value,
    source: &serde_json::Value,
) -> Result<(), String> {
    let target = target
        .as_object_mut()
        .ok_or_else(|| "internal Claude managed settings merge target is invalid".to_string())?;
    let source = source
        .as_object()
        .ok_or_else(|| "Claude managed settings must contain a JSON object".to_string())?;
    for (key, value) in source {
        if let (Some(existing @ serde_json::Value::Object(_)), serde_json::Value::Object(_)) =
            (target.get_mut(key), value)
        {
            merge_json_object(existing, value)?;
        } else {
            target.insert(key.clone(), value.clone());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn read_windows_claude_policy(key: &str) -> Result<Option<serde_json::Value>, String> {
    let output = Command::new("reg.exe")
        .args(["query", key, "/v", "Settings"])
        .output()
        .map_err(|error| format!("could not inspect Claude managed registry policy: {error}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json = stdout.lines().find_map(|line| {
        line.split_once("REG_SZ")
            .or_else(|| line.split_once("REG_EXPAND_SZ"))
            .map(|(_, value)| value.trim())
            .filter(|value| !value.is_empty())
    });
    let Some(json) = json else {
        return Err(format!(
            "Claude managed registry policy {key} has an unreadable Settings value"
        ));
    };
    serde_json::from_str(json)
        .map(Some)
        .map_err(|error| format!("Claude managed registry policy {key} is invalid JSON: {error}"))
}

fn is_official_anthropic_upstream(upstream: &str) -> bool {
    reqwest::Url::parse(upstream).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str() == Some("api.anthropic.com")
            && url.port_or_known_default() == Some(443)
    })
}

fn cloud_provider_enabled(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off"
    )
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn run_native_command_with_guards<G>(
    mut cmd: Command,
    display: &Path,
    _guards: G,
) -> Result<std::process::ExitStatus, String> {
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    cmd.status()
        .map_err(|error| format!("could not run '{}': {error}", display.display()))
}

struct MemoryStoreGuard {
    child: Option<Child>,
    _lease: Option<pentect_agent::MemoryStoreLease>,
    addr: String,
    token: String,
    process_host_candidate: Option<PathBuf>,
}

impl MemoryStoreGuard {
    fn start(pentect: &Path) -> Result<Self, String> {
        if let (Some(addr), Some(token), Some(launch_proof)) = (
            std::env::var_os(PENTECT_MEMORY_STORE_ADDR_ENV),
            std::env::var_os(PENTECT_MEMORY_STORE_TOKEN_ENV),
            std::env::var_os(PENTECT_AGENT_LAUNCHED_ENV),
        ) {
            let addr = addr.to_string_lossy().to_string();
            let token = token.to_string_lossy().to_string();
            let launch_proof = launch_proof.to_string_lossy();
            let process_host_root = process_host_root()?;
            if !addr.is_empty()
                && valid_runtime_token(&token)
                && launch_proof == token
                && addr
                    .parse::<std::net::SocketAddr>()
                    .is_ok_and(|addr| addr.ip().is_loopback())
                && pentect_agent::delegated_process_host_contains(&process_host_root, &addr, &token)
                && pentect_agent::memory_store_ready(&addr, &token)
            {
                return Ok(Self {
                    child: None,
                    _lease: None,
                    addr,
                    token,
                    process_host_candidate: None,
                });
            }
        }
        let mut command = Command::new(pentect);
        clear_pentect_control_env(&mut command);
        command
            .arg("agent")
            .arg("memory-store")
            .arg("--serve")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
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
        let (addr, token, mut process_host_read_token, mut process_host_write_token) =
            match parse_memory_store_startup(&line) {
                Ok(parsed) => parsed,
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e);
                }
            };
        let lease = match pentect_agent::open_memory_store_lease(&addr, &token) {
            Ok(lease) => Some(lease),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.to_string());
            }
        };
        let process_host_root = process_host_root()?;
        let process_host_candidate = match pentect_agent::register_process_host_candidate(
            &process_host_root,
            &addr,
            &token,
            &process_host_read_token,
            &process_host_write_token,
            child.id(),
        ) {
            Ok(path) => path,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        process_host_read_token.zeroize();
        process_host_write_token.zeroize();
        Ok(Self {
            child: Some(child),
            _lease: lease,
            addr,
            token,
            process_host_candidate: Some(process_host_candidate),
        })
    }
}

fn valid_runtime_token(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
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
    }
}

fn process_host_root() -> Result<PathBuf, String> {
    pentect_agent::process_host_root()
}

fn apply_pentect_env(
    cmd: &mut Command,
    pentect: &Path,
    launch_proof: Option<&str>,
) -> Result<(), String> {
    let absolute = if pentect.is_absolute() {
        pentect.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("could not read current dir: {error}"))?
            .join(pentect)
    };
    let directory = absolute
        .parent()
        .ok_or_else(|| format!("Pentect path has no parent: '{}'", pentect.display()))?;
    let mut path_entries = vec![directory.to_path_buf()];
    if let Some(path) = std::env::var_os("PATH") {
        path_entries.extend(std::env::split_paths(&path).filter(|entry| entry != directory));
    }
    let path = std::env::join_paths(path_entries)
        .map_err(|error| format!("could not prepare Pentect PATH: {error}"))?;
    cmd.env("PATH", path);
    cmd.env(PENTECT_BIN_ENV, &absolute);
    if let Some(launch_proof) = launch_proof.filter(|value| !value.is_empty()) {
        cmd.env(PENTECT_AGENT_LAUNCHED_ENV, launch_proof);
    } else {
        cmd.env_remove(PENTECT_AGENT_LAUNCHED_ENV);
    }
    Ok(())
}

fn clear_pentect_control_env(command: &mut Command) {
    for name in pentect_agent::pentect_control_env_names() {
        command.env_remove(name);
    }
    for (name, _) in std::env::vars_os() {
        if name
            .to_str()
            .is_some_and(pentect_agent::is_pentect_control_env_name)
        {
            command.env_remove(name);
        }
    }
}

fn apply_memory_store_env(cmd: &mut Command, memory_store: Option<&MemoryStoreGuard>) {
    let Some(memory_store) = memory_store else {
        return;
    };
    cmd.env(PENTECT_MEMORY_STORE_ADDR_ENV, &memory_store.addr);
    cmd.env(PENTECT_MEMORY_STORE_TOKEN_ENV, &memory_store.token);
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
    active_plugins: &plugins::ActivePlugins,
) -> Result<EnvVarGuard, String> {
    let config_env = active_plugins
        .config_env_value()
        .map_err(|e| e.to_string())?;
    let binary_env = active_plugins
        .binary_env_value()
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
        (PENTECT_BIN_ENV, Some(pentect.as_os_str().to_os_string())),
        (
            PENTECT_AGENT_LAUNCHED_ENV,
            Some(OsString::from(memory_store.token.as_str())),
        ),
        (plugins::CONFIGS_ENV, config_env),
        (plugins::BINARIES_ENV, binary_env),
    ]))
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

struct CodexHttpRouting {
    upstream: String,
    provider: String,
}

const CODEX_GATEWAY_PROVIDER: &str = "pentect-openai-gateway";

impl CodexHttpRouting {
    fn gateway_args(&self, gateway: &str) -> Vec<String> {
        let entries = if self.provider == "openai" {
            vec![
                format!("model_provider={}", toml_string(CODEX_GATEWAY_PROVIDER)),
                format!(
                    "model_providers.{CODEX_GATEWAY_PROVIDER}.name={}",
                    toml_string("OpenAI through Pentect")
                ),
                format!(
                    "model_providers.{CODEX_GATEWAY_PROVIDER}.base_url={}",
                    toml_string(gateway)
                ),
                format!(
                    "model_providers.{CODEX_GATEWAY_PROVIDER}.wire_api={}",
                    toml_string("responses")
                ),
                format!("model_providers.{CODEX_GATEWAY_PROVIDER}.requires_openai_auth=true"),
                format!("model_providers.{CODEX_GATEWAY_PROVIDER}.supports_websockets=false"),
            ]
        } else {
            let provider = codex_toml_key_segment(&self.provider);
            vec![
                format!(
                    "model_providers.{provider}.base_url={}",
                    toml_string(gateway)
                ),
                format!("model_providers.{provider}.supports_websockets=false"),
            ]
        };
        entries
            .into_iter()
            .flat_map(|entry| ["--config".to_string(), entry])
            .collect()
    }
}

fn codex_effective_routing(opts: &AgentToolOpts) -> Result<CodexHttpRouting, String> {
    let config = load_codex_user_config(&opts.tool_args)?;
    let provider = codex_cli_config_string(&opts.tool_args, "model_provider")
        .or_else(|| {
            config
                .get("model_provider")
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "openai".to_string());
    let config_key = if provider == "openai" {
        "openai_base_url".to_string()
    } else {
        format!(
            "model_providers.{}.base_url",
            codex_toml_key_segment(&provider)
        )
    };
    let configured_upstream = codex_cli_config_string(&opts.tool_args, &config_key).or_else(|| {
        if provider == "openai" {
            config
                .get("openai_base_url")
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        } else {
            config
                .get("model_providers")
                .and_then(toml::Value::as_table)
                .and_then(|providers| providers.get(&provider))
                .and_then(toml::Value::as_table)
                .and_then(|provider| provider.get("base_url"))
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        }
    });
    let upstream = opts
        .openai_upstream
        .clone()
        .or(configured_upstream)
        .or_else(|| {
            (provider == "openai")
                .then(|| nonempty_env("OPENAI_BASE_URL"))
                .flatten()
        })
        .or_else(|| {
            (provider == "openai").then(|| {
                if codex_uses_chatgpt_auth() {
                    "https://chatgpt.com/backend-api/codex".to_string()
                } else {
                    "https://api.openai.com/v1".to_string()
                }
            })
        })
        .ok_or_else(|| {
            format!(
                "could not determine upstream for Codex provider '{provider}'; pass `pentect codex --upstream URL`"
            )
        })?;
    if provider != "openai" {
        let wire_api = config
            .get("model_providers")
            .and_then(toml::Value::as_table)
            .and_then(|providers| providers.get(&provider))
            .and_then(toml::Value::as_table)
            .and_then(|provider| provider.get("wire_api"))
            .and_then(toml::Value::as_str)
            .unwrap_or("responses");
        if wire_api != "responses" {
            return Err(format!(
                "Codex provider '{provider}' uses unsupported wire_api '{wire_api}'; Pentect supports Responses-compatible providers"
            ));
        }
    }
    Ok(CodexHttpRouting { upstream, provider })
}

pub(crate) struct CodexAppRouting {
    upstream: String,
    provider: String,
}

/// Resolve the App's selected provider without changing user configuration.
/// The launcher installs a short-lived, recoverable base-url override only
/// when the selected provider cannot be redirected by OPENAI_BASE_URL.
pub(crate) fn codex_app_routing(explicit: Option<String>) -> Result<CodexAppRouting, String> {
    let config = load_codex_user_config(&[])?;
    let provider = config
        .get("model_provider")
        .and_then(toml::Value::as_str)
        .unwrap_or("openai")
        .to_string();
    let configured_upstream = if provider == "openai" {
        config
            .get("openai_base_url")
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
    } else {
        let provider_config = config
            .get("model_providers")
            .and_then(toml::Value::as_table)
            .and_then(|providers| providers.get(&provider))
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("Codex provider '{provider}' has no configuration"))?;
        let wire_api = provider_config
            .get("wire_api")
            .and_then(toml::Value::as_str)
            .unwrap_or("responses");
        if wire_api != "responses" {
            return Err(format!(
                "Codex App provider '{provider}' uses unsupported wire_api '{wire_api}'; Pentect currently supports Responses-compatible providers"
            ));
        }
        provider_config
            .get("base_url")
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
    };
    let upstream = explicit
        .or(configured_upstream)
        .or_else(|| (provider == "openai").then(|| nonempty_env("OPENAI_BASE_URL")).flatten())
        .or_else(|| (provider == "openai").then(|| {
            if codex_uses_chatgpt_auth() {
                "https://chatgpt.com/backend-api/codex".to_string()
            } else {
                "https://api.openai.com/v1".to_string()
            }
        }))
        .ok_or_else(|| {
            format!(
                "could not determine upstream for Codex App provider '{provider}'; pass --upstream URL"
            )
        })?;
    Ok(CodexAppRouting { upstream, provider })
}

fn load_codex_user_config(args: &[String]) -> Result<toml::Value, String> {
    let home = codex_home_dir()?;
    let mut merged = toml::Value::Table(toml::map::Map::new());
    let base = home.join("config.toml");
    if base.is_file() {
        merge_toml_value(&mut merged, &read_toml_file(&base)?);
    }
    if let Some(profile) = codex_profile_arg(args) {
        let profile_path = home.join(format!("{profile}.config.toml"));
        if profile_path.is_file() {
            merge_toml_value(&mut merged, &read_toml_file(&profile_path)?);
        }
    }
    Ok(merged)
}

fn read_toml_file(path: &Path) -> Result<toml::Value, String> {
    std::fs::read_to_string(path)
        .map_err(|error| format!("could not read '{}': {error}", path.display()))?
        .parse::<toml::Value>()
        .map_err(|error| format!("could not parse '{}': {error}", path.display()))
}

fn merge_toml_value(target: &mut toml::Value, source: &toml::Value) {
    match (target, source) {
        (toml::Value::Table(target), toml::Value::Table(source)) => {
            for (key, value) in source {
                if let Some(existing) = target.get_mut(key) {
                    merge_toml_value(existing, value);
                } else {
                    target.insert(key.clone(), value.clone());
                }
            }
        }
        (target, source) => *target = source.clone(),
    }
}

fn codex_profile_arg(args: &[String]) -> Option<&str> {
    let mut profile = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--profile" => {
                profile = args.get(index + 1).map(String::as_str);
                index += 2;
            }
            value if value.starts_with("--profile=") => {
                profile = value.split_once('=').map(|(_, value)| value);
                index += 1;
            }
            _ => index += 1,
        }
    }
    profile
}

fn codex_cli_config_string(args: &[String], wanted: &str) -> Option<String> {
    let mut found = None;
    let mut index = 0;
    while index < args.len() {
        let config = match args[index].as_str() {
            "-c" | "--config" => {
                index += 2;
                args.get(index - 1).map(String::as_str)
            }
            value if value.starts_with("--config=") => {
                index += 1;
                value.split_once('=').map(|(_, value)| value)
            }
            _ => {
                index += 1;
                None
            }
        };
        let Some((key, raw)) = config.and_then(|config| config.split_once('=')) else {
            continue;
        };
        if !toml_key_paths_equal(key.trim(), wanted) {
            continue;
        }
        let parsed = format!("value={raw}").parse::<toml::Value>().ok();
        found = parsed
            .as_ref()
            .and_then(|value| value.get("value"))
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
            .or_else(|| Some(raw.trim().trim_matches(['"', '\'']).to_string()));
    }
    found
}

fn toml_key_paths_equal(left: &str, right: &str) -> bool {
    fn path(value: &toml::Value, out: &mut Vec<String>) -> bool {
        match value {
            toml::Value::Table(table) if table.len() == 1 => {
                let (key, value) = table.iter().next().expect("single TOML key");
                out.push(key.clone());
                path(value, out)
            }
            toml::Value::String(_) => true,
            _ => false,
        }
    }

    fn parse(key: &str) -> Option<Vec<String>> {
        let value = format!("{key} = \"pentect\"").parse::<toml::Value>().ok()?;
        let mut segments = Vec::new();
        path(&value, &mut segments).then_some(segments)
    }

    parse(left).is_some_and(|left| parse(right).as_ref() == Some(&left))
}

fn codex_toml_key_segment(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        value.to_string()
    } else {
        toml_string(value)
    }
}

fn codex_uses_chatgpt_auth() -> bool {
    if nonempty_env("OPENAI_API_KEY").is_some() {
        return false;
    }
    let Ok(home) = codex_home_dir() else {
        return true;
    };
    let Ok(bytes) = std::fs::read(home.join("auth.json")) else {
        return true;
    };
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|value| {
            value
                .get("auth_mode")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .is_none_or(|mode| mode.eq_ignore_ascii_case("chatgpt"))
}

fn apply_plugin_env(cmd: &mut Command, active: &plugins::ActivePlugins) -> Result<(), String> {
    if let Some(value) = active.config_env_value().map_err(|e| e.to_string())? {
        cmd.env(plugins::CONFIGS_ENV, value);
    }
    if let Some(value) = active.binary_env_value().map_err(|e| e.to_string())? {
        cmd.env(plugins::BINARIES_ENV, value);
    }
    Ok(())
}

fn default_pentect_path() -> PathBuf {
    default_pentect_path_from(
        std::env::current_exe().ok(),
        std::env::current_dir().ok(),
        cfg!(windows),
    )
}

fn default_pentect_path_from(
    current_exe: Option<PathBuf>,
    current_dir: Option<PathBuf>,
    windows: bool,
) -> PathBuf {
    // The release asset may be executed before installation, under a
    // platform-qualified filename such as `pentect-linux-x86_64`.  Child
    // services must relaunch that exact executable instead of assuming a
    // sibling file named `pentect` exists.
    if let Some(current) = current_exe {
        return current;
    }

    let exe_name = if windows { "pentect.exe" } else { "pentect" };
    let mut candidates = Vec::new();
    if let Some(cwd) = current_dir {
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

fn input_adapter(args: &[String]) -> Result<Box<dyn InputAdapter>, String> {
    match arg_value(args, "--input").as_deref() {
        Some("image" | "ocr") => Ok(Box::new(ImageOcrInput)),
        Some("text") | None => Ok(Box::new(TextInput)),
        Some(other) => Err(format!("unknown --input: {other}")),
    }
}

fn parse_read_input_format(value: &str) -> Result<ReadInputFormat, String> {
    match value {
        "text" => Ok(ReadInputFormat::Text),
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
        "structured" | "config" => Ok(Kind::Other("structured".to_string())),
        "secret" | "secret-file" => Ok(Kind::Other("secret-file:SECRET".to_string())),
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
    packs.extend(plugins::load_config_packs_from_args(args, true).map_err(|e| e.to_string())?);
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
    fn public_command_snapshot_is_intentional() {
        assert_eq!(
            command_names(CommandAudience::Public),
            [
                "aider",
                "antigravity",
                "claude",
                "codex",
                "doctor",
                "exec",
                "help",
                "log",
                "mask",
                "opencode",
                "pi",
                "plugins",
                "read",
                "uninstall",
                "update",
                "version",
                "view",
            ]
        );
        assert_eq!(command_names(CommandAudience::Advanced), ["resolve"]);
    }

    #[test]
    fn command_catalog_has_unique_names_and_hidden_internal_usage() {
        let mut names = std::collections::HashSet::new();
        for command in COMMANDS {
            assert!(
                names.insert(command.name),
                "duplicate command {}",
                command.name
            );
            match command.audience {
                CommandAudience::Public | CommandAudience::Advanced => {
                    assert!(!command.usage.is_empty());
                    assert!(!command.summary.is_empty());
                }
                CommandAudience::Internal => {
                    assert!(command.usage.is_empty());
                    assert!(command.summary.is_empty());
                }
            }
        }
    }

    #[test]
    fn help_lists_public_and_advanced_commands_but_no_internal_commands() {
        let help = help_text();
        for command in command_names(CommandAudience::Public)
            .into_iter()
            .chain(command_names(CommandAudience::Advanced))
        {
            assert!(help.contains(command), "help omitted {command}");
        }
        assert!(help.contains("Advanced:\n"));
        assert!(help.contains("pentect resolve [PATH...]"));
        for command in COMMANDS
            .iter()
            .filter(|command| command.audience == CommandAudience::Internal)
        {
            assert!(
                !help.contains(&format!("pentect {}", command.name)),
                "help exposed internal command {}",
                command.name
            );
        }
    }

    #[test]
    fn agent_options_keep_provider_upstreams_out_of_tool_args() {
        let codex = AgentToolOpts::parse(
            AgentTool::Codex,
            &[
                "pentect".to_string(),
                "codex".to_string(),
                "--upstream".to_string(),
                "https://gateway.example/v1".to_string(),
                "--upstream-header-env".to_string(),
                "x-bf-vk=BIFROST_API_KEY".to_string(),
                "--".to_string(),
                "exec".to_string(),
                "hello".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(
            codex.openai_upstream.as_deref(),
            Some("https://gateway.example/v1")
        );
        assert_eq!(codex.upstream_header_env, ["x-bf-vk=BIFROST_API_KEY"]);
        assert_eq!(codex.tool_args, ["exec", "hello"]);

        let claude = AgentToolOpts::parse(
            AgentTool::Claude,
            &[
                "pentect".to_string(),
                "claude".to_string(),
                "--upstream".to_string(),
                "https://gateway.example/anthropic".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(
            claude.anthropic_upstream.as_deref(),
            Some("https://gateway.example/anthropic")
        );

        let opencode = AgentToolOpts::parse(
            AgentTool::OpenCode,
            &[
                "pentect".to_string(),
                "opencode".to_string(),
                "--upstream".to_string(),
                "http://127.0.0.1:8080/openai/v1".to_string(),
                "--model".to_string(),
                "anthropic/claude-sonnet".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(
            opencode.openai_upstream.as_deref(),
            Some("http://127.0.0.1:8080/openai/v1")
        );
        assert_eq!(opencode.model.as_deref(), Some("anthropic/claude-sonnet"));

        let aider = AgentToolOpts::parse(
            AgentTool::Aider,
            &[
                "pentect".to_string(),
                "aider".to_string(),
                "--upstream".to_string(),
                "http://127.0.0.1:8080/openai/v1".to_string(),
                "--model".to_string(),
                "gpt-5.1".to_string(),
                "--".to_string(),
                "src/main.rs".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(
            aider.openai_upstream.as_deref(),
            Some("http://127.0.0.1:8080/openai/v1")
        );
        assert_eq!(aider.model.as_deref(), Some("gpt-5.1"));
        assert_eq!(aider.tool_args, ["src/main.rs"]);

        let antigravity = AgentToolOpts::parse(
            AgentTool::Antigravity,
            &[
                "pentect".to_string(),
                "antigravity".to_string(),
                "--upstream".to_string(),
                "https://cloud-code.example/base".to_string(),
                "--".to_string(),
                "--agent".to_string(),
                "reviewer".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(
            antigravity.cloud_code_upstream.as_deref(),
            Some("https://cloud-code.example/base")
        );
        assert_eq!(antigravity.tool_args, ["--agent", "reviewer"]);
    }

    #[test]
    fn client_commands_and_aliases_come_from_descriptors() {
        assert_eq!(AgentTool::from_command("codex"), Some(AgentTool::Codex));
        assert_eq!(AgentTool::from_command("agy"), Some(AgentTool::Antigravity));
        assert_eq!(AgentTool::from_command("aider"), Some(AgentTool::Aider));
        assert_eq!(AgentTool::from_command("unknown"), None);
    }

    #[test]
    fn agent_options_forward_client_arguments_without_separator() {
        let codex = AgentToolOpts::parse(
            AgentTool::Codex,
            &[
                "pentect".to_string(),
                "codex".to_string(),
                "exec".to_string(),
                "--full-auto".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(codex.tool_args, ["exec", "--full-auto"]);

        let claude = AgentToolOpts::parse(
            AgentTool::Claude,
            &[
                "pentect".to_string(),
                "claude".to_string(),
                "--model".to_string(),
                "sonnet".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(claude.tool_args, ["--model", "sonnet"]);
    }

    #[test]
    fn codex_cli_config_uses_the_last_string_value() {
        let args = vec![
            "-c".to_string(),
            "openai_base_url=\"https://first.example/v1\"".to_string(),
            "--config=openai_base_url=\"https://last.example/v1\"".to_string(),
        ];
        assert_eq!(
            codex_cli_config_string(&args, "openai_base_url").as_deref(),
            Some("https://last.example/v1")
        );
    }

    #[test]
    fn codex_cli_config_compares_toml_key_segments_semantically() {
        let args = vec![
            "-c".to_string(),
            "model_providers.'team.proxy'.base_url=\"https://proxy.example/v1\"".to_string(),
        ];
        assert_eq!(
            codex_cli_config_string(&args, "model_providers.\"team.proxy\".base_url").as_deref(),
            Some("https://proxy.example/v1")
        );
    }

    #[test]
    fn codex_provider_key_segments_are_safe_toml() {
        assert_eq!(codex_toml_key_segment("local-proxy"), "local-proxy");
        assert_eq!(codex_toml_key_segment("team.proxy"), "\"team.proxy\"");
    }

    #[test]
    fn only_long_lived_agent_commands_support_process_host_handoff() {
        for command in ["exec", "log", "bridge"] {
            let args = vec!["pentect".to_string(), command.to_string()];
            assert!(supports_process_host(&args));
        }
        for command in ["codex", "claude", "claude-app", "scan", "read"] {
            let args = vec!["pentect".to_string(), command.to_string()];
            assert!(!supports_process_host(&args));
        }
    }

    #[test]
    fn child_services_relaunch_the_exact_current_executable() {
        let release_asset = PathBuf::from("/tmp/pentect-linux-x86_64");
        assert_eq!(
            default_pentect_path_from(
                Some(release_asset.clone()),
                Some(PathBuf::from("/workspace")),
                false,
            ),
            release_asset
        );
    }
}
