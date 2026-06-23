//! Pentect CLI: local secret-capability tool boundary for AI agents.

mod input;
mod terminal;

use input::{InputAdapter, TextInput};
use pentect_core::{load_pack, Config, Engine, Input, Kind, Pack, Profile, RuleDetector};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Refuse oversized input rather than emit partially-masked output (a masked
/// head plus a raw tail would leak the tail).
const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const PENTECT_AGENT_INSTRUCTIONS: &str = concat!(
    "Pentect agent contract:\n",
    "- Run normal shell commands. The hook layer routes them through `pentect exec`; do not nest Pentect wrappers.\n",
    "- Masked handles like `<<NAME_hash>>` are local capabilities. Later commands get them as `$env:PENTECT_NAME_hash` on PowerShell or `$PENTECT_NAME_hash` on Unix; `KEY=<<...>>` also exposes `$env:KEY` / `$KEY`.\n",
    "- To register a secret from a file, API, browser, or MCP result, run the normal read/fetch command and let masked output appear.\n",
    "- When using a secret, use its env var capability. Do not re-read source files, echo handles for inspection, or run help to discover extra flags.\n",
    "- Do not exfiltrate secrets through encodings, chunks, screenshots, prefixes/suffixes, or derived previews. Report only non-secret outcomes.\n",
);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None => cmd_agent_passthrough_from(1, &args),
        Some("help" | "--help" | "-h") => cmd_help(),
        Some("dashboard") => cmd_agent_passthrough_from(1, &args),
        Some("--dir" | "--session") => cmd_agent_passthrough_from(1, &args),
        Some("mask") => cmd_mask(&args),
        Some("read") => cmd_read(&args),
        Some("exec" | "resolve" | "approve" | "hook" | "purge") => {
            cmd_agent_passthrough_from(1, &args)
        }
        Some("agent") => cmd_agent_passthrough(&args),
        Some("codex") => cmd_agent_tool(AgentTool::Codex, &args),
        Some("claude") => cmd_agent_tool(AgentTool::Claude, &args),
        Some("gemini") => cmd_agent_tool(AgentTool::Gemini, &args),
        _ => usage(),
    }
}

fn usage() {
    eprintln!(
        "pentect\n\
         pentect codex|claude|gemini\n\
         pentect exec \"<command>\"\n\
         pentect resolve [PATH...]\n\
         pentect help\n\
         \n\
         exec runs commands with masked output.\n\
         resolve rewrites files containing handles, or resolves stdin when no path is given."
    );
}

fn cmd_help() {
    print!("{}", help_text());
}

fn help_text() -> &'static str {
    concat!(
        "pentect protects AI tool boundaries.\n\n",
        "Use:\n",
        "  pentect codex|claude|gemini\n",
        "  pentect exec \"<command>\"\n\n",
        "`pentect exec` returns normal stdout/stderr with secrets masked.\n",
        "Masked handles resolve locally in later `pentect exec` commands.\n",
        "Every handle also becomes a `PENTECT_...` env var for later execs.\n",
        "Masked env lines become env vars in later execs: `$env:KEY` on PowerShell, `$KEY` on Unix.\n",
        "Masked output and referenced local files register capabilities for later execs.\n",
        "Use normal commands and let Pentect return masked handles.\n",
        "Use `pentect resolve <path>` only when a local file must be materialized with real values.\n",
    )
}

fn die(msg: &str) -> ! {
    eprintln!("[pentect] {msg}");
    std::process::exit(2);
}

fn cmd_agent_passthrough(args: &[String]) {
    if matches!(args.get(2).map(String::as_str), Some("--probe")) {
        println!("pentect-agent-passthrough");
        return;
    }
    cmd_agent_passthrough_from(2, args)
}

fn cmd_agent_passthrough_from(start: usize, args: &[String]) {
    let agent = std::env::var_os("PENTECT_AGENT")
        .map(PathBuf::from)
        .unwrap_or_else(default_agent_path);
    let mut cmd = Command::new(&agent);
    cmd.args(&args[start..]);
    let status = run_command(cmd, &agent);
    std::process::exit(status.code().unwrap_or(1));
}

fn cmd_agent_tool(tool: AgentTool, args: &[String]) {
    let opts = match AgentToolOpts::parse(tool, args) {
        Ok(o) => o,
        Err(e) => die(&e),
    };
    let agent = opts.agent.clone().unwrap_or_else(default_agent_path);
    if !agent.exists() && agent.components().count() > 1 {
        die(&format!(
            "pentect-agent not found at '{}'; run `cargo build -p pentect-agent --release` or pass --agent PATH",
            agent.display()
        ));
    }
    if !opts.dry_run {
        terminal::restore_after_tui();
    }
    let status = match tool {
        AgentTool::Codex => run_codex(&opts, &agent),
        AgentTool::Claude => run_claude(&opts, &agent),
        AgentTool::Gemini => run_gemini(&opts, &agent),
    };
    std::process::exit(status.code().unwrap_or(1));
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
            Err(e) => {
                eprintln!("[pentect] {e}");
                std::process::exit(2);
            }
        },
        None => Profile::Balanced,
    };
    let disclose_length = has_flag(args, "--length");
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
    let engine = build_engine(profile, aggressive, packs, args);
    let cfg = Config {
        disclose_length,
        ..Config::generate()
    };
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
            "--kind" | "--profile" | "--input" | "--pack" | "--pack-dir" | "--disable"
            | "--enable" => {
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
                i += 2;
            }
            "--length" | "--aggressive" | "--semantic" => {
                i += 1;
            }
            "--ner" => {
                return Err("--ner was removed; use --semantic".to_string());
            }
            "--semantic-provider" | "--semantic-script" => {
                return Err(format!(
                    "{} was removed; use --semantic with the default sidecar",
                    args[i]
                ));
            }
            flag if flag.starts_with("--semantic=") => {
                return Err("--semantic no longer accepts a provider; use --semantic".to_string());
            }
            flag if flag.starts_with("--") => {
                return Err(format!("unknown option: {flag}"));
            }
            value => {
                return Err(format!(
                    "unexpected argument for mask: {value}; --semantic takes no provider"
                ));
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
    let engine = Engine::with_profile(opts.profile);
    let cfg = Config {
        disclose_length: opts.disclose_length,
        ..Config::generate()
    };
    let result = engine.mask(Input { kind, data }, &cfg);
    print!("{}", result.masked);
    let _ = std::io::stdout().flush();
    if opts.emit_meta {
        eprintln!(
            "[pentect] masked={}, warned={}",
            result.summary.masked_count,
            result.summary.residual.len()
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentTool {
    Codex,
    Claude,
    Gemini,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadInputFormat {
    Text,
    Pdf,
}

struct ReadOpts {
    input_format: ReadInputFormat,
    kind: Option<Kind>,
    profile: Profile,
    disclose_length: bool,
    emit_meta: bool,
    path: PathBuf,
}

impl ReadOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut input_format = ReadInputFormat::Text;
        let mut kind = None;
        let mut profile = Profile::Strict;
        let mut disclose_length = false;
        let mut emit_meta = false;
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
                "--length" => {
                    disclose_length = true;
                    i += 1;
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
            profile,
            disclose_length,
            emit_meta,
            path: path.ok_or_else(|| "read requires PATH".to_string())?,
        })
    }
}

impl AgentTool {
    fn name(self) -> &'static str {
        match self {
            AgentTool::Codex => "codex",
            AgentTool::Claude => "claude",
            AgentTool::Gemini => "gemini",
        }
    }

    fn env_var(self) -> &'static str {
        match self {
            AgentTool::Codex => "PENTECT_CODEX",
            AgentTool::Claude => "PENTECT_CLAUDE",
            AgentTool::Gemini => "PENTECT_GEMINI",
        }
    }

    fn default_command(self) -> &'static str {
        match self {
            AgentTool::Gemini if cfg!(windows) => "gemini.cmd",
            _ => self.name(),
        }
    }

    fn path_flag(self) -> &'static str {
        match self {
            AgentTool::Codex => "--codex",
            AgentTool::Claude => "--claude",
            AgentTool::Gemini => "--gemini",
        }
    }
}

#[derive(Debug)]
struct AgentToolOpts {
    session: Option<String>,
    agent: Option<PathBuf>,
    command: PathBuf,
    dry_run: bool,
    allow_unverified_hooks: bool,
    tool_args: Vec<String>,
}

impl AgentToolOpts {
    fn parse(tool: AgentTool, args: &[String]) -> Result<Self, String> {
        let mut session = None;
        let mut agent = None;
        let mut command = std::env::var_os(tool.env_var())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(tool.default_command()));
        let mut dry_run = false;
        let mut allow_unverified_hooks = false;
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
                "--agent" => {
                    agent = Some(PathBuf::from(required_value(args, &mut i, "--agent")?));
                }
                "--tool" => {
                    command = PathBuf::from(required_value(args, &mut i, "--tool")?);
                }
                flag if flag == tool.path_flag() => {
                    command = PathBuf::from(required_value(args, &mut i, flag)?);
                }
                "--dry-run" => {
                    dry_run = true;
                    i += 1;
                }
                "--allow-unverified-hooks" => {
                    allow_unverified_hooks = true;
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
            agent: agent.or_else(|| std::env::var_os("PENTECT_AGENT").map(PathBuf::from)),
            command,
            dry_run,
            allow_unverified_hooks,
            tool_args,
        })
    }
}

fn run_codex(opts: &AgentToolOpts, agent: &Path) -> std::process::ExitStatus {
    let configs = codex_hook_config_args(agent, opts.session.as_deref());
    if opts.dry_run {
        if codex_uses_unverified_headless_hook_path(&opts.tool_args) {
            eprintln!(
                "[pentect] note: Codex headless hook execution was not verified for this invocation; non-dry runs fail closed for this subcommand."
            );
        }
        print_dry_run(&opts.command, &codex_args(&configs, &opts.tool_args));
        return success_status();
    }
    if codex_uses_unverified_headless_hook_path(&opts.tool_args) && !opts.allow_unverified_hooks {
        die("refusing to start Codex headless subcommand with Pentect hooks: local probes showed `codex exec` runs shell commands without dispatching PreToolUse/PostToolUse hooks, even under a TTY. Use interactive `pentect codex`, `pentect claude`, `pentect exec`, or pass --allow-unverified-hooks only for debugging.");
    }
    let mut cmd = Command::new(&opts.command);
    for config in configs {
        cmd.arg("--config").arg(config);
    }
    cmd.args(&opts.tool_args);
    run_interactive_command(cmd, &opts.command)
}

fn run_claude(opts: &AgentToolOpts, agent: &Path) -> std::process::ExitStatus {
    let settings = claude_settings_json(agent, opts.session.as_deref());
    let args = claude_args(&settings, &opts.tool_args);
    if opts.dry_run {
        print_dry_run(&opts.command, &args);
        return success_status();
    }
    let mut cmd = Command::new(&opts.command);
    cmd.args(&args);
    run_interactive_command(cmd, &opts.command)
}

fn run_gemini(opts: &AgentToolOpts, agent: &Path) -> std::process::ExitStatus {
    let settings_path = PathBuf::from(".gemini").join("settings.json");
    if opts.dry_run {
        eprintln!(
            "[pentect] would temporarily merge Pentect hooks into {}",
            settings_path.display()
        );
        print_dry_run(&opts.command, &opts.tool_args);
        return success_status();
    }
    if !opts.allow_unverified_hooks && !gemini_cli_mentions_hooks(&opts.command) {
        die("refusing to start Gemini with Pentect hooks: this Gemini CLI does not advertise hook support, so temporary settings may be ignored and raw tool output could leak. Upgrade Gemini CLI or pass --allow-unverified-hooks only for debugging.");
    }
    let original = match install_gemini_hooks(&settings_path, agent, opts.session.as_deref()) {
        Ok(o) => o,
        Err(e) => die(&e),
    };
    let status = {
        let mut cmd = Command::new(&opts.command);
        cmd.args(&opts.tool_args);
        run_interactive_command(cmd, &opts.command)
    };
    if let Err(e) = restore_gemini_settings(&settings_path, original) {
        eprintln!("[pentect] WARNING: {e}");
    }
    status
}

fn run_command(mut cmd: Command, display: &Path) -> std::process::ExitStatus {
    cmd.status()
        .unwrap_or_else(|e| die(&format!("could not start '{}': {e}", display.display())))
}

fn run_interactive_command(cmd: Command, display: &Path) -> std::process::ExitStatus {
    terminal::restore_after_tui();
    let status = run_command(cmd, display);
    terminal::restore_after_tui();
    status
}

fn codex_args(configs: &[String], tool_args: &[String]) -> Vec<String> {
    let mut args = Vec::with_capacity(configs.len() * 2 + 2 + tool_args.len());
    for config in configs {
        args.push("--config".to_string());
        args.push(config.clone());
    }
    args.push("--config".to_string());
    args.push(format!(
        "developer_instructions={}",
        toml_string(PENTECT_AGENT_INSTRUCTIONS)
    ));
    args.extend(tool_args.iter().cloned());
    args
}

fn claude_args(settings: &str, tool_args: &[String]) -> Vec<String> {
    let mut args = vec![
        "--settings".to_string(),
        settings.to_string(),
        "--append-system-prompt".to_string(),
        PENTECT_AGENT_INSTRUCTIONS.to_string(),
    ];
    args.extend(tool_args.iter().cloned());
    args
}

fn codex_hook_config_args(agent: &Path, session: Option<&str>) -> Vec<String> {
    let unix = hook_command_unix(agent, "codex", session);
    let windows = hook_command_windows(agent, "codex", session);
    vec![
        "features.hooks=true".to_string(),
        format!(
            "hooks.PreToolUse=[{{matcher=\"*\",hooks=[{{type=\"command\",command={},commandWindows={},timeout=30}}]}}]",
            toml_string(&unix),
            toml_string(&windows)
        ),
        format!(
            "hooks.PostToolUse=[{{matcher=\"*\",hooks=[{{type=\"command\",command={},commandWindows={},timeout=30}}]}}]",
            toml_string(&unix),
            toml_string(&windows)
        ),
    ]
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

fn gemini_cli_mentions_hooks(command: &Path) -> bool {
    let Ok(output) = Command::new(command).arg("--help").output() else {
        return false;
    };
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text.to_ascii_lowercase().contains("hook")
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

fn gemini_hook_settings(agent: &Path, session: Option<&str>) -> Value {
    let command = if cfg!(windows) {
        hook_command_windows(agent, "gemini", session)
    } else {
        hook_command_unix(agent, "gemini", session)
    };
    json!({
        "hooks": {
            "BeforeTool": [{
                "matcher": "*",
                "hooks": [{
                    "name": "pentect-wrap-tool-input",
                    "type": "command",
                    "command": command,
                    "timeout": 30000
                }]
            }],
            "AfterTool": [{
                "matcher": "*",
                "hooks": [{
                    "name": "pentect-mask-tool-output",
                    "type": "command",
                    "command": command,
                    "timeout": 30000
                }]
            }]
        }
    })
}

fn install_gemini_hooks(
    settings_path: &Path,
    agent: &Path,
    session: Option<&str>,
) -> Result<Option<Vec<u8>>, String> {
    let original = if settings_path.exists() {
        Some(
            std::fs::read(settings_path)
                .map_err(|e| format!("could not read '{}': {e}", settings_path.display()))?,
        )
    } else {
        None
    };
    let mut settings = match &original {
        Some(bytes) => serde_json::from_slice(bytes).map_err(|e| {
            format!(
                "Gemini settings '{}' is not valid JSON: {e}",
                settings_path.display()
            )
        })?,
        None => json!({}),
    };
    merge_hooks(&mut settings, &gemini_hook_settings(agent, session))?;
    if let Some(parent) = settings_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create '{}': {e}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(&settings)
        .map_err(|e| format!("could not serialize Gemini settings: {e}"))?;
    std::fs::write(settings_path, bytes)
        .map_err(|e| format!("could not write '{}': {e}", settings_path.display()))?;
    Ok(original)
}

fn restore_gemini_settings(settings_path: &Path, original: Option<Vec<u8>>) -> Result<(), String> {
    match original {
        Some(bytes) => std::fs::write(settings_path, bytes)
            .map_err(|e| format!("could not restore '{}': {e}", settings_path.display())),
        None => {
            if settings_path.exists() {
                std::fs::remove_file(settings_path)
                    .map_err(|e| format!("could not remove '{}': {e}", settings_path.display()))?;
            }
            if let Some(parent) = settings_path.parent() {
                match std::fs::remove_dir(parent) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                    Err(e) => return Err(format!("could not remove '{}': {e}", parent.display())),
                }
            }
            Ok(())
        }
    }
}

fn merge_hooks(settings: &mut Value, extra: &Value) -> Result<(), String> {
    let Some(settings_object) = settings.as_object_mut() else {
        return Err("Gemini settings root must be a JSON object".to_string());
    };
    let hooks = settings_object.entry("hooks").or_insert_with(|| json!({}));
    let Some(hooks_object) = hooks.as_object_mut() else {
        return Err("Gemini settings `hooks` must be a JSON object".to_string());
    };
    let Some(extra_hooks) = extra.get("hooks").and_then(Value::as_object) else {
        return Ok(());
    };
    for (event, additions) in extra_hooks {
        let target = hooks_object
            .entry(event.clone())
            .or_insert_with(|| Value::Array(Vec::new()));
        let Some(target_array) = target.as_array_mut() else {
            return Err(format!("Gemini settings `hooks.{event}` must be an array"));
        };
        let Some(additions) = additions.as_array() else {
            return Err(format!("Pentect internal `hooks.{event}` must be an array"));
        };
        target_array.extend(additions.iter().cloned());
    }
    Ok(())
}

fn hook_command_unix(agent: &Path, provider: &str, session: Option<&str>) -> String {
    hook_words(agent, provider, session)
        .iter()
        .map(|word| shell_quote_unix(word))
        .collect::<Vec<_>>()
        .join(" ")
}

fn hook_command_windows(agent: &Path, provider: &str, session: Option<&str>) -> String {
    let mut out = String::from("& ");
    out.push_str(
        &hook_words(agent, provider, session)
            .iter()
            .map(|word| powershell_quote(word))
            .collect::<Vec<_>>()
            .join(" "),
    );
    out
}

fn hook_words(agent: &Path, provider: &str, session: Option<&str>) -> Vec<String> {
    if pentect_agent_passthrough_available() {
        let mut words = vec![
            "pentect".to_string(),
            "hook".to_string(),
            "--capability".to_string(),
            provider.to_string(),
        ];
        add_explicit_session(&mut words, session);
        return words;
    }
    let agent = agent_command_path(agent);
    let mut words = vec![
        agent.to_string_lossy().into_owned(),
        "hook".to_string(),
        "--capability".to_string(),
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

fn pentect_agent_passthrough_available() -> bool {
    let Ok(output) = Command::new("pentect").arg("agent").arg("--probe").output() else {
        return false;
    };
    output.status.success()
        && String::from_utf8_lossy(&output.stdout).trim() == "pentect-agent-passthrough"
}

fn agent_command_path(agent: &Path) -> PathBuf {
    if agent.is_absolute() {
        return agent.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(agent))
        .unwrap_or_else(|_| agent.to_path_buf())
}

fn default_agent_path() -> PathBuf {
    let exe_name = if cfg!(windows) {
        "pentect-agent.exe"
    } else {
        "pentect-agent"
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
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(0)
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(0)
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

fn powershell_quote(value: &str) -> String {
    if is_simple_shell_word(value) {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "''"))
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
        Some("text") | None => Ok(Box::new(TextInput)),
        Some(other) => Err(format!("unknown --input: {other}")),
    }
}

fn parse_read_input_format(value: &str) -> Result<ReadInputFormat, String> {
    match value {
        "text" => Ok(ReadInputFormat::Text),
        "pdf" => Ok(ReadInputFormat::Pdf),
        other => Err(format!("unknown --input: {other}")),
    }
}

fn parse_kind(value: &str) -> Result<Kind, String> {
    match value {
        "text" => Ok(Kind::Text),
        "json" => Ok(Kind::Json),
        "env" => Ok(Kind::Env),
        "har" => Ok(Kind::Har),
        other => Err(format!("unknown kind: {other}")),
    }
}

fn read_input(path: &Path, format: ReadInputFormat) -> Result<String, String> {
    let bytes = read_bytes(path)?;
    match format {
        ReadInputFormat::Text => String::from_utf8(bytes)
            .map_err(|_| format!("input '{}' is not UTF-8 text", path.display())),
        ReadInputFormat::Pdf => pdf_text(&bytes),
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

fn infer_kind(path: &Path) -> Kind {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            let lower = name.to_ascii_lowercase();
            lower == ".env" || lower.starts_with(".env.")
        })
    {
        return Kind::Env;
    }
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("json") => Kind::Json,
        Some("env") => Kind::Env,
        Some("har") => Kind::Har,
        _ => Kind::Text,
    }
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
fn build_engine(profile: Profile, aggressive: bool, packs: Vec<Pack>, args: &[String]) -> Engine {
    if aggressive {
        eprintln!("[pentect] WARNING: --aggressive disables benign-shape guards; output likely unusable for reasoning.");
    }
    Engine::with_profile_packs_detectors(profile, packs, semantic_detectors(args), aggressive)
}

fn semantic_requested(args: &[String]) -> bool {
    has_flag(args, "--semantic")
}

/// `--semantic` adds the semantic sidecar (person/location/org/address).
/// Built only with `--features semantic`; the script defaults to
/// PENTECT_SEMANTIC_SCRIPT or tools/ner_sidecar.py.
#[cfg(feature = "semantic")]
fn semantic_detectors(args: &[String]) -> Vec<Box<dyn pentect_core::Detector>> {
    if !semantic_requested(args) {
        return Vec::new();
    }
    let script =
        std::env::var("PENTECT_SEMANTIC_SCRIPT").unwrap_or_else(|_| "tools/ner_sidecar.py".into());
    match pentect_core::SemanticDetector::spawn(&script) {
        Ok(d) => vec![Box::new(d)],
        Err(e) => {
            eprintln!(
                "[pentect] --semantic: could not start semantic sidecar ({e}); continuing without semantic detection."
            );
            Vec::new()
        }
    }
}

#[cfg(not(feature = "semantic"))]
fn semantic_detectors(args: &[String]) -> Vec<Box<dyn pentect_core::Detector>> {
    if semantic_requested(args) {
        eprintln!("[pentect] --semantic requires a build with `--features semantic`; ignoring.");
    }
    Vec::new()
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
    // --disable / --enable are a pack with no rules, only toggles.
    let disable = arg_values(args, "--disable");
    let enable = arg_values(args, "--enable");
    if !disable.is_empty() || !enable.is_empty() {
        packs.push(Pack {
            rules: RuleDetector::from_specs(Vec::new())?,
            disable,
            enable,
        });
    }
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
    fn semantic_flag_requests_semantic_sidecar() {
        let args = vec!["pentect".into(), "mask".into(), "--semantic".into()];
        assert!(semantic_requested(&args));
        assert!(validate_mask_args(&args).is_ok());
    }

    #[test]
    fn semantic_provider_argument_is_rejected() {
        let args = vec![
            "pentect".into(),
            "mask".into(),
            "--semantic".into(),
            "gliner".into(),
        ];
        assert!(validate_mask_args(&args)
            .unwrap_err()
            .contains("no provider"));
    }

    #[test]
    fn mask_rejects_unknown_kind_and_missing_values() {
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
            "--semantic".into(),
        ];
        assert!(validate_mask_args(&args)
            .unwrap_err()
            .contains("requires a value"));
    }

    #[test]
    fn semantic_equals_provider_is_rejected() {
        let args = vec![
            "pentect".into(),
            "mask".into(),
            "--semantic=presidio".into(),
        ];
        assert!(validate_mask_args(&args).unwrap_err().contains("no longer"));
    }

    #[test]
    fn removed_semantic_provider_flags_are_rejected() {
        let args = vec![
            "pentect".into(),
            "mask".into(),
            "--semantic-provider".into(),
            "gliner".into(),
            "--semantic-script".into(),
            "tools/custom_sidecar.py".into(),
        ];
        assert!(validate_mask_args(&args).unwrap_err().contains("removed"));
    }

    #[test]
    fn legacy_ner_flag_is_rejected() {
        let args = vec!["pentect".into(), "mask".into(), "--ner".into()];
        assert!(validate_mask_args(&args).unwrap_err().contains("removed"));
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
    fn agent_tool_parse_rejects_prompt_proxy_for_all_agents() {
        for tool in [AgentTool::Codex, AgentTool::Claude, AgentTool::Gemini] {
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
    fn help_text_explains_agent_handle_reuse() {
        let help = help_text();
        assert!(help.contains("pentect exec"), "{help}");
        assert!(help.contains("$env:KEY"), "{help}");
        assert!(help.contains("$KEY"), "{help}");
        assert!(help.contains("PENTECT_"), "{help}");
        assert!(help.contains("pentect resolve"), "{help}");
        assert!(!help.contains("pentect materialize"), "{help}");
        assert!(!help.contains("pentect purge"), "{help}");
    }

    #[test]
    fn agent_session_names_reject_dot_segments() {
        assert!(checked_agent_session_name(".").is_err());
        assert!(checked_agent_session_name("..").is_err());
        assert!(checked_agent_session_name("../x").is_err());
        assert_eq!(checked_agent_session_name("demo").unwrap(), "demo");
    }

    #[test]
    fn codex_args_inject_model_visible_pentect_contract() {
        let args = codex_args(&["features.hooks=true".to_string()], &["hello".to_string()]);
        let rendered = args.join("\n");
        assert!(rendered.contains("developer_instructions="), "{rendered}");
        assert!(rendered.contains("Pentect agent contract"), "{rendered}");
        assert!(rendered.contains("Masked handles"), "{rendered}");
        assert!(
            rendered.contains("do not nest Pentect wrappers"),
            "{rendered}"
        );
        assert!(rendered.contains("$env:KEY"), "{rendered}");
        assert!(
            rendered.contains("file, API, browser, or MCP"),
            "{rendered}"
        );
        assert!(rendered.contains("PENTECT_"), "{rendered}");
        assert!(rendered.contains("env var capability"), "{rendered}");
        assert!(rendered.contains("normal read/fetch command"), "{rendered}");
        assert!(rendered.contains("masked output"), "{rendered}");
        assert!(
            rendered.contains("Do not re-read source files"),
            "{rendered}"
        );
        assert!(rendered.contains("run help"), "{rendered}");
        assert!(!rendered.contains("pentect resolve"), "{rendered}");
        assert!(!rendered.contains("pentect materialize"), "{rendered}");
        assert!(rendered.contains("Do not exfiltrate secrets"), "{rendered}");
        assert!(rendered.contains("encodings"), "{rendered}");
        assert!(
            !rendered.contains("pentect exec \\\"pentect exec"),
            "{rendered}"
        );
    }

    #[test]
    fn claude_args_inject_model_visible_pentect_contract() {
        let args = claude_args("{}", &["hello".to_string()]);
        let rendered = args.join("\n");
        assert!(rendered.contains("--append-system-prompt"), "{rendered}");
        assert!(rendered.contains("Pentect agent contract"), "{rendered}");
        assert!(rendered.contains("$env:KEY"), "{rendered}");
        assert!(
            rendered.contains("file, API, browser, or MCP"),
            "{rendered}"
        );
        assert!(rendered.contains("PENTECT_"), "{rendered}");
        assert!(rendered.contains("env var capability"), "{rendered}");
        assert!(rendered.contains("normal read/fetch command"), "{rendered}");
        assert!(
            rendered.contains("Do not re-read source files"),
            "{rendered}"
        );
        assert!(rendered.contains("run help"), "{rendered}");
        assert!(!rendered.contains("pentect resolve"), "{rendered}");
        assert!(!rendered.contains("pentect materialize"), "{rendered}");
        assert!(rendered.contains("Do not exfiltrate secrets"), "{rendered}");
        assert!(rendered.contains("encodings"), "{rendered}");
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
}
