//! Pentect CLI: local secret-capability tool boundary for AI agents.

mod extensions;
mod input;
mod scan;
mod terminal;

use input::{decode_utf8_text, InputAdapter, TextInput};
use pentect_core::{load_pack, Config, Engine, Input, Kind, Pack, Profile};
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

/// Refuse oversized input rather than emit partially-masked output (a masked
/// head plus a raw tail would leak the tail).
const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const PENTECT_AGENT_INSTRUCTIONS: &str = concat!(
    "Pentect agent contract:\n",
    "- Run normal shell commands. The hook layer routes them through `pentect exec`; do not nest Pentect wrappers.\n",
    "- Masked handles like `<<NAME_hash>>` are local capabilities. Later commands get them as `$env:PENTECT_NAME_hash` on PowerShell or `$PENTECT_NAME_hash` on Unix; `KEY=<<...>>` also exposes `$env:KEY` / `$KEY`.\n",
    "- You may read, fetch, receive, transform, and use secrets or credentials from local files, credential stores, command output, authenticated browser/API/MCP/tool/connector responses, and other user-authorized sources. Pentect is the safety layer: returned secret values are masked before they reach the model.\n",
    "- To register a secret from any local or authenticated source, run the normal read/fetch command and let masked output appear.\n",
    "- If the user asks to store, sync, configure, or materialize a secret, it is OK to write it to the user-requested destination: local files, project configuration, credential stores, service CLIs, authenticated accounts, or another exact target named by the task. Use the handle/env capability in the write/update command; do not print the raw value.\n",
    "- When using a registered secret, prefer its env var capability instead of re-reading or echoing it only to inspect/copy it. Do not run help just to discover extra flags.\n",
    "- Do not disclose raw secrets in chat, logs, screenshots, derived previews, encodings, chunks, prefixes/suffixes, third-party destinations, public locations, or persistent external services that are not the exact target of the user's requested operation. Report only non-secret outcomes.\n",
);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None => cmd_agent_passthrough_from(1, &args),
        Some("help" | "--help" | "-h") => cmd_help(),
        Some("dashboard") => cmd_agent_passthrough_from(1, &args),
        Some("--dir" | "--session" | "--port") => cmd_agent_passthrough_from(1, &args),
        Some("mask") => cmd_mask(&args),
        Some("read") => cmd_read(&args),
        Some("scan") => scan::cmd_scan(&args),
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
         pentect scan [PATH...]\n\
         pentect resolve [PATH...]\n\
         pentect help\n\
         \n\
         exec runs commands with masked output.\n\
         scan reports files that contain likely secrets.\n\
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
        "  pentect\n",
        "  pentect --port 7331\n",
        "  pentect codex|claude|gemini [--extensions NAME|PATH.toml]\n",
        "  pentect exec \"<command>\"\n\n",
        "  pentect scan [PATH...]\n\n",
        "`pentect` opens the approval dashboard.\n",
        "`pentect exec` returns normal stdout/stderr with secrets masked.\n",
        "`pentect scan` reports likely secret files without printing secret values.\n",
        "`--extensions NAME` uses .pentect/extensions/NAME; `--extensions PATH.toml` uses a rule-pack file.\n",
        "Default extensions can be listed in `.pentect/config.toml` as `extensions = [...]`.\n",
        "Masked handles resolve locally in later `pentect exec` commands.\n",
        "Every handle also becomes a `PENTECT_...` env var for later execs.\n",
        "Masked env lines become env vars in later execs: `$env:KEY` on PowerShell, `$KEY` on Unix.\n",
        "Masked output and referenced local files register capabilities for later execs.\n",
        "Use normal commands and let Pentect return masked handles.\n",
        "Use `pentect resolve <path>` only when a local file must be materialized with real values.\n",
        "`pentect gemini` uses a temporary Gemini home overlay when hook support is available; otherwise it fails closed.\n",
    )
}

fn die(msg: impl std::fmt::Display) -> ! {
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
    let (forward_args, explicit_extensions) = match extensions::strip_from_args(&args[start..]) {
        Ok(parsed) => parsed,
        Err(e) => die(&e),
    };
    let active_extensions = match extensions::active_from_specs(explicit_extensions, true) {
        Ok(active) => active,
        Err(e) => die(&e),
    };
    let mut cmd = Command::new(&agent);
    if let Some(value) = match active_extensions.env_value() {
        Ok(value) => value,
        Err(e) => die(&e),
    } {
        cmd.env(extensions::PACKS_ENV, value);
    }
    cmd.args(&forward_args);
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
        die(format!(
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
            Err(e) => die(&e),
        },
        None => Profile::Strict,
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
    let engine = build_engine(profile, aggressive, packs);
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
            "--length" | "--aggressive" => {
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
    let packs = match extensions::load_packs_from_specs(opts.extensions.clone(), true) {
        Ok(packs) => packs,
        Err(e) => die(&e),
    };
    let engine = Engine::with_profile_and_packs(opts.profile, packs, false);
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
    extensions: Vec<String>,
    path: PathBuf,
}

impl ReadOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut input_format = ReadInputFormat::Text;
        let mut kind = None;
        let mut profile = Profile::Strict;
        let mut disclose_length = false;
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
                "--length" => {
                    disclose_length = true;
                    i += 1;
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
            disclose_length,
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
    extensions: Vec<String>,
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
        let mut extensions = Vec::new();
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
            extensions,
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
    let active_extensions = match extensions::active_from_specs(opts.extensions.clone(), true) {
        Ok(active) => active,
        Err(e) => die(&e),
    };
    let mut cmd = Command::new(&opts.command);
    apply_extension_env(&mut cmd, &active_extensions);
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
    let active_extensions = match extensions::active_from_specs(opts.extensions.clone(), true) {
        Ok(active) => active,
        Err(e) => die(&e),
    };
    let mut cmd = Command::new(&opts.command);
    apply_extension_env(&mut cmd, &active_extensions);
    cmd.args(&args);
    run_interactive_command(cmd, &opts.command)
}

fn run_gemini(opts: &AgentToolOpts, agent: &Path) -> std::process::ExitStatus {
    if opts.dry_run {
        eprintln!(
            "[pentect] note: Gemini will run with a temporary home overlay containing Pentect hooks and context."
        );
        print_dry_run(&opts.command, &opts.tool_args);
        return success_status();
    }
    if !opts.allow_unverified_hooks {
        if let Err(reason) = gemini_hook_support(&opts.command) {
            die(format!(
                "refusing to start Gemini with Pentect hooks: {reason}. Pentect will not launch Gemini without verified BeforeTool/AfterTool support because raw tool output could reach the model. Upgrade Gemini CLI to a hook-capable release, use `pentect codex`, `pentect claude`, or pass --allow-unverified-hooks only for manual adapter debugging."
            ));
        }
    }
    let active_extensions = match extensions::active_from_specs(opts.extensions.clone(), true) {
        Ok(active) => active,
        Err(e) => die(&e),
    };
    let overlay = match GeminiHookOverlay::install(agent, opts.session.as_deref()) {
        Ok(overlay) => overlay,
        Err(e) => die(e),
    };
    let mut cmd = Command::new(&opts.command);
    apply_extension_env(&mut cmd, &active_extensions);
    overlay.apply_env(&mut cmd);
    cmd.args(&opts.tool_args);
    let status = run_interactive_command(cmd, &opts.command);
    drop(overlay);
    status
}

struct GeminiHookOverlay {
    root: PathBuf,
}

impl GeminiHookOverlay {
    fn install(agent: &Path, session: Option<&str>) -> Result<Self, String> {
        let root = unique_temp_root("pentect-gemini")?;
        Self::install_at(root, agent, session)
    }

    fn install_at(root: PathBuf, agent: &Path, session: Option<&str>) -> Result<Self, String> {
        let gemini_dir = root.join(".gemini");
        fs::create_dir_all(&gemini_dir)
            .map_err(|e| format!("could not create Gemini hook overlay: {e}"))?;
        fs::write(gemini_dir.join("GEMINI.md"), PENTECT_AGENT_INSTRUCTIONS)
            .map_err(|e| format!("could not write Gemini Pentect context: {e}"))?;
        let session_start_path = root.join("pentect-session-start.json");
        fs::write(
            &session_start_path,
            serde_json::to_string(&json!({
                "suppressOutput": true,
                "hookSpecificOutput": {
                    "additionalContext": PENTECT_AGENT_INSTRUCTIONS
                }
            }))
            .map_err(|e| format!("could not render Gemini session context hook: {e}"))?,
        )
        .map_err(|e| format!("could not write Gemini session context hook: {e}"))?;
        let settings = gemini_hook_settings(agent, session, &session_start_path);
        fs::write(
            gemini_dir.join("settings.json"),
            serde_json::to_string_pretty(&settings)
                .map_err(|e| format!("could not render Gemini hook settings: {e}"))?,
        )
        .map_err(|e| format!("could not write Gemini hook settings: {e}"))?;
        Ok(Self { root })
    }

    fn apply_env(&self, cmd: &mut Command) {
        cmd.env("HOME", &self.root);
        cmd.env("USERPROFILE", &self.root);
    }
}

impl Drop for GeminiHookOverlay {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn gemini_hook_settings(
    agent: &Path,
    session: Option<&str>,
    session_start_path: &Path,
) -> serde_json::Value {
    let hook_command = gemini_hook_command(agent, session);
    let context_command = if cfg!(windows) {
        format!(
            "cmd /c type {}",
            shell_quote_windows(&session_start_path.to_string_lossy())
        )
    } else {
        format!(
            "cat {}",
            shell_quote_unix(&session_start_path.to_string_lossy())
        )
    };
    json!({
        "hooks": {
            "SessionStart": [{
                "hooks": [{
                    "type": "command",
                    "name": "pentect-context",
                    "description": "Inject the Pentect agent contract without mutating workspace files.",
                    "command": context_command,
                    "timeout": 30000
                }]
            }],
            "BeforeTool": [{
                "matcher": ".*",
                "hooks": [{
                    "type": "command",
                    "name": "pentect-before-tool",
                    "description": "Route shell commands through Pentect before execution.",
                    "command": hook_command,
                    "timeout": 30000
                }]
            }],
            "AfterTool": [{
                "matcher": ".*",
                "hooks": [{
                    "type": "command",
                    "name": "pentect-after-tool",
                    "description": "Mask tool output before it is returned to the model.",
                    "command": hook_command,
                    "timeout": 30000
                }]
            }]
        }
    })
}

fn gemini_hook_command(agent: &Path, session: Option<&str>) -> String {
    if cfg!(windows) {
        format!(
            "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command {}",
            shell_quote_windows(&hook_command_windows(agent, "gemini", session))
        )
    } else {
        hook_command_unix(agent, "gemini", session)
    }
}

fn unique_temp_root(prefix: &str) -> Result<PathBuf, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock is before UNIX_EPOCH: {e}"))?
        .as_millis();
    for attempt in 0..100 {
        let root =
            std::env::temp_dir().join(format!("{prefix}-{}-{stamp}-{attempt}", std::process::id()));
        match fs::create_dir(&root) {
            Ok(()) => return Ok(root),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "could not create temporary Gemini hook overlay: {e}"
                ))
            }
        }
    }
    Err("could not allocate a unique temporary Gemini hook overlay".to_string())
}

fn gemini_hook_support(command: &Path) -> Result<(), String> {
    if let Some(path) = resolve_command_path(command) {
        if let Some(package_root) = gemini_package_root_from_command(&path) {
            if gemini_package_tree_has_hooks(&package_root) {
                return Ok(());
            }
            let version = gemini_package_version(&package_root)
                .map(|v| format!(" @google/gemini-cli {v}"))
                .unwrap_or_default();
            return Err(format!(
                "'{}' resolves to{} at '{}', but its installed source has no Gemini hook runtime symbols (BeforeTool/AfterTool)",
                command.display(),
                version,
                package_root.display()
            ));
        }
    }
    let Some(help) = command_output_text_with_timeout(command, &["--help"], Duration::from_secs(3))
    else {
        return Err(format!(
            "could not verify hook support for '{}' from installed source or `--help`",
            command.display()
        ));
    };
    if help.contains("BeforeTool") || help.contains("AfterTool") || help.contains("hook_event_name")
    {
        Ok(())
    } else {
        Err(format!(
            "'{} --help' does not advertise Gemini hook events",
            command.display()
        ))
    }
}

fn resolve_command_path(command: &Path) -> Option<PathBuf> {
    if command.is_absolute() || command.components().count() > 1 {
        return command.exists().then(|| command.to_path_buf());
    }
    let name = command.to_string_lossy();
    for dir in std::env::split_paths(&std::env::var_os("PATH")?) {
        let candidate = dir.join(name.as_ref());
        if candidate.exists() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            if Path::new(name.as_ref()).extension().is_none() {
                let pathext = std::env::var_os("PATHEXT")
                    .and_then(|v| v.into_string().ok())
                    .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());
                for ext in pathext.split(';').filter(|ext| !ext.is_empty()) {
                    let candidate = dir.join(format!("{name}{ext}"));
                    if candidate.exists() {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    None
}

fn gemini_package_root_from_command(command_path: &Path) -> Option<PathBuf> {
    let command_dir = command_path.parent()?;
    let package_root = command_dir
        .join("node_modules")
        .join("@google")
        .join("gemini-cli");
    if package_root.exists() {
        return Some(package_root);
    }
    let wrapper = fs::read_to_string(command_path).ok()?;
    if wrapper.contains("node_modules\\@google\\gemini-cli\\dist\\index.js")
        || wrapper.contains("node_modules/@google/gemini-cli/dist/index.js")
    {
        return Some(package_root);
    }
    None
}

fn gemini_package_tree_has_hooks(package_root: &Path) -> bool {
    let dist = package_root.join("dist");
    if !dist.exists() {
        return false;
    }
    let settings_have_hooks = [
        package_root.join("dist/src/config/settings.d.ts"),
        package_root.join("dist/src/config/settings.js"),
    ]
    .iter()
    .any(|path| file_contains(path, "hooks"));
    settings_have_hooks
        && tree_contains_all(
            &dist,
            &["BeforeTool", "AfterTool", "hookSpecificOutput"],
            4096,
        )
}

fn gemini_package_version(package_root: &Path) -> Option<String> {
    let package = fs::read_to_string(package_root.join("package.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&package).ok()?;
    value.get("version")?.as_str().map(str::to_string)
}

fn file_contains(path: &Path, needle: &str) -> bool {
    fs::read_to_string(path).is_ok_and(|text| text.contains(needle))
}

fn tree_contains_all(root: &Path, needles: &[&str], max_files: usize) -> bool {
    let mut found = vec![false; needles.len()];
    let mut stack = vec![root.to_path_buf()];
    let mut seen_files = 0usize;
    while let Some(path) = stack.pop() {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            let Ok(entries) = fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.flatten() {
                stack.push(entry.path());
            }
            continue;
        }
        if seen_files >= max_files {
            break;
        }
        seen_files += 1;
        if !matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("js" | "mjs" | "cjs" | "ts" | "d.ts" | "md")
        ) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for (idx, needle) in needles.iter().enumerate() {
            if text.contains(needle) {
                found[idx] = true;
            }
        }
        if found.iter().all(|value| *value) {
            return true;
        }
    }
    false
}

fn command_output_text_with_timeout(
    command: &Path,
    args: &[&str],
    timeout: Duration,
) -> Option<String> {
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let start = Instant::now();
    loop {
        if child.try_wait().ok()?.is_some() {
            let output = child.wait_with_output().ok()?;
            let mut text = String::new();
            text.push_str(&String::from_utf8_lossy(&output.stdout));
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            return Some(text);
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn run_command(mut cmd: Command, display: &Path) -> std::process::ExitStatus {
    cmd.status()
        .unwrap_or_else(|e| die(format!("could not start '{}': {e}", display.display())))
}

fn run_interactive_command(cmd: Command, display: &Path) -> std::process::ExitStatus {
    terminal::restore_after_tui();
    let status = run_command(cmd, display);
    terminal::restore_after_tui();
    status
}

fn apply_extension_env(cmd: &mut Command, active: &extensions::ActiveExtensions) {
    if let Some(value) = match active.env_value() {
        Ok(value) => value,
        Err(e) => die(&e),
    } {
        cmd.env(extensions::PACKS_ENV, value);
    }
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
        ReadInputFormat::Text => decode_utf8_text(
            bytes,
            format!("input '{}' is not UTF-8 text", path.display()),
        ),
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
fn build_engine(profile: Profile, aggressive: bool, packs: Vec<Pack>) -> Engine {
    if aggressive {
        eprintln!("[pentect] WARNING: --aggressive disables benign-shape guards; output likely unusable for reasoning.");
    }
    Engine::with_profile_and_packs(profile, packs, aggressive)
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
    packs.extend(extensions::load_packs_from_args(args, true).map_err(|e| e.to_string())?);
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
    fn gemini_hook_overlay_writes_temp_hooks_and_context() {
        let root = cli_test_temp("gemini-overlay");
        let _ = std::fs::remove_dir_all(&root);
        let overlay =
            GeminiHookOverlay::install_at(root.clone(), Path::new("pentect-agent"), Some("demo"))
                .unwrap();
        let settings = std::fs::read_to_string(root.join(".gemini/settings.json")).unwrap();
        assert!(settings.contains("SessionStart"), "{settings}");
        assert!(settings.contains("BeforeTool"), "{settings}");
        assert!(settings.contains("AfterTool"), "{settings}");
        assert!(settings.contains("\"matcher\": \".*\""), "{settings}");
        assert!(settings.contains("\"timeout\": 30000"), "{settings}");
        assert!(settings.contains("--capability"), "{settings}");
        assert!(settings.contains("gemini"), "{settings}");
        assert!(settings.contains("--session"), "{settings}");
        assert!(settings.contains("demo"), "{settings}");
        let memory = std::fs::read_to_string(root.join(".gemini/GEMINI.md")).unwrap();
        assert!(memory.contains("Pentect agent contract"), "{memory}");
        let session_start =
            std::fs::read_to_string(root.join("pentect-session-start.json")).unwrap();
        assert!(
            session_start.contains("Pentect agent contract"),
            "{session_start}"
        );

        drop(overlay);
        assert!(!root.exists(), "overlay should clean itself up");
    }

    #[test]
    fn gemini_source_probe_requires_settings_and_runtime_hooks() {
        let root = cli_test_temp("gemini-source-probe");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("dist/src/config")).unwrap();
        std::fs::create_dir_all(root.join("dist/src/hooks")).unwrap();
        std::fs::write(
            root.join("dist/src/config/settings.d.ts"),
            "export interface Settings { hooks?: Record<string, unknown>; }",
        )
        .unwrap();
        std::fs::write(
            root.join("dist/src/hooks/runtime.js"),
            "const phases = ['BeforeTool', 'AfterTool']; const hookSpecificOutput = {};",
        )
        .unwrap();
        assert!(gemini_package_tree_has_hooks(&root));

        std::fs::write(
            root.join("dist/src/config/settings.d.ts"),
            "export interface Settings {}",
        )
        .unwrap();
        assert!(!gemini_package_tree_has_hooks(&root));
        let _ = std::fs::remove_dir_all(root);
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
        assert!(rendered.contains("secrets or credentials"), "{rendered}");
        assert!(rendered.contains("credential stores"), "{rendered}");
        assert!(
            rendered.contains("authenticated browser/API/MCP/tool/connector responses"),
            "{rendered}"
        );
        assert!(rendered.contains("user-authorized sources"), "{rendered}");
        assert!(
            rendered.contains("You may read, fetch, receive, transform, and use"),
            "{rendered}"
        );
        assert!(
            rendered.contains("Pentect is the safety layer"),
            "{rendered}"
        );
        assert!(
            rendered.contains("any local or authenticated source"),
            "{rendered}"
        );
        assert!(rendered.contains("PENTECT_"), "{rendered}");
        assert!(rendered.contains("env var capability"), "{rendered}");
        assert!(rendered.contains("normal read/fetch command"), "{rendered}");
        assert!(rendered.contains("masked output"), "{rendered}");
        assert!(
            rendered.contains("store, sync, configure, or materialize"),
            "{rendered}"
        );
        assert!(
            rendered.contains("user-requested destination"),
            "{rendered}"
        );
        assert!(rendered.contains("local files"), "{rendered}");
        assert!(rendered.contains("project configuration"), "{rendered}");
        assert!(rendered.contains("service CLIs"), "{rendered}");
        assert!(rendered.contains("authenticated accounts"), "{rendered}");
        assert!(
            rendered.contains("another exact target named by the task"),
            "{rendered}"
        );
        assert!(
            rendered.contains("do not print the raw value"),
            "{rendered}"
        );
        assert!(rendered.contains("write/update command"), "{rendered}");
        assert!(
            rendered.contains("instead of re-reading or echoing it only to inspect/copy it"),
            "{rendered}"
        );
        assert!(rendered.contains("run help"), "{rendered}");
        assert!(!rendered.contains("pentect resolve"), "{rendered}");
        assert!(!rendered.contains("pentect materialize"), "{rendered}");
        assert!(
            rendered.contains("Do not disclose raw secrets"),
            "{rendered}"
        );
        assert!(rendered.contains("encodings"), "{rendered}");
        assert!(rendered.contains("third-party destinations"), "{rendered}");
        assert!(rendered.contains("public locations"), "{rendered}");
        assert!(
            rendered.contains("persistent external services that are not the exact target"),
            "{rendered}"
        );
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
        assert!(rendered.contains("secrets or credentials"), "{rendered}");
        assert!(rendered.contains("credential stores"), "{rendered}");
        assert!(
            rendered.contains("authenticated browser/API/MCP/tool/connector responses"),
            "{rendered}"
        );
        assert!(rendered.contains("user-authorized sources"), "{rendered}");
        assert!(
            rendered.contains("You may read, fetch, receive, transform, and use"),
            "{rendered}"
        );
        assert!(
            rendered.contains("Pentect is the safety layer"),
            "{rendered}"
        );
        assert!(
            rendered.contains("any local or authenticated source"),
            "{rendered}"
        );
        assert!(rendered.contains("PENTECT_"), "{rendered}");
        assert!(rendered.contains("env var capability"), "{rendered}");
        assert!(rendered.contains("normal read/fetch command"), "{rendered}");
        assert!(
            rendered.contains("store, sync, configure, or materialize"),
            "{rendered}"
        );
        assert!(
            rendered.contains("user-requested destination"),
            "{rendered}"
        );
        assert!(rendered.contains("local files"), "{rendered}");
        assert!(rendered.contains("project configuration"), "{rendered}");
        assert!(rendered.contains("service CLIs"), "{rendered}");
        assert!(rendered.contains("authenticated accounts"), "{rendered}");
        assert!(
            rendered.contains("another exact target named by the task"),
            "{rendered}"
        );
        assert!(
            rendered.contains("do not print the raw value"),
            "{rendered}"
        );
        assert!(rendered.contains("write/update command"), "{rendered}");
        assert!(
            rendered.contains("instead of re-reading or echoing it only to inspect/copy it"),
            "{rendered}"
        );
        assert!(rendered.contains("run help"), "{rendered}");
        assert!(!rendered.contains("pentect resolve"), "{rendered}");
        assert!(!rendered.contains("pentect materialize"), "{rendered}");
        assert!(
            rendered.contains("Do not disclose raw secrets"),
            "{rendered}"
        );
        assert!(rendered.contains("encodings"), "{rendered}");
        assert!(rendered.contains("third-party destinations"), "{rendered}");
        assert!(rendered.contains("public locations"), "{rendered}");
        assert!(
            rendered.contains("persistent external services that are not the exact target"),
            "{rendered}"
        );
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

    fn cli_test_temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("pentect-cli-{name}-{}", std::process::id()))
    }
}
