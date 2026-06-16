//! pentect-agent: a minimal tool-boundary adapter.
//!
//! It demonstrates the product loop:
//! read tool output -> mask before the AI sees it;
//! write/exec tool input -> resolve placeholders locally;
//! command output -> remask before it returns to the AI.

use data_encoding::BASE64URL_NOPAD;
use pentect_core::{Config, Engine, Input, Kind, Profile, Recovery};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_SESSION: &str = "default";
const KEY_FILE: &str = "key.bin";
const RECOVERY_DIR: &str = "recoveries";

static RECOVERY_COUNTER: AtomicU64 = AtomicU64::new(0);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        Some("read") => cmd_read(&args),
        Some("write") => cmd_write(&args),
        Some("exec") => cmd_exec(&args),
        Some("hook") => cmd_hook(&args),
        Some("resolve") => cmd_filter(&args, FilterMode::Resolve),
        Some("remask") => cmd_filter(&args, FilterMode::Remask),
        _ => {
            usage();
            2
        }
    };
    std::process::exit(code);
}

fn usage() {
    eprintln!(
        "pentect-agent read [--session NAME] [--input text|pdf] [--kind text|json|env|har] [--profile strict|balanced|dev|paranoid] [--length] PATH\n\
         pentect-agent write [--session NAME] PATH < masked-text\n\
         pentect-agent exec [--session NAME] -- PROGRAM [ARG...]\n\
         pentect-agent exec [--session NAME] --shell COMMAND\n\
         pentect-agent exec [--session NAME] --shell-b64 BASE64URL_COMMAND\n\
         pentect-agent hook codex|claude|gemini [--session NAME] < hook-json\n\
         pentect-agent resolve [--session NAME] < masked-text\n\
         pentect-agent remask [--session NAME] < command-output\n\
         \n\
         read stores local recovery state; write/exec resolve placeholders using that state;\n\
         exec remasks stdout/stderr before printing them back."
    );
}

fn cmd_read(args: &[String]) -> i32 {
    let opts = match ReadOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let session = match Session::open(&opts.session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let data = match read_input(&opts.path, opts.input_format) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let kind = opts.kind.unwrap_or_else(|| infer_kind(&opts.path));
    let engine = Engine::with_profile(opts.profile);
    let cfg = Config {
        disclose_length: opts.disclose_length,
        ..Config::new(session.key)
    };
    let result = engine.mask(Input { kind, data }, &cfg);
    if !result.recovery.is_empty() {
        if let Err(e) = session.save_recovery(&result.recovery) {
            return die(&e);
        }
    }
    print!("{}", result.masked);
    let _ = std::io::stdout().flush();
    eprintln!(
        "[pentect-agent] session={} masked {} value(s), {} warned.",
        opts.session,
        result.summary.masked_count,
        result.summary.residual.len()
    );
    0
}

fn cmd_write(args: &[String]) -> i32 {
    let opts = match WriteOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let session = match Session::open_existing(&opts.session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let masked = match read_stdin_text() {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let resolved = match session.resolve_all(&masked) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    if let Err(e) = std::fs::write(&opts.path, resolved) {
        return die(&format!("could not write '{}': {e}", opts.path.display()));
    }
    eprintln!(
        "[pentect-agent] session={} wrote resolved content to {}",
        opts.session,
        opts.path.display()
    );
    0
}

fn cmd_exec(args: &[String]) -> i32 {
    let opts = match ExecOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let session = match Session::open_existing(&opts.session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let output = match run_resolved_command(&session, &opts.mode) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let safe_stdout = match session.remask_all(&stdout) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let safe_stderr = match session.remask_all(&stderr) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    print!("{safe_stdout}");
    let _ = std::io::stdout().flush();
    eprint!("{safe_stderr}");
    let _ = std::io::stderr().flush();
    exit_code(output.status)
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
    let input: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return die(&format!("hook input must be JSON: {e}")),
    };
    let session_name = match opts.session_name(&input) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let session = match Session::open(&session_name) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let output = match handle_hook(opts.provider, &session_name, &session, input) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    match serde_json::to_string(&output) {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => die(&format!("could not serialize hook output: {e}")),
    }
}

fn cmd_filter(args: &[String], mode: FilterMode) -> i32 {
    let opts = match FilterOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let session = match Session::open_existing(&opts.session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let input = match read_stdin_text() {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let out = match mode {
        FilterMode::Resolve => session.resolve_all(&input),
        FilterMode::Remask => session.remask_all(&input),
    };
    match out {
        Ok(s) => {
            print!("{s}");
            let _ = std::io::stdout().flush();
            0
        }
        Err(e) => die(&e),
    }
}

fn run_resolved_command(
    session: &Session,
    mode: &ExecMode,
) -> Result<std::process::Output, String> {
    match mode {
        ExecMode::Program(args) => {
            if args.is_empty() {
                return Err("exec requires a program after `--`".to_string());
            }
            let program = session.resolve_all(&args[0])?;
            let resolved_args: Result<Vec<String>, String> = args[1..]
                .iter()
                .map(|arg| session.resolve_all(arg))
                .collect();
            Command::new(program)
                .args(resolved_args?)
                .output()
                .map_err(|e| format!("could not execute command: {e}"))
        }
        ExecMode::Shell(command) => {
            let resolved = session.resolve_all(command)?;
            run_shell_script(&resolved)
        }
    }
}

fn run_shell_script(script: &str) -> Result<std::process::Output, String> {
    let mut child = shell_script_command()
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

#[cfg(windows)]
fn shell_script_command() -> Command {
    let mut cmd = Command::new("powershell");
    cmd.arg("-NoProfile").arg("-Command").arg("-");
    cmd
}

#[cfg(not(windows))]
fn shell_script_command() -> Command {
    let mut cmd = Command::new("sh");
    cmd.arg("-s");
    cmd
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

#[derive(Clone, Copy)]
enum FilterMode {
    Resolve,
    Remask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookProvider {
    Codex,
    Claude,
    Gemini,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookPhase {
    BeforeTool,
    AfterTool,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InputFormat {
    Text,
    Pdf,
}

struct ReadOpts {
    session: String,
    input_format: InputFormat,
    kind: Option<Kind>,
    profile: Profile,
    disclose_length: bool,
    path: PathBuf,
}

impl ReadOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut session = DEFAULT_SESSION.to_string();
        let mut input_format = InputFormat::Text;
        let mut kind = None;
        let mut profile = Profile::Balanced;
        let mut disclose_length = false;
        let mut path = None;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--session" => {
                    session = value(args, &mut i, "--session")?;
                }
                "--input" => {
                    input_format = parse_input_format(&value(args, &mut i, "--input")?)?;
                }
                "--kind" => {
                    kind = Some(parse_kind(&value(args, &mut i, "--kind")?)?);
                }
                "--profile" => {
                    profile = value(args, &mut i, "--profile")?.parse()?;
                }
                "--length" => {
                    disclose_length = true;
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
            session: checked_session_name(&session)?,
            input_format,
            kind,
            profile,
            disclose_length,
            path: path.ok_or_else(|| "read requires PATH".to_string())?,
        })
    }
}

struct WriteOpts {
    session: String,
    path: PathBuf,
}

impl WriteOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let (session, rest) = parse_session_and_rest(args, 2)?;
        if rest.len() != 1 {
            return Err("write requires exactly one PATH".to_string());
        }
        Ok(Self {
            session,
            path: PathBuf::from(&rest[0]),
        })
    }
}

struct FilterOpts {
    session: String,
}

impl FilterOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let (session, rest) = parse_session_and_rest(args, 2)?;
        if !rest.is_empty() {
            return Err("resolve/remask read from stdin and accept no positional args".to_string());
        }
        Ok(Self { session })
    }
}

struct HookOpts {
    provider: HookProvider,
    session: Option<String>,
}

impl HookOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut provider = None;
        let mut session = None;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--session" => {
                    session = Some(checked_session_name(&value(args, &mut i, "--session")?)?);
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
            provider: provider
                .ok_or_else(|| "hook requires provider: codex, claude, or gemini".to_string())?,
            session,
        })
    }

    fn session_name(&self, input: &Value) -> Result<String, String> {
        if let Some(session) = &self.session {
            return Ok(session.clone());
        }
        if let Ok(session) = std::env::var("PENTECT_AGENT_SESSION") {
            return checked_session_name(&session);
        }
        let from_hook = input
            .get("session_id")
            .and_then(Value::as_str)
            .and_then(sanitize_session_name)
            .unwrap_or_else(|| DEFAULT_SESSION.to_string());
        checked_session_name(&from_hook)
    }
}

struct ExecOpts {
    session: String,
    mode: ExecMode,
}

enum ExecMode {
    Program(Vec<String>),
    Shell(String),
}

impl ExecOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut session = DEFAULT_SESSION.to_string();
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--session" => {
                    session = value(args, &mut i, "--session")?;
                }
                "--shell" => {
                    let command = value(args, &mut i, "--shell")?;
                    if i != args.len() {
                        return Err("--shell must be the final exec option".to_string());
                    }
                    return Ok(Self {
                        session: checked_session_name(&session)?,
                        mode: ExecMode::Shell(command),
                    });
                }
                "--shell-b64" => {
                    let encoded = value(args, &mut i, "--shell-b64")?;
                    if i != args.len() {
                        return Err("--shell-b64 must be the final exec option".to_string());
                    }
                    return Ok(Self {
                        session: checked_session_name(&session)?,
                        mode: ExecMode::Shell(decode_shell_b64(&encoded)?),
                    });
                }
                "--" => {
                    let command = args[i + 1..].to_vec();
                    if command.is_empty() {
                        return Err("exec requires a command after `--`".to_string());
                    }
                    return Ok(Self {
                        session: checked_session_name(&session)?,
                        mode: ExecMode::Program(command),
                    });
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                _ => {
                    return Err("exec command must follow `--` or use `--shell COMMAND`".to_string())
                }
            }
        }
        Err("exec requires `-- PROGRAM...` or `--shell COMMAND`".to_string())
    }
}

struct Session {
    root: PathBuf,
    key: [u8; 32],
}

impl Session {
    fn open(name: &str) -> Result<Self, String> {
        let root = session_root(name)?;
        std::fs::create_dir_all(root.join(RECOVERY_DIR))
            .map_err(|e| format!("could not create session '{}': {e}", root.display()))?;
        let key_path = root.join(KEY_FILE);
        let key = if key_path.exists() {
            read_key(&key_path)?
        } else {
            let key = Config::generate().key;
            write_key(&key_path, &key)?;
            key
        };
        Ok(Self { root, key })
    }

    fn open_existing(name: &str) -> Result<Self, String> {
        let root = session_root(name)?;
        let key = read_key(&root.join(KEY_FILE)).map_err(|_| {
            format!("session '{name}' does not exist; run `pentect-agent read` first")
        })?;
        Ok(Self { root, key })
    }

    #[cfg(test)]
    fn open_at(base: &Path, name: &str) -> Result<Self, String> {
        let name = checked_session_name(name)?;
        let root = base.join(name);
        std::fs::create_dir_all(root.join(RECOVERY_DIR))
            .map_err(|e| format!("could not create session '{}': {e}", root.display()))?;
        let key = Config::generate().key;
        write_key(&root.join(KEY_FILE), &key)?;
        Ok(Self { root, key })
    }

    fn save_recovery(&self, recovery: &Recovery) -> Result<(), String> {
        let dir = self.root.join(RECOVERY_DIR);
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("could not create recovery dir '{}': {e}", dir.display()))?;
        let path = dir.join(format!(
            "recovery-{}-{}-{}.pnr",
            unix_millis(),
            std::process::id(),
            RECOVERY_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, recovery.serialize(&self.key))
            .map_err(|e| format!("could not write recovery '{}': {e}", path.display()))
    }

    fn resolve_all(&self, text: &str) -> Result<String, String> {
        let mut out = text.to_string();
        for rec in self.recoveries()? {
            out = rec.resolve(&out);
        }
        Ok(out)
    }

    fn remask_all(&self, text: &str) -> Result<String, String> {
        let mut out = text.to_string();
        for rec in self.recoveries()? {
            out = rec.remask(&out);
        }
        Ok(out)
    }

    fn recoveries(&self) -> Result<Vec<Recovery>, String> {
        let dir = self.root.join(RECOVERY_DIR);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| format!("could not read recovery dir '{}': {e}", dir.display()))?
        {
            let path = entry
                .map_err(|e| format!("could not read recovery dir '{}': {e}", dir.display()))?
                .path();
            if path.extension().is_some_and(|ext| ext == "pnr") {
                paths.push(path);
            }
        }
        paths.sort();
        paths
            .into_iter()
            .map(|path| {
                let bytes = std::fs::read(&path)
                    .map_err(|e| format!("could not read recovery '{}': {e}", path.display()))?;
                Recovery::load(&bytes, &self.key)
                    .map_err(|e| format!("could not load recovery '{}': {e}", path.display()))
            })
            .collect()
    }
}

fn handle_hook(
    provider: HookProvider,
    session_name: &str,
    session: &Session,
    input: Value,
) -> Result<Value, String> {
    match hook_phase(provider, &input) {
        HookPhase::BeforeTool => {
            let Some(tool_input) = hook_field(&input, &["tool_input"]) else {
                return Ok(json!({}));
            };
            let (updated, changed) =
                before_tool_updated_input(provider, session_name, session, tool_input)?;
            if changed {
                Ok(before_tool_output(provider, updated))
            } else {
                Ok(json!({}))
            }
        }
        HookPhase::AfterTool => {
            let Some(tool_response) = hook_field(
                &input,
                &["tool_response", "tool_output", "response", "output"],
            ) else {
                return Ok(json!({}));
            };
            let (updated, changed) =
                transform_json_strings(tool_response, &mut |text| mask_hook_text(session, text))?;
            if changed {
                Ok(after_tool_output(provider, updated))
            } else {
                Ok(json!({}))
            }
        }
        HookPhase::Other => Ok(json!({})),
    }
}

fn before_tool_updated_input(
    provider: HookProvider,
    session_name: &str,
    session: &Session,
    tool_input: &Value,
) -> Result<(Value, bool), String> {
    if let Some(command) = tool_input.get("command").and_then(Value::as_str) {
        let resolved = session.resolve_all(command)?;
        if resolved == command {
            return Ok((tool_input.clone(), false));
        }
        let mut updated = tool_input.clone();
        if let Some(object) = updated.as_object_mut() {
            object.insert(
                "command".to_string(),
                Value::String(wrap_shell_command(provider, session_name, command)?),
            );
            return Ok((updated, true));
        }
    }
    transform_json_strings(tool_input, &mut |text| session.resolve_all(text))
}

fn wrap_shell_command(
    _provider: HookProvider,
    session_name: &str,
    masked_command: &str,
) -> Result<String, String> {
    let agent = std::env::current_exe()
        .map_err(|e| format!("could not resolve pentect-agent executable: {e}"))?;
    let encoded = BASE64URL_NOPAD.encode(masked_command.as_bytes());
    if cfg!(windows) {
        Ok(format!(
            "& {} exec --session {} --shell-b64 {}",
            powershell_quote(&agent.to_string_lossy()),
            powershell_quote(session_name),
            powershell_quote(&encoded)
        ))
    } else {
        Ok(format!(
            "{} exec --session {} --shell-b64 {}",
            shell_quote_unix(&agent.to_string_lossy()),
            shell_quote_unix(session_name),
            shell_quote_unix(&encoded)
        ))
    }
}

fn decode_shell_b64(encoded: &str) -> Result<String, String> {
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|e| format!("--shell-b64 is not valid base64url: {e}"))?;
    String::from_utf8(bytes).map_err(|_| "--shell-b64 command is not UTF-8".to_string())
}

fn hook_phase(provider: HookProvider, input: &Value) -> HookPhase {
    let event = hook_event_name(input).unwrap_or_default();
    match provider {
        HookProvider::Codex | HookProvider::Claude => match event {
            "PreToolUse" => HookPhase::BeforeTool,
            "PostToolUse" => HookPhase::AfterTool,
            _ => HookPhase::Other,
        },
        HookProvider::Gemini => match event {
            "BeforeTool" => HookPhase::BeforeTool,
            "AfterTool" => HookPhase::AfterTool,
            _ => HookPhase::Other,
        },
    }
}

fn hook_event_name(input: &Value) -> Option<&str> {
    hook_field(input, &["hook_event_name", "event_name", "event"]).and_then(Value::as_str)
}

fn hook_field<'a>(input: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| input.get(*name))
}

fn before_tool_output(provider: HookProvider, updated_input: Value) -> Value {
    match provider {
        HookProvider::Codex | HookProvider::Claude => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": updated_input
            }
        }),
        HookProvider::Gemini => json!({
            "decision": "allow",
            "hookSpecificOutput": {
                "tool_input": updated_input
            }
        }),
    }
}

fn after_tool_output(provider: HookProvider, updated_output: Value) -> Value {
    match provider {
        HookProvider::Claude => json!({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": updated_output
            }
        }),
        HookProvider::Codex => json!({
            "decision": "block",
            "reason": stringify_tool_output(&updated_output),
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "Pentect replaced the original tool result with a masked version."
            }
        }),
        HookProvider::Gemini => json!({
            "decision": "deny",
            "reason": stringify_tool_output(&updated_output),
            "hookSpecificOutput": {
                "additionalContext": "Pentect replaced the original tool result with a masked version."
            }
        }),
    }
}

fn transform_json_strings<F>(value: &Value, f: &mut F) -> Result<(Value, bool), String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    match value {
        Value::String(text) => {
            let out = f(text)?;
            let changed = out != *text;
            Ok((Value::String(out), changed))
        }
        Value::Array(items) => {
            let mut changed = false;
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let (item, item_changed) = transform_json_strings(item, f)?;
                changed |= item_changed;
                out.push(item);
            }
            Ok((Value::Array(out), changed))
        }
        Value::Object(map) => {
            let mut changed = false;
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, value) in map {
                let (value, value_changed) = transform_json_strings(value, f)?;
                changed |= value_changed;
                out.insert(key.clone(), value);
            }
            Ok((Value::Object(out), changed))
        }
        other => Ok((other.clone(), false)),
    }
}

fn mask_hook_text(session: &Session, text: &str) -> Result<String, String> {
    let remasked = session.remask_all(text)?;
    let result = Engine::with_profile(Profile::Balanced).mask(
        Input {
            kind: Kind::Text,
            data: remasked,
        },
        &Config::new(session.key),
    );
    if !result.recovery.is_empty() {
        session.save_recovery(&result.recovery)?;
    }
    Ok(result.masked)
}

fn stringify_tool_output(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        _ => serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
    }
}

fn session_root(name: &str) -> Result<PathBuf, String> {
    let name = checked_session_name(name)?;
    let base = std::env::var_os("PENTECT_AGENT_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".pentect-agent"));
    Ok(base.join(name))
}

fn checked_session_name(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("session name must not be empty".to_string());
    }
    if name.chars().any(|c| {
        c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    }) {
        return Err("session name must be a simple file-name segment".to_string());
    }
    Ok(name.to_string())
}

fn sanitize_session_name(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len().min(96));
    for ch in value.chars().take(96) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn read_key(path: &Path) -> Result<[u8; 32], String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("could not read key '{}': {e}", path.display()))?;
    bytes
        .try_into()
        .map_err(|_| format!("key '{}' must be exactly 32 bytes", path.display()))
}

fn write_key(path: &Path, key: &[u8; 32]) -> Result<(), String> {
    std::fs::write(path, key).map_err(|e| format!("could not write key '{}': {e}", path.display()))
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn read_input(path: &Path, format: InputFormat) -> Result<String, String> {
    let bytes = read_bytes(path)?;
    match format {
        InputFormat::Text => String::from_utf8(bytes)
            .map_err(|_| format!("input '{}' is not UTF-8 text", path.display())),
        InputFormat::Pdf => pdf_text(&bytes),
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

fn shell_quote_unix(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn infer_kind(path: &Path) -> Kind {
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

fn parse_kind(value: &str) -> Result<Kind, String> {
    match value {
        "text" => Ok(Kind::Text),
        "json" => Ok(Kind::Json),
        "env" => Ok(Kind::Env),
        "har" => Ok(Kind::Har),
        other => Err(format!("unknown kind: {other}")),
    }
}

fn parse_hook_provider(value: &str) -> Result<HookProvider, String> {
    match value {
        "codex" => Ok(HookProvider::Codex),
        "claude" => Ok(HookProvider::Claude),
        "gemini" => Ok(HookProvider::Gemini),
        other => Err(format!("unknown hook provider: {other}")),
    }
}

fn parse_input_format(value: &str) -> Result<InputFormat, String> {
    match value {
        "text" => Ok(InputFormat::Text),
        "pdf" => Ok(InputFormat::Pdf),
        other => Err(format!("unknown input format: {other}")),
    }
}

fn parse_session_and_rest(args: &[String], start: usize) -> Result<(String, Vec<String>), String> {
    let mut session = DEFAULT_SESSION.to_string();
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
    Ok((checked_session_name(&session)?, rest))
}

fn value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    let Some(value) = args.get(*i + 1) else {
        return Err(format!("{flag} requires a value"));
    };
    *i += 2;
    Ok(value.clone())
}

fn die(msg: &str) -> i32 {
    eprintln!("[pentect-agent] {msg}");
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_round_trips_mask_resolve_remask() {
        let root = std::env::temp_dir().join(format!(
            "pentect-agent-test-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        let session = Session::open_at(&root, "t").unwrap();
        let input = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n";
        let result = Engine::with_profile(Profile::Balanced).mask(
            Input {
                kind: Kind::Env,
                data: input.to_string(),
            },
            &Config::new(session.key),
        );
        assert!(!result.masked.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"));
        session.save_recovery(&result.recovery).unwrap();

        let resolved = session.resolve_all(&result.masked).unwrap();
        assert_eq!(resolved, input);
        let remasked = session
            .remask_all("tool echoed sk-ABCDEFGHIJKLMNOPQRSTUVWX")
            .unwrap();
        assert!(remasked.contains("<<OPENAI_API_KEY_"), "{remasked}");
        assert!(!remasked.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_pathlike_session_names() {
        assert!(checked_session_name("../x").is_err());
        assert!(checked_session_name(r"a\b").is_err());
        assert_eq!(checked_session_name("demo").unwrap(), "demo");
    }

    #[test]
    fn exec_parse_requires_separator() {
        let args = strings(["pentect-agent", "exec", "echo", "hi"]);
        assert!(ExecOpts::parse(&args).is_err());
        let args = strings(["pentect-agent", "exec", "--", "echo", "hi"]);
        assert!(matches!(
            ExecOpts::parse(&args).unwrap().mode,
            ExecMode::Program(_)
        ));
    }

    #[test]
    fn claude_pretool_wraps_masked_shell_command() {
        let (root, session, masked) = masked_session("hook-pre");
        let input = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": format!("echo {masked}")
            }
        });
        let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
        let command = output["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(command.contains("exec"), "{command}");
        assert!(command.contains("--shell-b64"), "{command}");
        assert!(
            !command.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
            "{command}"
        );
        assert!(!command.contains("<<OPENAI_API_KEY_"), "{command}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn claude_posttool_masks_raw_output() {
        let (root, session) = empty_session("hook-post-claude");
        let input = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": {
                "content": "token=sk-ABCDEFGHIJKLMNOPQRSTUVWX"
            }
        });
        let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
        let content = output["hookSpecificOutput"]["updatedToolOutput"]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("<<OPENAI_API_KEY_"), "{content}");
        assert!(
            !content.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
            "{content}"
        );
        assert_eq!(
            session.resolve_all(content).unwrap(),
            "token=sk-ABCDEFGHIJKLMNOPQRSTUVWX"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn codex_posttool_blocks_with_masked_feedback() {
        let (root, session) = empty_session("hook-post-codex");
        let input = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX"
        });
        let output = handle_hook(HookProvider::Codex, "t", &session, input).unwrap();
        assert_eq!(output["decision"], "block");
        let reason = output["reason"].as_str().unwrap();
        assert!(reason.contains("<<OPENAI_API_KEY_"), "{reason}");
        assert!(!reason.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"), "{reason}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn gemini_beforetool_uses_tool_input_override() {
        let (root, session, masked) = masked_session("hook-before-gemini");
        let input = json!({
            "event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {
                "command": format!("echo {masked}")
            }
        });
        let output = handle_hook(HookProvider::Gemini, "t", &session, input).unwrap();
        assert_eq!(output["decision"], "allow");
        let command = output["hookSpecificOutput"]["tool_input"]["command"]
            .as_str()
            .unwrap();
        assert!(command.contains("exec"), "{command}");
        assert!(command.contains("--shell-b64"), "{command}");
        assert!(
            !command.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
            "{command}"
        );
        assert!(!command.contains("<<OPENAI_API_KEY_"), "{command}");
        let _ = std::fs::remove_dir_all(root);
    }

    fn masked_session(name: &str) -> (PathBuf, Session, String) {
        let (root, session) = empty_session(name);
        let result = Engine::with_profile(Profile::Balanced).mask(
            Input {
                kind: Kind::Env,
                data: "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n".to_string(),
            },
            &Config::new(session.key),
        );
        session.save_recovery(&result.recovery).unwrap();
        (root, session, result.masked)
    }

    fn empty_session(name: &str) -> (PathBuf, Session) {
        let root = std::env::temp_dir().join(format!(
            "pentect-agent-test-{}-{}-{name}",
            std::process::id(),
            unix_millis()
        ));
        let session = Session::open_at(&root, "t").unwrap();
        (root, session)
    }

    fn strings<const N: usize>(items: [&str; N]) -> Vec<String> {
        items.into_iter().map(str::to_string).collect()
    }
}
