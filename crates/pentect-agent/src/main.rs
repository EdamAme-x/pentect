//! pentect-agent: a minimal tool-boundary adapter.
//!
//! It demonstrates the product loop:
//! shell tool input -> force execution through `pentect exec`;
//! write/exec tool input -> resolve placeholders locally;
//! command output -> remask before it returns to the AI.

mod approve_ui;

use approve_ui::{ApprovalDecision, ApprovalRequest, EnvAction, EnvReview};
use pentect_core::{Config, Engine, Input, Kind, Profile, Recovery};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_SESSION: &str = "default";
const KEY_FILE: &str = "key.bin";
const RECOVERY_DIR: &str = "recoveries";
const LIVE_MASK_CHUNK_BYTES: usize = 64 * 1024;
const LIVE_MASK_CHUNK_LINES: usize = 2048;

static RECOVERY_COUNTER: AtomicU64 = AtomicU64::new(0);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        Some("read") => cmd_read(&args),
        Some("write") => cmd_write(&args),
        Some("exec") => cmd_exec(&args),
        Some("approve") => cmd_approve(&args),
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
        "pentect exec [--session NAME] [--approve] [--live] [--env NAME=VALUE]... [--allow-env NAME]... [--deny-env NAME]... COMMAND\n\
         pentect exec [--session NAME] [--approve] [--live] [--env NAME=VALUE]... [--allow-env NAME]... [--deny-env NAME]... -- PROGRAM [ARG...]\n\
         pentect approve [--session NAME] [--env NAME=VALUE]... [--allow-env NAME]... [--deny-env NAME]... COMMAND\n\
         pentect write PATH < masked-text\n\
         pentect read [--session NAME] [--input text|pdf] [--kind text|json|env|har] [--profile strict|balanced|dev|paranoid] [--length] [--meta] PATH\n\
         pentect hook codex|claude|gemini < hook-json\n\
         pentect resolve < masked-text\n\
         pentect remask < command-output\n\
         \n\
         agent hooks force shell tools through exec and block direct read tools;\n\
         read is a human masked-preview helper."
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
    if opts.emit_meta {
        eprintln!(
            "[pentect] masked={}, warned={}",
            result.summary.masked_count,
            result.summary.residual.len()
        );
    }
    0
}

fn cmd_write(args: &[String]) -> i32 {
    let opts = match WriteOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let session = match Session::open(&opts.session) {
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
    0
}

fn cmd_exec(args: &[String]) -> i32 {
    let opts = match ExecOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let session = match Session::open(&opts.session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let store = match RecoveryStore::load(&session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    if opts.approve {
        match request_approval(&store, &opts, "Approve command execution") {
            Ok(ApprovalDecision::Approve) => {}
            Ok(ApprovalDecision::Deny) => {
                eprintln!("[pentect] command denied");
                return 1;
            }
            Err(e) => return die(&e),
        }
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
    let mut masker = OutputMasker::new_shared(store);
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

fn cmd_approve(args: &[String]) -> i32 {
    let opts = match ExecOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let session = match Session::open(&opts.session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let store = match RecoveryStore::load(&session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    match request_approval(&store, &opts, "Preview Pentect approval") {
        Ok(ApprovalDecision::Approve) => 0,
        Ok(ApprovalDecision::Deny) => 1,
        Err(e) => die(&e),
    }
}

fn request_approval(
    store: &RecoveryStore,
    opts: &ExecOpts,
    title: &str,
) -> Result<ApprovalDecision, String> {
    let command = display_exec_mode(&opts.mode);
    let request = ApprovalRequest {
        title: title.to_string(),
        command: command.clone(),
        session: opts.session.clone(),
        mode: exec_mode_label(&opts.mode).to_string(),
        env: approval_env_rows(opts),
        warnings: approval_warnings(store, opts, &command)?,
    };
    approve_ui::run(&request)
}

fn approval_env_rows(opts: &ExecOpts) -> Vec<EnvReview> {
    let mut rows = Vec::new();
    for binding in &opts.env {
        let detail = if binding.value.contains("<<") {
            "placeholder resolves only inside child process".to_string()
        } else {
            "literal value is hidden from this review".to_string()
        };
        rows.push(EnvReview {
            name: binding.name.clone(),
            action: EnvAction::Inject,
            detail,
        });
    }
    for name in &opts.allow_env {
        rows.push(EnvReview {
            name: name.clone(),
            action: EnvAction::Allow,
            detail: "direct env references for this name pass policy".to_string(),
        });
    }
    for name in &opts.deny_env {
        rows.push(EnvReview {
            name: name.clone(),
            action: EnvAction::Deny,
            detail: "direct env references for this name are blocked".to_string(),
        });
    }
    rows
}

fn approval_warnings(
    store: &RecoveryStore,
    opts: &ExecOpts,
    display_command: &str,
) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    let env = opts
        .env
        .iter()
        .map(|binding| (binding.name.clone(), String::new()))
        .collect::<Vec<_>>();
    let policy = exec_env_policy(&env, opts)?;
    let resolved_for_policy = store.resolve_all(display_command)?;
    let guard = match &opts.mode {
        ExecMode::Program(args) => {
            let program = args.first().map(String::as_str).unwrap_or_default();
            guard_program_invocation_with_env(program, &args[1..], &policy)
        }
        ExecMode::Shell(_) => guard_shell_script_with_env(&resolved_for_policy, &policy),
    };
    if let Err(reason) = guard {
        warnings.push(reason);
    }
    if opts.env.is_empty() && opts.allow_env.is_empty() && opts.deny_env.is_empty() {
        warnings.push("ambient environment is inherited by the child process today; explicit env policy is still recommended".to_string());
    }
    if opts.live {
        warnings.push(
            "live output is masked in chunks; very long partial lines flush at chunk boundaries"
                .to_string(),
        );
    }
    Ok(warnings)
}

fn display_exec_mode(mode: &ExecMode) -> String {
    match mode {
        ExecMode::Shell(command) => command.clone(),
        ExecMode::Program(args) => args
            .iter()
            .map(|arg| {
                if cfg!(windows) {
                    powershell_word(arg)
                } else {
                    shell_quote_unix(arg)
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn exec_mode_label(mode: &ExecMode) -> &'static str {
    match mode {
        ExecMode::Shell(_) => "shell",
        ExecMode::Program(_) => "program",
    }
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
    store: &RecoveryStore,
    opts: &ExecOpts,
) -> Result<std::process::Output, String> {
    let env = resolve_env_bindings(store, &opts.env)?;
    let env_policy = exec_env_policy(&env, opts)?;
    match &opts.mode {
        ExecMode::Program(args) => {
            if args.is_empty() {
                return Err("exec requires a program after `--`".to_string());
            }
            let program = store.resolve_all(&args[0])?;
            let resolved_args: Result<Vec<String>, String> =
                args[1..].iter().map(|arg| store.resolve_all(arg)).collect();
            let resolved_args = resolved_args?;
            guard_program_invocation_with_env(&program, &resolved_args, &env_policy)?;
            let mut command = Command::new(program);
            command.args(resolved_args);
            apply_env_bindings(&mut command, &env);
            command
                .output()
                .map_err(|e| format!("could not execute command: {e}"))
        }
        ExecMode::Shell(command) => {
            let resolved = store.resolve_all(command)?;
            guard_shell_script_with_env(&resolved, &env_policy)?;
            run_shell_script(&resolved, &env)
        }
    }
}

fn run_resolved_command_live(store: &RecoveryStore, opts: &ExecOpts) -> Result<ExitStatus, String> {
    let env = resolve_env_bindings(store, &opts.env)?;
    let env_policy = exec_env_policy(&env, opts)?;
    match &opts.mode {
        ExecMode::Program(args) => {
            if args.is_empty() {
                return Err("exec requires a program after `--`".to_string());
            }
            let program = store.resolve_all(&args[0])?;
            let resolved_args: Result<Vec<String>, String> =
                args[1..].iter().map(|arg| store.resolve_all(arg)).collect();
            let resolved_args = resolved_args?;
            guard_program_invocation_with_env(&program, &resolved_args, &env_policy)?;
            let mut command = Command::new(program);
            command.args(resolved_args);
            apply_env_bindings(&mut command, &env);
            run_live_command(command, None, store.clone())
        }
        ExecMode::Shell(command) => {
            let resolved = store.resolve_all(command)?;
            guard_shell_script_with_env(&resolved, &env_policy)?;
            let mut command = shell_script_command();
            apply_env_bindings(&mut command, &env);
            run_live_command(command, Some(&resolved), store.clone())
        }
    }
}

fn resolve_env_bindings(
    store: &RecoveryStore,
    env: &[EnvBinding],
) -> Result<Vec<(String, String)>, String> {
    env.iter()
        .map(|binding| Ok((binding.name.clone(), store.resolve_all(&binding.value)?)))
        .collect()
}

fn apply_env_bindings(command: &mut Command, env: &[(String, String)]) {
    for (name, value) in env {
        command.env(name, value);
    }
}

#[derive(Debug, Default)]
struct EnvPolicy {
    allowed: Vec<String>,
    denied: Vec<String>,
}

impl EnvPolicy {
    fn allows_direct_read(&self, name: &str) -> bool {
        !self.is_denied(name) && self.is_allowed(name)
    }

    fn blocks_shell_var_read(&self, name: &str) -> bool {
        self.is_denied(name) || (is_sensitive_env_name(name) && !self.is_allowed(name))
    }

    fn is_allowed(&self, name: &str) -> bool {
        let normalized = name.to_ascii_lowercase();
        self.allowed.iter().any(|allowed| allowed == &normalized)
    }

    fn is_denied(&self, name: &str) -> bool {
        let normalized = name.to_ascii_lowercase();
        self.denied.iter().any(|denied| denied == &normalized)
    }
}

fn exec_env_policy(env: &[(String, String)], opts: &ExecOpts) -> Result<EnvPolicy, String> {
    let mut allowed = Vec::new();
    for (name, _) in env {
        push_unique_env_name(&mut allowed, name);
    }
    for name in &opts.allow_env {
        push_unique_env_name(&mut allowed, name);
    }
    let mut denied = Vec::new();
    for name in &opts.deny_env {
        push_unique_env_name(&mut denied, name);
    }
    for name in &denied {
        if allowed.iter().any(|allowed| allowed == name) {
            return Err(format!(
                "environment variable is both allowed and denied: {name}"
            ));
        }
    }
    Ok(EnvPolicy { allowed, denied })
}

fn push_unique_env_name(names: &mut Vec<String>, name: &str) {
    let normalized = name.to_ascii_lowercase();
    if !names.iter().any(|existing| existing == &normalized) {
        names.push(normalized);
    }
}

fn guard_program_invocation_with_env(
    program: &str,
    args: &[String],
    env_policy: &EnvPolicy,
) -> Result<(), String> {
    let mut text = String::from(program);
    for arg in args {
        text.push(' ');
        text.push_str(arg);
    }
    guard_sensitive_source_access_with_env(&text, env_policy)
}

fn guard_shell_script_with_env(script: &str, env_policy: &EnvPolicy) -> Result<(), String> {
    guard_sensitive_source_access_with_env(script, env_policy)
}

fn guard_sensitive_source_access_with_env(
    text: &str,
    env_policy: &EnvPolicy,
) -> Result<(), String> {
    let normalized = normalize_policy_text(text);
    if contains_env_read_reference(&normalized, env_policy) {
        return Err(
            "Pentect blocked direct environment-variable access; pass approved values through Pentect placeholders instead."
                .to_string(),
        );
    }
    Ok(())
}

fn run_shell_script(
    script: &str,
    env: &[(String, String)],
) -> Result<std::process::Output, String> {
    let mut command = shell_script_command();
    apply_env_bindings(&mut command, env);
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
    store: RecoveryStore,
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
    let stderr_store = store;
    let stdout_thread = std::thread::spawn(move || {
        let mut masker = OutputMasker::new_deferred(stdout_store)?;
        stream_masked_reader(&mut masker, stdout, StreamTarget::Stdout)?;
        masker.flush()
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut masker = OutputMasker::new_deferred(stderr_store)?;
        stream_masked_reader(&mut masker, stderr, StreamTarget::Stderr)?;
        masker.flush()
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
    let mut reader = BufReader::new(reader);
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
        let text = String::from_utf8_lossy(&buf);
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
    emit_meta: bool,
    path: PathBuf,
}

impl ReadOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut session = DEFAULT_SESSION.to_string();
        let mut input_format = InputFormat::Text;
        let mut kind = None;
        let mut profile = Profile::Strict;
        let mut disclose_length = false;
        let mut emit_meta = false;
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
            session: checked_session_name(&session)?,
            input_format,
            kind,
            profile,
            disclose_length,
            emit_meta,
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
        let _ = input;
        Ok(DEFAULT_SESSION.to_string())
    }
}

struct ExecOpts {
    session: String,
    env: Vec<EnvBinding>,
    allow_env: Vec<String>,
    deny_env: Vec<String>,
    live: bool,
    approve: bool,
    mode: ExecMode,
}

struct EnvBinding {
    name: String,
    value: String,
}

enum ExecMode {
    Program(Vec<String>),
    Shell(String),
}

impl ExecOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut session = DEFAULT_SESSION.to_string();
        let mut env = Vec::new();
        let mut allow_env = Vec::new();
        let mut deny_env = Vec::new();
        let mut live = false;
        let mut approve = false;
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
                "--approve" => {
                    approve = true;
                    i += 1;
                }
                "--env" => {
                    env.push(parse_env_binding(&value(args, &mut i, "--env")?)?);
                }
                "--allow-env" => {
                    allow_env.push(checked_env_name(&value(args, &mut i, "--allow-env")?)?);
                }
                "--deny-env" => {
                    deny_env.push(checked_env_name(&value(args, &mut i, "--deny-env")?)?);
                }
                "--shell" => {
                    return Err(
                        "`--shell` was removed; use `pentect exec \"<command>\"`".to_string()
                    );
                }
                "--" => {
                    let command = args[i + 1..].to_vec();
                    if command.is_empty() {
                        return Err("exec requires a command after `--`".to_string());
                    }
                    return Ok(Self {
                        session: checked_session_name(&session)?,
                        env,
                        allow_env,
                        deny_env,
                        live,
                        approve,
                        mode: ExecMode::Program(command),
                    });
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                _ => {
                    return Ok(Self {
                        session: checked_session_name(&session)?,
                        env,
                        allow_env,
                        deny_env,
                        live,
                        approve,
                        mode: ExecMode::Shell(args[i..].join(" ")),
                    });
                }
            }
        }
        Err("exec requires COMMAND or `-- PROGRAM...`".to_string())
    }
}

fn parse_env_binding(raw: &str) -> Result<EnvBinding, String> {
    let Some((name, value)) = raw.split_once('=') else {
        return Err("--env requires NAME=VALUE".to_string());
    };
    Ok(EnvBinding {
        name: checked_env_name(name)?,
        value: value.to_string(),
    })
}

fn checked_env_name(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("--env name must not be empty".to_string());
    }
    if name.as_bytes()[0].is_ascii_digit() || !name.bytes().all(is_env_name_byte) {
        return Err("--env name must be a shell-style environment variable name".to_string());
    }
    Ok(name.to_string())
}

#[derive(Clone)]
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
            format!("session '{name}' does not exist; run `pentect exec \"...\"` first")
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

#[derive(Clone)]
struct RecoveryStore {
    session: Session,
    recoveries: Arc<Mutex<Vec<Recovery>>>,
}

impl RecoveryStore {
    fn load(session: &Session) -> Result<Self, String> {
        Ok(Self {
            session: session.clone(),
            recoveries: Arc::new(Mutex::new(session.recoveries()?)),
        })
    }

    fn resolve_all(&self, text: &str) -> Result<String, String> {
        let recoveries = self.lock()?;
        let mut out = text.to_string();
        for rec in recoveries.iter() {
            out = rec.resolve(&out);
        }
        Ok(out)
    }

    fn remask_all(&self, text: &str) -> Result<String, String> {
        let recoveries = self.lock()?;
        let mut out = text.to_string();
        for rec in recoveries.iter() {
            out = rec.remask(&out);
        }
        Ok(out)
    }

    fn snapshot(&self) -> Result<Vec<Recovery>, String> {
        Ok(self.lock()?.clone())
    }

    fn save_recovery(&self, recovery: Recovery) -> Result<(), String> {
        if recovery.is_empty() {
            return Ok(());
        }
        self.session.save_recovery(&recovery)?;
        self.lock()?.push(recovery);
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Vec<Recovery>>, String> {
        self.recoveries
            .lock()
            .map_err(|_| "recovery cache lock poisoned".to_string())
    }
}

struct OutputMasker {
    store: RecoveryStore,
    engine: Engine,
    mode: OutputMaskerMode,
    pending: Recovery,
}

enum OutputMaskerMode {
    Shared,
    Deferred { remask_recoveries: Vec<Recovery> },
}

impl OutputMasker {
    fn new_shared(store: RecoveryStore) -> Self {
        let key = store.session.key;
        Self {
            store,
            engine: Engine::with_profile(Profile::Strict),
            mode: OutputMaskerMode::Shared,
            pending: Recovery::empty_for_key(&key),
        }
    }

    fn new_deferred(store: RecoveryStore) -> Result<Self, String> {
        let key = store.session.key;
        let remask_recoveries = store.snapshot()?;
        Ok(Self {
            store,
            engine: Engine::with_profile(Profile::Strict),
            mode: OutputMaskerMode::Deferred { remask_recoveries },
            pending: Recovery::empty_for_key(&key),
        })
    }

    fn flush(&mut self) -> Result<(), String> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let next = Recovery::empty_for_key(&self.store.session.key);
        let pending = std::mem::replace(&mut self.pending, next);
        self.store.save_recovery(pending)
    }

    fn mask_tool_output(&mut self, text: &str) -> Result<String, String> {
        let kind = if looks_like_sensitive_env_output(text) || looks_like_env_output(text) {
            Kind::Env
        } else {
            Kind::Text
        };
        self.mask_text(text, kind)
    }

    fn mask_text(&mut self, text: &str, kind: Kind) -> Result<String, String> {
        let remasked = self.remask_all(text)?;
        let result = self.engine.mask(
            Input {
                kind,
                data: remasked,
            },
            &Config::new(self.store.session.key),
        );
        let masked = result.masked;
        match &mut self.mode {
            OutputMaskerMode::Shared => self.store.save_recovery(result.recovery)?,
            OutputMaskerMode::Deferred { .. } => self.pending.extend_same_key(result.recovery),
        }
        Ok(masked)
    }

    fn remask_all(&self, text: &str) -> Result<String, String> {
        match &self.mode {
            OutputMaskerMode::Shared => self.store.remask_all(text),
            OutputMaskerMode::Deferred { remask_recoveries } => {
                let mut out = text.to_string();
                for rec in remask_recoveries {
                    out = rec.remask(&out);
                }
                Ok(out)
            }
        }
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
            let tool_name = hook_field(&input, &["tool_name"])
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
    tool_name: &str,
    tool_input: &Value,
) -> Result<(Value, bool), String> {
    if is_read_like_tool_name(tool_name) {
        return Err(read_tool_block_reason(tool_name));
    }
    if let Some(command) = tool_input.get("command").and_then(Value::as_str) {
        if is_pentect_read_command(command) {
            return Err(
                "use `pentect exec \"Get-Content ...\"` instead of `pentect read` from AI hooks"
                    .to_string(),
            );
        }
        if is_pentect_exec_program_command(command) {
            return Ok((tool_input.clone(), false));
        }
        let command = extract_pentect_exec_shell_payload(command).unwrap_or_else(|| command.into());
        let mut updated = tool_input.clone();
        if let Some(object) = updated.as_object_mut() {
            object.insert(
                "command".to_string(),
                Value::String(wrap_shell_command(provider, session_name, &command)?),
            );
            return Ok((updated, true));
        }
    }
    transform_json_strings(tool_input, &mut |text| session.resolve_all(text))
}

fn is_read_like_tool_name(tool_name: &str) -> bool {
    matches!(
        tool_name.to_ascii_lowercase().as_str(),
        "read" | "read_file" | "read_many_files" | "multiread" | "notebookread" | "notebook_read"
    )
}

fn is_pentect_exec_program_command(command: &str) -> bool {
    matches!(
        parse_pentect_subcommand(command),
        Some(PentectInvocation {
            subcommand: PentectSubcommand::Exec,
            rest
        }) if rest.trim_start().starts_with("-- ")
    )
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
            "--shell" => {
                return Some(unquote_wrapped_shell_arg(rest[word_end..].trim_start()));
            }
            "--" => return None,
            _ => return Some(unquote_wrapped_shell_arg(rest)),
        }
    }
}

fn is_pentect_read_command(command: &str) -> bool {
    matches!(
        parse_pentect_subcommand(command),
        Some(PentectInvocation {
            subcommand: PentectSubcommand::Read,
            ..
        })
    )
}

fn read_tool_block_reason(tool_name: &str) -> String {
    format!(
        "{tool_name} is human-only; use `pentect exec \"Get-Content ...\"` from AI hooks instead."
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PentectSubcommand {
    Exec,
    Read,
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
        _ => return None,
    };
    Some(PentectInvocation {
        subcommand,
        rest: &command[end..],
    })
}

fn next_shell_word(text: &str, start: usize) -> Option<(String, usize, usize)> {
    let mut word_start = start;
    while word_start < text.len() {
        let ch = text[word_start..].chars().next()?;
        if !ch.is_whitespace() {
            break;
        }
        word_start += ch.len_utf8();
    }
    if word_start >= text.len() {
        return None;
    }
    let first = text[word_start..].chars().next()?;
    if matches!(first, '\'' | '"') {
        let mut end = word_start + first.len_utf8();
        let mut word = String::new();
        while end < text.len() {
            let ch = text[end..].chars().next()?;
            end += ch.len_utf8();
            if ch == first {
                return Some((word, word_start, end));
            }
            word.push(ch);
        }
        return Some((word, word_start, end));
    }
    let mut end = word_start;
    while end < text.len() {
        let ch = text[end..].chars().next()?;
        if ch.is_whitespace() {
            break;
        }
        end += ch.len_utf8();
    }
    Some((text[word_start..end].to_string(), word_start, end))
}

fn is_pentect_command(command: &str) -> bool {
    let normalized = command.replace('\\', "/");
    let command = normalized.trim_start_matches("./");
    command == "pentect"
        || command == "pentect.exe"
        || command == "pentect-agent"
        || command == "pentect-agent.exe"
        || command.ends_with("/pentect")
        || command.ends_with("/pentect.exe")
        || command.ends_with("/pentect-agent")
        || command.ends_with("/pentect-agent.exe")
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
    _provider: HookProvider,
    session_name: &str,
    masked_command: &str,
) -> Result<String, String> {
    let words = agent_exec_words(session_name, masked_command)?;
    if cfg!(windows) {
        Ok(powershell_command(&words))
    } else {
        Ok(shell_command(&words))
    }
}

fn agent_exec_words(session_name: &str, masked_command: &str) -> Result<Vec<String>, String> {
    if pentect_agent_passthrough_available() {
        let mut words = vec!["pentect".to_string(), "exec".to_string()];
        add_non_default_session(&mut words, session_name);
        words.push(masked_command.to_string());
        return Ok(words);
    }
    if command_available("pentect-agent") {
        let mut words = vec!["pentect-agent".to_string(), "exec".to_string()];
        add_non_default_session(&mut words, session_name);
        words.push(masked_command.to_string());
        return Ok(words);
    }
    let agent = std::env::current_exe()
        .map_err(|e| format!("could not resolve pentect-agent executable: {e}"))?;
    let mut words = vec![agent.to_string_lossy().into_owned(), "exec".to_string()];
    add_non_default_session(&mut words, session_name);
    words.push(masked_command.to_string());
    Ok(words)
}

fn add_non_default_session(words: &mut Vec<String>, session_name: &str) {
    if session_name != DEFAULT_SESSION {
        words.push("--session".to_string());
        words.push(session_name.to_string());
    }
}

fn pentect_agent_passthrough_available() -> bool {
    let Ok(output) = Command::new("pentect").arg("agent").arg("--probe").output() else {
        return false;
    };
    output.status.success()
        && String::from_utf8_lossy(&output.stdout).trim() == "pentect-agent-passthrough"
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

fn before_tool_block_output(provider: HookProvider, reason: &str) -> Value {
    match provider {
        HookProvider::Codex | HookProvider::Claude => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason
            }
        }),
        HookProvider::Gemini => json!({
            "decision": "deny",
            "reason": reason
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
    mask_tool_output(session, text)
}

fn mask_tool_output(session: &Session, text: &str) -> Result<String, String> {
    let kind = if looks_like_sensitive_env_output(text) || looks_like_env_output(text) {
        Kind::Env
    } else {
        Kind::Text
    };
    mask_text(session, text, kind)
}

#[cfg(test)]
fn mask_live_output(session: &Session, text: &str) -> Result<String, String> {
    mask_text(session, text, live_output_kind(text))
}

fn live_output_kind(text: &str) -> Kind {
    if looks_like_sensitive_env_output(text)
        || looks_like_env_output(text)
        || text.lines().any(|line| is_env_assignment_line(line.trim()))
    {
        Kind::Env
    } else {
        Kind::Text
    }
}

fn mask_text(session: &Session, text: &str, kind: Kind) -> Result<String, String> {
    let remasked = session.remask_all(text)?;
    let result = Engine::with_profile(Profile::Strict).mask(
        Input {
            kind,
            data: remasked,
        },
        &Config::new(session.key),
    );
    if !result.recovery.is_empty() {
        session.save_recovery(&result.recovery)?;
    }
    Ok(result.masked)
}

fn looks_like_env_output(text: &str) -> bool {
    let mut env_lines = 0usize;
    let mut non_empty_lines = 0usize;
    for line in text.lines().take(256) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        non_empty_lines += 1;
        if is_env_assignment_line(trimmed) {
            env_lines += 1;
        }
    }
    env_lines >= 2 && env_lines == non_empty_lines
}

fn looks_like_sensitive_env_output(text: &str) -> bool {
    for line in text.lines().take(256) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(key) = env_assignment_key(trimmed) {
            if is_sensitive_env_name(&key.to_ascii_lowercase()) {
                return true;
            }
        }
    }
    false
}

fn is_env_assignment_line(line: &str) -> bool {
    env_assignment_key(line).is_some()
}

fn env_assignment_key(line: &str) -> Option<&str> {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let (key, value) = line.split_once('=')?;
    if key.is_empty() || value.is_empty() {
        return None;
    }
    if key
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
    {
        Some(key)
    } else {
        None
    }
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

fn command_available(command: &str) -> bool {
    let status = if cfg!(windows) {
        Command::new("where.exe")
            .arg(command)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    } else {
        Command::new("sh")
            .arg("-c")
            .arg("command -v \"$1\" >/dev/null 2>&1")
            .arg("sh")
            .arg(command)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    };
    status.is_ok_and(|s| s.success())
}

fn shell_command(words: &[String]) -> String {
    words
        .iter()
        .map(|word| shell_quote_unix(word))
        .collect::<Vec<_>>()
        .join(" ")
}

fn powershell_command(words: &[String]) -> String {
    if let Some((first, rest)) = words.split_first() {
        if is_simple_shell_word(first) {
            let mut out = powershell_word(first);
            if !rest.is_empty() {
                out.push(' ');
                out.push_str(
                    &rest
                        .iter()
                        .map(|word| powershell_word(word))
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }
            return out;
        }
    }
    let mut out = String::from("& ");
    out.push_str(
        &words
            .iter()
            .map(|word| powershell_word(word))
            .collect::<Vec<_>>()
            .join(" "),
    );
    out
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

fn powershell_word(value: &str) -> String {
    if is_simple_shell_word(value) {
        value.to_string()
    } else {
        powershell_quote(value)
    }
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn is_simple_shell_word(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn normalize_policy_text(text: &str) -> String {
    text.to_ascii_lowercase().replace('\\', "/")
}

fn contains_env_read_reference(normalized: &str, env_policy: &EnvPolicy) -> bool {
    has_disallowed_powershell_env_ref(normalized, env_policy)
        || normalized.contains(" env:")
        || normalized.starts_with("env:")
        || normalized.contains("[environment]::getenvironmentvariable")
        || normalized.contains("[environment]::getenvironmentvariables")
        || has_disallowed_printenv_reference(normalized, env_policy)
        || references_sensitive_env_name(normalized, env_policy)
}

fn has_disallowed_powershell_env_ref(normalized: &str, env_policy: &EnvPolicy) -> bool {
    let mut offset = 0usize;
    while let Some(index) = normalized[offset..].find("$env:") {
        let name_start = offset + index + "$env:".len();
        let mut name_end = name_start;
        let bytes = normalized.as_bytes();
        while name_end < bytes.len() && is_env_name_byte(bytes[name_end]) {
            name_end += 1;
        }
        if name_end == name_start {
            return true;
        }
        if !env_policy.allows_direct_read(&normalized[name_start..name_end]) {
            return true;
        }
        offset = name_end;
    }
    false
}

fn has_disallowed_printenv_reference(normalized: &str, env_policy: &EnvPolicy) -> bool {
    let mut offset = 0usize;
    while let Some(index) = normalized[offset..].find("printenv") {
        let word_start = offset + index;
        let word_end = word_start + "printenv".len();
        let before = normalized[..word_start].chars().next_back();
        let after = normalized[word_end..].chars().next();
        if !is_ascii_word_char(before) && !is_ascii_word_char(after) {
            let mut cursor = word_end;
            let mut saw_name = false;
            while let Some((word, _, next)) = next_shell_word(normalized, cursor) {
                if is_shell_separator_word(&word) {
                    break;
                }
                if word.starts_with('-') || !looks_like_env_name(&word) {
                    return true;
                }
                saw_name = true;
                if !env_policy.allows_direct_read(&word) {
                    return true;
                }
                cursor = next;
            }
            if !saw_name {
                return true;
            }
        }
        offset = word_end;
    }
    false
}

fn is_shell_separator_word(word: &str) -> bool {
    matches!(word, "|" | ";" | "&&" | "||") || word.starts_with('<') || word.starts_with('>')
}

fn looks_like_env_name(name: &str) -> bool {
    !name.is_empty() && !name.as_bytes()[0].is_ascii_digit() && name.bytes().all(is_env_name_byte)
}

fn references_sensitive_env_name(normalized: &str, env_policy: &EnvPolicy) -> bool {
    let bytes = normalized.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let marker = bytes[i] as char;
        if marker == '$' || marker == '%' {
            if let Some((name, next)) = env_name_after_marker(normalized, i + 1, marker) {
                if env_policy.blocks_shell_var_read(name) {
                    return true;
                }
                i = next;
                continue;
            }
        }
        i += 1;
    }
    false
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

fn is_env_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_sensitive_env_name(name: &str) -> bool {
    if name == "auth" || name.contains("auth_") || name.contains("_auth") {
        return true;
    }
    [
        "api_key",
        "apikey",
        "access_key",
        "secret",
        "token",
        "password",
        "passwd",
        "private",
        "credential",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

fn is_ascii_word_char(ch: Option<char>) -> bool {
    ch.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

fn infer_kind(path: &Path) -> Kind {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(".env"))
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
    eprintln!("[pentect] {msg}");
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
    fn exec_parse_accepts_split_shell_command_as_shell_text() {
        let args = strings(["pentect-agent", "exec", "echo", "hi"]);
        assert!(matches!(
            ExecOpts::parse(&args).unwrap().mode,
            ExecMode::Shell(command) if command == "echo hi"
        ));
        let args = strings(["pentect-agent", "exec", "echo hi"]);
        assert!(matches!(
            ExecOpts::parse(&args).unwrap().mode,
            ExecMode::Shell(command) if command == "echo hi"
        ));
    }

    #[test]
    fn exec_parse_accepts_env_bindings() {
        let args = strings([
            "pentect-agent",
            "exec",
            "--env",
            "RUNPOD_API_KEY=<<RUNPOD_API_KEY_abc>>",
            "echo",
            "hi",
        ]);
        let opts = ExecOpts::parse(&args).unwrap();
        assert_eq!(opts.env.len(), 1);
        assert_eq!(opts.env[0].name, "RUNPOD_API_KEY");
        assert_eq!(opts.env[0].value, "<<RUNPOD_API_KEY_abc>>");
        assert!(matches!(
            opts.mode,
            ExecMode::Shell(command) if command == "echo hi"
        ));
    }

    #[test]
    fn exec_parse_accepts_live_and_env_policy() {
        let args = strings([
            "pentect-agent",
            "exec",
            "--live",
            "--approve",
            "--allow-env",
            "RUNPOD_API_KEY",
            "--deny-env",
            "AWS_SECRET_ACCESS_KEY",
            "echo",
            "hi",
        ]);
        let opts = ExecOpts::parse(&args).unwrap();
        assert!(opts.live);
        assert!(opts.approve);
        assert_eq!(opts.allow_env, ["RUNPOD_API_KEY"]);
        assert_eq!(opts.deny_env, ["AWS_SECRET_ACCESS_KEY"]);
        assert!(matches!(
            opts.mode,
            ExecMode::Shell(command) if command == "echo hi"
        ));
    }

    #[test]
    fn exec_parse_rejects_shell_flag() {
        let args = strings(["pentect-agent", "exec", "--shell", "echo hi"]);
        let err = match ExecOpts::parse(&args) {
            Ok(_) => panic!("expected --shell to be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("removed"), "{err}");
    }

    #[test]
    fn exec_parse_accepts_program_after_separator() {
        let args = strings(["pentect-agent", "exec", "--", "echo", "hi"]);
        assert!(matches!(
            ExecOpts::parse(&args).unwrap().mode,
            ExecMode::Program(_)
        ));
    }

    #[test]
    fn read_defaults_to_strict_and_infers_dotenv() {
        let args = strings(["pentect-agent", "read", r".\.env"]);
        let opts = ReadOpts::parse(&args).unwrap();
        assert_eq!(opts.profile, Profile::Strict);
        assert!(!opts.emit_meta);
        assert_eq!(infer_kind(&opts.path), Kind::Env);

        let args = strings(["pentect-agent", "read", "--meta", r".\.env"]);
        assert!(ReadOpts::parse(&args).unwrap().emit_meta);
    }

    #[test]
    fn read_dotenv_masks_all_values() {
        let root = std::env::temp_dir().join(format!(
            "pentect-agent-test-{}-{}-read-dotenv",
            std::process::id(),
            unix_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(".env");
        std::fs::write(
            &path,
            "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\nTEST_SECRET=114514810\nNOTE=hello world\n",
        )
        .unwrap();

        let session = Session::open_at(&root.join("agent-home"), "t").unwrap();
        let data = read_input(&path, InputFormat::Text).unwrap();
        let result = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: infer_kind(&path),
                data,
            },
            &Config::new(session.key),
        );

        assert!(!result
            .masked
            .contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"));
        assert!(!result.masked.contains("114514810"), "{}", result.masked);
        assert!(!result.masked.contains("hello world"), "{}", result.masked);
        assert!(
            result.masked.contains("TEST_SECRET=<<SECRET_"),
            "{}",
            result.masked
        );
        assert!(
            result.masked.contains("NOTE=<<SECRET_"),
            "{}",
            result.masked
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn exec_allows_secret_file_reads_because_output_is_remasked() {
        guard_shell_script_with_env(r"Get-Content .\.env", &EnvPolicy::default()).unwrap();
        guard_shell_script_with_env("cat .env | Select-String RUNPOD", &EnvPolicy::default())
            .unwrap();
        guard_shell_script_with_env(
            r#"python -c "open('.env').read()" # pentect-agent read"#,
            &EnvPolicy::default(),
        )
        .unwrap();
    }

    #[test]
    fn exec_policy_blocks_environment_reads() {
        let err =
            guard_shell_script_with_env("Get-ChildItem Env:", &EnvPolicy::default()).unwrap_err();
        assert!(err.contains("environment-variable"), "{err}");

        let err = guard_shell_script_with_env("printenv RUNPOD_API_KEY", &EnvPolicy::default())
            .unwrap_err();
        assert!(err.contains("environment-variable"), "{err}");

        let err =
            guard_shell_script_with_env("echo $RUNPOD_API_KEY", &EnvPolicy::default()).unwrap_err();
        assert!(err.contains("environment-variable"), "{err}");

        let err =
            guard_shell_script_with_env("Write-Output %RUNPOD_API_KEY%", &EnvPolicy::default())
                .unwrap_err();
        assert!(err.contains("environment-variable"), "{err}");
    }

    #[test]
    fn exec_policy_allows_and_denies_named_environment_reads() {
        let allowed = env_policy(&["RUNPOD_API_KEY"], &[]);
        guard_shell_script_with_env("printenv RUNPOD_API_KEY", &allowed).unwrap();
        guard_shell_script_with_env("echo $RUNPOD_API_KEY", &allowed).unwrap();
        guard_shell_script_with_env("Write-Output $env:RUNPOD_API_KEY", &allowed).unwrap();

        let denied = env_policy(&["RUNPOD_API_KEY"], &["USERNAME"]);
        let err = guard_shell_script_with_env("Write-Output %USERNAME%", &denied).unwrap_err();
        assert!(err.contains("environment-variable"), "{err}");
    }

    #[test]
    fn exec_policy_does_not_block_regular_shell_state_changes() {
        guard_shell_script_with_env("export PATH=/tmp:$PATH", &EnvPolicy::default()).unwrap();
        guard_shell_script_with_env("Set-Content note.txt hello", &EnvPolicy::default()).unwrap();
        guard_shell_script_with_env("echo $AUTHOR", &EnvPolicy::default()).unwrap();
        guard_shell_script_with_env("Write-Output %USERNAME%", &EnvPolicy::default()).unwrap();
    }

    #[test]
    fn exec_env_binding_resolves_placeholder_for_child_process() {
        let (root, session) = empty_session("exec-env-binding");
        let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
        let masked = mask_text(&session, raw, Kind::Text).unwrap();
        let command = if cfg!(windows) {
            "Write-Output $env:OPENAI_API_KEY".to_string()
        } else {
            "printf '%s' \"$OPENAI_API_KEY\"".to_string()
        };
        let opts = ExecOpts {
            session: DEFAULT_SESSION.to_string(),
            env: vec![EnvBinding {
                name: "OPENAI_API_KEY".to_string(),
                value: masked,
            }],
            allow_env: Vec::new(),
            deny_env: Vec::new(),
            live: false,
            approve: false,
            mode: ExecMode::Shell(command),
        };

        let store = RecoveryStore::load(&session).unwrap();
        let output = run_resolved_command(&store, &opts).unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(raw), "{stdout}");

        let safe = mask_tool_output(&session, &stdout).unwrap();
        assert!(!safe.contains(raw), "{safe}");
        assert!(safe.contains("<<OPENAI_API_KEY_"), "{safe}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn env_like_tool_output_masks_all_env_values() {
        let (root, session) = empty_session("exec-dotenv-output");
        let output = "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\nTEST_SECRET=114514810\nNOTE=hello world\n";
        let masked = mask_tool_output(&session, output).unwrap();
        assert!(!masked.contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"));
        assert!(!masked.contains("114514810"), "{masked}");
        assert!(!masked.contains("hello world"), "{masked}");
        assert!(masked.contains("TEST_SECRET=<<SECRET_"), "{masked}");
        assert!(masked.contains("NOTE=<<SECRET_"), "{masked}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn single_assignment_output_stays_text() {
        let (root, session) = empty_session("exec-single-assignment");
        let masked = mask_tool_output(&session, "NOTE=hello world\n").unwrap();
        assert_eq!(masked, "NOTE=hello world\n");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn live_single_assignment_output_masks_value() {
        let (root, session) = empty_session("exec-live-single-assignment");
        let masked = mask_live_output(&session, "NOTE=hello world\n").unwrap();
        assert!(!masked.contains("hello world"), "{masked}");
        assert!(masked.contains("NOTE=<<SECRET_"), "{masked}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn single_sensitive_assignment_output_is_masked_as_env() {
        let (root, session) = empty_session("exec-single-sensitive-assignment");
        let output = "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\n";
        let masked = mask_tool_output(&session, output).unwrap();
        assert!(!masked.contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"));
        assert!(
            masked.contains("RUNPOD_API_KEY=<<RUNPOD_API_KEY_"),
            "{masked}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn claude_pretool_wraps_plain_shell_command() {
        let (root, session) = empty_session("hook-pre-plain");
        let input = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": r"Get-Content .\.env"
            }
        });
        let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
        let command = output["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(command.contains("pentect"), "{command}");
        assert!(command.contains("exec"), "{command}");
        assert!(command.contains("Get-Content"), "{command}");
        assert!(command.contains(".\\.env"), "{command}");
        assert!(!command.contains("--shell-b64"), "{command}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pretool_blocks_pentect_read_from_ai_hooks() {
        let (root, session) = empty_session("hook-pre-read");
        let input = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": r"pentect read .\.env"
            }
        });
        let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
        let reason = output["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(reason.contains("pentect exec"), "{reason}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pretool_blocks_direct_read_tools() {
        let (root, session) = empty_session("hook-pre-direct-read");
        let input = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {
                "file_path": r".\.env"
            }
        });
        let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
        let reason = output["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(reason.contains("human-only"), "{reason}");
        assert!(reason.contains("pentect exec"), "{reason}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pretool_canonicalizes_quoted_pentect_exec_shell_command() {
        let (root, session) = empty_session("hook-pre-exec");
        let input = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": r#"pentect exec "Get-Content .\.env""#
            }
        });
        let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
        let command = output["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(command.contains("pentect"), "{command}");
        assert!(command.contains("exec"), "{command}");
        assert!(!command.contains("--shell"), "{command}");
        assert!(command.contains("Get-Content"), "{command}");
        assert_eq!(command.matches(" exec ").count(), 1, "{command}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pretool_canonicalizes_pentect_exec_shell_commands() {
        let (root, session) = empty_session("hook-pre-canonical");
        let input = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "pentect exec if (!(Test-Path -LiteralPath $path)) { Write-Output \"missing\"; exit 0 }"
            }
        });
        let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
        let command = output["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(command.contains("pentect"), "{command}");
        assert!(command.contains("exec"), "{command}");
        assert!(!command.contains("--shell"), "{command}");
        assert!(command.contains("Test-Path"), "{command}");
        assert!(command.contains("missing"), "{command}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pretool_wraps_plain_shell_commands_for_every_provider() {
        for provider in [
            HookProvider::Codex,
            HookProvider::Claude,
            HookProvider::Gemini,
        ] {
            let (root, session) = empty_session("hook-pre-provider");
            let input = match provider {
                HookProvider::Gemini => json!({
                    "event_name": "BeforeTool",
                    "tool_name": "run_shell_command",
                    "tool_input": {
                        "command": "echo hello"
                    }
                }),
                _ => json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {
                        "command": "echo hello"
                    }
                }),
            };
            let output = handle_hook(provider, DEFAULT_SESSION, &session, input).unwrap();
            let command = match provider {
                HookProvider::Gemini => output["hookSpecificOutput"]["tool_input"]["command"]
                    .as_str()
                    .unwrap(),
                _ => output["hookSpecificOutput"]["updatedInput"]["command"]
                    .as_str()
                    .unwrap(),
            };
            assert!(command.contains("exec"), "{command}");
            assert!(command.contains("echo hello"), "{command}");
            assert!(!command.contains("--shell-b64"), "{command}");
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn pretool_non_default_session_is_inserted_before_command() {
        let (root, session) = empty_session("hook-pre-session");
        let input = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "echo hello"
            }
        });
        let output = handle_hook(HookProvider::Claude, "project-a", &session, input).unwrap();
        let command = output["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(command.contains("--session"), "{command}");
        assert!(command.contains("project-a"), "{command}");
        assert!(command.contains("echo hello"), "{command}");
        assert!(!command.contains("--shell-b64"), "{command}");
        let _ = std::fs::remove_dir_all(root);
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
        let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
        let command = output["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(command.contains("exec"), "{command}");
        assert!(!command.contains("--shell-b64"), "{command}");
        assert!(
            !command.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
            "{command}"
        );
        assert!(command.contains("<<OPENAI_API_KEY_"), "{command}");
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
    fn hook_text_masks_runpod_token_as_plain_text() {
        let (root, session) = empty_session("hook-runpod-text");
        let raw = concat!("RUNPOD=", "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef");
        let masked = mask_hook_text(&session, raw).unwrap();
        assert!(!masked.contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"));
        assert!(masked.contains("<<RUNPOD_API_KEY_"), "{masked}");
        assert_eq!(session.resolve_all(&masked).unwrap(), raw);
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
        let output = handle_hook(HookProvider::Gemini, DEFAULT_SESSION, &session, input).unwrap();
        assert_eq!(output["decision"], "allow");
        let command = output["hookSpecificOutput"]["tool_input"]["command"]
            .as_str()
            .unwrap();
        assert!(command.contains("exec"), "{command}");
        assert!(!command.contains("--shell-b64"), "{command}");
        assert!(
            !command.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
            "{command}"
        );
        assert!(command.contains("<<OPENAI_API_KEY_"), "{command}");
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

    fn env_policy(allowed: &[&str], denied: &[&str]) -> EnvPolicy {
        EnvPolicy {
            allowed: allowed
                .iter()
                .map(|name| name.to_ascii_lowercase())
                .collect(),
            denied: denied
                .iter()
                .map(|name| name.to_ascii_lowercase())
                .collect(),
        }
    }
}
