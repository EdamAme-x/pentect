//! `pentect agent`: a minimal tool-boundary adapter.
//!
//! It demonstrates the product loop:
//! shell tool input -> force execution through `pentect exec`;
//! command output -> mask before it returns to the AI.
//! `read` is a one-way human preview. `exec` and hooks keep vault handles in
//! process memory so later tool commands can reuse them without persisting raw
//! recovery material.

mod approval;
mod approve_ui;
mod config;
mod extension_adapter;
mod image_ocr;
mod masking;
mod memory_vault;
mod session;
mod shell;

use approval::{ticket_summary, ApprovalQueue, ApprovalTicket, ApprovalTicketDraft};
use approve_ui::{ApprovalDecision, ApprovalRequest};
use config::{approval_bypassed_by_config, approval_config_state};
use masking::{
    contains_unresolved_masked_handle, env_alias_recovery, is_ascii_word_char, is_env_name_byte,
    live_output_kind, OutputMasker, ToolScalarInput,
};
#[cfg(test)]
use masking::{first_reusable_env_name, mask_live_output, mask_tool_output};
use memory_vault::{MemoryVaultClient, ENV_ADDR, ENV_TOKEN};
use pentect_core::{
    infer_kind, parse_placeholder, Config, Engine, Input, Kind, MaskResult, Pack, Profile,
    RegionKind,
};
use serde_json::{json, Value};
use session::{checked_session_name, session_root, RecoveryStore, Session};
use sha2::{Digest, Sha256};
use shell::{next_shell_word, powershell_word, shell_quote_unix};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_SESSION: &str = "default";
const PENTECT_AGENT_LAUNCHED_ENV: &str = "PENTECT_AGENT_LAUNCHED";
const PENTECT_CODEX_EXEC_PROXY_ENV: &str = "PENTECT_CODEX_EXEC_PROXY";
const LIVE_MASK_CHUNK_BYTES: usize = 64 * 1024;
const LIVE_MASK_CHUNK_LINES: usize = 2048;
const DASHBOARD_HEARTBEAT_MAX_AGE: Duration = Duration::from_secs(3);

pub(crate) type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

pub fn run() -> i32 {
    run_from(std::env::args().collect())
}

pub fn run_from(args: Vec<String>) -> i32 {
    match args.get(1).map(String::as_str) {
        None => cmd_dashboard(&args),
        Some("dashboard") => cmd_dashboard(&args),
        Some("--dir" | "--session" | "--port") => cmd_dashboard(&args),
        Some("read") => cmd_read(&args),
        Some("view") => cmd_view(&args),
        Some("exec") => cmd_exec(&args),
        Some("resolve") => cmd_resolve(&args),
        Some("approve") => cmd_approve(&args),
        Some("hook") => cmd_hook(&args),
        Some("vault") => cmd_vault(&args),
        Some("purge") => cmd_purge(&args),
        _ => {
            usage();
            2
        }
    }
}

pub fn mask_input_into_active_memory_vault(
    input: Input,
    profile: Profile,
    packs: Vec<Pack>,
    disclose_length: bool,
) -> Result<Option<MaskResult>, String> {
    let Some(client) = MemoryVaultClient::from_env() else {
        return Ok(None);
    };
    mask_input_into_memory_vault_client(&client, input, profile, packs, disclose_length).map(Some)
}

fn mask_input_into_memory_vault_client(
    client: &MemoryVaultClient,
    input: Input,
    profile: Profile,
    packs: Vec<Pack>,
    disclose_length: bool,
) -> Result<MaskResult, String> {
    let key = client.key().map_err(|e| e.to_string())?;
    let engine = Engine::with_profile_and_packs(profile, packs, false);
    let cfg = Config {
        disclose_length,
        ..Config::new(key)
    };
    let result = engine.mask(input, &cfg);
    let mut recovery = result.recovery.clone();
    recovery.extend_same_key(env_alias_recovery(&result.masked, &key));
    client
        .add_recovery(&key, &recovery)
        .map_err(|e| e.to_string())?;
    client
        .add_masked_count(result.summary.masked_count as u64)
        .map_err(|e| e.to_string())?;
    Ok(result)
}

pub fn active_masked_count() -> Result<Option<u64>, String> {
    let Some(client) = MemoryVaultClient::from_env() else {
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

pub fn resolve_text_from_active_memory_vault(text: &str) -> Result<Option<String>, String> {
    if MemoryVaultClient::from_env().is_none() {
        return Ok(None);
    }
    let session = Session::open_capability("default").map_err(|e| e.to_string())?;
    let store = RecoveryStore::load(&session).map_err(|e| e.to_string())?;
    let resolved = store.resolve_all(text).map_err(|e| e.to_string())?;
    if contains_unresolved_masked_handle(&resolved) {
        return Err("unknown masked handle in exec-server request".to_string());
    }
    Ok(Some(resolved))
}

pub fn preflight_exec_server_process_start_from_active_memory_vault(
    argv: &[String],
    env: &[(String, String)],
) -> Result<Option<Vec<(String, String)>>, String> {
    if MemoryVaultClient::from_env().is_none() {
        return Ok(None);
    }
    let session_name = default_session_name()?;
    let session = Session::open_capability(&session_name).map_err(|e| e.to_string())?;
    let store = RecoveryStore::load(&session).map_err(|e| e.to_string())?;
    let argv_mode = ExecMode::Program(argv.to_vec());
    let opts = ExecOpts {
        session: session_name,
        live: false,
        approve: false,
        mode: ExecMode::Shell(exec_server_approval_command(&argv_mode, env)),
    };
    prepare_exec_secret_inputs(&store, &opts)?;
    let approval = exec_approval(&store, &opts)?;
    let already_allowed = approval_always_granted(&opts.session, &approval)?;
    if approval.requires_approval() && !already_allowed {
        match approval_decision_for_exec(&opts.session, &approval)? {
            ApprovalDecision::Once | ApprovalDecision::Always => {}
            ApprovalDecision::Decline => return Err("command declined".to_string()),
        }
    }
    requested_env_bindings(&store, &argv_mode).map(Some)
}

pub fn mask_tool_output_into_active_memory_vault(text: &str) -> Result<Option<String>, String> {
    let Some(client) = MemoryVaultClient::from_env() else {
        return Ok(None);
    };
    let session = Session::open_capability("default").map_err(|e| e.to_string())?;
    let store = RecoveryStore::load(&session).map_err(|e| e.to_string())?;
    let mut masker = OutputMasker::new_deferred(store)?;
    let masked = masker.mask_tool_output(text)?;
    let masked_count = masker.masked_count();
    masker.flush()?;
    client
        .add_masked_count(masked_count)
        .map_err(|e| e.to_string())?;
    Ok(Some(masked))
}

fn exec_server_approval_command(mode: &ExecMode, env: &[(String, String)]) -> String {
    let mut command = display_exec_mode(mode);
    for (name, value) in env {
        if contains_pentect_masked_handle(value) {
            command.push(' ');
            command.push_str(name);
            command.push('=');
            command.push_str(value);
        }
    }
    command
}

fn usage() {
    eprintln!(
        "pentect\n\
         pentect exec \"<command>\"\n\
         pentect view <HANDLE>\n\
         pentect resolve [PATH...]\n\
         \n\
         exec runs commands with masked output.\n\
         view handle metadata.\n\
         resolve rewrites files containing handles, or resolves stdin when no path is given."
    );
}

fn cmd_dashboard(args: &[String]) -> i32 {
    let opts = match DashboardOpts::parse(args) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    if let Some(dir) = &opts.dir {
        if let Err(e) = std::env::set_current_dir(dir) {
            return die(format!("could not open directory '{}': {e}", dir.display()));
        }
    }
    let session = match opts.session {
        Some(session) => session,
        None => match default_session_name() {
            Ok(session) => session,
            Err(e) => return die(&e),
        },
    };
    match run_dashboard(&session, opts.port) {
        Ok(()) => 0,
        Err(e) => die(&e),
    }
}

fn dashboard_request(session: &str) -> Result<ApprovalRequest, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("could not read current dir: {e}"))?;
    let vault = Session::vault_status(session).map_err(|e| e.to_string())?;
    let vault_line = match &vault {
        Some(status) => format!("active ({status})"),
        None => "not created yet".to_string(),
    };
    let implicit_session = default_session_name().is_ok_and(|default| default == session);
    let body = if implicit_session {
        format!("{}\nvault: {vault_line}", cwd.display())
    } else {
        format!("{}\nsession: {session}\nvault: {vault_line}", cwd.display())
    };
    let warnings = if vault.is_some() {
        vec!["Memory vault is active for this process tree.".to_string()]
    } else {
        Vec::new()
    };
    Ok(ApprovalRequest {
        prompt: "status".to_string(),
        body,
        approve_label: "close".to_string(),
        deny_label: "close".to_string(),
        allow_always: false,
        warnings,
    })
}

fn run_dashboard(session: &str, port: Option<u16>) -> Result<(), String> {
    let queue = ApprovalQueue::open_dashboard(session)?;
    if let Some(port) = port {
        return queue
            .serve_web(session, port, DASHBOARD_HEARTBEAT_MAX_AGE)
            .map_err(|e| e.to_string());
    }

    let heartbeat_queue = queue.clone();
    let _heartbeat_thread = std::thread::spawn(move || loop {
        let _ = heartbeat_queue.heartbeat(None);
        std::thread::sleep(Duration::from_millis(500));
    });

    print_dashboard_status(session, &queue, None)?;
    loop {
        if approval_bypassed_by_config()? {
            print_dashboard_status(session, &queue, None)?;
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }
        if let Some(ticket) = queue.next_pending()? {
            let request = ApprovalRequest {
                prompt: "secret".to_string(),
                body: ticket_summary(&ticket),
                approve_label: "once".to_string(),
                deny_label: "decline".to_string(),
                allow_always: true,
                warnings: ticket_warnings(&ticket),
            };
            let decision = approve_ui::run(&request).map_err(|e| e.to_string())?;
            queue.decide(&ticket, decision, "ui")?;
            print_dashboard_status(session, &queue, None)?;
        } else {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

fn print_dashboard_status(
    session: &str,
    queue: &ApprovalQueue,
    port: Option<u16>,
) -> Result<(), String> {
    let request = dashboard_request(session)?;
    let config = approval_config_state()?;
    print!("\x1b[2J\x1b[H");
    println!("pentect");
    println!("{}", request.body);
    if let Some(port) = port {
        println!("port: {port}");
    }
    println!();
    if config.effective_no_approve {
        println!(
            "approval: no-approve ({})",
            approval_source_label(config.effective_source)
        );
    } else {
        println!(
            "approval: required ({})",
            approval_source_label(config.effective_source)
        );
    }
    let history = queue.recent_history(5)?;
    if !history.is_empty() {
        println!();
        println!("history");
        for line in history {
            println!("{line}");
        }
    }
    let _ = std::io::stdout().flush();
    Ok(())
}

fn approval_source_label(source: config::ApprovalConfigSource) -> &'static str {
    match source {
        config::ApprovalConfigSource::Project => "project config",
        config::ApprovalConfigSource::Global => "global config",
        config::ApprovalConfigSource::Default => "default",
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
    let input = Input { kind, data };
    match mask_input_into_active_memory_vault(
        input.clone(),
        Profile::Strict,
        Vec::new(),
        opts.disclose_length,
    ) {
        Ok(Some(result)) => {
            print_read_result(result, opts.emit_meta);
            return 0;
        }
        Ok(None) => {}
        Err(e) => return die(&e),
    }
    let engine = Engine::with_profile(Profile::Strict);
    let cfg = Config {
        disclose_length: opts.disclose_length,
        ..Config::generate()
    };
    let result = engine.mask(input, &cfg);
    print_read_result(result, opts.emit_meta);
    0
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
    match parts.length_hint {
        Some(hint) => println!("length: {}", hint.short()),
        None => println!("length: -"),
    }
    0
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
    let store = match RecoveryStore::load(&session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    if let Err(e) = prepare_exec_secret_inputs(&store, &opts) {
        return die(&e);
    }
    let approval = match exec_approval(&store, &opts) {
        Ok(approval) => approval,
        Err(e) => return die(&e),
    };
    let already_allowed = match approval_always_granted(&opts.session, &approval) {
        Ok(allowed) => allowed,
        Err(e) => return die(&e),
    };
    if opts.approve {
        match request_approval(&opts, &approval, false) {
            Ok(ApprovalDecision::Once) => {}
            Ok(ApprovalDecision::Always) => {
                if let Err(e) = ApprovalQueue::open(&opts.session).and_then(|queue| {
                    queue.record(&approval.ticket(), ApprovalDecision::Always, "local")
                }) {
                    return die(&e);
                }
            }
            Ok(ApprovalDecision::Decline) => {
                eprintln!("[pentect] command declined");
                return 1;
            }
            Err(e) => return die(&e),
        }
    } else if approval.requires_approval() && !already_allowed {
        match approval_decision_for_exec(&opts.session, &approval) {
            Ok(ApprovalDecision::Once | ApprovalDecision::Always) => {}
            Ok(ApprovalDecision::Decline) => {
                eprintln!("[pentect] command declined");
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
    let store = match RecoveryStore::load(&session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    match opts.mode {
        ResolveMode::Files(paths) => {
            match approval_decision_for_resolve(&opts.session, &paths) {
                Ok(ApprovalDecision::Once | ApprovalDecision::Always) => {}
                Ok(ApprovalDecision::Decline) => {
                    eprintln!("[pentect] resolve declined");
                    return 1;
                }
                Err(e) => return die(&e),
            }
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
                match approval_decision_for_resolve_stdin(&opts.session, &input) {
                    Ok(ApprovalDecision::Once | ApprovalDecision::Always) => {}
                    Ok(ApprovalDecision::Decline) => {
                        eprintln!("[pentect] resolve declined");
                        return 1;
                    }
                    Err(e) => return die(&e),
                }
            }
            print!("{resolved}");
            let _ = std::io::stdout().flush();
        }
    }
    0
}

fn approval_decision_for_resolve(
    session: &str,
    paths: &[PathBuf],
) -> Result<ApprovalDecision, String> {
    let ticket = resolve_approval_ticket(paths);
    if ApprovalQueue::open(session)?.always_granted(&ticket.fingerprint) {
        return Ok(ApprovalDecision::Always);
    }
    approval_decision_for_ticket(session, &ticket)
}

fn approval_decision_for_resolve_stdin(
    session: &str,
    input: &str,
) -> Result<ApprovalDecision, String> {
    let ticket = resolve_stdin_approval_ticket(input);
    if ApprovalQueue::open(session)?.always_granted(&ticket.fingerprint) {
        return Ok(ApprovalDecision::Always);
    }
    approval_decision_for_ticket(session, &ticket)
}

fn resolve_approval_ticket(paths: &[PathBuf]) -> ApprovalTicket {
    let command = format!(
        "pentect resolve {}",
        paths
            .iter()
            .map(|path| shell_quote_path(path))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut material = String::from("resolve-local-write-v1\0");
    material.push_str(&command);
    material.push('\0');
    for path in paths {
        material.push_str(&path.to_string_lossy());
        material.push('\0');
        if let Ok(input) = read_input(path, InputFormat::Text) {
            material.push_str(&secret_value_hash(&input));
        }
        material.push('\0');
    }
    let digest = Sha256::digest(material.as_bytes());
    ApprovalTicket::new(ApprovalTicketDraft {
        fingerprint: data_encoding::HEXLOWER.encode(&digest[..16]),
        command,
        env_names: Vec::new(),
        secret_files: paths
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect(),
        direct_handles: 0,
        destinations: Vec::new(),
        may_send_network: false,
        may_write_local_file: true,
    })
}

fn resolve_stdin_approval_ticket(input: &str) -> ApprovalTicket {
    let command = "pentect resolve <stdin>".to_string();
    let mut material = String::from("resolve-stdin-local-write-v1\0");
    material.push_str(&secret_value_hash(input));
    material.push('\0');
    let digest = Sha256::digest(material.as_bytes());
    ApprovalTicket::new(ApprovalTicketDraft {
        fingerprint: data_encoding::HEXLOWER.encode(&digest[..16]),
        command,
        env_names: Vec::new(),
        secret_files: Vec::new(),
        direct_handles: masked_handles_in_text(input).len(),
        destinations: Vec::new(),
        may_send_network: false,
        may_write_local_file: true,
    })
}

fn shell_quote_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    if cfg!(windows) {
        powershell_word(&value)
    } else {
        shell_quote_unix(&value)
    }
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
            "approve: .pentect/config.toml\n",
        )
    );
}

fn cmd_approve(args: &[String]) -> i32 {
    let opts = match ExecOpts::parse(args).and_then(prepare_stdin_exec_opts) {
        Ok(o) => o,
        Err(e) => return die(&e),
    };
    let session = match Session::open_capability(&opts.session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    let store = match RecoveryStore::load(&session) {
        Ok(s) => s,
        Err(e) => return die(&e),
    };
    if let Err(e) = prepare_exec_secret_inputs(&store, &opts) {
        return die(&e);
    }
    let approval = match exec_approval(&store, &opts) {
        Ok(approval) => approval,
        Err(e) => return die(&e),
    };
    match request_approval(&opts, &approval, true) {
        Ok(ApprovalDecision::Once) => 0,
        Ok(ApprovalDecision::Always) => match ApprovalQueue::open(&opts.session)
            .and_then(|queue| queue.record(&approval.ticket(), ApprovalDecision::Always, "local"))
        {
            Ok(()) => 0,
            Err(e) => die(&e),
        },
        Ok(ApprovalDecision::Decline) => 1,
        Err(e) => die(&e),
    }
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

fn cmd_vault(args: &[String]) -> i32 {
    match args.get(2).map(String::as_str) {
        Some("--serve") if args.len() == 3 => memory_vault::serve_memory_vault(),
        _ => die("vault accepts only `--serve`"),
    }
}

fn request_approval(
    opts: &ExecOpts,
    approval: &ExecApproval,
    preview: bool,
) -> Result<ApprovalDecision, String> {
    if approval_bypassed_by_config()? {
        return Ok(ApprovalDecision::Once);
    }
    let request = ApprovalRequest {
        prompt: if preview {
            "preview".to_string()
        } else {
            "run".to_string()
        },
        body: approval.body(),
        approve_label: "once".to_string(),
        deny_label: "decline".to_string(),
        allow_always: true,
        warnings: approval_warnings(opts, approval),
    };
    approve_ui::run(&request).map_err(|e| e.to_string())
}

fn approval_warnings(opts: &ExecOpts, approval: &ExecApproval) -> Vec<String> {
    let mut warnings = Vec::new();
    if opts.live {
        warnings.push("live output is masked in chunks".to_string());
    }
    if !approval.secret_files.is_empty() {
        warnings.push("this command can read local secret file content".to_string());
    }
    if approval.may_send_network && approval.requires_approval() {
        warnings.push("this command may send approved secrets to the network".to_string());
    }
    if approval.may_write_local_file && approval.requires_approval() {
        warnings.push("this command may write approved secrets to local files".to_string());
    }
    warnings
}

fn approval_decision_for_exec(
    session: &str,
    approval: &ExecApproval,
) -> Result<ApprovalDecision, String> {
    let ticket = approval.ticket();
    approval_decision_for_ticket(session, &ticket)
}

fn approval_decision_for_ticket(
    session: &str,
    ticket: &ApprovalTicket,
) -> Result<ApprovalDecision, String> {
    if approval_bypassed_by_config()? {
        return Ok(ApprovalDecision::Once);
    }
    let queue = ApprovalQueue::open(session)?;
    if !queue.dashboard_alive(DASHBOARD_HEARTBEAT_MAX_AGE) {
        queue.record(ticket, ApprovalDecision::Decline, "auto")?;
        return Err(
            "approval needed; run `pentect` or set `.pentect/config.toml` no_approve = true."
                .to_string(),
        );
    }
    queue.submit(ticket)?;
    queue.wait_for_decision(ticket, DASHBOARD_HEARTBEAT_MAX_AGE)
}

fn ticket_warnings(ticket: &ApprovalTicket) -> Vec<String> {
    let mut warnings = Vec::new();
    if ticket.may_send_network {
        warnings.push("may send secret".to_string());
    }
    if ticket.may_write_local_file {
        warnings.push("may write secret".to_string());
    }
    warnings
}

#[derive(Debug)]
struct ExecApproval {
    command: String,
    env_refs: Vec<EnvApprovalRef>,
    secret_files: Vec<SecretFileRef>,
    direct_handles: Vec<String>,
    destinations: Vec<String>,
    may_send_network: bool,
    may_write_local_file: bool,
}

#[derive(Debug)]
struct EnvApprovalRef {
    name: String,
    value_hash: String,
}

#[derive(Debug)]
struct SecretFileRef {
    path: String,
    value_hashes: Vec<String>,
}

impl ExecApproval {
    fn requires_approval(&self) -> bool {
        !self.env_refs.is_empty()
            || !self.secret_files.is_empty()
            || !self.direct_handles.is_empty()
            || self.may_send_network
    }

    fn env_names(&self) -> Vec<String> {
        self.env_refs.iter().map(|env| env.name.clone()).collect()
    }

    fn fingerprint(&self) -> String {
        let mut material = String::new();
        material.push_str("approval-v1\0");
        material.push_str(&self.command);
        material.push('\0');
        for env in &self.env_refs {
            material.push_str(&env.name);
            material.push('\0');
            material.push_str(&env.value_hash);
            material.push('\0');
        }
        material.push_str("files:");
        for file in &self.secret_files {
            material.push_str(&file.path);
            material.push('\0');
            for hash in &file.value_hashes {
                material.push_str(hash);
                material.push('\0');
            }
        }
        material.push_str("handles:");
        for handle in &self.direct_handles {
            material.push_str(handle);
            material.push('\0');
        }
        material.push_str("network:");
        material.push_str(if self.may_send_network {
            "true"
        } else {
            "false"
        });
        material.push('\0');
        material.push_str("local-write:");
        material.push_str(if self.may_write_local_file {
            "true"
        } else {
            "false"
        });
        material.push('\0');
        let digest = Sha256::digest(material.as_bytes());
        data_encoding::HEXLOWER.encode(&digest[..16])
    }

    fn body(&self) -> String {
        let mut lines = vec!["command".to_string(), self.command.clone()];
        if self.requires_approval() {
            lines.push(String::new());
            let env_names = self.env_names();
            if !env_names.is_empty() {
                lines.push(format!("secret {}", env_names.join(", ")));
            }
            if !self.secret_files.is_empty() {
                lines.push(format!(
                    "file {}",
                    self.secret_files
                        .iter()
                        .map(|file| file.path.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !self.direct_handles.is_empty() {
                lines.push(format!("handles {}", self.direct_handles.len()));
            }
            if !self.destinations.is_empty() {
                lines.push(format!("send {}", self.destinations.join(", ")));
            } else if self.may_send_network {
                lines.push("send possible".to_string());
            }
            if self.may_write_local_file {
                lines.push("write local file".to_string());
            }
        } else {
            lines.push(String::new());
            lines.push("no secret".to_string());
        }
        lines.join("\n")
    }

    fn ticket(&self) -> ApprovalTicket {
        ApprovalTicket::new(ApprovalTicketDraft {
            fingerprint: self.fingerprint(),
            command: self.command.clone(),
            env_names: self.env_names(),
            secret_files: self
                .secret_files
                .iter()
                .map(|file| file.path.clone())
                .collect(),
            direct_handles: self.direct_handles.len(),
            destinations: self.destinations.clone(),
            may_send_network: self.may_send_network,
            may_write_local_file: self.may_write_local_file,
        })
    }
}

fn exec_approval(store: &RecoveryStore, opts: &ExecOpts) -> Result<ExecApproval, String> {
    let command = display_exec_mode(&opts.mode);
    let env = requested_env_bindings(store, &opts.mode)?;
    let mut env_refs = env
        .into_iter()
        .map(|(name, value)| EnvApprovalRef {
            name,
            value_hash: secret_value_hash(&value),
        })
        .collect::<Vec<_>>();
    env_refs.sort_by_key(|env| env.name.to_ascii_lowercase());
    env_refs.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name));
    let secret_files = secret_file_refs_for_mode(store, &opts.mode)?;
    let direct_handles = masked_handles_in_mode(&opts.mode);
    let destinations = network_destinations(&command);
    let may_send_network = !destinations.is_empty() || command_may_send_network(&command);
    let may_write_local_file = command_may_write_local_file(&command);
    Ok(ExecApproval {
        command,
        env_refs,
        secret_files,
        direct_handles,
        destinations,
        may_send_network,
        may_write_local_file,
    })
}

fn approval_always_granted(session: &str, approval: &ExecApproval) -> Result<bool, String> {
    if !approval.requires_approval() {
        return Ok(false);
    }
    Ok(ApprovalQueue::open(session)?.always_granted(&approval.fingerprint()))
}

fn prepare_exec_secret_inputs(store: &RecoveryStore, opts: &ExecOpts) -> Result<(), String> {
    if let ExecMode::Shell(command) = &opts.mode {
        let command = resolve_command_text(store, command)?;
        register_local_file_inputs(store, &command)?;
    }
    Ok(())
}

fn secret_file_refs_for_mode(
    store: &RecoveryStore,
    mode: &ExecMode,
) -> Result<Vec<SecretFileRef>, String> {
    let ExecMode::Shell(command) = mode else {
        return Ok(Vec::new());
    };
    let command = resolve_command_text(store, command)?;
    secret_file_refs_for_script(&command)
}

fn secret_file_refs_for_script(script: &str) -> Result<Vec<SecretFileRef>, String> {
    let mut refs = Vec::new();
    let mut seen = BTreeSet::new();
    let engine = Engine::with_profile(Profile::Strict);
    let cfg = Config::generate();
    for path in local_file_input_paths(script) {
        if !path.is_file() {
            continue;
        }
        let Ok(input) = read_input(&path, InputFormat::Text) else {
            continue;
        };
        let value_hash = secret_value_hash(&input);
        let result = engine.mask(
            Input {
                kind: infer_kind(&path),
                data: input,
            },
            &cfg,
        );
        if result.recovery.is_empty() {
            continue;
        }
        let display = path.to_string_lossy().to_string();
        if !seen.insert(display.clone()) {
            continue;
        }
        refs.push(SecretFileRef {
            path: display,
            value_hashes: vec![value_hash],
        });
    }
    Ok(refs)
}

fn secret_value_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    data_encoding::HEXLOWER.encode(&digest[..16])
}

fn masked_handles_in_mode(mode: &ExecMode) -> Vec<String> {
    let text = match mode {
        ExecMode::Shell(command) => command.clone(),
        ExecMode::Program(args) => args.join(" "),
        ExecMode::Stdin => String::new(),
    };
    masked_handles_in_text(&text)
}

fn masked_handles_in_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while let Some(start) = text[offset..].find("<<") {
        let start = offset + start;
        let Some(end_rel) = text[start + 2..].find(">>") else {
            break;
        };
        let end = start + 2 + end_rel + 2;
        let handle = &text[start..end];
        if !handle.starts_with("<<PENTECT_APPROVAL_")
            && !out.iter().any(|existing| existing == handle)
        {
            out.push(handle.to_string());
        }
        offset = end;
    }
    out
}

fn network_destinations(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some((word, _, next)) = next_shell_word(command, cursor) {
        let cleaned = word.trim_matches(|ch: char| matches!(ch, '\'' | '"' | ',' | ')' | ']'));
        if (cleaned.starts_with("https://") || cleaned.starts_with("http://"))
            && !out.iter().any(|existing| existing == cleaned)
        {
            out.push(cleaned.to_string());
        }
        cursor = next;
    }
    out
}

fn command_may_send_network(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    let mut cursor = 0usize;
    while let Some((word, _, next)) = next_shell_word(&lower, cursor) {
        let word = word.trim_matches(|ch: char| matches!(ch, '\'' | '"' | ',' | ';' | '(' | ')'));
        if matches!(
            word,
            "curl"
                | "curl.exe"
                | "wget"
                | "wget.exe"
                | "ssh"
                | "scp"
                | "gh"
                | "http"
                | "httpie"
                | "invoke-restmethod"
                | "invoke-webrequest"
                | "irm"
                | "iwr"
        ) {
            return true;
        }
        cursor = next;
    }
    lower.contains("://")
}

fn command_may_write_local_file(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    let mut cursor = 0usize;
    while let Some((word, _, next)) = next_shell_word(&lower, cursor) {
        let word = word.trim_matches(|ch: char| matches!(ch, '\'' | '"' | ',' | ';' | '(' | ')'));
        if matches!(
            word,
            "set-content" | "add-content" | "out-file" | "tee-object" | "sc" | "ac"
        ) || word.contains("::writealltext")
            || looks_like_shell_redirection(word)
        {
            return true;
        }
        cursor = next;
    }
    false
}

fn looks_like_shell_redirection(word: &str) -> bool {
    if !word.contains('>') {
        return false;
    }
    !word.contains("=>")
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
        ExecMode::Stdin => "<stdin>".to_string(),
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

fn open_hook_session(cli: bool, session_name: &str) -> Result<Session, String> {
    if cli {
        Session::open_capability(session_name)
    } else {
        Session::open(session_name)
    }
    .map_err(|e| e.to_string())
}

fn run_resolved_command(
    store: &RecoveryStore,
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
            run_shell_script(&command, &env, &opts.session)
        }
        ExecMode::Stdin => Err("internal error: exec stdin was not prepared".to_string()),
    }
}

fn run_resolved_command_live(store: &RecoveryStore, opts: &ExecOpts) -> Result<ExitStatus, String> {
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
            let mut shell = shell_script_command();
            apply_child_env_overlays(&mut shell, &env, &opts.session);
            run_live_command(shell, Some(&command), store.clone())
        }
        ExecMode::Stdin => Err("internal error: exec stdin was not prepared".to_string()),
    }
}

fn resolve_command_args(store: &RecoveryStore, args: &[String]) -> Result<Vec<String>, String> {
    args.iter()
        .map(|arg| resolve_command_text(store, arg))
        .collect()
}

fn resolve_command_text(store: &RecoveryStore, text: &str) -> Result<String, String> {
    let resolved = store.resolve_all(text).map_err(|e| e.to_string())?;
    if contains_unresolved_masked_handle(&resolved) {
        return Err(
            "unknown masked handle; use it inside the same running Pentect-launched agent session or re-register it with `pentect exec`"
                .to_string(),
        );
    }
    Ok(resolved)
}

fn resolve_path_in_place(store: &RecoveryStore, path: &Path) -> Result<(), String> {
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
    }
    Ok(())
}

fn apply_child_env_overlays(command: &mut Command, env: &[(String, String)], session: &str) {
    command.env_remove(ENV_ADDR);
    command.env_remove(ENV_TOKEN);
    command.env_remove(PENTECT_AGENT_LAUNCHED_ENV);
    apply_env_bindings(command, env);
    apply_pentect_session(command, session);
}

fn apply_env_bindings(command: &mut Command, env: &[(String, String)]) {
    for (name, value) in env {
        command.env(name, value);
    }
}

fn apply_pentect_session(command: &mut Command, session: &str) {
    command.env("PENTECT_SESSION", session);
}

fn requested_env_bindings(
    store: &RecoveryStore,
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
    let mut by_name = BTreeMap::new();
    for (name, value) in available {
        by_name.insert(name.to_ascii_lowercase(), (name, value));
    }
    let mut out = Vec::new();
    for name in names {
        if let Some(binding) = by_name.get(&name) {
            out.push(binding.clone());
        }
    }
    Ok(out)
}

fn referenced_env_names(mode: &ExecMode) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    match mode {
        ExecMode::Shell(command) => {
            collect_powershell_env_refs(command, &mut names);
            collect_printenv_refs(command, &mut names);
            collect_percent_env_refs(command, &mut names);
            if !cfg!(windows) {
                collect_bare_dollar_env_refs(command, &mut names);
            }
        }
        ExecMode::Stdin => {}
        ExecMode::Program(args) => {
            let text = args.join(" ");
            collect_powershell_env_refs(&text, &mut names);
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

fn register_local_file_inputs(store: &RecoveryStore, script: &str) -> Result<(), String> {
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
) -> Result<std::process::Output, String> {
    let mut command = shell_script_command();
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
fn shell_script_command() -> Command {
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
    fn pentect_launch_command(self) -> &'static str {
        match self {
            HookProvider::Codex => "pentect codex",
            HookProvider::Claude => "pentect claude",
            HookProvider::Generic => "pentect codex|claude",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookPhase {
    BeforeTool,
    AfterTool,
    Other,
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
    Pdf,
    Image,
}

struct ReadOpts {
    input_format: InputFormat,
    kind: Option<Kind>,
    disclose_length: bool,
    emit_meta: bool,
    path: PathBuf,
}

impl ReadOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut input_format = InputFormat::Text;
        let mut kind = None;
        let mut disclose_length = false;
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
            disclose_length,
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

struct DashboardOpts {
    session: Option<String>,
    dir: Option<PathBuf>,
    port: Option<u16>,
}

impl DashboardOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut session = None;
        let mut dir = None;
        let mut port = None;
        let mut i = if matches!(args.get(1).map(String::as_str), Some("dashboard")) {
            2
        } else {
            1
        };
        while i < args.len() {
            match args[i].as_str() {
                "--session" => {
                    session = Some(
                        checked_session_name(&value(args, &mut i, "--session")?)
                            .map_err(|e| e.to_string())?,
                    )
                }
                "--dir" => dir = Some(PathBuf::from(value(args, &mut i, "--dir")?)),
                "--port" => {
                    let raw = value(args, &mut i, "--port")?;
                    port = Some(
                        raw.parse::<u16>()
                            .map_err(|_| format!("invalid port: {raw}"))?,
                    );
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                arg => return Err(format!("unexpected dashboard argument: {arg}")),
            }
        }
        Ok(Self { session, dir, port })
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
        if let Ok(session) = std::env::var("PENTECT_SESSION") {
            return checked_session_name(&session).map_err(|e| e.to_string());
        }
        let _ = input;
        default_session_name()
    }
}

struct ExecOpts {
    session: String,
    live: bool,
    approve: bool,
    mode: ExecMode,
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

enum ResolveMode {
    Files(Vec<PathBuf>),
    Stdin,
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
        let mut approve = false;
        let mut stdin = false;
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
                "--stdin" => {
                    stdin = true;
                    i += 1;
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
                        approve,
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
                        approve,
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
                        approve,
                        mode: ExecMode::Shell(args[i..].join(" ")),
                    });
                }
            }
        }
        if stdin {
            return Ok(Self {
                session: checked_session_name(&session).map_err(|e| e.to_string())?,
                live,
                approve,
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
    let bytes = data_encoding::BASE64
        .decode(value.as_bytes())
        .map_err(|_| "exec --script-b64 requires valid base64".to_string())?;
    String::from_utf8(bytes).map_err(|_| "exec --script-b64 requires UTF-8 text".to_string())
}

fn default_session_name() -> Result<String, String> {
    match std::env::var("PENTECT_SESSION") {
        Ok(value) => checked_session_name(&value).map_err(|e| e.to_string()),
        Err(_) => default_directory_session_name(),
    }
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
            if let Some(reason) = image_tool_result_block_reason(session, tool_response)? {
                return Ok(after_tool_block_output(provider, &reason));
            }
            if let Some(reason) = unsupported_tool_result_reason(tool_response) {
                return Ok(after_tool_block_output(provider, &reason));
            }
            let store = RecoveryStore::load(session).map_err(|e| e.to_string())?;
            let mut masker = OutputMasker::new_deferred(store)?;
            let (updated, changed) = mask_tool_json(tool_response, &mut masker)?;
            masker.flush()?;
            if changed {
                Ok(after_tool_output(provider, updated))
            } else {
                Ok(json!({}))
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
            if let Some(reason) = image_tool_result_block_reason(&session, tool_response)? {
                return Ok(after_tool_block_output(provider, &reason));
            }
            if let Some(reason) = unsupported_tool_result_reason(tool_response) {
                return Ok(after_tool_block_output(provider, &reason));
            }
            let store = RecoveryStore::load(&session).map_err(|e| e.to_string())?;
            let mut masker = OutputMasker::new_deferred(store)?;
            let (updated, changed) = mask_tool_json(tool_response, &mut masker)?;
            masker.flush()?;
            if changed {
                Ok(after_tool_output(provider, updated))
            } else {
                Ok(json!({}))
            }
        }
        HookPhase::Other => Ok(json!({})),
    }
}

#[cfg(test)]
fn before_tool_updated_input(
    provider: HookProvider,
    session_name: &str,
    session: &Session,
    tool_name: &str,
    tool_input: &Value,
) -> Result<(Value, bool), String> {
    if is_read_like_tool_name(tool_name) {
        validate_read_before_tool(session, tool_name, tool_input)?;
    }
    if is_edit_like_tool_name(tool_name) {
        if let Some(updated) = apply_masked_old_edit_before_tool(session, tool_input)? {
            return Ok((updated, true));
        }
    }
    validate_masked_write_before_tool(session, tool_name, tool_input)?;
    if let Some(command) = tool_input.get("command").and_then(Value::as_str) {
        if let Some(reason) = pentect_human_only_command_reason(command) {
            return Err(reason);
        }
        if provider == HookProvider::Codex && codex_exec_proxy_enabled() {
            return Ok((tool_input.clone(), false));
        }
        let command = canonical_hook_shell_command(command)?;
        let mut updated = tool_input.clone();
        if let Some(object) = updated.as_object_mut() {
            object.insert(
                "command".to_string(),
                Value::String(wrap_shell_command(provider, session_name, &command)?),
            );
            return Ok((updated, true));
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
        validate_read_before_tool(&session, tool_name, tool_input)?;
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
    if let Some(command) = tool_input.get("command").and_then(Value::as_str) {
        if let Some(reason) = pentect_human_only_command_reason(command) {
            return Err(reason);
        }
        if provider == HookProvider::Codex && codex_exec_proxy_enabled() {
            return Ok((tool_input.clone(), false));
        }
        let command = canonical_hook_shell_command(command)?;
        let mut updated = tool_input.clone();
        if let Some(object) = updated.as_object_mut() {
            object.insert(
                "command".to_string(),
                Value::String(wrap_shell_command(provider, session_name, &command)?),
            );
            return Ok((updated, true));
        }
    }
    Ok((tool_input.clone(), false))
}

fn ensure_pentect_agent_launch(provider: HookProvider) -> Result<(), String> {
    ensure_pentect_agent_launch_required(provider, config::require_pentect_agent_by_config()?)
}

fn codex_exec_proxy_enabled() -> bool {
    std::env::var(PENTECT_CODEX_EXEC_PROXY_ENV).is_ok_and(|value| value == "1")
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
    Err(format!(
        "Pentect required; start with `{}`.",
        provider.pentect_launch_command()
    ))
}

fn agent_launch_proof_valid() -> bool {
    let Ok(proof) = std::env::var(PENTECT_AGENT_LAUNCHED_ENV) else {
        return false;
    };
    let Ok(token) = std::env::var(ENV_TOKEN) else {
        return false;
    };
    agent_launch_proof_matches(&proof, &token)
        && memory_vault_env_addr_is_loopback()
        && memory_vault_accepts_env_token()
}

fn agent_launch_proof_matches(proof: &str, token: &str) -> bool {
    token.len() >= 32 && proof == token
}

fn memory_vault_env_addr_is_loopback() -> bool {
    std::env::var(ENV_ADDR)
        .ok()
        .and_then(|addr| addr.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|addr| addr.ip().is_loopback())
}

fn memory_vault_accepts_env_token() -> bool {
    MemoryVaultClient::from_env().is_some_and(|client| client.key().is_ok())
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

fn validate_read_before_tool(
    session: &Session,
    tool_name: &str,
    tool_input: &Value,
) -> Result<(), String> {
    if !is_read_like_tool_name(tool_name) {
        return Ok(());
    }
    if read_tool_has_detected_secret(session, tool_input)? {
        return Err(read_tool_block_reason(tool_name));
    }
    Ok(())
}

fn read_tool_has_detected_secret(session: &Session, tool_input: &Value) -> Result<bool, String> {
    for path in read_tool_paths(tool_input) {
        let path = Path::new(path);
        let data = read_input(path, InputFormat::Text).map_err(|_| {
            "read target could not be scanned; use `pentect read PATH`.".to_string()
        })?;
        let result = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: infer_kind(path),
                data,
            },
            &Config::new(session.key),
        );
        if result.summary.masked_count > 0 {
            return Ok(true);
        }
    }
    Ok(false)
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
    let store = RecoveryStore::load(session).map_err(|e| e.to_string())?;
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
    let store = RecoveryStore::load(session).map_err(|e| e.to_string())?;
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
    let store = RecoveryStore::load(session).map_err(|e| e.to_string())?;
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
    let store = RecoveryStore::load(session).map_err(|e| e.to_string())?;
    let resolved = resolve_masked_text(&store, &content)?;
    if resolved != content {
        std::fs::write(&path, resolved)
            .map_err(|e| format!("could not repair '{}': {e}", path.display()))?;
    }
    Ok(true)
}

fn resolve_masked_text_if_needed(store: &RecoveryStore, content: &str) -> Result<String, String> {
    if contains_pentect_masked_handle(content) {
        resolve_masked_text(store, content)
    } else {
        Ok(content.to_string())
    }
}

fn resolve_masked_text(store: &RecoveryStore, content: &str) -> Result<String, String> {
    let resolved = store.resolve_all(content).map_err(|e| e.to_string())?;
    if contains_pentect_masked_handle(&resolved) {
        return Err(
            "resolve needed: re-read the source in this Pentect session, then retry Write."
                .to_string(),
        );
    }
    if resolved == content {
        return Err("resolve needed: no matching handle in this Pentect session.".to_string());
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
    let result = Engine::with_profile(Profile::Strict).mask(
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
            "--live" | "--approve" => {
                rest = rest[word_end..].trim_start();
            }
            "--stdin" => return None,
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

fn pentect_human_only_command_reason(command: &str) -> Option<String> {
    let invocation = parse_pentect_subcommand(command)?;
    match invocation.subcommand {
        PentectSubcommand::Exec | PentectSubcommand::Read | PentectSubcommand::Resolve => None,
    }
}

fn read_tool_block_reason(tool_name: &str) -> String {
    format!("{tool_name} found masked content; use `pentect read PATH`.")
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
    _provider: HookProvider,
    session_name: &str,
    masked_command: &str,
) -> Result<String, String> {
    let mut args = vec!["exec".to_string()];
    add_non_default_session(&mut args, session_name);
    args.push(exec_shell_argument(masked_command));
    Ok(visible_pentect_command(&args))
}

fn exec_shell_argument(command: &str) -> String {
    if command.starts_with('-') {
        format!(" {command}")
    } else {
        command.to_string()
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
            "reason": stringify_tool_output(&updated_output)
        }),
    }
}

fn after_tool_block_output(_provider: HookProvider, reason: &str) -> Value {
    json!({
        "decision": "block",
        "reason": reason
    })
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
            matches!(cfg.unreadable_images, config::UnreadableImagePolicy::Block)
                .then_some("image blocked: OCR is off.".to_string()),
        );
    }
    let inspection = image_ocr::inspect_tool_images_for_secrets(value, &session.key)?;
    if inspection.secret_images > 0 {
        return Ok(Some("image blocked: secret text detected.".to_string()));
    }
    if matches!(cfg.unreadable_images, config::UnreadableImagePolicy::Allow) {
        return Ok(None);
    }
    if inspection.unreadable_images > 0 {
        return Ok(Some(
            "image blocked: OCR needs inline image bytes.".to_string(),
        ));
    }
    if inspection.ocr_failures > 0 {
        return Ok(Some("image blocked: OCR failed.".to_string()));
    }
    Ok(None)
}

fn unsupported_tool_result_reason(value: &Value) -> Option<String> {
    if contains_unsupported_media_result(value) {
        return Some(
            "Pentect blocked non-text media output because media masking is not active yet."
                .to_string(),
        );
    }
    // TODO(side-effect-audit): replace this with explicit secret side-effect tracking
    // for clipboard/download/GUI-save destinations when those surfaces exist.
    if contains_unobserved_side_effect_result(value) {
        return Some(
            "Pentect blocked clipboard/download output because that side effect bypasses the hook boundary."
                .to_string(),
        );
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

fn contains_unobserved_side_effect_result(value: &Value) -> bool {
    match value {
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => false,
        Value::Array(items) => items.iter().any(contains_unobserved_side_effect_result),
        Value::Object(map) => map.iter().any(|(key, item)| {
            let key = normalized_json_key(key);
            key_marks_unobserved_side_effect(&key, item)
                || string_side_effect_field(&key, item)
                || contains_unobserved_side_effect_result(item)
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

fn key_marks_unobserved_side_effect(key: &str, value: &Value) -> bool {
    matches!(
        key,
        "clipboard"
            | "clipboardtext"
            | "clipboardcontent"
            | "download"
            | "downloadpath"
            | "downloadurl"
            | "downloadedfile"
            | "savedfile"
            | "savedpath"
    ) && !empty_json_value(value)
}

fn string_side_effect_field(key: &str, value: &Value) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    matches!(key, "type" | "kind")
        && matches!(
            normalized_json_key(text).as_str(),
            "clipboard" | "download" | "guisave" | "savedfile"
        )
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
            let image_object = image_ocr::is_image_object(value);
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
                    && item.is_string()
                    && image_ocr::image_payload_field_key(object_key))
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
            let image_object = image_ocr::is_image_object(value);
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, item) in map {
                let masked_key = take_masked(masked, cursor)?;
                let item = if image_object
                    && item.is_string()
                    && image_ocr::image_payload_field_key(key)
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
        InputFormat::Pdf => pdf_text(&bytes),
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
        "pdf" => Ok(InputFormat::Pdf),
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
