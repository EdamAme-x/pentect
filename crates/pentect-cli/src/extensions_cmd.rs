use crate::extensions;
use pentect_core::load_pack;
use serde::Deserialize;
use serde_json::json;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const PENTECT_DIR: &str = ".pentect";
const EXTENSIONS_DATA_DIR: &str = "extensions-data";
const EXTENSION_CONFIG_FILE: &str = "config.toml";
const EXTENSION_CACHE_DIR: &str = "cache";
const EXTENSION_NAME_ENV: &str = "PENTECT_EXTENSION_NAME";
const EXTENSION_DATA_DIR_ENV: &str = "PENTECT_EXTENSION_DATA_DIR";
const EXTENSION_CACHE_DIR_ENV: &str = "PENTECT_EXTENSION_CACHE_DIR";
const EXTENSION_CONFIG_ENV: &str = "PENTECT_EXTENSION_CONFIG";
const MAX_STDOUT_BYTES: usize = 1024 * 1024;

pub(crate) fn cmd_extensions(args: &[String]) {
    let opts = match ExtensionCmd::parse(args) {
        Ok(opts) => opts,
        Err(e) => crate::die(e),
    };
    let result = match opts.action {
        Action::List => list_extensions(opts.json),
        Action::Inspect { spec } => inspect_extension(&spec, opts.json),
        Action::Test { spec } => test_extension(&spec, opts.json),
    };
    if let Err(e) = result {
        crate::die(e);
    }
}

#[derive(Debug)]
struct ExtensionCmd {
    action: Action,
    json: bool,
}

#[derive(Debug)]
enum Action {
    List,
    Inspect { spec: String },
    Test { spec: String },
}

impl ExtensionCmd {
    fn parse(args: &[String]) -> Result<Self, String> {
        let Some(action) = args.get(2).map(String::as_str) else {
            return Err("extensions list|inspect|test".to_string());
        };
        let mut json = false;
        let mut values = Vec::new();
        for arg in &args[3..] {
            match arg.as_str() {
                "--json" => json = true,
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                value => values.push(value.to_string()),
            }
        }
        let action = match action {
            "list" => {
                if !values.is_empty() {
                    return Err("extensions list".to_string());
                }
                Action::List
            }
            "inspect" => Action::Inspect {
                spec: one_value("extensions inspect", values)?,
            },
            "test" => Action::Test {
                spec: one_value("extensions test", values)?,
            },
            other => return Err(format!("unknown extensions command: {other}")),
        };
        Ok(Self { action, json })
    }
}

fn one_value(command: &str, values: Vec<String>) -> Result<String, String> {
    match values.as_slice() {
        [value] => Ok(value.clone()),
        _ => Err(format!("{command} NAME|PATH")),
    }
}

fn list_extensions(json_output: bool) -> Result<(), String> {
    let mut rows = extension_rows()?;
    rows.sort_by(|a, b| a.name.cmp(&b.name).then(a.source.cmp(b.source)));
    if json_output {
        println!(
            "{}",
            json!({
                "extensions": rows.iter().map(|row| json!({
                    "name": row.name,
                    "source": row.source,
                    "status": row.status(),
                    "configs": row.configs,
                    "adapters": row.adapters,
                })).collect::<Vec<_>>()
            })
        );
        return Ok(());
    }
    if rows.is_empty() {
        println!("none");
        return Ok(());
    }
    for row in rows {
        println!(
            "{}: {} {} configs={} adapters={}",
            row.name,
            row.source,
            row.status(),
            row.configs,
            row.adapters
        );
    }
    Ok(())
}

fn inspect_extension(spec: &str, json_output: bool) -> Result<(), String> {
    let active = active_for_one(spec)?;
    if json_output {
        println!("{}", active_json(&active));
        return Ok(());
    }
    println!("configs: {}", active.config_paths().len());
    for path in active.config_paths() {
        println!("config: {}", display_path(path));
    }
    println!("adapters: {}", active.adapter_paths().len());
    for path in active.adapter_paths() {
        println!("adapter: {}", display_path(path));
    }
    Ok(())
}

fn test_extension(spec: &str, json_output: bool) -> Result<(), String> {
    let active = active_for_one(spec)?;
    let mut checks = Vec::new();
    for path in active.config_paths() {
        checks.push(test_pack(path));
    }
    for path in active.adapter_paths() {
        checks.push(test_adapter(path));
    }
    if checks.is_empty() {
        checks.push(Check::fail("extension", "empty"));
    }
    if json_output {
        println!(
            "{}",
            json!({
                "checks": checks.iter().map(|check| json!({
                    "name": check.name,
                    "status": check.status.as_str(),
                    "detail": check.detail,
                })).collect::<Vec<_>>()
            })
        );
    } else {
        for check in &checks {
            println!("{}: {}", check.name, check.status.as_str());
        }
    }
    if checks.iter().any(|check| check.status == Status::Fail) {
        return Err("extension test failed".to_string());
    }
    Ok(())
}

fn active_for_one(spec: &str) -> Result<extensions::ActiveExtensions, String> {
    let specs = extensions::parse_extension_value(spec).map_err(|e| e.to_string())?;
    extensions::active_from_explicit_specs(specs, true).map_err(|e| e.to_string())
}

fn active_json(active: &extensions::ActiveExtensions) -> String {
    json!({
        "configs": active.config_paths().iter().map(|path| display_path(path)).collect::<Vec<_>>(),
        "adapters": active.adapter_paths().iter().map(|path| display_path(path)).collect::<Vec<_>>(),
    })
    .to_string()
}

fn test_pack(path: &Path) -> Check {
    let src = match std::fs::read_to_string(path) {
        Ok(src) => src,
        Err(e) => return Check::fail("config", e.to_string()),
    };
    match load_pack(&src) {
        Ok(_) => Check::ok("config", display_path(path)),
        Err(e) => Check::fail("config", e),
    }
}

fn test_adapter(path: &Path) -> Check {
    let adapter = match AdapterFile::load(path) {
        Ok(adapter) => adapter,
        Err(e) => return Check::fail("adapter", e),
    };
    match adapter.run_probe() {
        Ok(count) => Check::ok("adapter", format!("spans={count}")),
        Err(e) => Check::fail("adapter", e),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterToml {
    schema: Option<String>,
    kind: Option<String>,
    name: Option<String>,
    command: Option<Vec<String>>,
    timeout_ms: Option<u64>,
    max_input_bytes: Option<usize>,
    max_spans: Option<usize>,
}

#[derive(Debug)]
struct AdapterFile {
    name: String,
    id: String,
    cwd: PathBuf,
    command: Vec<String>,
    timeout: Duration,
    max_input_bytes: usize,
    max_spans: usize,
}

impl AdapterFile {
    fn load(path: &Path) -> Result<Self, String> {
        let src = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read adapter '{}': {e}", display_path(path)))?;
        let manifest: AdapterToml = toml::from_str(&src)
            .map_err(|e| format!("invalid adapter '{}': {e}", display_path(path)))?;
        if manifest.schema.as_deref() != Some("pentect.model_adapter.v1") {
            return Err("schema".to_string());
        }
        if manifest.kind.as_deref() != Some("model") {
            return Err("kind".to_string());
        }
        let cwd = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let command = adapter_command_from_manifest(manifest.command)?;
        let program = adapter_program(&command[0], &cwd);
        if find_command(&program).is_none() {
            return Err("command not found".to_string());
        }
        let name = manifest
            .name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| adapter_default_name(path));
        let id = extension_id(&name);
        Ok(Self {
            name,
            id,
            cwd,
            command,
            timeout: Duration::from_millis(manifest.timeout_ms.unwrap_or(3_000)),
            max_input_bytes: manifest.max_input_bytes.unwrap_or(256 * 1024),
            max_spans: manifest.max_spans.unwrap_or(512),
        })
    }

    fn run_probe(&self) -> Result<usize, String> {
        let request = json!({
            "schema": "pentect.model_adapter.v1",
            "kind": "text",
            "text": "Alice Smith",
            "context": null,
        })
        .to_string();
        if request.len() > self.max_input_bytes {
            return Err(format!("{}: input limit", self.name));
        }
        let program = adapter_program(&self.command[0], &self.cwd);
        let mut command = adapter_command(&program, &self.id)?;
        command
            .args(&self.command[1..])
            .current_dir(&self.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|e| format!("{}: {e}", self.name))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("{}: stdout", self.name))?;
        let stdout_reader = spawn_adapter_stdout_reader(stdout);
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("{}: stdin", self.name))?;
        let stdin_writer = spawn_adapter_stdin_writer(stdin, request.as_bytes().to_vec());
        let status = match wait_for_adapter_child(&mut child, &self.name, self.timeout) {
            Ok(status) => status,
            Err(err) => {
                let _ = join_adapter_stdin(stdin_writer, &self.name);
                let _ = join_adapter_stdout(stdout_reader, &self.name);
                return Err(err);
            }
        };
        join_adapter_stdin(stdin_writer, &self.name)?;
        let stdout = join_adapter_stdout(stdout_reader, &self.name)?;
        if stdout.len() > MAX_STDOUT_BYTES {
            return Err(format!("{}: output limit", self.name));
        }
        if !status.success() {
            return Err(format!("{}: {status}", self.name));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&stdout).map_err(|e| format!("{}: {e}", self.name))?;
        let count = value
            .get("spans")
            .and_then(|spans| spans.as_array())
            .map(Vec::len)
            .unwrap_or(0);
        if count > self.max_spans {
            return Err(format!("{}: span limit", self.name));
        }
        Ok(count)
    }
}

fn spawn_adapter_stdin_writer(
    mut stdin: ChildStdin,
    request: Vec<u8>,
) -> JoinHandle<Result<(), String>> {
    std::thread::spawn(move || stdin.write_all(&request).map_err(|e| format!("stdin: {e}")))
}

fn spawn_adapter_stdout_reader(stdout: ChildStdout) -> JoinHandle<Result<Vec<u8>, String>> {
    std::thread::spawn(move || {
        let mut stdout = stdout.take(MAX_STDOUT_BYTES as u64 + 1);
        let mut out = Vec::new();
        stdout
            .read_to_end(&mut out)
            .map_err(|e| format!("stdout: {e}"))?;
        Ok(out)
    })
}

fn wait_for_adapter_child(
    child: &mut Child,
    name: &str,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{name}: timeout"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{name}: {e}"));
            }
        }
    }
}

fn join_adapter_stdin(writer: JoinHandle<Result<(), String>>, name: &str) -> Result<(), String> {
    writer
        .join()
        .map_err(|_| format!("{name}: stdin writer panicked"))?
        .map_err(|e| format!("{name}: {e}"))
}

fn join_adapter_stdout(
    reader: JoinHandle<Result<Vec<u8>, String>>,
    name: &str,
) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| format!("{name}: stdout reader panicked"))?
        .map_err(|e| format!("{name}: {e}"))
}

fn adapter_command_from_manifest(command: Option<Vec<String>>) -> Result<Vec<String>, String> {
    let Some(command) = command else {
        return Err("command".to_string());
    };
    if command.is_empty() || command.iter().any(|part| part.is_empty()) {
        return Err("command".to_string());
    }
    Ok(command)
}

fn adapter_command(program: &Path, id_or_name: &str) -> Result<Command, String> {
    let mut command = Command::new(program);
    command.env_clear();
    for env_name in safe_adapter_env_names() {
        if let Some(value) = std::env::var_os(env_name) {
            command.env(env_name, value);
        }
    }
    let id = extension_id(id_or_name);
    let dirs = extension_runtime_dirs(&id)?;
    command.env(EXTENSION_NAME_ENV, id);
    command.env(EXTENSION_DATA_DIR_ENV, dirs.data_dir);
    command.env(EXTENSION_CACHE_DIR_ENV, dirs.cache_dir);
    command.env(EXTENSION_CONFIG_ENV, dirs.config_file);
    Ok(command)
}

#[derive(Debug)]
struct ExtensionRuntimeDirs {
    data_dir: PathBuf,
    cache_dir: PathBuf,
    config_file: PathBuf,
}

fn extension_runtime_dirs(id_or_name: &str) -> Result<ExtensionRuntimeDirs, String> {
    let id = extension_id(id_or_name);
    let data_dir = PathBuf::from(PENTECT_DIR)
        .join(EXTENSIONS_DATA_DIR)
        .join(&id);
    let cache_dir = data_dir.join(EXTENSION_CACHE_DIR);
    std::fs::create_dir_all(&cache_dir).map_err(|e| {
        format!(
            "could not create extension data '{}': {e}",
            cache_dir.display()
        )
    })?;
    let config_file = data_dir.join(EXTENSION_CONFIG_FILE);
    Ok(ExtensionRuntimeDirs {
        data_dir,
        cache_dir,
        config_file,
    })
}

fn adapter_default_name(path: &Path) -> String {
    if path.file_name().and_then(|name| name.to_str()) == Some("adapter.toml") {
        if let Some(name) = path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .filter(|name| !name.trim().is_empty())
        {
            return name.to_string();
        }
    }
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("extension")
        .to_string()
}

fn extension_id(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in value.trim().chars() {
        let next = if ch.is_ascii_alphanumeric() {
            Some(ch.to_ascii_lowercase())
        } else if matches!(ch, '-' | '_' | '.' | ' ') {
            Some('-')
        } else {
            None
        };
        let Some(next) = next else {
            continue;
        };
        if next == '-' {
            if out.is_empty() || last_dash {
                continue;
            }
            last_dash = true;
        } else {
            last_dash = false;
        }
        out.push(next);
        if out.len() >= 64 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "extension".to_string()
    } else {
        out
    }
}

fn safe_adapter_env_names() -> &'static [&'static str] {
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
struct ExtensionRow {
    name: String,
    source: &'static str,
    configs: usize,
    adapters: usize,
}

impl ExtensionRow {
    fn status(&self) -> &'static str {
        if self.configs == 0 && self.adapters == 0 {
            "empty"
        } else {
            "ok"
        }
    }
}

fn extension_rows() -> Result<Vec<ExtensionRow>, String> {
    let mut rows = Vec::new();
    rows.extend(extension_rows_in(
        Path::new(".pentect").join("extensions"),
        "project",
    )?);
    rows.extend(extension_rows_in(
        Path::new("extensions").to_path_buf(),
        "official",
    )?);
    Ok(rows)
}

fn extension_rows_in(root: PathBuf, source: &'static str) -> Result<Vec<ExtensionRow>, String> {
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(&root).map_err(|e| {
        format!(
            "could not read extension dir '{}': {e}",
            display_path(&root)
        )
    })? {
        let path = entry
            .map_err(|e| {
                format!(
                    "could not read extension dir '{}': {e}",
                    display_path(&root)
                )
            })?
            .path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_string();
        let active = active_for_one(&path.to_string_lossy())?;
        if active.config_paths().is_empty() && active.adapter_paths().is_empty() {
            continue;
        }
        rows.push(ExtensionRow {
            name,
            source,
            configs: active.config_paths().len(),
            adapters: active.adapter_paths().len(),
        });
    }
    Ok(rows)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Ok,
    Fail,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Fail => "fail",
        }
    }
}

impl Check {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Ok,
            detail: detail.into(),
        }
    }

    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Fail,
            detail: detail.into(),
        }
    }
}

fn adapter_program(program: &str, cwd: &Path) -> PathBuf {
    let path = Path::new(program);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    if looks_like_path_command(program) {
        return cwd.join(path);
    }
    adapter_sidecar_program(program).unwrap_or_else(|| path.to_path_buf())
}

fn looks_like_path_command(program: &str) -> bool {
    program.contains('/') || program.contains('\\')
}

fn adapter_sidecar_program(program: &str) -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    for name in command_names(program) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn find_command(path: &Path) -> Option<PathBuf> {
    if path.is_file() {
        return Some(path.to_path_buf());
    }
    if path.is_absolute()
        || path
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        return None;
    }
    let name = path.to_str()?;
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        for candidate in command_names(name) {
            let full = dir.join(candidate);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

#[cfg(windows)]
fn command_names(name: &str) -> Vec<String> {
    if Path::new(name).extension().is_some() {
        return vec![name.to_string()];
    }
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    pathext
        .split(';')
        .filter(|ext| !ext.is_empty())
        .map(|ext| format!("{name}{ext}"))
        .collect()
}

#[cfg(not(windows))]
fn command_names(name: &str) -> Vec<String> {
    vec![name.to_string()]
}

fn display_path(path: &Path) -> String {
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|cwd| cwd.canonicalize().ok());
    let target = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let rel = cwd
        .as_deref()
        .and_then(|cwd| target.strip_prefix(cwd).ok())
        .unwrap_or(&target);
    rel.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list() {
        let args = vec!["pentect".into(), "extensions".into(), "list".into()];
        assert!(matches!(
            ExtensionCmd::parse(&args).unwrap().action,
            Action::List
        ));
    }

    #[test]
    fn inspect_requires_one_spec() {
        let args = vec!["pentect".into(), "extensions".into(), "inspect".into()];
        assert!(ExtensionCmd::parse(&args).is_err());
    }

    #[test]
    fn adapter_probe_env_does_not_inherit_memory_store_credentials() {
        let command = adapter_command(Path::new("echo"), "test-env").unwrap();
        let names = command
            .get_envs()
            .map(|(name, _)| name.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert!(!names.iter().any(|name| name == "PENTECT_MEMORY_STORE_ADDR"));
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_MEMORY_STORE_TOKEN"));
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_PROCESS_HOST_READ_TOKEN"));
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_PROCESS_HOST_WRITE_TOKEN"));
    }

    #[test]
    fn adapter_probe_env_exposes_project_local_extension_data() {
        let command = adapter_command(Path::new("echo"), "My Ext!").unwrap();
        let envs = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().to_string(),
                    value
                        .map(|value| value.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_default(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            envs.get(EXTENSION_NAME_ENV).map(String::as_str),
            Some("my-ext")
        );
        assert!(
            envs.get(EXTENSION_DATA_DIR_ENV)
                .is_some_and(|path| path.ends_with(".pentect/extensions-data/my-ext")),
            "{envs:?}"
        );
        assert!(
            envs.get(EXTENSION_CACHE_DIR_ENV)
                .is_some_and(|path| path.ends_with(".pentect/extensions-data/my-ext/cache")),
            "{envs:?}"
        );
        assert!(
            envs.get(EXTENSION_CONFIG_ENV)
                .is_some_and(|path| path.ends_with(".pentect/extensions-data/my-ext/config.toml")),
            "{envs:?}"
        );
    }

    #[test]
    fn list_extensions_skips_empty_dirs() {
        let root =
            std::env::temp_dir().join(format!("pentect-extension-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::fs::create_dir_all(root.join("rules")).unwrap();
        std::fs::write(root.join("rules").join("config.toml"), "").unwrap();

        let rows = extension_rows_in(root.clone(), "official").unwrap();
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "rules");
        assert_eq!(rows[0].configs, 1);
        assert_eq!(rows[0].adapters, 0);
    }

    #[test]
    fn list_extensions_includes_official_model_and_rule_extensions() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap();
        let rows = extension_rows_in(repo.join("extensions"), "official").unwrap();
        let names = rows
            .iter()
            .filter(|row| row.source == "official")
            .map(|row| row.name.as_str())
            .collect::<std::collections::BTreeSet<_>>();

        assert!(names.contains("openai-privacy-filter"), "{names:?}");
        assert!(names.contains("pii-ner"), "{names:?}");
        assert!(names.contains("jp-pii"), "{names:?}");
    }

    #[test]
    fn adapter_command_path_is_checked_from_adapter_dir() {
        let root = std::env::temp_dir().join(format!(
            "pentect-cli-adapter-relative-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("tool"), "").unwrap();
        std::fs::write(
            root.join("adapter.toml"),
            r#"
schema = "pentect.model_adapter.v1"
kind = "model"
name = "relative"
command = ["./tool"]
"#,
        )
        .unwrap();

        let loaded = AdapterFile::load(&root.join("adapter.toml"));
        std::fs::remove_dir_all(root).unwrap();
        assert!(loaded.is_ok(), "{loaded:?}");
    }
}
