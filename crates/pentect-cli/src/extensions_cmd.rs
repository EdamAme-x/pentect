use crate::extensions;
use pentect_core::load_pack;
use serde::Deserialize;
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
                    "packs": row.packs,
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
            "{}: {} {} packs={} adapters={}",
            row.name,
            row.source,
            row.status(),
            row.packs,
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
    println!("packs: {}", active.pack_paths().len());
    for path in active.pack_paths() {
        println!("pack: {}", display_path(path));
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
    for path in active.pack_paths() {
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
        "packs": active.pack_paths().iter().map(|path| display_path(path)).collect::<Vec<_>>(),
        "adapters": active.adapter_paths().iter().map(|path| display_path(path)).collect::<Vec<_>>(),
    })
    .to_string()
}

fn test_pack(path: &Path) -> Check {
    let src = match std::fs::read_to_string(path) {
        Ok(src) => src,
        Err(e) => return Check::fail("pack", e.to_string()),
    };
    match load_pack(&src) {
        Ok(_) => Check::ok("pack", display_path(path)),
        Err(e) => Check::fail("pack", e),
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
    command: Vec<String>,
    timeout_ms: Option<u64>,
    max_input_bytes: Option<usize>,
    max_spans: Option<usize>,
}

#[derive(Debug)]
struct AdapterFile {
    name: String,
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
        if manifest.command.is_empty() || manifest.command.iter().any(|part| part.is_empty()) {
            return Err("command".to_string());
        }
        if find_command(&manifest.command[0]).is_none() {
            return Err("command not found".to_string());
        }
        let cwd = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Ok(Self {
            name: manifest.name.unwrap_or_else(|| "adapter".to_string()),
            cwd,
            command: manifest.command,
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
        let mut command = adapter_command(&self.command[0]);
        command
            .args(&self.command[1..])
            .current_dir(&self.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|e| format!("{}: {e}", self.name))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(request.as_bytes())
                .map_err(|e| format!("{}: {e}", self.name))?;
        }
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => break,
                Ok(Some(status)) => return Err(format!("{}: {status}", self.name)),
                Ok(None) if start.elapsed() >= self.timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{}: timeout", self.name));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(e) => return Err(format!("{}: {e}", self.name)),
            }
        }
        let output = child
            .wait_with_output()
            .map_err(|e| format!("{}: {e}", self.name))?;
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(|e| format!("{}: {e}", self.name))?;
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

fn adapter_command(name: &str) -> Command {
    let mut command = Command::new(name);
    command.env_clear();
    for env_name in safe_adapter_env_names() {
        if let Some(value) = std::env::var_os(env_name) {
            command.env(env_name, value);
        }
    }
    command
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
    packs: usize,
    adapters: usize,
}

impl ExtensionRow {
    fn status(&self) -> &'static str {
        if self.packs == 0 && self.adapters == 0 {
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
        Path::new("examples").join("extensions"),
        "example",
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
        rows.push(ExtensionRow {
            name,
            source,
            packs: active.pack_paths().len(),
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

fn find_command(name: &str) -> Option<PathBuf> {
    let path = Path::new(name);
    if path.is_file() {
        return Some(path.to_path_buf());
    }
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
    fn adapter_probe_env_does_not_inherit_in_memory_manager_credentials() {
        let command = adapter_command("echo");
        let names = command
            .get_envs()
            .map(|(name, _)| name.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_IN_MEMORY_MANAGER_ADDR"));
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_IN_MEMORY_MANAGER_TOKEN"));
    }
}
