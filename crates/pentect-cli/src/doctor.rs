use crate::plugins;
use serde_json::json;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

pub(crate) fn cmd_doctor(args: &[String]) {
    let json_output = match parse_args(args) {
        Ok(value) => value,
        Err(e) => crate::die(e),
    };
    let checks = run_checks();
    if json_output {
        println!("{}", checks_json(&checks));
    } else {
        for check in &checks {
            println!("{}: {} {}", check.name, check.status.as_str(), check.detail);
        }
    }
    if checks.iter().any(|check| check.status == Status::Fail) {
        std::process::exit(1);
    }
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
    Warn,
    Fail,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }
}

fn parse_args(args: &[String]) -> Result<bool, String> {
    let mut json_output = false;
    for arg in &args[2..] {
        match arg.as_str() {
            "--json" => json_output = true,
            flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
            value => return Err(format!("unexpected argument for doctor: {value}")),
        }
    }
    Ok(json_output)
}

fn run_checks() -> Vec<Check> {
    vec![
        check_pentect_binary(),
        check_memory_store(),
        check_config_plugins(),
        check_ocr(),
        check_command("codex"),
        check_command("claude"),
    ]
}

fn check_pentect_binary() -> Check {
    match std::env::current_exe() {
        Ok(path) if path.is_file() => Check::ok("pentect", compact_path(&path)),
        Ok(path) => Check::fail("pentect", format!("not a file: {}", compact_path(&path))),
        Err(e) => Check::fail("pentect", e.to_string()),
    }
}

fn check_memory_store() -> Check {
    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => return Check::fail("memory", e.to_string()),
    };
    let mut child = match Command::new(exe)
        .arg("agent")
        .arg("memory-store")
        .arg("--serve")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => return Check::fail("memory", e.to_string()),
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Check::fail("memory", "stdout unavailable");
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = tx.send(result);
    });
    let status = match rx.recv_timeout(Duration::from_secs(3)) {
        Ok(Ok(line)) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&line);
            match parsed {
                Ok(value)
                    if value.get("addr").and_then(|v| v.as_str()).is_some()
                        && value.get("token").and_then(|v| v.as_str()).is_some() =>
                {
                    Check::ok("memory", "ready")
                }
                Ok(_) => Check::fail("memory", "bad startup"),
                Err(_) => Check::fail("memory", "bad startup"),
            }
        }
        Ok(Err(e)) => Check::fail("memory", e.to_string()),
        Err(_) => Check::fail("memory", "timeout"),
    };
    let _ = child.kill();
    let _ = child.wait();
    status
}

fn check_config_plugins() -> Check {
    match plugins::active_from_specs(Vec::new(), true) {
        Ok(_) => Check::ok("plugins", "ready"),
        Err(e) => Check::fail("plugins", e.to_string()),
    }
}

fn check_ocr() -> Check {
    let status = pentect_agent::ocr_status();
    match status {
        "bundled" | "windows" | "macos" => Check::ok("ocr", status),
        "disabled" => Check::warn("ocr", "disabled"),
        "unsupported" => Check::warn("ocr", "unsupported"),
        status => Check::warn("ocr", status),
    }
}

fn check_command(name: &'static str) -> Check {
    match find_command(name) {
        Some(path) => Check::ok(name, compact_path(&path)),
        None => Check::warn(name, "not found"),
    }
}

fn find_command(name: &str) -> Option<PathBuf> {
    let path = Path::new(name);
    if path.is_file() {
        return Some(path.to_path_buf());
    }
    let paths = std::env::var_os("PATH")?;
    let candidates = command_names(name);
    for dir in std::env::split_paths(&paths) {
        for candidate in &candidates {
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
    let has_ext = Path::new(name).extension().is_some();
    if has_ext {
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

fn checks_json(checks: &[Check]) -> String {
    json!({
        "checks": checks.iter().map(|check| json!({
            "name": check.name,
            "status": check.status.as_str(),
            "detail": check.detail,
        })).collect::<Vec<_>>()
    })
    .to_string()
}

fn compact_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| path.display().to_string())
}

impl Check {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Ok,
            detail: detail.into(),
        }
    }

    fn warn(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Warn,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_rejects_positionals() {
        let args = vec!["pentect".into(), "doctor".into(), "codex".into()];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn doctor_accepts_json() {
        let args = vec!["pentect".into(), "doctor".into(), "--json".into()];
        assert!(parse_args(&args).unwrap());
    }

    #[test]
    fn doctor_reports_ocr_status() {
        let check = check_ocr();
        assert_eq!(check.name, "ocr");
        match check.detail.as_str() {
            "bundled" | "windows" | "macos" => assert_eq!(check.status, Status::Ok),
            "disabled" | "unsupported" => assert_eq!(check.status, Status::Warn),
            other => panic!("unexpected ocr detail: {other}"),
        }
    }
}
