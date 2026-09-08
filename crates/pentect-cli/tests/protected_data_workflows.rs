use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn root() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("pentect-workflows-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join(".pentect")).unwrap();
    std::fs::create_dir_all(root.join("home")).unwrap();
    root
}

fn isolated(command: &mut Command, root: &Path) {
    let os_vars: Vec<_> = [
        "PATH",
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TMP",
        "TEMP",
        "TMPDIR",
    ]
    .into_iter()
    .filter_map(|name| std::env::var_os(name).map(|value| (name, value)))
    .collect();
    command
        .env_clear()
        .envs(os_vars)
        .current_dir(root)
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env("LOCALAPPDATA", root.join("home/local"))
        .env("XDG_STATE_HOME", root.join("home/state"));
}

fn mask(root: &Path, input: &str, flags: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    isolated(&mut command, root);
    let mut child = command
        .arg("mask")
        .args(flags)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn normalize_handles(text: &str) -> String {
    let mut normalized = text.to_string();
    for view in pentect_core::scan_recovery_views(text).unwrap() {
        let label = pentect_core::parse_placeholder(&view.handle).unwrap().label;
        normalized = normalized.replace(&view.handle, &format!("[{label}]"));
    }
    normalized
}

#[test]
fn explanation_preserves_masking_and_reports_actual_multistage_evidence() {
    let root = root();
    std::fs::write(
        root.join(".pentect/config.toml"),
        "[update]\ncheck = false\n",
    )
    .unwrap();
    let input = "日本語🙂\nfirst = pentect(synthetic-first-value)\nsecond = pentect(synthetic-second-value)\nagain = pentect(synthetic-first-value)\n";
    let plain = mask(&root, input, &[]);
    let human = mask(&root, input, &["--explain"]);
    let json = mask(&root, input, &["--explain", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let masked = report["masked"].as_str().unwrap();
    assert_eq!(
        normalize_handles(masked),
        normalize_handles(std::str::from_utf8(&plain.stdout).unwrap())
    );
    assert_eq!(
        normalize_handles(masked),
        normalize_handles(std::str::from_utf8(&human.stdout).unwrap())
    );
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 3);
    assert_eq!(findings[0]["handle"], findings[2]["handle"]);
    assert_ne!(findings[0]["handle"], findings[1]["handle"]);
    assert_eq!(findings[0]["evidence"][0]["detector"], "explicit");
    assert!(String::from_utf8_lossy(&human.stderr).contains("occurrence 3"));
    for output in [&plain, &human, &json] {
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("synthetic-first-value"));
            assert!(!text.contains("synthetic-second-value"));
        }
    }
    let malformed = mask(
        &root,
        "{\"value\": pentect(synthetic-hidden) ",
        &["--kind", "json", "--explain", "--json"],
    );
    let report: serde_json::Value = serde_json::from_slice(&malformed.stdout).unwrap();
    assert_eq!(report["parser_fallback"], true);
    let public = serde_json::to_string(&report["public_report"]).unwrap();
    for excluded in ["synthetic-", "<<", "masked", "handle", "label", "日本語"] {
        assert!(
            !public.contains(excluded),
            "public report contains {excluded}"
        );
    }
    assert!(report["conditions"]["decode"]["max_depth"].is_number());
    assert_eq!(report["conditions"]["aggressive"], false);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn explanation_identifies_configured_patterns_and_supports_synthetic_rechecks() {
    let root = root();
    std::fs::create_dir(root.join("policy")).unwrap();
    std::fs::write(root.join("policy/plugin.toml"),
        "schema = 'pentect.plugin.v1'\nname = 'explanation-fixture'\n\n[[detector]]\nlabel = 'CASE_ID'\npattern = 'CASE-[0-9]{8}'\ncategory = 'identifier'\nconfidence = 'high'\n").unwrap();
    let flags = [
        "--kind",
        "text",
        "--plugins",
        "./policy",
        "--explain",
        "--json",
    ];
    let output = mask(&root, "公開 fixture: CASE-12345678", &flags);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let evidence = &report["findings"][0]["evidence"][0];
    assert_eq!(evidence["label"], "CASE_ID");
    assert_eq!(evidence["detector"], "rule");
    assert_eq!(evidence["reason"], "configured-pattern");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("CASE-12345678"));
    let rechecked = mask(&root, "公開 fixture: CASE-public", &flags);
    let report: serde_json::Value = serde_json::from_slice(&rechecked.stdout).unwrap();
    assert_eq!(report["findings"].as_array().unwrap().len(), 0);
    assert!(report["masked"].as_str().unwrap().contains("CASE-public"));
    std::fs::remove_dir_all(root).unwrap();
}

/// Each worker is a separate process: no fixture changes the test runner's
/// environment or shares the previous process's recovery store.
#[test]
fn resumed_file_handles_obey_identity_and_source_lifecycle() {
    for scope in ["device", "project", "session"] {
        let root = root();
        std::fs::write(
            root.join(".pentect/config.toml"),
            format!("[handles]\nscope = {scope:?}\n[update]\ncheck = false\n"),
        )
        .unwrap();
        std::fs::write(
            root.join("fixture.env"),
            "API_KEY=synthetic-original-value\n",
        )
        .unwrap();
        let mut read = Command::new(env!("CARGO_BIN_EXE_pentect"));
        isolated(&mut read, &root);
        let output = read.args(["read", "fixture.env"]).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let masked = std::str::from_utf8(&output.stdout).unwrap();
        let handles = pentect_core::scan_recovery_views(masked).unwrap();
        assert_eq!(handles.len(), 1);
        std::fs::write(root.join("handle.txt"), &handles[0].handle).unwrap();
        for case in if scope == "session" {
            vec!["scope"]
        } else {
            vec![
                "resume",
                "resume-direct",
                "scope",
                "changed",
                "missing",
                "disabled",
                "unknown",
                "other-project",
                "unsupported",
            ]
        } {
            std::fs::write(
                root.join(".pentect/config.toml"),
                format!("[handles]\nscope = {scope:?}\n[update]\ncheck = false\n"),
            )
            .unwrap();
            std::fs::write(
                root.join("fixture.env"),
                "API_KEY=synthetic-original-value\n",
            )
            .unwrap();
            let mut worker = Command::new(std::env::current_exe().unwrap());
            isolated(&mut worker, &root);
            let output = worker
                .args(["--exact", "resume_worker", "--nocapture"])
                .env("PENTECT_WORKFLOW_CASE", case)
                .env("PENTECT_WORKFLOW_ROOT", &root)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "scope={scope} case={case}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn resume_worker() {
    let Ok(case) = std::env::var("PENTECT_WORKFLOW_CASE") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("PENTECT_WORKFLOW_ROOT").unwrap());
    let handle = std::fs::read_to_string(root.join("handle.txt")).unwrap();
    match case.as_str() {
        "changed" => std::fs::write(
            root.join("fixture.env"),
            "API_KEY=synthetic-replaced-value\n",
        )
        .unwrap(),
        "missing" => {
            let _ = std::fs::remove_file(root.join("fixture.env"));
        }
        "disabled" => std::fs::write(
            root.join(".pentect/config.toml"),
            "[files]\nremember = false\n",
        )
        .unwrap(),
        "scope" => std::fs::write(
            root.join(".pentect/config.toml"),
            "[handles]\nscope = 'session'\n",
        )
        .unwrap(),
        "other-project" => {
            let other = root.join("other");
            std::fs::create_dir_all(other.join(".git")).unwrap();
            std::env::set_current_dir(other).unwrap();
        }
        _ => {}
    }
    let store = pentect_agent::start_in_process_memory_store().unwrap();
    let candidate = pentect_agent::register_process_host_candidate(
        &pentect_agent::process_host_root().unwrap(),
        store.addr(),
        store.token(),
        store.process_host_read_token(),
        store.process_host_write_token(),
        std::process::id(),
    )
    .unwrap();
    std::env::set_var("PENTECT_MEMORY_STORE_ADDR", store.addr());
    std::env::set_var("PENTECT_MEMORY_STORE_TOKEN", store.token());
    std::env::set_var("PENTECT_AGENT_LAUNCHED", store.token());
    // The same resolver factory used by HTTP gateways, with an empty live store.
    let masker = pentect_agent::ActiveToolOutputMasker::new().unwrap();
    let resolver = if case == "resume-direct" {
        pentect_agent::ActiveMemoryStoreResolver::new().unwrap()
    } else {
        masker.known_text_resolver().unwrap()
    };
    let input = if case == "unknown" {
        format!("{handle} <<UNKNOWN_0123456789abcdef>>")
    } else {
        handle.clone()
    };
    let kind = if case == "unsupported" {
        pentect_agent::ToolInputKind::Unknown
    } else {
        pentect_agent::ToolInputKind::Data
    };
    let result = resolver.resolve_tool_input(&input, kind);
    if case.starts_with("resume") {
        assert_eq!(result.unwrap().as_deref(), Some("synthetic-original-value"));
        let encoded = resolver
            .resolve_tool_input(
                &handle.replace(">>", "|base64>>"),
                pentect_agent::ToolInputKind::Code,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            data_encoding::BASE64.decode(encoded.as_bytes()).unwrap(),
            b"synthetic-original-value"
        );
        let mut remasker = pentect_agent::ActiveToolOutputMasker::new().unwrap();
        assert_eq!(
            remasker
                .mask_tool_output("synthetic-original-value")
                .unwrap()
                .unwrap(),
            handle
        );
    } else {
        let error = result.unwrap_err();
        let expected = match case.as_str() {
            "scope" => pentect_agent::ToolInputError::RecoveryScopeChanged,
            "changed" => pentect_agent::ToolInputError::RecoverySourceChanged,
            "missing" => pentect_agent::ToolInputError::RecoverySourceUnavailable,
            "disabled" => pentect_agent::ToolInputError::RecoveryDisabled,
            "unsupported" => pentect_agent::ToolInputError::UnknownSurface,
            _ => pentect_agent::ToolInputError::UnknownHandle,
        };
        assert_eq!(error, expected);
        assert!(!error.executed());
        if case != "unsupported" {
            assert!(
                error.to_string().contains("reread") || error.to_string().contains("new handle")
            );
        }
        let fresh = pentect_agent::ActiveMemoryStoreResolver::new().unwrap();
        assert_ne!(
            fresh.resolve_known_text(&handle).unwrap().as_deref(),
            Some("synthetic-original-value")
        );
        if case == "changed" {
            let mut reread = Command::new(env!("CARGO_BIN_EXE_pentect"));
            isolated(&mut reread, &root);
            let output = reread.args(["read", "fixture.env"]).output().unwrap();
            assert!(output.status.success());
            let preview = std::str::from_utf8(&output.stdout).unwrap();
            let new_handle = &pentect_core::scan_recovery_views(preview).unwrap()[0].handle;
            assert_ne!(new_handle, &handle);
            assert_eq!(
                fresh
                    .resolve_tool_input(new_handle, pentect_agent::ToolInputKind::Data)
                    .unwrap()
                    .as_deref(),
                Some("synthetic-replaced-value")
            );
        }
    }
    pentect_agent::unregister_process_host_candidate(&candidate);
}
