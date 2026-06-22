use super::*;

#[test]
fn session_recovery_is_process_local() {
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
    assert!(!root.exists(), "{}", root.display());

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
fn resolve_parse_accepts_multiple_paths() {
    let args = strings(["pentect-agent", "resolve", "a.env", "b.env"]);
    let opts = ResolveOpts::parse(&args).unwrap();
    assert!(matches!(
        opts.mode,
        ResolveMode::Files(paths)
            if paths == [PathBuf::from("a.env"), PathBuf::from("b.env")]
    ));
}

#[test]
fn resolve_parse_defaults_to_stdin_without_paths() {
    let args = strings(["pentect-agent", "resolve"]);
    let opts = ResolveOpts::parse(&args).unwrap();
    assert!(matches!(opts.mode, ResolveMode::Stdin));
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
fn recovery_store_is_process_local_only() {
    let root = std::env::temp_dir().join(format!(
        "pentect-agent-test-{}-{}-process-local",
        std::process::id(),
        unix_millis()
    ));
    let session = Session::open_at(&root, "t").unwrap();
    let store = RecoveryStore::load(&session).unwrap();
    let result = Engine::with_profile(Profile::Strict).mask(
        Input::text("OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
        &Config::new(session.key),
    );

    let masked = result.masked.clone();
    store.add_recovery(result.recovery).unwrap();

    assert_eq!(
        store.resolve_all(&masked).unwrap(),
        "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX"
    );
    assert!(!root.exists(), "{}", root.display());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn session_does_not_create_key_or_recovery_dir() {
    let root = std::env::temp_dir().join(format!(
        "pentect-agent-test-{}-{}-session",
        std::process::id(),
        unix_millis()
    ));

    let _session = Session::open_at(&root, "t").unwrap();
    assert!(!root.exists(), "{}", root.display());
    let _ = std::fs::remove_dir_all(root);
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
    guard_shell_script_with_env("cat .env | Select-String RUNPOD", &EnvPolicy::default()).unwrap();
    guard_shell_script_with_env(
        r#"python -c "open('.env').read()" # pentect-agent read"#,
        &EnvPolicy::default(),
    )
    .unwrap();
}

#[test]
fn exec_policy_blocks_environment_reads() {
    let err = guard_shell_script_with_env("Get-ChildItem Env:", &EnvPolicy::default()).unwrap_err();
    assert!(err.contains("environment-variable"), "{err}");

    let err =
        guard_shell_script_with_env("printenv RUNPOD_API_KEY", &EnvPolicy::default()).unwrap_err();
    assert!(err.contains("environment-variable"), "{err}");

    let err =
        guard_shell_script_with_env("echo $RUNPOD_API_KEY", &EnvPolicy::default()).unwrap_err();
    assert!(err.contains("environment-variable"), "{err}");

    let err = guard_shell_script_with_env("Write-Output %RUNPOD_API_KEY%", &EnvPolicy::default())
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
    guard_shell_script_with_env("$key = 'name'; Write-Output $key", &EnvPolicy::default()).unwrap();
}

#[test]
fn exec_resolves_masked_handle_in_command_text() {
    let root = temp_root("exec-command-handle");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let masked = mask_tool_output(&session, &format!("OPENAI_API_KEY={raw}\n")).unwrap();
    let handle = masked.split_once('=').unwrap().1.trim().to_string();
    drop(session);

    let session = Session::open_capability_at(&root, "t").unwrap();
    let command = if cfg!(windows) {
        format!("Write-Output '{handle}'")
    } else {
        format!("printf '%s' '{handle}'")
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
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
fn exec_auto_binds_masked_env_output_across_sessions() {
    let root = temp_root("capability-auto-env-binding");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let output = "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\nTEST_SECRET=114514810\nNOTE=hello world\n";
    let masked = mask_tool_output(&session, output).unwrap();
    assert!(
        masked.contains("RUNPOD_API_KEY=<<RUNPOD_API_KEY_"),
        "{masked}"
    );
    assert!(masked.contains("TEST_SECRET=<<SECRET_"), "{masked}");
    assert!(masked.contains("NOTE=<<SECRET_"), "{masked}");
    drop(session);

    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = RecoveryStore::load(&session).unwrap();
    let env = store.auto_env_bindings().unwrap();
    assert!(
        env.iter().any(|(name, value)| name == "RUNPOD_API_KEY"
            && value == "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"),
        "{env:?}"
    );
    assert!(
        env.iter()
            .any(|(name, value)| name == "TEST_SECRET" && value == "114514810"),
        "{env:?}"
    );
    assert!(
        env.iter()
            .any(|(name, value)| name == "NOTE" && value == "hello world"),
        "{env:?}"
    );

    let command = if cfg!(windows) {
        "Write-Output $env:RUNPOD_API_KEY; Write-Output $env:TEST_SECRET; Write-Output $env:NOTE"
            .to_string()
    } else {
        "printf '%s\n%s\n%s\n' \"$RUNPOD_API_KEY\" \"$TEST_SECRET\" \"$NOTE\"".to_string()
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        allow_env: Vec::new(),
        deny_env: Vec::new(),
        live: false,
        approve: false,
        mode: ExecMode::Shell(command),
    };
    let output = run_resolved_command(&store, &opts).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"),
        "{stdout}"
    );
    assert!(stdout.contains("114514810"), "{stdout}");
    assert!(stdout.contains("hello world"), "{stdout}");

    let safe = mask_tool_output(&session, &stdout).unwrap();
    assert!(!safe.contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "{safe}");
    assert!(!safe.contains("114514810"), "{safe}");
    assert!(!safe.contains("hello world"), "{safe}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn resolve_path_rewrites_known_handles_without_printing_secret() {
    let root = temp_root("resolve-file");
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = RecoveryStore::load(&session).unwrap();
    let raw = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n";
    let result = Engine::with_profile(Profile::Balanced).mask(
        Input {
            kind: Kind::Env,
            data: raw.to_string(),
        },
        &Config::new(session.key),
    );
    store.add_recovery(result.recovery).unwrap();

    let path = project.join(".env");
    std::fs::write(&path, result.masked).unwrap();
    resolve_path_in_place(&store, &path).unwrap();

    let written = std::fs::read_to_string(&path).unwrap();
    assert_eq!(written, raw);
    assert!(!written.contains("<<OPENAI_API_KEY_"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn child_commands_receive_pentect_session_name() {
    let mut command = Command::new("dummy");
    apply_pentect_session(&mut command, "child-session");
    assert!(command.get_envs().any(|(name, value)| {
        name == "PENTECT_AGENT_SESSION"
            && value.is_some_and(|value| value.to_string_lossy() == "child-session")
    }));
}

#[test]
fn unresolved_masked_command_handle_is_rejected() {
    let (root, session) = empty_session("unresolved-command-handle");
    let store = RecoveryStore::load(&session).unwrap();
    let err = resolve_command_text(
        &store,
        "curl -H \"Authorization: Bearer <<RUNPOD_API_KEY_missing>>\" example.test",
    )
    .unwrap_err();
    assert!(err.contains("unknown masked handle"), "{err}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_materializes_dotenv_without_returning_plaintext() {
    let root = temp_root("capability-write-dotenv");
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("RUNPOD_API_KEY={raw}\n")).unwrap();
    drop(session);

    let session = Session::open_capability_at(&root, "t").unwrap();
    let dotenv = project.join(".env");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": dotenv.to_string_lossy(),
            "content": masked
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("materialized masked .env"), "{reason}");
    assert!(!reason.contains(raw), "{reason}");

    let written = std::fs::read_to_string(&dotenv).unwrap();
    assert_eq!(written, format!("RUNPOD_API_KEY={raw}\n"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn mcp_style_tool_result_masks_content_and_structured_content() {
    let (root, session) = empty_session("hook-post-mcp");
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__browser__create_api_key",
        "tool_response": {
            "content": [{
                "type": "text",
                "text": "created RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"
            }],
            "structuredContent": {
                "apiKey": "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
            }
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    let updated = &output["hookSpecificOutput"]["updatedToolOutput"];
    let rendered = serde_json::to_string(updated).unwrap();
    assert!(rendered.contains("<<RUNPOD_API_KEY_"), "{rendered}");
    assert!(rendered.contains("<<OPENAI_API_KEY_"), "{rendered}");
    assert!(!rendered.contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"));
    assert!(!rendered.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"));
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
fn codex_posttool_does_not_block_already_masked_exec_output() {
    let (root, session) = empty_session("hook-post-codex-already-masked");
    let output = "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\nTEST_SECRET=114514810\nNOTE=hello world\n";
    let masked = mask_tool_output(&session, output).unwrap();
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "pentect exec 'Get-Content -LiteralPath .\\.env'"
        },
        "tool_response": masked
    });
    let output = handle_hook(HookProvider::Codex, "t", &session, input).unwrap();
    assert_eq!(output, json!({}));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn codex_posttool_does_not_block_legacy_exec_footer() {
    let (root, session) = empty_session("hook-post-codex-legacy-footer");
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "pentect exec 'Get-Content -LiteralPath .\\.env'"
        },
        "tool_response": "RUNPOD_API_KEY=<<RUNPOD_API_KEY_f6a375b6c449645f>>\nTEST_SECRET=<<SECRET_ea193cc4740362de>>\nNOTE=<<SECRET_36da7f6aab3d75f1>>\n# pentect: usage: use `pentect exec \"<command>\"`; known `<<...>>` handles resolve locally before execution; `RUNPOD_API_KEY` is available as `$env:RUNPOD_API_KEY` on PowerShell or `$RUNPOD_API_KEY` on Unix; opaque blobs may show `_length_at_least_N_chars`."
    });
    let output = handle_hook(HookProvider::Codex, "t", &session, input).unwrap();
    assert_eq!(output, json!({}));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn exec_tool_output_discloses_readable_coarse_opaque_length() {
    let (root, session) = empty_session("exec-readable-length");
    let blob = "Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh";
    let masked = mask_tool_output(&session, &format!("payload={blob}\n")).unwrap();
    assert!(!masked.contains(blob), "{masked}");
    assert!(masked.contains("<<LIKELY_SECRET_"), "{masked}");
    assert!(masked.contains("_length_at_least_24_chars>>"), "{masked}");
    assert!(!masked.contains("_len24"), "{masked}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn derived_redactions_do_not_claim_to_be_reusable_handles() {
    let (root, session) = empty_session("exec-derived-no-hint");
    let masked = mask_tool_output(&session, "PREFIX_32=rpa_FAKE\n").unwrap();
    assert_eq!(masked, "PREFIX_32=<<REDACTED_DERIVED>>\n");
    assert!(first_reusable_env_name(&masked).is_none(), "{masked}");
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
fn metadata_assignment_output_does_not_pollute_recovery() {
    let (root, session) = empty_session("exec-metadata-assignment");
    let metadata = "exists=true\ntotal_lines=3\nassignment_lines=3\n";
    let first = mask_tool_output(&session, metadata).unwrap();
    assert_eq!(first, metadata);

    let output = "RUNPOD_API_KEY=rpa_FAKEPENTECTJAILBREAK1234567890abcdef\nTEST_SECRET=114514810\nNOTE=hello world\n";
    let masked = mask_tool_output(&session, output).unwrap();
    assert!(!masked.contains("rpa_FAKEPENTECTJAILBREAK"), "{masked}");
    assert!(!masked.contains("4567890abcdef"), "{masked}");
    assert!(
        masked.contains("RUNPOD_API_KEY=<<RUNPOD_API_KEY_"),
        "{masked}"
    );
    assert!(masked.contains("TEST_SECRET=<<SECRET_"), "{masked}");
    assert!(masked.contains("NOTE=<<SECRET_"), "{masked}");
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
fn derived_env_summary_output_does_not_leak_prefix_suffix_or_length() {
    let (root, session) = empty_session("exec-derived-env-summary");
    let output = "RUNPOD_API_KEY length=46 masked=rpa_...cdef\nTEST_SECRET length=9 masked=1145...4810\nNOTE length=11 masked=hell...orld\nKEY length=5 masked=abc...xyz\nkey length=5 masked=abc...xyz\nRUNPOD_API_KEY     40\nTEST_SECRET        9\nNOTE               11\nPREFIX_32=rpa_FAKEPENTECTJAILBREAK\nSUFFIX_32=ET=114514810\nBASE64=77u/UlVOUE9E\n";
    let masked = mask_tool_output(&session, output).unwrap();

    for leaked in [
        "length=46",
        "length=9",
        "length=11",
        "     40",
        "        9",
        "               11",
        "rpa_",
        "cdef",
        "1145",
        "4810",
        "hell",
        "orld",
        "rpa_FAKE",
        "ET=114514810",
        "77u/",
        "abc",
        "xyz",
    ] {
        assert!(!masked.contains(leaked), "{masked}");
    }
    assert!(
        masked.contains("RUNPOD_API_KEY=<<REDACTED_DERIVED>>"),
        "{masked}"
    );
    assert!(
        masked.contains("TEST_SECRET=<<REDACTED_DERIVED>>"),
        "{masked}"
    );
    assert!(masked.contains("NOTE=<<REDACTED_DERIVED>>"), "{masked}");
    assert!(masked.contains("KEY=<<REDACTED_DERIVED>>"), "{masked}");
    assert!(masked.contains("key=<<REDACTED_DERIVED>>"), "{masked}");
    assert!(
        masked.contains("PREFIX_32=<<REDACTED_DERIVED>>"),
        "{masked}"
    );
    assert!(
        masked.contains("SUFFIX_32=<<REDACTED_DERIVED>>"),
        "{masked}"
    );
    assert!(masked.contains("BASE64=<<REDACTED_DERIVED>>"), "{masked}");
    assert_eq!(
        masked
            .matches("RUNPOD_API_KEY=<<REDACTED_DERIVED>>")
            .count(),
        2,
        "{masked}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn encoded_env_derivatives_do_not_leak() {
    let (root, session) = empty_session("exec-encoded-env-derivatives");
    let dotenv = "RUNPOD_API_KEY=rpa_FAKEPENTECTJAILBREAK1234567890abcdef\nTEST_SECRET=114514810\nNOTE=hello world\n";
    let b64 = data_encoding::BASE64.encode(dotenv.as_bytes());
    let output = format!(
            "B64_FILE:\n{b64}\nHEX_VALUES:\nRUNPOD_API_KEY hex=7270615f46414b4550454e544543544a41494c425245414b31323334353637383930616263646566\nNOTE hex=68656c6c6f20776f726c64\n"
        );
    let masked = mask_tool_output(&session, &output).unwrap();
    assert!(!masked.contains(&b64), "{masked}");
    assert!(!masked.contains("7270615f46414b"), "{masked}");
    assert!(!masked.contains("68656c6c6f20776f726c64"), "{masked}");
    assert!(masked.contains("<<SECRET_"), "{masked}");
    assert!(
        masked.contains("RUNPOD_API_KEY=<<REDACTED_DERIVED>>"),
        "{masked}"
    );
    assert!(masked.contains("NOTE=<<REDACTED_DERIVED>>"), "{masked}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn mixed_env_output_still_masks_encoded_non_env_lines() {
    let (root, session) = empty_session("exec-mixed-env-encoded");
    let dotenv = "RUNPOD_API_KEY=rpa_FAKEPENTECTJAILBREAK1234567890abcdef\r\nTEST_SECRET=114514810\r\nNOTE=hello world\r\n";
    let b64 = data_encoding::BASE64.encode(dotenv.as_bytes());
    let output = format!("{dotenv}B64_FILE:\n{b64}\n");
    let masked = mask_tool_output(&session, &output).unwrap();
    assert!(!masked.contains("rpa_FAKEPENTECTJAILBREAK"), "{masked}");
    assert!(!masked.contains(&b64), "{masked}");
    assert!(
        masked.contains("RUNPOD_API_KEY=<<RUNPOD_API_KEY_"),
        "{masked}"
    );
    assert!(masked.contains("B64_FILE:\n<<SECRET_"), "{masked}");
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
fn pretool_collapses_nested_pentect_exec_shell_commands() {
    let (root, session) = empty_session("hook-pre-nested-exec");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": r#"pentect exec "pentect exec 'Get-Content .\.env'""#
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    let command = output["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap();
    assert!(command.contains("pentect"), "{command}");
    assert!(command.contains("exec"), "{command}");
    assert!(command.contains("Get-Content"), "{command}");
    assert!(!command.contains("pentect exec 'pentect exec"), "{command}");
    assert!(
        !command.contains("pentect exec \"pentect exec"),
        "{command}"
    );
    assert_eq!(command.matches(" exec ").count(), 1, "{command}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pretool_blocks_nested_pentect_read_escape() {
    let (root, session) = empty_session("hook-pre-nested-read");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": r#"pentect exec "pentect read .\.env""#
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("pentect exec"), "{reason}");
    assert!(reason.contains("pentect read"), "{reason}");
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
fn implicit_directory_session_is_not_rendered_in_wrapped_command() {
    let implicit = default_directory_session_name().unwrap();
    let command = wrap_shell_command(HookProvider::Claude, &implicit, "echo hello").unwrap();
    assert!(command.contains("pentect"), "{command}");
    assert!(command.contains("exec"), "{command}");
    assert!(!command.contains("--session"), "{command}");
    assert!(command.contains("echo hello"), "{command}");
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
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn hook_text_masks_runpod_token_as_plain_text() {
    let (root, session) = empty_session("hook-runpod-text");
    let raw = concat!("RUNPOD=", "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef");
    let masked = mask_tool_output(&session, raw).unwrap();
    assert!(!masked.contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"));
    assert!(masked.contains("<<RUNPOD_API_KEY_"), "{masked}");
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
    (root, session, result.masked)
}

fn empty_session(name: &str) -> (PathBuf, Session) {
    let root = temp_root(name);
    let session = Session::open_at(&root, "t").unwrap();
    (root, session)
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "pentect-agent-test-{}-{}-{name}",
        std::process::id(),
        unix_millis()
    ))
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
