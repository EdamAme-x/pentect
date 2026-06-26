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
    assert!(checked_session_name(".").is_err());
    assert!(checked_session_name("..").is_err());
    assert_eq!(checked_session_name("demo").unwrap(), "demo");
}

#[cfg(unix)]
#[test]
fn directory_session_name_uses_canonical_directory_identity() {
    let root = temp_root("session-symlink");
    let real = root.join("real");
    let link = root.join("link");
    std::fs::create_dir_all(&real).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let a = directory_session_name_for(&real).unwrap();
    let b = directory_session_name_for(&link).unwrap();
    assert_eq!(a, b);
    let _ = std::fs::remove_dir_all(root);
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
fn exec_parse_accepts_live_and_approve_without_env_flags() {
    let args = strings(["pentect-agent", "exec", "--live", "--approve", "echo", "hi"]);
    let opts = ExecOpts::parse(&args).unwrap();
    assert!(opts.live);
    assert!(opts.approve);
    assert!(matches!(
        opts.mode,
        ExecMode::Shell(command) if command == "echo hi"
    ));
}

#[test]
fn exec_parse_rejects_manual_env_policy_flags() {
    let args = strings([
        "pentect-agent",
        "exec",
        "--allow-env",
        "RUNPOD_API_KEY",
        "echo",
        "hi",
    ]);
    let err = match ExecOpts::parse(&args) {
        Ok(_) => panic!("expected --allow-env to be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("unknown option"), "{err}");
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
fn dashboard_parse_accepts_top_level_port() {
    let args = strings(["pentect-agent", "--port", "7319"]);
    let opts = DashboardOpts::parse(&args).unwrap();
    assert_eq!(opts.port, Some(7319));
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
fn open_at_stays_in_memory_even_when_base_has_capability_vault() {
    let root = temp_root("open-at-in-memory");
    let persisted = Session::open_capability_at(&root, "t").unwrap();
    let persisted_key = persisted.key;
    drop(persisted);

    let opened = Session::open_at(&root, "t").unwrap();
    assert_ne!(opened.key, persisted_key);
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
fn exec_registers_referenced_local_files_as_env_capabilities() {
    guard_shell_script_with_env(
        "tool --config secrets.json >/dev/null",
        &EnvPolicy::default(),
    )
    .unwrap();
    guard_shell_script_with_env("curl -H @headers.txt example.test", &EnvPolicy::default())
        .unwrap();

    let root = temp_root("referenced-file-registers");
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let secrets = project.join("secrets.json");
    let raw = r#"{"apiKey":"sk-ABCDEFGHIJKLMNOPQRSTUVWX","runpod":"rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"}"#;
    std::fs::write(&secrets, raw).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = RecoveryStore::load(&session).unwrap();

    let command = if cfg!(windows) {
        format!("Get-Content -LiteralPath '{}' > $null", secrets.display())
    } else {
        format!("cat '{}' >/dev/null", secrets.display())
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        approve: false,
        mode: ExecMode::Shell(command),
    };
    run_resolved_command(&store, &opts).unwrap();
    let env = store.auto_env_bindings().unwrap();
    assert!(
        env.iter()
            .any(|(name, value)| name.starts_with("PENTECT_")
                && value == "sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
        "{env:?}"
    );
    assert!(
        env.iter().any(|(name, value)| name.starts_with("PENTECT_")
            && value == "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"),
        "{env:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn exec_approval_sees_capabilities_registered_from_referenced_files() {
    let root = temp_root("approval-registers-file-before-decision");
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("secrets.env"),
        "API_TOKEN=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\n",
    )
    .unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = RecoveryStore::load(&session).unwrap();
    let secret_path = project.join("secrets.env");
    let command = if cfg!(windows) {
        format!(
            "Get-Content -LiteralPath '{}' > $null; Write-Output $env:API_TOKEN",
            secret_path.display()
        )
    } else {
        format!(
            "cat '{}' >/dev/null; printf '%s' \"$API_TOKEN\"",
            secret_path.display()
        )
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        approve: false,
        mode: ExecMode::Shell(command),
    };

    let before = exec_approval(&store, &opts).unwrap();
    assert!(!before.requires_approval(), "{before:?}");

    prepare_exec_capabilities(&store, &opts).unwrap();
    let after = exec_approval(&store, &opts).unwrap();

    assert!(after.requires_approval(), "{after:?}");
    assert_eq!(after.env_names(), vec!["API_TOKEN".to_string()]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn always_fingerprint_includes_capability_value_identity() {
    let command = "Write-Output $env:API_TOKEN".to_string();
    let a = ExecApproval {
        command: command.clone(),
        env_refs: vec![EnvApprovalRef {
            name: "API_TOKEN".to_string(),
            value_hash: secret_value_hash("first-secret"),
        }],
        direct_handles: Vec::new(),
        destinations: Vec::new(),
        network_like: false,
    };
    let b = ExecApproval {
        command,
        env_refs: vec![EnvApprovalRef {
            name: "API_TOKEN".to_string(),
            value_hash: secret_value_hash("second-secret"),
        }],
        direct_handles: Vec::new(),
        destinations: Vec::new(),
        network_like: false,
    };

    assert_ne!(a.fingerprint(), b.fingerprint());
}

#[test]
fn exec_policy_blocks_environment_reads() {
    let err = guard_shell_script_with_env("Get-ChildItem Env:", &EnvPolicy::default()).unwrap_err();
    assert!(err.contains("environment variables"), "{err}");

    let err =
        guard_shell_script_with_env("printenv RUNPOD_API_KEY", &EnvPolicy::default()).unwrap_err();
    assert!(err.contains("environment variables"), "{err}");

    let err =
        guard_shell_script_with_env("echo $RUNPOD_API_KEY", &EnvPolicy::default()).unwrap_err();
    assert!(err.contains("environment variables"), "{err}");

    let err = guard_shell_script_with_env("Write-Output %RUNPOD_API_KEY%", &EnvPolicy::default())
        .unwrap_err();
    assert!(err.contains("environment variables"), "{err}");
}

#[test]
fn exec_policy_allows_auto_bound_environment_reads_only() {
    let allowed = env_policy(&["RUNPOD_API_KEY"]);
    guard_shell_script_with_env("printenv RUNPOD_API_KEY", &allowed).unwrap();
    guard_shell_script_with_env("echo $RUNPOD_API_KEY", &allowed).unwrap();
    guard_shell_script_with_env("Write-Output $env:RUNPOD_API_KEY", &allowed).unwrap();

    let err = guard_shell_script_with_env("Write-Output $env:AWS_SECRET_ACCESS_KEY", &allowed)
        .unwrap_err();
    assert!(err.contains("environment variables"), "{err}");
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
fn exec_does_not_inherit_parent_environment() {
    let root = temp_root("env-clear");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = RecoveryStore::load(&session).unwrap();
    let var = format!("PENTECT_PARENT_CANARY_{}", unix_millis());
    let value = "rpa_SHOULD_NOT_LEAK_FROM_PARENT_ENV_1234567890abcdef";
    std::env::set_var(&var, value);
    let mode = if cfg!(windows) {
        ExecMode::Program(vec![
            "cmd.exe".to_string(),
            "/C".to_string(),
            format!("if defined {var} (echo %{var}%) else (echo missing)"),
        ])
    } else {
        ExecMode::Program(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "if [ -z \"${{{var}}}\" ]; then printf missing; else printf '%s' \"${{{var}}}\"; fi"
            ),
        ])
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        approve: false,
        mode,
    };
    let output = run_resolved_command(&store, &opts);
    std::env::remove_var(&var);
    let output = output.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("missing"), "{stdout}");
    assert!(!stdout.contains(value), "{stdout}");
    let _ = std::fs::remove_dir_all(root);
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
    let runpod_handle = masked_handle_from_assignment(&masked, "RUNPOD_API_KEY");
    let runpod_pentect_env = pentect_env_name_for_handle(&runpod_handle);
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
    assert!(
        env.iter().any(|(name, value)| name == &runpod_pentect_env
            && value == "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"),
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
fn exec_only_injects_referenced_capability_env() {
    let root = temp_root("capability-env-least");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let output =
        "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\nTEST_SECRET=114514810\n";
    let _masked = mask_tool_output(&session, output).unwrap();
    let store = RecoveryStore::load(&session).unwrap();

    let none = requested_env_bindings(
        &store,
        &ExecMode::Shell(if cfg!(windows) {
            "Write-Output hi".to_string()
        } else {
            "printf hi".to_string()
        }),
    )
    .unwrap();
    assert!(none.is_empty(), "{none:?}");

    let one = requested_env_bindings(
        &store,
        &ExecMode::Shell(if cfg!(windows) {
            "Write-Output $env:RUNPOD_API_KEY".to_string()
        } else {
            "printf '%s' \"$RUNPOD_API_KEY\"".to_string()
        }),
    )
    .unwrap();
    assert_eq!(one.len(), 1, "{one:?}");
    assert_eq!(one[0].0, "RUNPOD_API_KEY");
    assert_eq!(one[0].1, "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn auto_env_bindings_do_not_override_baseline_environment() {
    let root = temp_root("capability-reserved-env-binding");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let output = "PATH=sk-ABCDEFGHIJKLMNOPQRSTUVWX\nDUMMY_SECRET=sk-YYYYYYYYYYYYYYYYYYYY\n";
    let masked = mask_tool_output(&session, output).unwrap();
    assert!(masked.contains("PATH=<<OPENAI_API_KEY_"), "{masked}");
    assert!(
        masked.contains("DUMMY_SECRET=<<OPENAI_API_KEY_"),
        "{masked}"
    );

    let store = RecoveryStore::load(&session).unwrap();
    let env = store.auto_env_bindings().unwrap();
    assert!(
        !env.iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("PATH")),
        "{env:?}"
    );
    assert!(
        env.iter()
            .any(|(name, value)| name == "DUMMY_SECRET" && value == "sk-YYYYYYYYYYYYYYYYYYYY"),
        "{env:?}"
    );
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
fn exec_auto_binds_generic_masked_handles_as_pentect_env_vars() {
    let root = temp_root("capability-generic-pentect-env");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let masked = mask_tool_output(&session, &format!("created token: {raw}\n")).unwrap();
    assert!(!masked.contains(raw), "{masked}");
    let handle = first_masked_handle(&masked);
    let env_name = pentect_env_name_for_handle(&handle);
    drop(session);

    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = RecoveryStore::load(&session).unwrap();
    let env = store.auto_env_bindings().unwrap();
    assert!(
        env.iter()
            .any(|(name, value)| name == &env_name && value == raw),
        "{env:?}"
    );

    let command = if cfg!(windows) {
        format!("Write-Output $env:{env_name}")
    } else {
        format!("printf '%s' \"${env_name}\"")
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        approve: false,
        mode: ExecMode::Shell(command),
    };
    let output = run_resolved_command(&store, &opts).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(raw), "{stdout}");

    let safe = mask_tool_output(&session, &stdout).unwrap();
    assert!(!safe.contains(raw), "{safe}");
    assert!(safe.contains("<<OPENAI_API_KEY_"), "{safe}");
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
fn write_tool_materializes_masked_content_without_returning_plaintext() {
    let root = temp_root("capability-write-generic");
    let project = PathBuf::from("target").join(format!(
        "pentect-agent-write-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();
    drop(session);

    let session = Session::open_capability_at(&root, "t").unwrap();
    let config = project.join("config.txt");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": config.to_string_lossy(),
            "content": masked
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("wrote resolved masked content"), "{reason}");
    assert!(reason.contains("treat this as success"), "{reason}");
    assert!(!reason.contains(raw), "{reason}");

    let written = std::fs::read_to_string(&config).unwrap();
    assert_eq!(written, format!("token={raw}\n"));
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_refuses_masked_materialization_outside_current_dir() {
    let root = temp_root("capability-write-outside");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();
    drop(session);

    let session = Session::open_capability_at(&root, "t").unwrap();
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": "../pentect-should-not-write.txt",
            "content": masked
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("outside the current directory"), "{reason}");
    assert!(!reason.contains(raw), "{reason}");
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn write_tool_refuses_masked_materialization_through_symlink_dir() {
    let root = temp_root("capability-write-symlink");
    let outside = temp_root("capability-write-symlink-outside");
    std::fs::create_dir_all(&outside).unwrap();
    let project = PathBuf::from("target").join(format!(
        "pentect-agent-symlink-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    std::os::unix::fs::symlink(&outside, project.join("link")).unwrap();

    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();
    drop(session);

    let session = Session::open_capability_at(&root, "t").unwrap();
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": project.join("link").join("config.txt").to_string_lossy(),
            "content": masked
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("outside the current directory"), "{reason}");
    assert!(!outside.join("config.txt").exists());
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(outside);
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
                "apiKey": "sk-ABCDEFGHIJKLMNOPQRSTUVWX",
                "password": "hunter2\nsecond-line",
                "otp": 100482
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
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(!rendered.contains("second-line"), "{rendered}");
    assert!(!rendered.contains("100482"), "{rendered}");
    let store = RecoveryStore::load(&session).unwrap();
    let env = store.auto_env_bindings().unwrap();
    assert!(
        env.iter().any(|(name, value)| name.starts_with("PENTECT_")
            && value == "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"),
        "{env:?}"
    );
    assert!(
        env.iter()
            .any(|(name, value)| name.starts_with("PENTECT_")
                && value == "sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
        "{env:?}"
    );
    assert!(
        env.iter()
            .any(|(name, value)| name.starts_with("PENTECT_PASSWORD_")
                && value == "hunter2\nsecond-line"),
        "{env:?}"
    );
    assert!(
        env.iter()
            .any(|(name, value)| name.starts_with("PENTECT_OTP_") && value == "100482"),
        "{env:?}"
    );
    assert!(updated.is_object(), "{updated}");
    assert!(updated["structuredContent"]["otp"].is_string(), "{updated}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn mcp_structured_secret_can_be_used_as_pentect_env_capability() {
    let (root, session) = empty_session("hook-post-mcp-env-use");
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__browser__create_api_key",
        "tool_response": {
            "structuredContent": {
                "apiKey": raw
            }
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    let rendered = serde_json::to_string(&output).unwrap();
    assert!(!rendered.contains(raw), "{rendered}");
    assert!(rendered.contains("<<OPENAI_API_KEY_"), "{rendered}");

    let store = RecoveryStore::load(&session).unwrap();
    let env = store.auto_env_bindings().unwrap();
    let env_name = env
        .iter()
        .find_map(|(name, value)| {
            (name.starts_with("PENTECT_OPENAI_API_KEY_") && value == raw).then(|| name.clone())
        })
        .unwrap_or_else(|| panic!("missing PENTECT env binding in {env:?}"));
    let command = if cfg!(windows) {
        format!("Write-Output $env:{env_name}")
    } else {
        format!("printf '%s' \"${env_name}\"")
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        approve: false,
        mode: ExecMode::Shell(command),
    };
    let output = run_resolved_command(&store, &opts).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(raw), "{stdout}");

    let safe = mask_tool_output(&session, &stdout).unwrap();
    assert!(!safe.contains(raw), "{safe}");
    assert!(safe.contains("<<OPENAI_API_KEY_"), "{safe}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn posttool_masks_secret_object_keys() {
    let (root, session) = empty_session("hook-post-secret-key");
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let mut structured = serde_json::Map::new();
    structured.insert(raw.to_string(), json!({"status": "created"}));
    structured.insert("token".to_string(), json!("hunter2"));
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__x__y",
        "tool_response": {
            "structuredContent": structured
        }
    });

    let output = handle_hook(HookProvider::Codex, "t", &session, input).unwrap();
    let rendered = serde_json::to_string(&output).unwrap();
    assert!(!rendered.contains(raw), "{rendered}");
    assert!(rendered.contains("<<OPENAI_API_KEY_"), "{rendered}");
    assert!(!rendered.contains("hunter2"), "{rendered}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn posttool_masks_authorization_structured_key() {
    let (root, session) = empty_session("hook-post-authz-key");
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__x__y",
        "tool_response": {
            "structuredContent": {
                "authorization": "Bearer short",
                "password": "hunter2"
            }
        }
    });

    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    let rendered = serde_json::to_string(&output).unwrap();
    assert!(!rendered.contains("Bearer short"), "{rendered}");
    assert!(!rendered.contains("hunter2"), "{rendered}");
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
fn codex_posttool_does_not_block_short_exec_footer() {
    let (root, session) = empty_session("hook-post-codex-legacy-footer");
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "pentect exec 'Get-Content -LiteralPath .\\.env'"
        },
        "tool_response": "RUNPOD_API_KEY=<<RUNPOD_API_KEY_f6a375b6c449645f>>\nTEST_SECRET=<<SECRET_ea193cc4740362de>>\nNOTE=<<SECRET_36da7f6aab3d75f1>>\n# pentect: help: `pentect help`."
    });
    let output = handle_hook(HookProvider::Codex, "t", &session, input).unwrap();
    assert_eq!(output, json!({}));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn codex_posttool_masks_pentect_exec_with_trailing_shell_escape() {
    let (root, session) = empty_session("hook-post-codex-exec-trailing-shell");
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "pentect exec -- echo ok; Write-Output OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX"
        },
        "tool_response": "ok\nOPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n"
    });
    let output = handle_hook(HookProvider::Codex, "t", &session, input).unwrap();
    let rendered = serde_json::to_string(&output).unwrap();
    assert_eq!(output["decision"], "block");
    assert!(
        !rendered.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
        "{rendered}"
    );
    assert!(rendered.contains("<<OPENAI_API_KEY_"), "{rendered}");
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
fn pretool_wraps_pentect_exec_with_trailing_shell_escape() {
    let (root, session) = empty_session("hook-pre-exec-trailing-shell");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "pentect exec -- echo ok; Write-Output OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX"
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    let command = output["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap();
    assert!(command.contains(" exec "), "{command}");
    assert!(command.contains("echo ok; Write-Output"), "{command}");
    assert!(!command.contains("pentect exec -- echo ok"), "{command}");
    assert_eq!(command.matches(" exec ").count(), 1, "{command}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pretool_preserves_pentect_exec_live_flag() {
    let (root, session) = empty_session("hook-pre-exec-live");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": r#"pentect exec --live "Write-Output hi""#
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    assert_eq!(output, json!({}));
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

fn env_policy(allowed: &[&str]) -> EnvPolicy {
    EnvPolicy {
        allowed: allowed
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect(),
    }
}

fn masked_handle_from_assignment(masked: &str, key: &str) -> String {
    let prefix = format!("{key}=");
    let line = masked
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("missing {key}= line in {masked}"));
    line[prefix.len()..].trim().to_string()
}

fn first_masked_handle(masked: &str) -> String {
    let start = masked
        .find("<<")
        .unwrap_or_else(|| panic!("missing handle in {masked}"));
    let end = masked[start..]
        .find(">>")
        .map(|offset| start + offset + 2)
        .unwrap_or_else(|| panic!("unterminated handle in {masked}"));
    masked[start..end].to_string()
}

fn pentect_env_name_for_handle(handle: &str) -> String {
    let inner = handle
        .strip_prefix("<<")
        .and_then(|value| value.strip_suffix(">>"))
        .unwrap_or_else(|| panic!("not a handle: {handle}"));
    let core = match inner.rsplit_once("_length_at_least_") {
        Some((prefix, suffix))
            if suffix
                .strip_suffix("_chars")
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit())) =>
        {
            prefix
        }
        _ => inner,
    };
    let core = match core.rsplit_once("_len") {
        Some((prefix, suffix)) if suffix.bytes().all(|b| b.is_ascii_digit()) => prefix,
        _ => core,
    };
    format!("PENTECT_{core}")
}
