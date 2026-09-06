use super::*;

struct RecoveringTestMutex(std::sync::Mutex<()>);

impl RecoveringTestMutex {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ()>, std::convert::Infallible> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }
}

// A failing assertion must not turn every later environment-isolated test
// into a misleading PoisonError. Tests still fail at their original assertion.
static TEST_ENV_LOCK: RecoveringTestMutex = RecoveringTestMutex(std::sync::Mutex::new(()));

#[test]
fn canonical_engine_construction_stays_off_the_warm_up_path() {
    let started = std::time::Instant::now();
    let _engine = build_masking_engine(
        Profile::Strict,
        Vec::new(),
        false,
        pentect_core::DecodeConfig::default(),
    )
    .expect("canonical engine");
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "canonical engine construction took {elapsed:?}; detector warm-up must remain lazy"
    );
}

#[test]
fn claude_hook_cli_is_retired_in_favor_of_http_gateway() {
    let error = parse_hook_provider("claude").unwrap_err();
    assert!(error.contains("HTTP gateway"), "{error}");
}

struct ActiveMemoryStoreEnv {
    candidate: std::path::PathBuf,
    base: std::path::PathBuf,
    runtime_env_name: &'static str,
    previous_runtime_env: Option<std::ffi::OsString>,
}

impl ActiveMemoryStoreEnv {
    fn start(name: &str) -> (Self, String, String) {
        let token = data_encoding::HEXLOWER.encode(&Config::generate().key);
        let read_token = data_encoding::HEXLOWER.encode(&Config::generate().key);
        let write_token = data_encoding::HEXLOWER.encode(&Config::generate().key);
        let addr = memory_store::spawn_test_memory_store_with_activity(
            token.clone(),
            read_token.clone(),
            write_token.clone(),
        );
        let base = temp_root(name);
        let (runtime_env_name, root) = test_process_host_root(&base);
        let previous_runtime_env = std::env::var_os(runtime_env_name);
        std::env::set_var(runtime_env_name, &base);
        let candidate = register_process_host_candidate(
            &root,
            &addr,
            &token,
            &read_token,
            &write_token,
            std::process::id(),
        )
        .unwrap();
        for (env_name, value) in [
            (ENV_ADDR, addr.as_str()),
            (ENV_TOKEN, token.as_str()),
            (PENTECT_AGENT_LAUNCHED_ENV, token.as_str()),
        ] {
            std::env::set_var(env_name, value);
        }
        (
            Self {
                candidate,
                base,
                runtime_env_name,
                previous_runtime_env,
            },
            addr,
            token,
        )
    }
}

impl Drop for ActiveMemoryStoreEnv {
    fn drop(&mut self) {
        for name in [ENV_ADDR, ENV_TOKEN, PENTECT_AGENT_LAUNCHED_ENV] {
            std::env::remove_var(name);
        }
        unregister_process_host_candidate(&self.candidate);
        match self.previous_runtime_env.take() {
            Some(value) => std::env::set_var(self.runtime_env_name, value),
            None => std::env::remove_var(self.runtime_env_name),
        }
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[cfg(windows)]
fn test_process_host_root(base: &std::path::Path) -> (&'static str, std::path::PathBuf) {
    ("LOCALAPPDATA", base.join("pentect"))
}

#[cfg(target_os = "macos")]
fn test_process_host_root(base: &std::path::Path) -> (&'static str, std::path::PathBuf) {
    ("HOME", base.join("Library").join("Caches").join("pentect"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn test_process_host_root(base: &std::path::Path) -> (&'static str, std::path::PathBuf) {
    ("XDG_RUNTIME_DIR", base.join("pentect"))
}

fn first_handle_with_prefix(text: &str, prefix: &str) -> String {
    let start = text.find(prefix).unwrap_or_else(|| panic!("{text}"));
    let end = text[start..]
        .find(">>")
        .map(|offset| start + offset + 2)
        .unwrap_or_else(|| panic!("{text}"));
    text[start..end].to_string()
}

#[cfg(feature = "ocr")]
fn qr_png(payload: &str) -> Vec<u8> {
    use image::{GrayImage, ImageFormat, Luma};
    use rxing::{BarcodeFormat, Writer};
    use std::io::Cursor;

    let writer = rxing::qrcode::QRCodeWriter {};
    let matrix = writer
        .encode(payload, &BarcodeFormat::QR_CODE, 192, 192)
        .unwrap();
    let mut img = GrayImage::from_pixel(matrix.getWidth(), matrix.getHeight(), Luma([255]));
    for y in 0..matrix.getHeight() {
        for x in 0..matrix.getWidth() {
            if matrix.get(x, y) {
                img.put_pixel(x, y, Luma([0]));
            }
        }
    }
    let mut out = Vec::new();
    image::DynamicImage::ImageLuma8(img)
        .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
        .unwrap();
    out
}

#[test]
fn session_recovery_is_process_local() {
    let root = std::env::temp_dir().join(format!(
        "pentect-test-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let session = Session::open_at(&root, "t").unwrap();
    let input = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n";
    let result = Engine::with_profile(Profile::Strict).mask(
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
    let args = strings(["pentect", "exec", "echo", "hi"]);
    assert!(matches!(
        ExecOpts::parse(&args).unwrap().mode,
        ExecMode::Shell(command) if command == "echo hi"
    ));
    let args = strings(["pentect", "exec", "echo hi"]);
    assert!(matches!(
        ExecOpts::parse(&args).unwrap().mode,
        ExecMode::Shell(command) if command == "echo hi"
    ));
}

#[test]
fn exec_parse_accepts_live_without_env_flags() {
    let args = strings(["pentect", "exec", "--live", "echo", "hi"]);
    let opts = ExecOpts::parse(&args).unwrap();
    assert!(opts.live);
    assert!(matches!(
        opts.mode,
        ExecMode::Shell(command) if command == "echo hi"
    ));
}

#[test]
fn child_env_overlays_strip_memory_store_credentials() {
    let mut cmd = Command::new("echo");
    for name in pentect_control_env_names() {
        cmd.env(name, "attacker-selected-value");
    }
    apply_child_env_overlays(&mut cmd, &[], "demo");
    let envs: Vec<_> = cmd
        .get_envs()
        .map(|(name, value)| {
            (
                name.to_string_lossy().to_string(),
                value.map(|value| value.to_string_lossy().to_string()),
            )
        })
        .collect();
    for reserved in pentect_control_env_names() {
        assert!(
            matches!(
                envs.iter().find(|(name, _)| name == reserved),
                Some((_, None))
            ),
            "{reserved}: {envs:?}"
        );
    }
}

#[test]
fn exec_parse_accepts_stdin_mode_without_shell_text() {
    let args = strings(["pentect", "exec", "--stdin"]);
    let opts = ExecOpts::parse(&args).unwrap();
    assert!(matches!(opts.mode, ExecMode::Stdin));

    let args = strings(["pentect", "exec", "--stdin", "echo", "hi"]);
    let err = match ExecOpts::parse(&args) {
        Ok(_) => panic!("expected --stdin with shell text to fail"),
        Err(err) => err,
    };
    assert!(err.contains("--stdin"), "{err}");
}

#[test]
fn exec_parse_accepts_base64_script_mode() {
    let script = "Write-Output \"日本語|OK\"";
    let encoded = data_encoding::BASE64URL_NOPAD.encode(script.as_bytes());
    let args = strings(["pentect", "exec", "--script-b64", &encoded]);
    let opts = ExecOpts::parse(&args).unwrap();
    assert!(matches!(opts.mode, ExecMode::Shell(command) if command == script));
}

#[test]
fn exec_parse_rejects_manual_env_policy_flags() {
    let args = strings([
        "pentect",
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
    let args = strings(["pentect", "exec", "--shell", "echo hi"]);
    let err = match ExecOpts::parse(&args) {
        Ok(_) => panic!("expected --shell to be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("removed"), "{err}");
}

#[test]
fn exec_parse_accepts_program_after_separator() {
    let args = strings(["pentect", "exec", "--", "echo", "hi"]);
    let opts = ExecOpts::parse(&args).unwrap();
    assert!(!opts.allow_secret_argv);
    assert!(matches!(opts.mode, ExecMode::Program(_)));

    let args = strings(["pentect", "exec", "--allow-secret-argv", "--", "echo", "hi"]);
    let opts = ExecOpts::parse(&args).unwrap();
    assert!(opts.allow_secret_argv);
    assert!(matches!(opts.mode, ExecMode::Program(_)));
}

#[test]
fn exec_parse_accepts_one_handle_for_program_stdin_only() {
    let handle = "<<API_TOKEN_0123456789abcdef>>";
    let args = strings(["pentect", "exec", "--secret-stdin", handle, "--", "tool"]);
    let opts = ExecOpts::parse(&args).unwrap();
    assert_eq!(opts.secret_stdin.as_deref(), Some(handle));
    assert!(matches!(opts.mode, ExecMode::Program(_)));

    let args = strings([
        "pentect",
        "exec",
        "--secret-stdin",
        "not-a-handle",
        "--",
        "tool",
    ]);
    let error = match ExecOpts::parse(&args) {
        Ok(_) => panic!("expected a non-handle to fail"),
        Err(error) => error,
    };
    assert!(error.contains("exactly one masked handle"), "{error}");

    let args = strings(["pentect", "exec", "--secret-stdin", handle, "echo ok"]);
    let error = match ExecOpts::parse(&args) {
        Ok(_) => panic!("expected shell mode to fail"),
        Err(error) => error,
    };
    assert!(error.contains("program after `--`"), "{error}");
}

#[test]
fn direct_program_secret_arguments_require_explicit_opt_in() {
    let root = temp_root("secret-argv-opt-in");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = MemoryStore::for_session(&session);
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let masked = mask_tool_output(&session, &format!("OPENAI_API_KEY={raw}\n")).unwrap();
    let handle = masked.split_once('=').unwrap().1.trim().to_string();
    let args = vec!["tool".to_string(), handle];

    let error = resolve_command_args(&store, &args, false).unwrap_err();
    assert!(error.contains("refusing"), "{error}");
    assert!(!error.contains(raw), "{error}");

    let resolved = resolve_command_args(&store, &args, true).unwrap();
    assert_eq!(resolved, ["tool", raw]);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn direct_program_receives_a_known_secret_only_on_stdin() {
    let root = temp_root("secret-stdin");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = MemoryStore::for_session(&session);
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let masked = mask_tool_output(&session, &format!("OPENAI_API_KEY={raw}\n")).unwrap();
    let handle = masked.split_once('=').unwrap().1.trim().to_string();
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        allow_secret_argv: false,
        secret_stdin: Some(handle),
        script_shell: ScriptShell::Native,
        mode: ExecMode::Program(vec![
            "sh".to_string(),
            "-c".to_string(),
            "printf 'STDIN='; cat".to_string(),
        ]),
    };

    let output = run_resolved_command(&store, &opts).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, format!("STDIN={raw}"));
    let masked = mask_tool_output(&session, &stdout).unwrap();
    assert!(!masked.contains(raw), "{masked}");
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn secret_stdin_does_not_create_an_inherited_binding_for_a_descendant() {
    let root = temp_root("secret-stdin-descendant");
    std::fs::create_dir_all(&root).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = MemoryStore::for_session(&session);
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let masked = mask_tool_output(&session, &format!("OPENAI_API_KEY={raw}\n")).unwrap();
    let handle = masked.split_once('=').unwrap().1.trim().to_string();
    let binding_name = store
        .auto_env_bindings()
        .unwrap()
        .into_iter()
        .find_map(|(name, value)| (value == raw).then_some(name))
        .unwrap();
    let descendant_env = root.join("descendant.env");
    let script = format!(
        "secret=$(cat); printf 'TARGET=%s' \"$secret\"; sh -c 'env > \"$1\"' sh '{}'",
        descendant_env.display()
    );
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        allow_secret_argv: false,
        secret_stdin: Some(handle),
        script_shell: ScriptShell::Native,
        mode: ExecMode::Program(vec!["sh".to_string(), "-c".to_string(), script]),
    };

    let output = run_resolved_command(&store, &opts).unwrap();
    assert!(
        output.status.success(),
        "descendant fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("TARGET={raw}")
    );
    let inherited = std::fs::read_to_string(&descendant_env).unwrap();
    assert!(!inherited.contains(raw), "descendant inherited plaintext");
    assert!(
        !inherited
            .lines()
            .any(|line| line.starts_with(&format!("{binding_name}="))),
        "descendant inherited the Pentect binding"
    );
    let safe = mask_tool_output(&session, &String::from_utf8_lossy(&output.stdout)).unwrap();
    assert!(!safe.contains(raw), "masked stdout exposed plaintext");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn resolve_parse_accepts_multiple_paths() {
    let args = strings(["pentect", "resolve", "a.env", "b.env"]);
    let opts = ResolveOpts::parse(&args).unwrap();
    assert!(matches!(
        opts.mode,
        ResolveMode::Files(paths)
            if paths == [PathBuf::from("a.env"), PathBuf::from("b.env")]
    ));
}

#[test]
fn resolve_parse_defaults_to_stdin_without_paths() {
    let args = strings(["pentect", "resolve"]);
    let opts = ResolveOpts::parse(&args).unwrap();
    assert!(matches!(opts.mode, ResolveMode::Stdin));
}

#[test]
fn read_defaults_to_strict_and_infers_dotenv() {
    let args = strings(["pentect", "read", r".\.env"]);
    let opts = ReadOpts::parse(&args).unwrap();
    assert!(!opts.emit_meta);
    assert_eq!(infer_kind(&opts.path), Kind::Env);

    let args = strings(["pentect", "read", "--meta", r".\.env"]);
    assert!(ReadOpts::parse(&args).unwrap().emit_meta);
}

#[test]
fn memory_store_is_process_local_only() {
    let root = std::env::temp_dir().join(format!(
        "pentect-test-{}-{}-process-local",
        std::process::id(),
        unix_millis()
    ));
    let session = Session::open_at(&root, "t").unwrap();
    let store = MemoryStore::for_session(&session);
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
        "pentect-test-{}-{}-session",
        std::process::id(),
        unix_millis()
    ));

    let _session = Session::open_at(&root, "t").unwrap();
    assert!(!root.exists(), "{}", root.display());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn default_session_root_lives_under_project_pentect_dir() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    std::env::set_var("PENTECT_HOME", "attacker-selected-directory");
    let root = session_root("demo").unwrap();
    std::env::remove_var("PENTECT_HOME");
    assert_eq!(
        root,
        config::project_root()
            .unwrap()
            .join(".pentect")
            .join("agent")
            .join("demo")
    );
}

#[test]
fn project_config_remains_effective_from_a_nested_working_directory() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("nested-project-config");
    write_project_config(&root, "[output]\nrestore = false\n");
    let _home = write_user_config(&root, "");
    let nested = root.join("src").join("nested");
    {
        let _cwd = enter_temp_cwd(&nested);
        assert!(!output_restore_enabled().unwrap());
    }
    write_project_config(&nested, "[output]\nrestore = true\n");
    {
        let _cwd = enter_temp_cwd(&nested.join("deeper"));
        assert!(output_restore_enabled().unwrap());
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn open_at_stays_process_local() {
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
        "pentect-test-{}-{}-read-dotenv",
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
        result.masked.contains("TEST_SECRET=<<TEST_SECRET_"),
        "{}",
        result.masked
    );
    assert!(result.masked.contains("NOTE=<<NOTE_"), "{}", result.masked);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn exec_allows_secret_file_reads_because_output_is_remasked() {
    let root = temp_root("secret-file-read");
    let secret = root.join(".env");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        &secret,
        "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\n",
    )
    .unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = MemoryStore::for_session(&session);
    let command = if cfg!(windows) {
        format!("Get-Content -LiteralPath '{}'", secret.display())
    } else {
        format!("cat '{}'", secret.display())
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        allow_secret_argv: false,
        secret_stdin: None,
        script_shell: ScriptShell::Native,
        mode: ExecMode::Shell(command),
    };
    let output = run_resolved_command(&store, &opts).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"),
        "{stdout}"
    );
    let masked = mask_tool_output(&session, &stdout).unwrap();
    assert!(
        !masked.contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"),
        "{masked}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn exec_registers_referenced_local_files_as_env_capabilities() {
    let root = temp_root("referenced-file-registers");
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let secrets = project.join("secrets.json");
    let raw = r#"{"apiKey":"sk-ABCDEFGHIJKLMNOPQRSTUVWX","runpod":"rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"}"#;
    std::fs::write(&secrets, raw).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = MemoryStore::for_session(&session);

    let command = if cfg!(windows) {
        format!("Get-Content -LiteralPath '{}' > $null", secrets.display())
    } else {
        format!("cat '{}' >/dev/null", secrets.display())
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        allow_secret_argv: false,
        secret_stdin: None,
        script_shell: ScriptShell::Native,
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
        !env.iter()
            .any(|(_, value)| value == "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"),
        "{env:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn exec_inherits_parent_environment_and_masks_output() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("env-pass-through");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = MemoryStore::for_session(&session);
    let var = format!("PENTECT_PARENT_CANARY_{}", unix_millis());
    let value = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    std::env::set_var(&var, value);
    let mode = if cfg!(windows) {
        ExecMode::Program(vec![
            "cmd.exe".to_string(),
            "/C".to_string(),
            format!("echo RUNPOD_API_KEY=%{var}%"),
        ])
    } else {
        ExecMode::Program(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("printf 'RUNPOD_API_KEY=%s' \"${{{var}}}\""),
        ])
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        allow_secret_argv: false,
        secret_stdin: None,
        script_shell: ScriptShell::Native,
        mode,
    };
    let output = run_resolved_command(&store, &opts);
    std::env::remove_var(&var);
    let output = output.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(value), "{stdout}");
    let masked = mask_tool_output(&session, &stdout).unwrap();
    assert!(!masked.contains(value), "{masked}");
    assert!(masked.contains("RUNPOD_API_KEY=<<"), "{masked}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn active_tool_output_masker_reuses_in_memory_state() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("active-masker");

    let client = MemoryStoreClient::from_env().unwrap();
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let mut masker = ActiveToolOutputMasker::new().unwrap();
    let first = masker
        .mask_tool_output(&format!("OPENAI_API_KEY={raw}\n"))
        .unwrap()
        .unwrap();
    assert!(!first.contains(raw), "{first}");
    let handle = first.split_once('=').unwrap().1.trim().to_string();

    let repeated = masker
        .mask_tool_output(&format!("OPENAI_API_KEY={raw}\n"))
        .unwrap()
        .unwrap();
    assert_eq!(repeated, first);

    let second = masker
        .mask_tool_output(&format!("echoed {raw}\n"))
        .unwrap()
        .unwrap();
    assert!(!second.contains(raw), "{second}");
    assert!(second.contains(&handle), "{second}");
    let resolver = masker.known_text_resolver().unwrap();
    assert_eq!(resolver.resolve_known_text(&handle).unwrap().unwrap(), raw);
    assert_eq!(client.masked_count().unwrap(), 2);
}

#[test]
fn active_tool_output_inspection_has_no_recovery_or_metric_side_effects() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("active-masker-inspection");

    let client = MemoryStoreClient::from_env().unwrap();
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let mut masker = ActiveToolOutputMasker::new().unwrap();

    assert_eq!(
        masker
            .tool_output_contains_sensitive_text(&format!("OPENAI_API_KEY={raw}\n"))
            .unwrap(),
        Some(true)
    );
    assert_eq!(
        masker
            .tool_output_contains_sensitive_text("ordinary provider history")
            .unwrap(),
        Some(false)
    );
    assert_eq!(client.masked_count().unwrap(), 0);
    assert_eq!(masker.reported_masked_count, 0);
    assert!(masker.cache.is_empty());

    let masked = masker
        .mask_tool_output(&format!("OPENAI_API_KEY={raw}\n"))
        .unwrap()
        .unwrap();
    assert!(!masked.contains(raw), "{masked}");
    assert_eq!(client.masked_count().unwrap(), 1);

    let arbitrary = "cabbage";
    masker
        .mask_tool_output(&format!("TEST_SECRET={arbitrary}\n"))
        .unwrap()
        .unwrap();
    let count_before_known_value_inspection = client.masked_count().unwrap();
    assert_eq!(
        masker
            .tool_output_contains_sensitive_text(&format!("provider repeated {arbitrary}"))
            .unwrap(),
        Some(true)
    );
    assert_eq!(
        client.masked_count().unwrap(),
        count_before_known_value_inspection
    );
}

#[test]
fn active_prompt_masks_keyed_and_vendor_secrets_in_prose() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("active-prompt-keyed-detector");

    let password = ["test-pentect", "-password-284-regression"].concat();
    let openrouter = [
        "sk-or-v1-",
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef",
    ]
    .concat();
    let prompt =
        format!("Audit fixture: sudo password is {password} and OPENROUTER_API_KEY={openrouter}.");
    let mut masker = ActiveToolOutputMasker::new().unwrap();
    let masked = masker.mask_prompt_text(&prompt).unwrap().unwrap();

    assert!(!masked.contains(&password), "password was not masked");
    assert!(
        !masked.contains(&openrouter),
        "OpenRouter key was not masked"
    );
    assert!(
        masked.contains("<<KEYED_SECRET_"),
        "keyed-secret handle was not emitted"
    );
    assert!(
        masked.matches("<<").count() >= 2,
        "expected prompt handles were not emitted"
    );
}

#[test]
fn active_prompt_preserves_label_like_plain_prose() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("active-prompt-prose-precision");
    let mut masker = ActiveToolOutputMasker::new().unwrap();

    for prompt in [
        "NOTE: please read the documentation before continuing.",
        "Error: connection refused while contacting the service.",
        "Summary: the build passed and all tests are green.",
        "Question: why does the build fail on Windows only?",
        "Traceback: File main.py line 12 in handler raise ValueError",
        "Result: 42",
        "Error connection refused while contacting the service",
        "IMPORTANT: this context may or may not be relevant to your tasks.",
    ] {
        let masked = masker.mask_prompt_text(prompt).unwrap().unwrap();
        assert_eq!(masked, prompt, "plain prompt was changed: {prompt}");
    }
}

#[test]
fn active_prompt_explicit_marker_masks_low_entropy_value_and_removes_wrapper() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("active-prompt-explicit-marker");

    let mut masker = ActiveToolOutputMasker::new().unwrap();
    let masked = masker
        .mask_prompt_text("sudo password is pentect(abc)")
        .unwrap()
        .unwrap();

    assert!(
        masked.starts_with("sudo password is <<KEYED_SECRET_"),
        "{masked}"
    );
    assert!(!masked.contains("pentect("), "{masked}");
    assert!(!masked.contains("abc"), "{masked}");

    let handle = masked
        .split_whitespace()
        .last()
        .expect("masked prompt contains a handle");
    let output = masker.mask_tool_output("echo abc xabc").unwrap().unwrap();
    assert_eq!(output, format!("echo {handle} xabc"));
}

#[test]
fn active_tool_output_masks_low_entropy_session_log_fields() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("active-output-session-fields");
    let mut masker = ActiveToolOutputMasker::new().unwrap();
    let output = "audit session_id=abc123 csrf_token=short refresh_token=refresh";
    let masked = masker.mask_tool_output(output).unwrap().unwrap();

    for leaked_fragment in [
        "session_id=abc123",
        "csrf_token=short",
        "refresh_token=refresh",
    ] {
        assert!(
            !masked.contains(leaked_fragment),
            "{leaked_fragment:?} remained in {masked}"
        );
    }
    assert_eq!(masked.matches("<<").count(), 3, "{masked}");
}

#[test]
fn active_prompt_supports_mask_and_prompt_only_unmask_aliases() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("active-prompt-marker-aliases");

    let openai = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let aws = "AKIA7K9Q2M4N6P8R1T3V";
    let mut masker = ActiveToolOutputMasker::new().unwrap();
    let masked = masker
        .mask_prompt_text(&format!(
            "pentect(abc) mask(def) unpentect({openai}) unmask({aws})"
        ))
        .unwrap()
        .unwrap();

    assert_eq!(masked.matches("<<KEYED_SECRET_").count(), 2, "{masked}");
    assert!(masked.contains(openai), "{masked}");
    assert!(masked.contains(aws), "{masked}");
    for wrapper in ["pentect(", "mask(", "unpentect(", "unmask("] {
        assert!(!masked.contains(wrapper), "{masked}");
    }

    let output = masker
        .mask_tool_output(&format!("unmask({aws})"))
        .unwrap()
        .unwrap();
    assert!(!output.contains(aws), "{output}");
    assert!(output.contains("<<"), "{output}");
}

#[test]
fn bridge_masks_prompt_restores_tools_and_masks_result() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("bridge-mask");

    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let session = Session::open_capability(DEFAULT_SESSION).unwrap();
    let mut masker = ActiveToolOutputMasker::new().unwrap();
    let prompt = handle_bridge_request(
        &session,
        &mut masker,
        &json!({ "op": "prompt", "value": format!("OPENAI_API_KEY={raw}") }),
    )
    .unwrap();
    let prompt = prompt.as_str().unwrap();
    assert!(!prompt.contains(raw), "{prompt}");
    assert!(prompt.contains("<<OPENAI_API_KEY_"), "{prompt}");

    let before = handle_bridge_request(
        &session,
        &mut masker,
        &json!({
            "op": "before",
            "tool": "bash",
            "value": { "command": "Get-Content .env" }
        }),
    )
    .unwrap();
    let command = before["command"].as_str().unwrap();
    assert_eq!(command, "Get-Content .env");

    let after = handle_bridge_request(
        &session,
        &mut masker,
        &json!({
            "op": "after",
            "tool": "connector",
            "input": {},
            "value": { "content": format!("OPENAI_API_KEY={raw}") }
        }),
    )
    .unwrap();
    let rendered = serde_json::to_string(&after).unwrap();
    assert!(!rendered.contains(raw), "{rendered}");
    assert!(rendered.contains("<<OPENAI_API_KEY_"), "{rendered}");
}

#[test]
fn bridge_session_exports_only_the_owned_runtime_session() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("bridge-session");
    std::env::set_var("PENTECT_BIN", "/tmp/pentect-bin");

    let session = bridge_session_value().unwrap();
    let contract = session["contract"].as_str().unwrap();
    assert!(contract.contains("Session rules"));
    assert!(contract.contains("not corruption, truncation, invalid file content"));
    assert!(contract.contains("Preserve every handle byte-for-byte"));
    let environment = session["environment"].as_object().unwrap();
    assert_eq!(environment.len(), 4);
    for name in [ENV_ADDR, ENV_TOKEN, PENTECT_AGENT_LAUNCHED_ENV] {
        assert_eq!(environment[name], std::env::var(name).unwrap());
    }
    assert!(!environment.contains_key("PENTECT_PROCESS_HOST_READ_TOKEN"));
    assert!(!environment.contains_key("PENTECT_PROCESS_HOST_WRITE_TOKEN"));
    assert_eq!(environment["PENTECT_BIN"], "/tmp/pentect-bin");
    std::env::remove_var("PENTECT_BIN");
}

#[test]
fn bridge_owned_environment_preserves_only_verified_plugin_state() {
    let values = HashMap::from([
        (ENV_ADDR, "127.0.0.1:1234"),
        (ENV_TOKEN, "memory-token"),
        (PENTECT_AGENT_LAUNCHED_ENV, "launch-proof"),
        ("PENTECT_BIN", "pentect-bin"),
        (PENTECT_PLUGIN_CONFIGS_ENV, "configs"),
        (PENTECT_PLUGIN_BINARIES_ENV, "binaries"),
        ("PENTECT_PROCESS_HOST_ROOT", "untrusted"),
    ]);
    let environment =
        bridge_owned_environment(|name| values.get(name).map(|value| (*value).to_string()))
            .unwrap();
    assert_eq!(environment.len(), 6);
    assert_eq!(environment[PENTECT_PLUGIN_CONFIGS_ENV], "configs");
    assert_eq!(environment[PENTECT_PLUGIN_BINARIES_ENV], "binaries");
    assert!(!environment.contains_key("PENTECT_PROCESS_HOST_ROOT"));
}

#[test]
fn bridge_line_reader_discards_oversized_request() {
    let mut input = vec![b'x'; 9];
    input.extend_from_slice(b"\n{}\n");
    let mut reader = std::io::Cursor::new(input);
    let mut line = Vec::new();
    assert!(matches!(
        read_bridge_line_with_limit(&mut reader, &mut line, 8).unwrap(),
        BridgeLine::Oversized
    ));
    assert!(line.is_empty());
    assert!(matches!(
        read_bridge_line(&mut reader, &mut line).unwrap(),
        BridgeLine::Ready
    ));
    assert_eq!(line, b"{}\n");
}

#[test]
fn bridge_error_preserves_phase_and_execution_state() {
    let mut output = Vec::new();
    write_bridge_response(
        &mut output,
        json!(7),
        "after",
        Err("Media output unavailable.".to_string()),
    )
    .unwrap();
    let response: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "output_unavailable");
    assert_eq!(response["error"]["phase"], "after");
    assert_eq!(response["error"]["executed"], true);
    assert_eq!(response["error"]["message"], "Media output unavailable.");
}

#[test]
fn prompt_masked_env_is_available_to_direct_execution() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("prompt-exec-proxy");

    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let prompt = mask_prompt_text_into_active_memory_store(&format!("OPENAI_API_KEY={raw}"))
        .unwrap()
        .unwrap();
    assert!(!prompt.contains(raw), "{prompt}");
    assert!(prompt.contains("OPENAI_API_KEY=<<"), "{prompt}");
    let env_name =
        pentect_env_name_for_handle(&masked_handle_from_assignment(&prompt, "OPENAI_API_KEY"));

    let argv_mode = if cfg!(windows) {
        vec![
            "powershell".to_string(),
            "-Command".to_string(),
            format!("Write-Output $env:{env_name}"),
        ]
    } else {
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("printf '%s' \"${env_name}\""),
        ]
    };
    let session = Session::open_capability("default").unwrap();
    let store = MemoryStore::for_session(&session);
    let overlays = requested_env_bindings(&store, &ExecMode::Program(argv_mode)).unwrap();
    assert!(
        overlays
            .iter()
            .any(|(name, value)| name == &env_name && value == raw),
        "{overlays:?}"
    );
}

#[test]
fn prompt_masking_uses_strict_input_detection_for_env_lines_in_prose() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("prompt-strict");

    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let prompt = format!(
        "Synthetic local E2E credential:\nOPENAI_API_KEY={raw}\nUse this value for the requested task."
    );
    let masked = mask_prompt_text_into_active_memory_store(&prompt)
        .unwrap()
        .unwrap();
    assert!(!masked.contains(raw), "{masked}");
    assert!(masked.contains("OPENAI_API_KEY=<<"), "{masked}");
}

#[test]
fn prompt_masking_runs_prepare_and_finalize_once() {
    let Some(python) = ["python3", "python"].into_iter().find(|candidate| {
        std::process::Command::new(candidate)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }) else {
        return;
    };
    let root = temp_root("prompt-plugin-stage-count");
    std::fs::create_dir_all(&root).unwrap();
    let calls = root.join("calls.txt");
    let script = r#"import json,sys
path=sys.argv[1]
for line in sys.stdin:
    request=json.loads(line)
    with open(path, 'a', encoding='utf-8') as output:
        output.write(request['hook'] + '\t' + request['payload']['text'] + '\n')
    print(json.dumps({
        'schema':'pentect.plugin.v1',
        'id':request['id'],
        'type':'result',
        'action':'next',
        'payload':request['payload'],
    }), flush=True)
"#;
    let plugins = plugin_middleware::PluginMiddleware::from_test_command(
        vec![
            python.to_string(),
            "-u".to_string(),
            "-c".to_string(),
            script.to_string(),
            calls.display().to_string(),
        ],
        [
            plugin_middleware::MiddlewareStage::Prepare,
            plugin_middleware::MiddlewareStage::Finalize,
        ],
    )
    .unwrap();
    let session = Session::open_capability_at(&root, "stage-count").unwrap();
    let store = MemoryStore::for_session(&session);
    let mut masker = masking::OutputMasker::new_shared_with_plugins(store, plugins).unwrap();

    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    masker
        .mask_prompt_text(&format!("OPENAI_API_KEY={raw}"))
        .unwrap();

    let calls = std::fs::read_to_string(&calls).unwrap();
    let calls = calls.lines().collect::<Vec<_>>();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(calls[0].starts_with("prepare\tOPENAI_API_KEY=<<"));
    assert!(calls[1].starts_with("finalize\tOPENAI_API_KEY=<<"));
    assert!(calls.iter().all(|call| !call.contains(raw)), "{calls:?}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn prompt_dotenv_activity_counts_each_finding_once() {
    const CHILD_ROOT_ENV: &str = "PENTECT_TEST_DOTENV_ACTIVITY_CHILD_ROOT";
    const MIXED_PROMPT: &str =
        "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\nContact alice@example.com";

    if let Some(child_root) = std::env::var_os(CHILD_ROOT_ENV) {
        let child_root = PathBuf::from(child_root);
        let session = Session::open_capability_at(&child_root, "emitted-activity").unwrap();
        let store = MemoryStore::for_session(&session);
        let mut masker = masking::OutputMasker::new_shared(store).unwrap();
        let masked = masker
            .mask_prompt_text_without_plugins(MIXED_PROMPT)
            .unwrap();
        assert_eq!(
            MemoryStore::for_session(&session)
                .resolve_all(&masked)
                .unwrap(),
            MIXED_PROMPT
        );
        masker.flush_activity();
        activity_log::flush_persistent();
        return;
    }

    let root = temp_root("prompt-dotenv-activity-count");
    std::fs::create_dir_all(&root).unwrap();

    for (session_name, prompt, expected_count, expected_labels) in [
        (
            "dotenv-only",
            "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX",
            1,
            [("OPENAI_API_KEY", 1), ("EMAIL_ADDRESS", 0)],
        ),
        (
            "dotenv-and-text",
            MIXED_PROMPT,
            2,
            [("OPENAI_API_KEY", 1), ("EMAIL_ADDRESS", 1)],
        ),
    ] {
        let session = Session::open_capability_at(&root, session_name).unwrap();
        let store = MemoryStore::for_session(&session);
        let mut masker = masking::OutputMasker::new_shared(store).unwrap();
        let masked = masker.mask_prompt_text_without_plugins(prompt).unwrap();
        assert_ne!(masked, prompt);
        assert!(!masked.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"));
        assert!(!masked.contains("alice@example.com"));
        assert_eq!(
            MemoryStore::for_session(&session)
                .resolve_all(&masked)
                .unwrap(),
            prompt
        );

        let (count, labels) = masker.pending_activity_for("prompt").unwrap();
        assert_eq!(count, expected_count);
        for (label, expected) in expected_labels {
            assert_eq!(labels.get(label).copied().unwrap_or_default(), expected);
        }
        assert_eq!(labels.values().sum::<u64>(), count);
    }

    let child_root = root.join("activity-child");
    let child_home = child_root.join("home");
    let child_work = child_root.join("work");
    let child_log = child_root.join("logs");
    std::fs::create_dir_all(&child_home).unwrap();
    std::fs::create_dir_all(child_root.join("runtime")).unwrap();
    std::fs::create_dir_all(child_root.join("tmp")).unwrap();
    std::fs::create_dir_all(child_work.join(".pentect")).unwrap();
    std::fs::write(
        child_work.join(".pentect/config.toml"),
        "[activity]\nshare = false\n[update]\ncheck = false\n",
    )
    .unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg("tests::prompt_dotenv_activity_counts_each_finding_once")
        .arg("--nocapture")
        .env_clear()
        .env(CHILD_ROOT_ENV, &child_root)
        .env("PENTECT_LOG_DIR", &child_log)
        .env("HOME", &child_home)
        .env("USERPROFILE", &child_home)
        .env("XDG_CONFIG_HOME", child_home.join(".config"))
        .env("XDG_RUNTIME_DIR", child_root.join("runtime"))
        .env("TMPDIR", child_root.join("tmp"))
        .env("TMP", child_root.join("tmp"))
        .env("TEMP", child_root.join("tmp"))
        .current_dir(&child_work);
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = std::fs::read_to_string(child_log.join("pentect.log")).unwrap();
    let events = payload
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1, "{payload}");
    assert_eq!(events[0]["action"], "mask");
    assert_eq!(events[0]["surface"], "prompt");
    assert_eq!(events[0]["count"], 2);
    assert_eq!(
        events[0]["labels"],
        json!([
            { "name": "EMAIL_ADDRESS", "count": 1 },
            { "name": "OPENAI_API_KEY", "count": 1 }
        ])
    );
    for private_value in [
        MIXED_PROMPT,
        "sk-ABCDEFGHIJKLMNOPQRSTUVWX",
        "alice@example.com",
        "Contact alice",
    ] {
        assert!(!payload.contains(private_value), "{payload}");
    }

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn active_prompt_masker_reuses_bounded_cached_result() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("prompt-cache");
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let prompt = format!("OPENAI_API_KEY={raw}");
    let mut masker = ActiveToolOutputMasker::new().unwrap();

    let first = masker.mask_prompt_text(&prompt).unwrap().unwrap();
    assert!(!first.contains(raw), "{first}");
    assert_eq!(masker.prompt_cache.len(), 1);
    assert_eq!(masker.prompt_cache_order.len(), 1);
    let reported_after_first = masker.reported_masked_count;

    let second = masker.mask_prompt_text(&prompt).unwrap().unwrap();
    assert_eq!(second, first);
    assert_eq!(masker.prompt_cache.len(), 1);
    assert_eq!(masker.prompt_cache_order.len(), 1);
    assert_eq!(masker.reported_masked_count, reported_after_first);
}

#[test]
fn embedded_env_assignment_detection_is_structural_and_sensitive() {
    assert_eq!(
        masking::embedded_sensitive_env_assignment_start("output: RUNPOD_API_KEY=rpa_example"),
        Some("output: ".len())
    );
    assert_eq!(
        masking::embedded_sensitive_env_assignment_start("created OPENAI_API_KEY=sk-example"),
        Some("created ".len())
    );
    assert_eq!(
        masking::embedded_sensitive_env_assignment_start("status=created"),
        None
    );
}

#[test]
fn embedded_env_masking_preserves_a_trailing_carriage_return() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("prompt-carriage-return");
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let input = format!("output: OPENAI_API_KEY={raw}\r");
    let session = Session::open_capability("default").unwrap();
    let store = MemoryStore::for_session(&session);
    let mut masker = masking::OutputMasker::new_shared(store).unwrap();

    let masked = masker.mask_embedded_env_assignments(&input).unwrap();
    assert!(masked.ends_with('\r'), "{masked:?}");
    assert!(!masked.contains(raw), "{masked}");
}

#[test]
fn active_memory_store_resolver_reuses_one_snapshot_for_many_scalars() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("resolver-snapshot");
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let masked = mask_prompt_text_into_active_memory_store(&format!("OPENAI_API_KEY={raw}"))
        .unwrap()
        .unwrap();
    let handle = masked_handle_from_assignment(&masked, "OPENAI_API_KEY");
    let env_name = pentect_env_name_for_handle(&handle);
    let resolver = ActiveMemoryStoreResolver::new().unwrap();

    assert_eq!(
        resolver.resolve_known_text(&handle).unwrap().as_deref(),
        Some(raw)
    );
    assert_eq!(
        resolver
            .resolve_known_text("before <<UNKNOWN_0123456789abcdef>> after")
            .unwrap()
            .as_deref(),
        Some("before <<UNKNOWN_0123456789abcdef>> after")
    );
    for reference in [
        format!("$env:{env_name}"),
        format!("${{{env_name}}}"),
        format!("${env_name}"),
        format!("%{env_name}%"),
    ] {
        assert_eq!(
            resolver.resolve_known_text(&reference).unwrap().as_deref(),
            Some(raw),
            "{reference}"
        );
    }
    assert_eq!(
        resolver
            .resolve_known_text("$env:PENTECT_UNKNOWN_deadbeef")
            .unwrap()
            .as_deref(),
        Some("$env:PENTECT_UNKNOWN_deadbeef")
    );
}

#[test]
fn ocr_off_obeys_block_policy_for_active_image_redaction() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("ocr-off-block-active");
    let _home = write_user_config(&root, "[image]\nocr = \"off\"\nunscanned = \"block\"\n");
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("ocr-off-block-store");
    let _cwd = enter_temp_cwd(&root);
    let image = json!({
        "content": [{
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/png",
                "data": "aGVsbG8="
            }
        }]
    });

    let error = redact_tool_images_into_active_memory_store(&image).unwrap_err();
    assert_eq!(error, "image blocked: OCR is off.");
    assert!(unscanned_images_should_block().unwrap());
}

#[cfg(feature = "ocr")]
#[test]
fn active_image_byte_redaction_returns_opaque_annotation_without_plaintext() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("active-image-byte-annotation");
    write_project_config(&root, "[image]\nocr = \"on\"\nunscanned = \"block\"\n");
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("active-image-byte-store");
    let _cwd = enter_temp_cwd(&root);
    let raw = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX";

    let protected = redact_image_bytes_into_active_memory_store(&qr_png(raw))
        .unwrap()
        .expect("secret image should be redacted");

    assert!(!protected.bytes.is_empty());
    assert!(
        protected.note.contains("Masked regions:"),
        "{}",
        protected.note
    );
    assert!(
        protected.note.contains("<<KEYED_SECRET_"),
        "{}",
        protected.note
    );
    assert!(!protected.note.contains(raw), "{}", protected.note);
}

#[test]
fn exec_capability_env_does_not_shadow_parent_environment() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("env-overlay");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let value = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("RUNPOD_API_KEY={value}\n")).unwrap();
    let store = MemoryStore::for_session(&session);
    let env_name =
        pentect_env_name_for_handle(&masked_handle_from_assignment(&masked, "RUNPOD_API_KEY"));
    std::env::set_var("RUNPOD_API_KEY", "parent-value");
    let mode = if cfg!(windows) {
        ExecMode::Shell(format!(
            "Write-Output $env:RUNPOD_API_KEY; Write-Output $env:{env_name}"
        ))
    } else {
        ExecMode::Shell(format!(
            "printf '%s\\n%s' \"$RUNPOD_API_KEY\" \"${env_name}\""
        ))
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        allow_secret_argv: false,
        secret_stdin: None,
        script_shell: ScriptShell::Native,
        mode,
    };
    let output = run_resolved_command(&store, &opts);
    std::env::remove_var("RUNPOD_API_KEY");
    let output = output.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(value), "{stdout}");
    assert!(stdout.contains("parent-value"), "{stdout}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn exec_resolves_masked_handle_in_command_text() {
    let root = temp_root("exec-command-handle");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let masked = mask_tool_output(&session, &format!("OPENAI_API_KEY={raw}\n")).unwrap();
    let handle = masked.split_once('=').unwrap().1.trim().to_string();

    let command = if cfg!(windows) {
        format!("Write-Output '{handle}'")
    } else {
        format!("printf '%s' '{handle}'")
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        allow_secret_argv: false,
        secret_stdin: None,
        script_shell: ScriptShell::Native,
        mode: ExecMode::Shell(command),
    };

    let store = MemoryStore::for_session(&session);
    let output = run_resolved_command(&store, &opts).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(raw), "{stdout}");

    let safe = mask_tool_output(&session, &stdout).unwrap();
    assert!(!safe.contains(raw), "{safe}");
    assert!(safe.contains("<<OPENAI_API_KEY_"), "{safe}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn exec_auto_binds_masked_env_output_in_running_session() {
    let root = temp_root("capability-auto-env-binding");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let output = "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\nTEST_SECRET=114514810\nNOTE=hello world\n";
    let masked = mask_tool_output(&session, output).unwrap();
    assert!(
        masked.contains("RUNPOD_API_KEY=<<RUNPOD_API_KEY_"),
        "{masked}"
    );
    assert!(masked.contains("TEST_SECRET=<<TEST_SECRET_"), "{masked}");
    assert!(masked.contains("NOTE=<<NOTE_"), "{masked}");
    let runpod_handle = masked_handle_from_assignment(&masked, "RUNPOD_API_KEY");
    let runpod_pentect_env = pentect_env_name_for_handle(&runpod_handle);
    let test_secret_env =
        pentect_env_name_for_handle(&masked_handle_from_assignment(&masked, "TEST_SECRET"));
    let note_env = pentect_env_name_for_handle(&masked_handle_from_assignment(&masked, "NOTE"));

    let store = MemoryStore::for_session(&session);
    let env = store.auto_env_bindings().unwrap();
    assert!(
        env.iter().any(|(name, value)| name == &runpod_pentect_env
            && value == "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"),
        "{env:?}"
    );
    assert!(
        env.iter()
            .any(|(name, value)| name == &test_secret_env && value == "114514810"),
        "{env:?}"
    );
    assert!(
        env.iter()
            .any(|(name, value)| name == &note_env && value == "hello world"),
        "{env:?}"
    );
    assert!(
        !env.iter()
            .any(|(name, _)| matches!(name.as_str(), "RUNPOD_API_KEY" | "TEST_SECRET" | "NOTE")),
        "{env:?}"
    );

    let command = if cfg!(windows) {
        format!(
            "Write-Output $env:{runpod_pentect_env}; Write-Output $env:{test_secret_env}; Write-Output $env:{note_env}"
        )
    } else {
        format!(
            "printf '%s\\n%s\\n%s\\n' \"${runpod_pentect_env}\" \"${test_secret_env}\" \"${note_env}\""
        )
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        allow_secret_argv: false,
        secret_stdin: None,
        script_shell: ScriptShell::Native,
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
fn handle_core_is_also_a_valid_environment_binding() {
    let root = temp_root("capability-short-env-binding");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let value = "KGAT_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("KAGGLE_API_TOKEN={value}\n")).unwrap();
    let handle = masked_handle_from_assignment(&masked, "KAGGLE_API_TOKEN");
    let short_name = handle
        .strip_prefix("<<")
        .and_then(|value| value.strip_suffix(">>"))
        .unwrap();
    let store = MemoryStore::for_session(&session);

    let bindings = requested_env_bindings(
        &store,
        &ExecMode::Shell(format!("Write-Output $env:{short_name}")),
    )
    .unwrap();
    assert_eq!(bindings, vec![(short_name.to_string(), value.to_string())]);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn deferred_shell_output_publishes_bindings_when_flushed() {
    let root = temp_root("deferred-shell-env-binding");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = MemoryStore::for_session(&session);
    let value = "KGAT_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let mut masker = OutputMasker::new_deferred(store.clone()).unwrap();
    let masked = masker
        .mask_text(
            &format!("KAGGLE_API_TOKEN={value}\n"),
            pentect_core::Kind::Env,
        )
        .unwrap();
    let handle = masked_handle_from_assignment(&masked, "KAGGLE_API_TOKEN");
    let short_name = handle
        .strip_prefix("<<")
        .and_then(|value| value.strip_suffix(">>"))
        .unwrap();

    assert!(store.auto_env_bindings().unwrap().is_empty());
    masker.flush().unwrap();
    let bindings =
        requested_env_bindings(&store, &ExecMode::Shell(format!("echo $env:{short_name}")))
            .unwrap();
    assert_eq!(bindings, vec![(short_name.to_string(), value.to_string())]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn env_alias_recovery_uses_explicit_prefix() {
    let key = [7u8; 32];
    let masked = "OPENAI_API_KEY=<<OPENAI_API_KEY_0123456789abcdef>>\n";
    let recovery = env_alias_recovery(masked, &key, "SAFE_");
    let aliases: Vec<_> = recovery
        .placeholders()
        .into_iter()
        .filter(|placeholder| masking::is_env_alias_placeholder(placeholder))
        .filter_map(|placeholder| {
            let record = recovery.resolve(&placeholder);
            masking::decode_env_alias_record(&record)
                .map(|(name, handle)| (name.to_string(), handle.to_string()))
        })
        .collect();
    assert_eq!(
        aliases,
        vec![(
            "SAFE_OPENAI_API_KEY_0123456789abcdef".to_string(),
            "<<OPENAI_API_KEY_0123456789abcdef>>".to_string()
        )]
    );
}

#[test]
fn output_keeps_generated_environment_alias_references_readable() {
    let (root, session) = empty_session("output-env-alias-reference");
    let alias = "PENTECT_RUNPOD_API_KEY_80fba8fb9b3928a8";
    let output = format!(
        "At line:1 char:1\n+ $env:{alias}\n+ ${alias}\n+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
    );
    let masked = mask_tool_output(&session, &output).unwrap();
    assert!(masked.contains(alias), "{masked}");
    assert!(!masked.contains("<<LIKELY_SECRET_"), "{masked}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn exec_only_injects_referenced_capability_env() {
    let root = temp_root("capability-env-least");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let output =
        "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\nTEST_SECRET=114514810\n";
    let masked = mask_tool_output(&session, output).unwrap();
    let store = MemoryStore::for_session(&session);
    let env_name =
        pentect_env_name_for_handle(&masked_handle_from_assignment(&masked, "RUNPOD_API_KEY"));

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
            format!("Write-Output $env:{env_name}")
        } else {
            format!("printf '%s' \"${env_name}\"")
        }),
    )
    .unwrap();
    assert_eq!(one.len(), 1, "{one:?}");
    assert_eq!(one[0].0, env_name);
    assert_eq!(one[0].1, "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn exec_injects_powershell_env_provider_references() {
    let root = temp_root("capability-env-provider");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let value = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let masked = mask_tool_output(&session, &format!("OPENAI_API_KEY={value}\n")).unwrap();
    let store = MemoryStore::for_session(&session);
    let env_name =
        pentect_env_name_for_handle(&masked_handle_from_assignment(&masked, "OPENAI_API_KEY"));
    let env = requested_env_bindings(
        &store,
        &ExecMode::Shell(format!("Test-Path Env:{env_name}")),
    )
    .unwrap();
    assert!(
        env.iter()
            .any(|(name, found)| name == &env_name && found == value),
        "{env:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn braced_powershell_environment_reference_excludes_provider_prefix() {
    assert_eq!(
        environment_reference_at("${env:PENTECT_KEY_123}", 0),
        Some((22, "PENTECT_KEY_123"))
    );
    assert_eq!(
        environment_reference_at("${ENV:PENTECT_KEY_123}", 0),
        Some((22, "PENTECT_KEY_123"))
    );
}

#[test]
fn auto_env_bindings_do_not_override_baseline_environment() {
    let root = temp_root("capability-reserved-env-binding");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let output = "PATH=sk-ABCDEFGHIJKLMNOPQRSTUVWX\nPENTECT_MEMORY_STORE_TOKEN=sk-ZZZZZZZZZZZZZZZZZZZZ\nDUMMY_SECRET=sk-YYYYYYYYYYYYYYYYYYYY\n";
    let masked = mask_tool_output(&session, output).unwrap();
    assert!(masked.contains("PATH=<<PATH_"), "{masked}");
    assert!(masked.contains("DUMMY_SECRET=<<DUMMY_SECRET_"), "{masked}");

    let store = MemoryStore::for_session(&session);
    let env = store.auto_env_bindings().unwrap();
    assert!(
        !env.iter().any(|(name, _)| matches!(
            name.as_str(),
            "PATH" | "PENTECT_MEMORY_STORE_TOKEN" | "DUMMY_SECRET"
        )),
        "{env:?}"
    );
    assert!(
        env.iter()
            .any(|(name, value)| name.starts_with("PENTECT_DUMMY_SECRET_")
                && value == "sk-YYYYYYYYYYYYYYYYYYYY"),
        "{env:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn resolve_path_rewrites_known_handles_without_printing_secret() {
    let root = temp_root("resolve-file");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = MemoryStore::for_session(&session);
    let raw = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n";
    let result = Engine::with_profile(Profile::Strict).mask(
        Input {
            kind: Kind::Env,
            data: raw.to_string(),
        },
        &Config::new(session.key),
    );
    store.add_recovery(result.recovery).unwrap();

    let path = PathBuf::from(format!(
        ".pentect-test-resolve-{}-{}.env",
        std::process::id(),
        unix_millis()
    ));
    std::fs::write(&path, result.masked).unwrap();
    resolve_path_in_place(&store, &path).unwrap();

    let written = std::fs::read_to_string(&path).unwrap();
    assert_eq!(written, raw);
    assert!(!written.contains("<<OPENAI_API_KEY_"));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn resolve_path_refuses_parent_traversal() {
    let root = temp_root("resolve-file-traversal");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let store = MemoryStore::for_session(&session);
    let err = resolve_path_in_place(&store, Path::new("../outside.env")).unwrap_err();
    assert!(err.contains("outside the current directory"), "{err}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn exec_auto_binds_generic_masked_handles_as_pentect_env_vars() {
    let root = temp_root("capability-generic-pentect-env");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = [
        "sk-qa25MV9c7Qu0EjDIEWdcT3",
        "Blbk",
        "FJ83uCF0K4yw7RzpY39bio",
    ]
    .concat();
    let masked = mask_tool_output(&session, &format!("created token: {raw}\n")).unwrap();
    assert!(!masked.contains(&raw), "{masked}");
    let handle = first_masked_handle(&masked);
    let env_name = pentect_env_name_for_handle(&handle);

    let store = MemoryStore::for_session(&session);
    let env = store.auto_env_bindings().unwrap();
    assert!(
        env.iter()
            .any(|(name, value)| name == &env_name && value == &raw),
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
        allow_secret_argv: false,
        secret_stdin: None,
        script_shell: ScriptShell::Native,
        mode: ExecMode::Shell(command),
    };
    let output = run_resolved_command(&store, &opts).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&raw), "{stdout}");

    let safe = mask_tool_output(&session, &stdout).unwrap();
    assert!(!safe.contains(&raw), "{safe}");
    assert!(safe.contains("<<OPENAI_TOKEN_"), "{safe}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn session_environment_name_is_reserved_for_internal_use() {
    assert!(is_pentect_control_env_name("PENTECT_SESSION"));
    assert!(is_pentect_control_env_name("pentect_session"));
    assert!(is_pentect_control_env_name(
        "PENTECT_UPSTREAM_AUTHORIZATION"
    ));
    assert!(is_pentect_control_env_name("PENTECT_UPSTREAM_CA_CERT"));
    assert!(is_pentect_control_env_name("PENTECT_UPSTREAM_IDENTITY"));
    assert!(is_pentect_control_env_name(
        "PENTECT_ALLOW_INSECURE_UPSTREAM"
    ));
    assert!(is_pentect_control_env_name(
        "PENTECT_GLOBAL_PLUGIN_BINARIES"
    ));
    assert!(is_pentect_control_env_name("pentect_global_plugin_ids"));
    for name in [
        "PENTECT_ANTHROPIC_UPSTREAM",
        "PENTECT_JUNIE_API_KEY",
        "PENTECT_PROXY_URL",
        "PENTECT_PROVIDER_MODEL",
        "PENTECT_PROVIDER_API",
        "PENTECT_GATEWAY_API_KEY",
        "PENTECT_API_KEY",
        "PENTECT_LOG_DIR",
    ] {
        assert!(is_pentect_control_env_name(name), "{name}");
        assert!(is_pentect_control_env_name(&name.to_ascii_lowercase()));
    }
    for name in [
        "PENTECT_PI_REASONING",
        "PENTECT_PI_CONTEXT_WINDOW",
        "PENTECT_PI_MAX_TOKENS",
        "PENTECT_PI_INPUTS",
    ] {
        assert!(!is_pentect_control_env_name(name), "{name}");
    }
    let mut names = pentect_control_env_names().to_vec();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), pentect_control_env_names().len());
}

#[test]
fn unresolved_masked_command_handle_is_rejected() {
    let (root, session) = empty_session("unresolved-command-handle");
    let store = MemoryStore::for_session(&session);
    let err = resolve_command_text(
        &store,
        "curl -H \"Authorization: Bearer <<RUNPOD_API_KEY_missing>>\" example.test",
    )
    .unwrap_err();
    assert!(err.contains("unknown masked handle"), "{err}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_passes_through_regular_ui_content() {
    let (root, session) = empty_session("write-regular-ui");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": "src/App.tsx",
            "content": "export function App() { return <main>Settings</main>; }\n"
        }
    });

    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    assert_eq!(output, json!({}));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_passes_through_non_pentect_templates() {
    let (root, session) = empty_session("write-template-ui");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": "templates/email.txt",
            "content": "Hello <<customer_name>>, your order is ready.\n"
        }
    });

    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    assert_eq!(output, json!({}));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_blocks_unknown_masked_handles_that_need_resolve() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("write-unknown-handle");
    let project = PathBuf::from("target").join(format!(
        "pentect-write-unknown-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let config = project.join("config.env");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": config.to_string_lossy(),
            "content": "RUNPOD_API_KEY=<<RUNPOD_API_KEY_0123456789abcdef>>\n"
        }
    });

    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("masked handle is unavailable"), "{reason}");
    assert!(!config.exists());
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_allows_resolvable_masked_content_before_tool() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("capability-write-generic");
    let project = PathBuf::from("target").join(format!(
        "pentect-write-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();

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
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "allow");
    assert_eq!(
        output["hookSpecificOutput"]["updatedInput"]["content"],
        format!("token={raw}\n")
    );
    assert!(!config.exists());
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_repairs_masked_file_after_tool() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("capability-write-repair");
    let project = PathBuf::from("target").join(format!(
        "pentect-write-repair-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();
    let config = project.join("config.txt");

    std::fs::write(&config, &masked).unwrap();
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": config.to_string_lossy(),
            "content": masked
        },
        "tool_response": "Edited config.txt"
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    assert_eq!(output, json!({}));
    let written = std::fs::read_to_string(&config).unwrap();
    assert!(written.contains(raw), "{written}");
    assert!(!written.contains("<<"), "{written}");
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_does_not_repair_when_tool_left_existing_file_unchanged() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("capability-write-repair-unchanged");
    let project = PathBuf::from("target").join(format!(
        "pentect-write-repair-unchanged-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();
    let config = project.join("config.txt");
    std::fs::write(&config, "token=existing\n").unwrap();

    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": config.to_string_lossy(),
            "content": masked
        },
        "tool_response": "Write failed"
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    assert_eq!(output, json!({}));
    let written = std::fs::read_to_string(&config).unwrap();
    assert_eq!(written, "token=existing\n");
    assert!(!written.contains(raw), "{written}");
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_allows_and_repairs_absolute_file_path() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("capability-write-absolute");
    let project = PathBuf::from("target").join(format!(
        "pentect-write-absolute-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();
    let config = std::env::current_dir()
        .unwrap()
        .join(&project)
        .join("config.txt");

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": config.to_string_lossy(),
            "content": masked
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input.clone()).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "allow");
    assert_eq!(
        output["hookSpecificOutput"]["updatedInput"]["content"],
        format!("token={raw}\n")
    );
    assert!(!config.exists());

    std::fs::write(&config, &masked).unwrap();
    let mut post = input;
    post.as_object_mut()
        .unwrap()
        .insert("hook_event_name".to_string(), json!("PostToolUse"));
    post.as_object_mut()
        .unwrap()
        .insert("tool_response".to_string(), json!("Edited config.txt"));
    let output = handle_hook(HookProvider::Claude, "t", &session, post).unwrap();
    assert_eq!(output, json!({}));
    let written = std::fs::read_to_string(&config).unwrap();
    assert!(written.contains(raw), "{written}");
    assert!(!written.contains("<<"), "{written}");
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_refuses_masked_repair_outside_current_dir() {
    let root = temp_root("capability-write-outside");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();

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

#[test]
fn write_tool_validates_the_resolved_handle_path() {
    let root = temp_root("capability-write-handle-path");
    let session = Session::open_capability_at(&root, "t").unwrap();
    let handle = "<<FILE_PATH_0123456789abcdef>>";
    let recovery = pentect_core::Recovery::seal(
        std::collections::HashMap::from([(
            handle.to_string(),
            "../pentect-should-not-write.txt".to_string(),
        )]),
        &session.key,
    );
    MemoryStore::for_session(&session)
        .add_recovery(recovery)
        .unwrap();

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": handle,
            "content": "ordinary content\n"
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("outside the current directory"), "{reason}");
    assert!(!reason.contains("pentect-should-not-write"), "{reason}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_repairs_camel_case_external_schema_after_tool() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("capability-write-camel");
    let project = PathBuf::from("target").join(format!(
        "pentect-write-camel-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();

    let config = project.join("config.txt");
    let input = json!({
        "hookEventName": "PreToolUse",
        "toolName": "external__write_file",
        "toolInput": {
            "filePath": config.to_string_lossy(),
            "fileContent": masked
        }
    });
    let output = handle_hook(HookProvider::Generic, "t", &session, input.clone()).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "allow");
    assert_eq!(
        output["hookSpecificOutput"]["updatedInput"]["fileContent"],
        format!("token={raw}\n")
    );

    std::fs::write(&config, &masked).unwrap();
    let mut post = input;
    let object = post.as_object_mut().unwrap();
    object.insert("hookEventName".to_string(), json!("PostToolUse"));
    object.insert("toolResponse".to_string(), json!("Edited config.txt"));
    let output = handle_hook(HookProvider::Generic, "t", &session, post).unwrap();
    assert_eq!(output, json!({}));
    let written = std::fs::read_to_string(&config).unwrap();
    assert!(written.contains(raw), "{written}");
    assert!(!written.contains("<<"), "{written}");
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_repairs_edit_masked_new_string_after_tool() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("capability-edit-repair");
    let project = PathBuf::from("target").join(format!(
        "pentect-edit-repair-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();
    let config = std::env::current_dir()
        .unwrap()
        .join(&project)
        .join("config.txt");
    std::fs::write(&config, "token=old\n").unwrap();

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": config.to_string_lossy(),
            "old_string": "token=old\n",
            "new_string": masked
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input.clone()).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "allow");
    assert_eq!(
        output["hookSpecificOutput"]["updatedInput"]["new_string"],
        format!("token={raw}\n")
    );

    std::fs::write(&config, &masked).unwrap();
    let mut post = input;
    post.as_object_mut()
        .unwrap()
        .insert("hook_event_name".to_string(), json!("PostToolUse"));
    post.as_object_mut()
        .unwrap()
        .insert("tool_response".to_string(), json!("Edited config.txt"));
    let output = handle_hook(HookProvider::Claude, "t", &session, post).unwrap();
    assert_eq!(output, json!({}));
    let written = std::fs::read_to_string(&config).unwrap();
    assert!(written.contains(raw), "{written}");
    assert!(!written.contains("<<"), "{written}");
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_repairs_multiedit_masked_new_string_after_tool() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("capability-multiedit-repair");
    let project = PathBuf::from("target").join(format!(
        "pentect-multiedit-repair-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();
    let config = std::env::current_dir()
        .unwrap()
        .join(&project)
        .join("config.txt");
    std::fs::write(&config, "name=old\ntoken=old\n").unwrap();

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": config.to_string_lossy(),
            "edits": [
                {"old_string": "name=old", "new_string": "name=new"},
                {"old_string": "token=old\n", "new_string": masked}
            ]
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input.clone()).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "allow");
    assert_eq!(
        output["hookSpecificOutput"]["updatedInput"]["edits"][1]["new_string"],
        format!("token={raw}\n")
    );

    std::fs::write(&config, format!("name=new\n{masked}")).unwrap();
    let mut post = input;
    post.as_object_mut()
        .unwrap()
        .insert("hook_event_name".to_string(), json!("PostToolUse"));
    post.as_object_mut()
        .unwrap()
        .insert("tool_response".to_string(), json!("Edited config.txt"));
    let output = handle_hook(HookProvider::Claude, "t", &session, post).unwrap();
    assert_eq!(output, json!({}));
    let written = std::fs::read_to_string(&config).unwrap();
    assert!(written.contains("name=new"), "{written}");
    assert!(written.contains(raw), "{written}");
    assert!(!written.contains("<<"), "{written}");
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_applies_edit_with_masked_old_string_before_tool() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("capability-edit-old-handle");
    let project = PathBuf::from("target").join(format!(
        "pentect-edit-old-handle-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();
    let config = std::env::current_dir()
        .unwrap()
        .join(&project)
        .join("config.txt");
    std::fs::write(&config, format!("token={raw}\n")).unwrap();

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": config.to_string_lossy(),
            "old_string": masked,
            "new_string": "token=rotated\n"
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"], "allow",
        "{output}"
    );
    let updated = &output["hookSpecificOutput"]["updatedInput"];
    let old_string = updated["old_string"].as_str().unwrap();
    let new_string = updated["new_string"].as_str().unwrap();
    assert_eq!(old_string, format!("token={raw}\n"));
    assert_eq!(new_string, "token=rotated\n");
    assert!(!old_string.contains("<<"), "{old_string}");
    let current = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, current.replace(old_string, new_string)).unwrap();
    let written = std::fs::read_to_string(&config).unwrap();
    assert_eq!(written, "token=rotated\n");
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_applies_multiedit_with_masked_old_string_before_tool() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("capability-multiedit-old-handle");
    let project = PathBuf::from("target").join(format!(
        "pentect-multiedit-old-handle-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();
    let config = std::env::current_dir()
        .unwrap()
        .join(&project)
        .join("config.txt");
    std::fs::write(&config, format!("name=old\ntoken={raw}\n")).unwrap();

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": config.to_string_lossy(),
            "edits": [
                {"old_string": "name=old\n", "new_string": "name=new\n"},
                {"old_string": masked, "new_string": "token=rotated\n"}
            ]
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "allow");
    let updated = &output["hookSpecificOutput"]["updatedInput"];
    let rendered = serde_json::to_string(updated).unwrap();
    assert!(rendered.contains(raw), "{rendered}");
    assert!(!rendered.contains("<<"), "{rendered}");
    assert_eq!(updated["edits"].as_array().unwrap().len(), 2);
    let mut current = std::fs::read_to_string(&config).unwrap();
    for edit in updated["edits"].as_array().unwrap() {
        current = current.replace(
            edit["old_string"].as_str().unwrap(),
            edit["new_string"].as_str().unwrap(),
        );
    }
    std::fs::write(&config, &current).unwrap();
    assert_eq!(current, "name=new\ntoken=rotated\n");
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_tool_leaves_unknown_old_handle_for_the_client_to_match() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let project = PathBuf::from("target").join(format!(
        "pentect-edit-old-handle-lazy-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let config = std::env::current_dir()
        .unwrap()
        .join(&project)
        .join("config.txt");
    std::fs::write(&config, "token=raw\n").unwrap();

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": config.to_string_lossy(),
            "old_string": "token=<<RUNPOD_API_KEY_0123456789abcdef>>\n",
            "new_string": "token=rotated\n"
        }
    });
    let output = handle_hook_lazy(HookProvider::Claude, "t", true, input).unwrap();
    assert_eq!(output, json!({}));
    assert_eq!(std::fs::read_to_string(&config).unwrap(), "token=raw\n");
    let _ = std::fs::remove_dir_all(project);
}

#[cfg(unix)]
#[test]
fn write_tool_refuses_masked_repair_through_symlink_dir() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("capability-write-symlink");
    let outside = temp_root("capability-write-symlink-outside");
    std::fs::create_dir_all(&outside).unwrap();
    let project = PathBuf::from("target").join(format!(
        "pentect-symlink-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    std::os::unix::fs::symlink(&outside, project.join("link")).unwrap();

    let session = Session::open_capability_at(&root, "t").unwrap();
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let masked = mask_tool_output(&session, &format!("token={raw}\n")).unwrap();

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
    assert!(rendered.contains("<<APIKEY_"), "{rendered}");
    assert!(!rendered.contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"));
    assert!(!rendered.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"));
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(!rendered.contains("second-line"), "{rendered}");
    assert!(!rendered.contains("100482"), "{rendered}");
    let store = MemoryStore::for_session(&session);
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
fn generic_posttool_masks_external_tool_response_aliases() {
    let (root, session) = empty_session("hook-post-generic-aliases");
    let raw_runpod = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let raw_openai = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let input = json!({
        "hookEventName": "PostToolUse",
        "toolName": "connector__browser__create_api_key",
        "toolResponse": {
            "content": [{
                "type": "text",
                "text": format!("RUNPOD_API_KEY={raw_runpod}")
            }],
            "structured_content": {
                "apiKey": raw_openai
            },
            "data": {
                "Authorization": format!("Bearer {raw_openai}")
            }
        }
    });
    let output = handle_hook(HookProvider::Generic, "t", &session, input).unwrap();
    let updated = &output["hookSpecificOutput"]["updatedToolOutput"];
    let rendered = serde_json::to_string(updated).unwrap();
    assert!(rendered.contains("<<RUNPOD_API_KEY_"), "{rendered}");
    assert!(rendered.contains("<<APIKEY_"), "{rendered}");
    assert!(rendered.contains("<<AUTHORIZATION_"), "{rendered}");
    assert!(!rendered.contains(raw_runpod), "{rendered}");
    assert!(!rendered.contains(raw_openai), "{rendered}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn generic_posttool_masks_payload_alias() {
    let (root, session) = empty_session("hook-post-generic-payload");
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let input = json!({
        "eventName": "PostToolUse",
        "tool": "connector",
        "payload": {
            "stdout": format!("OPENAI_API_KEY={raw}\n"),
            "ok": true
        }
    });
    let output = handle_hook(HookProvider::Generic, "t", &session, input).unwrap();
    let rendered = serde_json::to_string(&output).unwrap();
    assert!(rendered.contains("updatedToolOutput"), "{rendered}");
    assert!(rendered.contains("<<OPENAI_API_KEY_"), "{rendered}");
    assert!(!rendered.contains(raw), "{rendered}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn posttool_masks_secret_query_inside_image_url() {
    let (root, session) = empty_session("hook-post-image-url-query");
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__browser__screenshot",
        "tool_response": {
            "content": [{
                "type": "image_url",
                "image_url": {
                    "url": format!("https://cdn.example.com/screenshot.png?api_key={raw}")
                }
            }]
        }
    });
    let output = {
        let _lock = TEST_ENV_LOCK.lock().unwrap();
        let _home = write_user_config(&root, "[image]\nocr = \"off\"\nunscanned = \"allow\"\n");
        let _cwd = enter_temp_cwd(&root);
        handle_hook(HookProvider::Claude, "t", &session, input).unwrap()
    };
    let updated = &output["hookSpecificOutput"]["updatedToolOutput"];
    let rendered = serde_json::to_string(updated).unwrap();
    assert!(rendered.contains("<<API_KEY_"), "{rendered}");
    assert!(!rendered.contains(raw), "{rendered}");
    assert!(rendered.contains("screenshot.png?api_key="), "{rendered}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn posttool_masks_text_in_invalid_image_shaped_object() {
    let (root, session) = empty_session("hook-post-invalid-image-object");
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__browser__screenshot",
        "tool_response": {
            "content": [{
                "type": "image",
                "content": format!("OPENAI_API_KEY={raw}")
            }]
        }
    });
    let output = {
        let _lock = TEST_ENV_LOCK.lock().unwrap();
        let _home = write_user_config(&root, "[image]\nocr = \"off\"\nunscanned = \"allow\"\n");
        let _cwd = enter_temp_cwd(&root);
        handle_hook(HookProvider::Claude, "t", &session, input).unwrap()
    };
    let rendered =
        serde_json::to_string(&output["hookSpecificOutput"]["updatedToolOutput"]).unwrap();
    assert!(rendered.contains("<<OPENAI_API_KEY_"), "{rendered}");
    assert!(!rendered.contains(raw), "{rendered}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn tool_text_output_masks_mcp_connector_and_plugin_envelopes() {
    let (root, session) = empty_session("hook-post-tool-text-unified");
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let inputs = [
        json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "mcp__vault__get_key",
            "tool_response": {
                "content": [{
                    "type": "text",
                    "text": format!("OPENAI_API_KEY={raw}")
                }]
            }
        }),
        json!({
            "hookEventName": "PostToolUse",
            "toolName": "connector__browser__text",
            "toolResponse": {
                "visibleText": format!("OPENAI_API_KEY={raw}")
            }
        }),
        json!({
            "eventName": "PostToolUse",
            "tool": "plugin__browser_text",
            "payload": {
                "text": format!("OPENAI_API_KEY={raw}")
            }
        }),
    ];

    for input in inputs {
        let output = handle_hook(HookProvider::Generic, "t", &session, input).unwrap();
        let rendered = serde_json::to_string(&output).unwrap();
        assert!(rendered.contains("updatedToolOutput"), "{rendered}");
        assert!(rendered.contains("<<OPENAI_API_KEY_"), "{rendered}");
        assert!(!rendered.contains(raw), "{rendered}");
    }

    let unchanged = json!({
        "eventName": "PostToolUse",
        "tool": "plugin__browser_text",
        "payload": {
            "text": "visible page title only"
        }
    });
    let output = handle_hook(HookProvider::Generic, "t", &session, unchanged).unwrap();
    assert_eq!(output, json!({}));

    let blocked = json!({
        "eventName": "PostToolUse",
        "tool": "plugin__browser_media",
        "payload": {
            "url": "data:video/mp4;base64,AAAA"
        }
    });
    let output = handle_hook(HookProvider::Generic, "t", &session, blocked).unwrap();
    assert_eq!(output["decision"], "block");
    let reason = output["reason"].as_str().unwrap();
    assert!(reason.starts_with("Tool completed"), "{reason}");
    assert!(reason.contains("Media output unavailable"), "{reason}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn posttool_allows_unscanned_image_output_when_user_configured() {
    let (root, session) = empty_session("hook-post-image-best-effort");
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__chrome__screenshot",
        "tool_response": {
            "content": [{
                "type": "image",
                "mimeType": "image/png",
                "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB"
            }]
        }
    });
    let output = {
        let _lock = TEST_ENV_LOCK.lock().unwrap();
        let _home = write_user_config(&root, "[image]\nocr = \"on\"\nunscanned = \"allow\"\n");
        let _cwd = enter_temp_cwd(&root);
        handle_hook(HookProvider::Claude, "t", &session, input).unwrap()
    };
    assert!(output.get("decision").is_none(), "{output}");
    assert!(output.get("hookSpecificOutput").is_none(), "{output}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn posttool_blocks_unscanned_image_output_when_configured() {
    let (root, session) = empty_session("hook-post-image-strict");
    write_project_config(&root, "[image]\nocr = \"on\"\nunscanned = \"block\"\n");
    let input = json!({
        "hookEventName": "PostToolUse",
        "toolName": "connector__browser__capture",
        "toolResponse": {
            "url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB"
        }
    });
    let output = {
        let _lock = TEST_ENV_LOCK.lock().unwrap();
        let _cwd = enter_temp_cwd(&root);
        handle_hook(HookProvider::Generic, "t", &session, input).unwrap()
    };
    assert_eq!(output["decision"], "block");
    let reason = output["reason"].as_str().unwrap();
    assert!(reason.contains("image blocked"), "{reason}");
    assert!(reason.contains("image scan failed"), "{reason}");
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(feature = "ocr")]
#[test]
fn claude_posttool_redacts_secret_qr_image_instead_of_blocking() {
    let (root, session) = empty_session("hook-post-claude-image-redact");
    let raw = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let original = data_encoding::BASE64.encode(&qr_png(raw));
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__chrome__screenshot",
        "tool_response": {
            "content": [{
                "type": "image",
                "mimeType": "image/png",
                "data": original
            }]
        }
    });
    let output = {
        let _lock = TEST_ENV_LOCK.lock().unwrap();
        let _cwd = enter_temp_cwd(&root);
        handle_hook(HookProvider::Claude, "t", &session, input).unwrap()
    };
    assert!(output.get("decision").is_none(), "{output}");
    let updated = &output["hookSpecificOutput"]["updatedToolOutput"];
    let rendered = serde_json::to_string(updated).unwrap();
    assert!(
        rendered.contains("Pentect masked sensitive information in this image with black boxes."),
        "{rendered}"
    );
    assert!(rendered.contains("Masked regions:"), "{rendered}");
    assert!(rendered.contains("[1] <<KEYED_SECRET_"), "{rendered}");
    assert!(
        rendered.contains("\"mimeType\":\"image/png\""),
        "{rendered}"
    );
    assert!(!rendered.contains(&original), "{rendered}");
    assert!(!rendered.contains(raw), "{rendered}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn image_mask_note_describes_metadata_only_protection_accurately() {
    let updated = append_image_mask_notes(
        json!({"content": []}),
        &[],
        &["[1] <<OPENAI_API_KEY_0011223344556677>>".to_string()],
        config::ImageRedactionStyle::Black,
    );
    let rendered = serde_json::to_string(&updated).unwrap();
    assert!(
        rendered.contains("Pentect removed sensitive metadata from this image."),
        "{rendered}"
    );
    assert!(rendered.contains("Protected values:"), "{rendered}");
    assert!(!rendered.contains("black boxes"), "{rendered}");
}

#[test]
fn image_mask_note_separates_visual_and_metadata_protection() {
    let updated = append_image_mask_notes(
        json!({"content": []}),
        &["[1] <<AWS_AKID_0011223344556677>>".to_string()],
        &["[2] <<OPENAI_API_KEY_0011223344556677>>".to_string()],
        config::ImageRedactionStyle::Black,
    );
    let rendered = serde_json::to_string(&updated).unwrap();
    assert!(rendered.contains("black boxes"), "{rendered}");
    assert!(rendered.contains("Masked regions:"), "{rendered}");
    assert!(
        rendered.contains("removed sensitive metadata"),
        "{rendered}"
    );
    assert!(rendered.contains("Protected values:"), "{rendered}");
}

#[cfg(feature = "ocr")]
#[test]
fn codex_posttool_still_blocks_secret_qr_image() {
    let (root, session) = empty_session("hook-post-codex-image-block");
    let raw = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__chrome__screenshot",
        "tool_response": {
            "content": [{
                "type": "image",
                "mimeType": "image/png",
                "data": data_encoding::BASE64.encode(&qr_png(raw))
            }]
        }
    });
    let output = {
        let _lock = TEST_ENV_LOCK.lock().unwrap();
        let _cwd = enter_temp_cwd(&root);
        handle_hook(HookProvider::Codex, "t", &session, input).unwrap()
    };
    assert_eq!(output["decision"], "block");
    let reason = output["reason"].as_str().unwrap();
    assert!(reason.contains("secret text detected"), "{reason}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn posttool_masks_clipboard_text_without_misreporting_completed_side_effects() {
    let (root, session) = empty_session("hook-post-side-effect-mask");
    let raw = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    for response in [
        json!({"clipboardText": format!("OPENAI_API_KEY={raw}")}),
        json!({"downloadPath": "C:\\Users\\demo\\Downloads\\secret.txt"}),
    ] {
        let input = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "connector__browser",
            "tool_response": response
        });
        let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
        assert!(output.get("decision").is_none(), "{output}");
        assert!(
            !serde_json::to_string(&output).unwrap().contains(raw),
            "{output}"
        );
    }
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
    assert!(rendered.contains("<<APIKEY_"), "{rendered}");

    let store = MemoryStore::for_session(&session);
    let env = store.auto_env_bindings().unwrap();
    let env_name = env
        .iter()
        .find_map(|(name, value)| {
            (name.starts_with("PENTECT_APIKEY_") && value == raw).then(|| name.clone())
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
        allow_secret_argv: false,
        secret_stdin: None,
        script_shell: ScriptShell::Native,
        mode: ExecMode::Shell(command),
    };
    let output = run_resolved_command(&store, &opts).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(raw), "{stdout}");

    let safe = mask_tool_output(&session, &stdout).unwrap();
    assert!(!safe.contains(raw), "{safe}");
    assert!(safe.contains("<<"), "{safe}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn canonical_claude_hook_applies_otp_detection_to_browser_mail() {
    let (root, session) = empty_session("hook-post-browser-mail-text");
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__chrome__snapshot",
        "tool_response": {
            "content": [{
                "type": "text",
                "text": concat!(
                    "Subject: Sign-in request\n",
                    "Your verification code is 837291.\n",
                    "Device: Chrome on Windows. Seat 12A stays visible."
                )
            }],
            "structuredContent": {
                "url": "https://mail.example.test/inbox/42",
                "emailText": "Security code: 402118. Expires in 10 minutes.",
                "visibleText": "認証コード: 483920 を入力してください\nInvoice INV-100482 remains readable."
            }
        }
    });

    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    let rendered = serde_json::to_string(&output).unwrap();
    for secret in ["837291", "402118", "483920"] {
        assert!(!rendered.contains(secret), "{rendered}");
    }
    assert!(rendered.contains("<<OTP_"), "{rendered}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn browser_api_key_issue_flow_masks_value_and_keeps_capability_usable() {
    let (root, session) = empty_session("hook-post-browser-apikey-html");
    let raw = "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__playwright__browser_snapshot",
        "tool_response": {
            "content": [{
                "type": "text",
                "text": format!(
                    "Page snapshot\nbutton: Create API key\noutput: RUNPOD_API_KEY={raw}\nstatus: created"
                )
            }],
            "structuredContent": {
                "ariaSnapshot": format!("textbox RUNPOD_API_KEY={raw}"),
                "html": format!(r#"<input aria-label="API key" value="{raw}"><button>Copy</button>"#),
                "nextStep": "Use this key to call the health endpoint."
            }
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    let rendered = serde_json::to_string(&output).unwrap();
    assert!(!rendered.contains(raw), "{rendered}");
    assert!(
        rendered.contains("RUNPOD_API_KEY=<<RUNPOD_API_KEY_"),
        "{rendered}"
    );
    assert!(rendered.contains("Create API key"), "{rendered}");
    assert!(
        rendered.contains("Use this key to call the health endpoint."),
        "{rendered}"
    );

    let store = MemoryStore::for_session(&session);
    let env = store.auto_env_bindings().unwrap();
    let env_name = env
        .iter()
        .find_map(|(name, value)| {
            (name.starts_with("PENTECT_RUNPOD_API_KEY_") && value == raw).then(|| name.clone())
        })
        .unwrap_or_else(|| panic!("missing RUNPOD capability in {env:?}"));
    let command = if cfg!(windows) {
        format!("Write-Output $env:{env_name}")
    } else {
        format!("printf '%s' \"${env_name}\"")
    };
    let opts = ExecOpts {
        session: DEFAULT_SESSION.to_string(),
        live: false,
        allow_secret_argv: false,
        secret_stdin: None,
        script_shell: ScriptShell::Native,
        mode: ExecMode::Shell(command),
    };
    let output = run_resolved_command(&store, &opts).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(raw), "{stdout}");
    let safe = mask_tool_output(&session, &stdout).unwrap();
    assert!(!safe.contains(raw), "{safe}");
    assert!(safe.contains("<<RUNPOD_API_KEY_"), "{safe}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn browser_structured_otp_fields_mask_without_locking_to_email_format() {
    let (root, session) = empty_session("hook-post-browser-otp-fields");
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__chrome__get_page_content",
        "tool_response": {
            "structuredContent": {
                "verificationCode": "837291",
                "mfaCode": "402118",
                "formFields": [
                    {"label": "One-time passcode", "value": "483920"},
                    {"label": "Order code", "value": "ORD-100482"}
                ],
                "bodyText": "Login code: 729004\nDelivery code ORD-100482 remains visible."
            }
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    let rendered = serde_json::to_string(&output).unwrap();
    for secret in ["837291", "402118", "483920"] {
        assert!(!rendered.contains(secret), "{rendered}");
    }
    assert!(!rendered.contains("729004"), "{rendered}");
    assert!(rendered.contains("<<OTP_"), "{rendered}");
    assert!(rendered.contains("ORD-100482"), "{rendered}");

    let env = MemoryStore::for_session(&session)
        .auto_env_bindings()
        .unwrap();
    for secret in ["837291", "402118", "483920", "729004"] {
        assert!(
            env.iter()
                .any(|(name, value)| name.starts_with("PENTECT_OTP_") && value == secret),
            "{env:?}"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn canonical_claude_hook_applies_otp_detection_to_browser_rows() {
    let (root, session) = empty_session("hook-post-gmail-row-otp");
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__chrome__snapshot",
        "tool_response": {
            "content": [{
                "type": "text",
                "text": concat!(
                    "Gmail row snapshot\n",
                    "tr role=row aria-labelledby=:2c class='zA zE s00Hgd'\n",
                    "td class='yX xY ulKHrd' text='Service Alerts'\n",
                    "td class='xY a4W' text='New sign-in - Your verification code expires in 10 minutes: 837291.'\n",
                    "td class='xY a4W' text='Use AB12-CD to sign in from this browser.'\n",
                    "td class='xW xY' text='8:42 AM'\n",
                    "Order code ORD-100482 and invoice INV-100482 remain visible.\n"
                )
            }],
            "structuredContent": {
                "rows": [{
                    "tag": "TR",
                    "role": "row",
                    "ariaLabelledBy": ":2c :2d :2e",
                    "className": "zA zE s00Hgd",
                    "cells": [
                        {"tag": "TD", "className": "PF xY", "text": ""},
                        {"tag": "TD", "className": "yX xY ulKHrd", "text": "Service Alerts"},
                        {"tag": "TD", "className": "xY a4W", "text": "New sign-in - Your verification code expires in 10 minutes: 837291."},
                        {"tag": "TD", "className": "xY a4W", "text": "Your sign-in code is 1234."},
                        {"tag": "TD", "className": "xY a4W", "text": "Enter 7QK4P on the login page."},
                        {"tag": "TD", "className": "xW xY", "text": "8:42 AM"}
                    ]
                }],
                "messageText": "Your verification code expires in 10 minutes: 729004.",
                "visibleText": concat!(
                    "確認コードは5分後に期限切れです: 483920\n",
                    "サインインするには 7391 を入力してください\n",
                    "Support ticket SUP-100482 remains visible.\n",
                    "Use SAVE10 to continue checkout.\n",
                    "Order code GH56-JK ships tomorrow."
                )
            }
        }
    });
    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    let rendered = serde_json::to_string(&output).unwrap();
    let store = MemoryStore::for_session(&session);
    let without_known_handles = without_known_opaque_handles(&rendered, &store);
    for secret in ["837291", "1234", "7QK4P", "729004", "483920", "7391"] {
        assert!(
            !without_known_handles.contains(secret),
            "raw OTP remained outside a known opaque handle: {rendered}"
        );
        assert!(store.resolve_all(&rendered).unwrap().contains(secret));
    }
    assert!(rendered.contains("<<OTP_"), "{rendered}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn otp_assertion_ignores_only_well_formed_known_handles() {
    let (root, session) = empty_session("otp-known-handle-assertion");
    let store = MemoryStore::for_session(&session);
    let handle = "<<OTP_3a78a312691234b3>>";
    store
        .add_recovery(pentect_core::Recovery::seal(
            std::collections::HashMap::from([(handle.to_string(), "1234".to_string())]),
            &session.key,
        ))
        .unwrap();

    assert_eq!(
        without_known_opaque_handles(&format!("masked={handle}"), &store),
        "masked=<KNOWN_OPAQUE_HANDLE>"
    );
    for visible in [
        "raw=1234",
        "unknown=<<OTP_1234deadbeef5678>>",
        "broken=<<OTP_1234",
    ] {
        assert!(without_known_opaque_handles(visible, &store).contains("1234"));
    }
    assert_eq!(store.resolve_all(handle).unwrap(), "1234");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn canonical_claude_hook_applies_bip39_detection_to_browser_wallets() {
    let (root, session) = empty_session("hook-post-browser-seed-phrase");
    let phrase = concat!(
        "abandon abandon abandon abandon abandon abandon ",
        "abandon abandon abandon abandon abandon about"
    );
    let numbered = concat!(
        "1. abandon\n2. abandon\n3. abandon\n4. abandon\n",
        "5. abandon\n6. abandon\n7. abandon\n8. abandon\n",
        "9. abandon\n10. abandon\n11. abandon\n12. about"
    );
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__chrome__snapshot",
        "tool_response": {
            "content": [{
                "type": "text",
                "text": format!("Wallet setup page\nRecovery phrase:\n{phrase}")
            }],
            "structuredContent": {
                "visibleText": numbered,
                "nonSecret": "invoice INV-100482 and checkout code SAVE10 remain visible"
            }
        }
    });

    let output = handle_hook(HookProvider::Claude, "t", &session, input).unwrap();
    let rendered = serde_json::to_string(&output).unwrap();
    assert!(!rendered.contains(phrase), "{rendered}");
    assert!(rendered.contains("<<BIP39_MNEMONIC_"), "{rendered}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn posttool_masks_secret_object_keys() {
    let (root, session) = empty_session("hook-post-secret-key");
    // Use the shape owned by the embedded CredSweeper definition. The old
    // sequential alphabet fixture was accepted only by Pentect's retired
    // provider-specific OpenAI regex.
    let raw = [
        "sk-qa25MV9c7Qu0EjDIEWdcT3",
        "Blbk",
        "FJ83uCF0K4yw7RzpY39bio",
    ]
    .concat();
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
    assert!(!rendered.contains(&raw), "{rendered}");
    assert!(rendered.contains("<<"), "{rendered}");
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
    assert!(masked.contains("TEST_SECRET=<<TEST_SECRET_"), "{masked}");
    assert!(masked.contains("NOTE=<<NOTE_"), "{masked}");
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
fn codex_posttool_masks_raw_output_even_if_command_claims_pentect_exec() {
    let (root, session) = empty_session("hook-post-codex-fake-pentect-exec");
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "pentect exec 'echo OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX'"
        },
        "tool_response": "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n"
    });
    let output = handle_hook(HookProvider::Codex, "t", &session, input).unwrap();
    let rendered = serde_json::to_string(&output).unwrap();
    assert_eq!(output["decision"], "block");
    assert!(output.get("hookSpecificOutput").is_none(), "{rendered}");
    assert!(
        !rendered.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
        "{rendered}"
    );
    assert!(rendered.contains("<<OPENAI_API_KEY_"), "{rendered}");
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
    assert!(output.get("hookSpecificOutput").is_none(), "{rendered}");
    assert!(
        !rendered.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
        "{rendered}"
    );
    assert!(rendered.contains("<<OPENAI_API_KEY_"), "{rendered}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn generic_entropy_is_not_masked_without_a_supported_detector() {
    let (root, session) = empty_session("exec-short-handle");
    let blob = "Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh";
    let masked = mask_tool_output(&session, &format!("payload={blob}\n")).unwrap();
    assert!(masked.contains(blob), "{masked}");
    assert!(!masked.contains("<<"), "{masked}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn view_length_comes_from_recovery_not_label() {
    let secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWX";
    let key = Config::generate().key;
    let result = Engine::with_profile(Profile::Strict).mask(
        Input {
            kind: Kind::Env,
            data: format!("OPENAI_API_KEY={secret}\n"),
        },
        &Config {
            disclose_length: false,
            ..Config::new(key)
        },
    );
    assert!(!result.masked.contains("_length_"), "{}", result.masked);
    let handle = first_handle_with_prefix(&result.masked, "<<OPENAI_API_KEY_");
    assert_eq!(
        handle_length_from_recovery(&result.recovery, &handle),
        Some(secret.chars().count())
    );
}

#[test]
fn derived_redactions_do_not_claim_to_be_reusable_handles() {
    let (root, session) = empty_session("exec-derived-no-hint");
    let masked = mask_tool_output(&session, "PREFIX_32=rpa_FAKE\n").unwrap();
    assert_eq!(masked, "PREFIX_32=<<REDACTED_DERIVED_0000000000000000>>\n");
    assert!(
        first_reusable_env_name(&masked, "PENTECT_").is_none(),
        "{masked}"
    );
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
    assert!(masked.contains("TEST_SECRET=<<TEST_SECRET_"), "{masked}");
    assert!(masked.contains("NOTE=<<NOTE_"), "{masked}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn live_single_assignment_output_masks_value() {
    let (root, session) = empty_session("exec-live-single-assignment");
    let masked = mask_live_output(&session, "NOTE=hello world\n").unwrap();
    assert!(!masked.contains("hello world"), "{masked}");
    assert!(masked.contains("NOTE=<<NOTE_"), "{masked}");
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
        masked.contains("RUNPOD_API_KEY=<<REDACTED_DERIVED_0000000000000000>>"),
        "{masked}"
    );
    assert!(
        masked.contains("TEST_SECRET=<<REDACTED_DERIVED_0000000000000000>>"),
        "{masked}"
    );
    assert!(
        masked.contains("NOTE=<<REDACTED_DERIVED_0000000000000000>>"),
        "{masked}"
    );
    assert!(
        masked.contains("KEY=<<REDACTED_DERIVED_0000000000000000>>"),
        "{masked}"
    );
    assert!(
        masked.contains("key=<<REDACTED_DERIVED_0000000000000000>>"),
        "{masked}"
    );
    assert!(
        masked.contains("PREFIX_32=<<REDACTED_DERIVED_0000000000000000>>"),
        "{masked}"
    );
    assert!(
        masked.contains("SUFFIX_32=<<REDACTED_DERIVED_0000000000000000>>"),
        "{masked}"
    );
    assert!(
        masked.contains("BASE64=<<REDACTED_DERIVED_0000000000000000>>"),
        "{masked}"
    );
    assert_eq!(
        masked
            .matches("RUNPOD_API_KEY=<<REDACTED_DERIVED_0000000000000000>>")
            .count(),
        2,
        "{masked}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn api_reference_text_is_not_redacted_as_env_derivatives() {
    let (root, session) = empty_session("exec-api-reference-text");
    let output = concat!(
        "- Do not pass a regex as `name` to `getByRole(...)` in this environment.\n",
        "openTabs(): Promise<Array<BrowserUserTabInfo>>; // List currently open tabs.\n",
        "downloadMedia(options: LocatorDownloadMediaOptions): Promise<void>;\n",
        "getAttribute(name: string): Promise<string | null>;\n",
        "innerText(): Promise<string>;\n",
        "isEnabled(): Promise<boolean>;\n",
        "lastOpened?: string; // User-visible timestamp.\n",
        "On `getByRole(..., { name })`, prefer plain strings.\n",
    );
    let masked = mask_tool_output(&session, output).unwrap();
    assert_eq!(masked, output);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn local_home_paths_remain_visible_without_a_username_detector() {
    let (root, session) = empty_session("exec-local-home-paths");
    let output = concat!(
        r#"at C:\Users\yun40\Desktop\app\src\main.ts:12:34"#,
        "\n",
        r#"  File "/home/yun40/demo/app.py", line 8, in main"#,
        "\n",
        r#"at /mnt/c/Users/yun40/project/src/main.rs:12:34"#,
        "\n",
    );
    let masked = mask_tool_output(&session, output).unwrap();
    assert_eq!(masked, output);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn common_dev_tool_output_does_not_block_codex_posttool() {
    let cases = [
        (
            "next",
            concat!(
                "Next.js 15.3.4\n",
                "- Local:        http://localhost:3000\n",
                "- Network:      http://192.168.1.42:3000\n",
                "Ready in 1290ms\n",
            ),
        ),
        (
            "astro",
            concat!(
                "astro 5.9.0 ready in 358 ms\n",
                "Local    http://localhost:4321/\n",
                "Network  http://192.168.1.42:4321/\n",
            ),
        ),
        (
            "webpack",
            concat!(
                "Project is running at:\n",
                "Loopback: http://localhost:8080/\n",
                "On Your Network (IPv4): http://192.168.1.42:8080/\n",
                "webpack compiled successfully\n",
            ),
        ),
        (
            "uvicorn",
            concat!(
                "INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)\n",
                "INFO:     127.0.0.1:53721 - \"GET /docs HTTP/1.1\" 200 OK\n",
            ),
        ),
        (
            "playwright",
            "Listening on ws://127.0.0.1:9222/devtools/browser/4f3a2e9e-88a0-4e99-a000-abcdef123456\n",
        ),
    ];

    for (name, output) in cases {
        let (root, session) = empty_session(&format!("hook-post-codex-dev-{name}"));
        let input = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": output,
        });
        let hook_output = handle_hook(HookProvider::Codex, "t", &session, input).unwrap();
        assert_eq!(hook_output, json!({}), "{name}");
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn codex_posttool_does_not_block_vite_dev_server_banner() {
    let (root, session) = empty_session("hook-post-codex-vite-banner");
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_response": concat!(
            "  VITE v6.3.5  ready in 281 ms\n\n",
            "  Local:   http://localhost:5173/\n",
            "  Local:   http://127.0.0.1:5173/\n",
            "  Local:   http://[::1]:5173/\n",
            "  Network: http://192.168.1.42:5173/\n",
            "  press h + enter to show help\n",
        )
    });
    let output = handle_hook(HookProvider::Codex, "t", &session, input).unwrap();
    assert_eq!(output, json!({}));
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
        masked.contains("RUNPOD_API_KEY=<<REDACTED_DERIVED_0000000000000000>>"),
        "{masked}"
    );
    assert!(
        masked.contains("NOTE=<<REDACTED_DERIVED_0000000000000000>>"),
        "{masked}"
    );
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
fn claude_pretool_leaves_plain_shell_command_unchanged() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (root, session) = empty_session("hook-pre-plain");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": r"Get-Content .\.env"
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    assert_eq!(output, json!({}));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn require_pentect_blocks_unwrapped_agent_when_enabled() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    std::env::remove_var(PENTECT_AGENT_LAUNCHED_ENV);
    std::env::remove_var(ENV_TOKEN);
    let reason = ensure_pentect_agent_launch_required(HookProvider::Claude, true).unwrap_err();
    assert!(reason.contains("pentect claude"), "{reason}");
}

#[test]
fn require_pentect_rejects_matching_env_without_live_memory_store() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    std::env::set_var(PENTECT_AGENT_LAUNCHED_ENV, token);
    std::env::set_var(ENV_TOKEN, token);
    std::env::set_var(ENV_ADDR, "127.0.0.1:9");
    let reason = ensure_pentect_agent_launch_required(HookProvider::Claude, true).unwrap_err();
    assert!(reason.contains("pentect claude"), "{reason}");
    std::env::remove_var(PENTECT_AGENT_LAUNCHED_ENV);
    std::env::remove_var(ENV_TOKEN);
    std::env::remove_var(ENV_ADDR);
}

#[test]
fn reserved_control_environment_cannot_redirect_an_active_store() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("control-env-redirect");
    assert!(active_memory_store_ready());

    std::env::set_var(
        "PENTECT_PROCESS_HOST_ROOT",
        temp_root("attacker-selected-root"),
    );
    std::env::set_var("PENTECT_PROCESS_HOST_READ_TOKEN", "attacker-selected-token");
    std::env::set_var(
        "PENTECT_PROCESS_HOST_WRITE_TOKEN",
        "attacker-selected-token",
    );

    assert!(active_memory_store_ready());
    assert!(MemoryStoreClient::from_env().is_some());
    let environment = bridge_session_value().unwrap()["environment"]
        .as_object()
        .unwrap()
        .clone();
    assert!(!environment.contains_key("PENTECT_PROCESS_HOST_ROOT"));
    assert!(!environment.contains_key("PENTECT_PROCESS_HOST_READ_TOKEN"));
    assert!(!environment.contains_key("PENTECT_PROCESS_HOST_WRITE_TOKEN"));

    std::env::remove_var("PENTECT_PROCESS_HOST_ROOT");
    std::env::remove_var("PENTECT_PROCESS_HOST_READ_TOKEN");
    std::env::remove_var("PENTECT_PROCESS_HOST_WRITE_TOKEN");
}

#[test]
fn replaced_runtime_credentials_cannot_impersonate_the_active_store() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, addr, token) = ActiveMemoryStoreEnv::start("credential-redirect");
    assert!(active_memory_store_ready());

    let replacement = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    std::env::set_var(ENV_TOKEN, replacement);
    std::env::set_var(PENTECT_AGENT_LAUNCHED_ENV, replacement);
    assert!(MemoryStoreClient::from_env().is_none());

    std::env::set_var(ENV_TOKEN, &token);
    std::env::set_var(PENTECT_AGENT_LAUNCHED_ENV, &token);
    std::env::set_var(ENV_ADDR, "127.0.0.1:9");
    assert!(MemoryStoreClient::from_env().is_none());

    std::env::set_var(ENV_ADDR, addr);
    assert!(MemoryStoreClient::from_env().is_some());
}

#[test]
fn require_pentect_allows_wrapped_agent_with_memory_store_proof() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (_active_store, _, _) = ActiveMemoryStoreEnv::start("launch-proof");
    ensure_pentect_agent_launch_required(HookProvider::Claude, true).unwrap();
}

#[test]
fn pretool_leaves_explicit_pentect_read_unchanged() {
    let (root, session) = empty_session("hook-pre-read");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": r"pentect read .\.env"
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    assert_eq!(output, json!({}));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pretool_leaves_explicit_pentect_resolve_unchanged() {
    let (root, session) = empty_session("hook-pre-resolve");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": r"pentect resolve .\.env.prod"
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    assert_eq!(output, json!({}));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pretool_allows_direct_read_tool_for_clean_file() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (root, session) = empty_session("hook-pre-direct-read-clean");
    let project = PathBuf::from("target").join(format!(
        "pentect-read-clean-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let readme = project.join("README.txt");
    std::fs::write(&readme, "Settings\nNo credentials here.\n").unwrap();
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": readme.to_string_lossy()
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    assert_eq!(output, json!({}));
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pretool_rewrites_direct_read_tool_to_masked_copy() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (root, session) = empty_session("hook-pre-direct-read-secret");
    let project = PathBuf::from("target").join(format!(
        "pentect-read-secret-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    let env = project.join(".env");
    std::fs::write(&env, "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n").unwrap();
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": env.to_string_lossy()
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "allow");
    let masked_path = output["hookSpecificOutput"]["updatedInput"]["file_path"]
        .as_str()
        .unwrap();
    let masked_path_buf = PathBuf::from(masked_path);
    assert!(
        masked_path_buf.starts_with(
            config::project_root()
                .unwrap()
                .join(".pentect")
                .join("read")
        ),
        "{masked_path}"
    );
    assert!(
        masked_path_buf.ends_with(project.join(".env")),
        "{masked_path}"
    );
    assert!(!masked_path.contains("masked-read"), "{masked_path}");
    let masked = std::fs::read_to_string(masked_path).unwrap();
    assert!(masked.contains("<<OPENAI_API_KEY_"), "{masked}");
    assert!(!masked.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"), "{masked}");
    assert_eq!(
        session.resolve_all(&masked).unwrap(),
        "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n"
    );
    let _ = std::fs::remove_dir_all(project);
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(".pentect/read");
}

#[test]
fn pretool_rewrites_secret_read_many_paths_to_masked_copies() {
    let session_fixture = TestDirectory::new("hook-pre-read-many-secret-session");
    let session = Session::open_at(session_fixture.path(), "t").unwrap();
    let fixture = TestDirectory::new("pentect-read-many-secret");
    std::fs::create_dir_all(fixture.path().join(".pentect")).unwrap();
    let project = fixture.path().join("project");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    let result = {
        let _lock = TEST_ENV_LOCK.lock().unwrap();
        let _cwd = enter_temp_cwd(&project);
        let readme = PathBuf::from("README.txt");
        let env = PathBuf::from(".env");
        std::fs::write(&readme, "Settings\n").unwrap();
        std::fs::write(
            &env,
            "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\n",
        )
        .unwrap();
        let input = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "ReadManyFiles",
            "tool_input": {
                "paths": [readme.to_string_lossy(), env.to_string_lossy()]
            }
        });
        let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "allow");
        let paths = output["hookSpecificOutput"]["updatedInput"]["paths"]
            .as_array()
            .unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].as_str().unwrap(), readme.to_string_lossy());
        let masked_path = paths[1].as_str().unwrap();
        let masked_path_buf = PathBuf::from(masked_path);
        assert!(
            masked_path_buf.starts_with(project.join(".pentect").join("read")),
            "{masked_path}"
        );
        assert!(masked_path_buf.ends_with(&env), "{masked_path}");
        assert!(!masked_path.contains("masked-read"), "{masked_path}");
        std::fs::read_to_string(masked_path).unwrap()
    };
    assert!(result.contains("<<RUNPOD_API_KEY_"), "{result}");
    assert!(!result.contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"));
    assert_directory_empty(&fixture.path().join(".pentect"));
}

#[test]
fn masked_read_copy_path_mirrors_relative_paths() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("masked-read-project-root");
    let project = root.join("project");
    let nested = project.join("src").join("nested");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(&nested).unwrap();
    let source = project.join("config.env");
    std::fs::write(
        &source,
        "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\n",
    )
    .unwrap();

    let (relative_copy, absolute_copy) = {
        let _cwd = enter_temp_cwd(&nested);
        let session = Session::open_at(&project, "t").unwrap();
        let relative = masked_read_copy(&session, Path::new("../../config.env").to_str().unwrap())
            .unwrap()
            .unwrap();
        let absolute = masked_read_copy(&session, source.to_str().unwrap())
            .unwrap()
            .unwrap();
        (relative, absolute)
    };

    let expected = project
        .canonicalize()
        .unwrap()
        .join(".pentect")
        .join("read")
        .join("config.env");
    assert_eq!(relative_copy, expected);
    assert_eq!(absolute_copy, expected);
    assert!(!nested.join(".pentect").exists());
    assert!(std::fs::read_to_string(&expected)
        .unwrap()
        .contains("<<RUNPOD_API_KEY_"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn masked_read_copy_paths_do_not_collide_for_external_same_basename() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let fixture = TestDirectory::new("masked-read-external-collision");
    std::fs::create_dir_all(fixture.path().join(".pentect")).unwrap();
    let root = fixture.path();
    let project = root.join("project");
    let external = root.join("external");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(external.join("one")).unwrap();
    std::fs::create_dir_all(external.join("two")).unwrap();
    let first = external.join("one").join(".env");
    let second = external.join("two").join(".env");
    std::fs::write(
        &first,
        "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\n",
    )
    .unwrap();
    std::fs::write(&second, "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n").unwrap();

    let first_masked = {
        let _cwd = enter_temp_cwd(&project);
        let session = Session::open_at(&project, "t").unwrap();
        masked_read_copy(&session, first.to_str().unwrap())
            .unwrap()
            .unwrap()
    };
    let second_masked = {
        let _cwd = enter_temp_cwd(&project);
        let session = Session::open_at(&project, "t").unwrap();
        masked_read_copy(&session, second.to_str().unwrap())
            .unwrap()
            .unwrap()
    };

    assert_ne!(first_masked, second_masked);
    let external_root = project.join(".pentect").join("read").join("_external");
    assert!(first_masked.starts_with(&external_root));
    assert!(second_masked.starts_with(&external_root));
    let first_text = std::fs::read_to_string(&first_masked).unwrap();
    let second_text = std::fs::read_to_string(&second_masked).unwrap();
    assert!(first_text.contains("<<RUNPOD_API_KEY_"), "{first_text}");
    assert!(second_text.contains("<<OPENAI_API_KEY_"), "{second_text}");
    assert_directory_empty(&root.join(".pentect"));
}

#[test]
fn file_pointer_manager_recovers_read_handle_after_restart() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("file-pointer-recover");
    let _cwd = enter_temp_cwd(&root);
    write_project_config(&root, "[files]\nremember = true\n");
    let project = PathBuf::from("project");
    std::fs::create_dir_all(&project).unwrap();
    let env = project.join(".env");
    std::fs::write(&env, "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n").unwrap();

    let session = Session::open_at(&root, "t").unwrap();
    let masked_path = masked_read_copy(&session, env.to_str().unwrap())
        .unwrap()
        .unwrap();
    let masked = std::fs::read_to_string(masked_path).unwrap();
    let handle = masked_handle_from_assignment(&masked, "OPENAI_API_KEY");
    assert_eq!(file_pointer_manager::handle_length(&handle), Some(27));

    let restarted = Session::open_at(&root.join("restart"), "t").unwrap();
    let store = MemoryStore::for_session(&restarted);
    assert_eq!(
        store.resolve_all(&handle).unwrap(),
        "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
    );

    let index = std::fs::read(
        Path::new(".pentect")
            .join("file-pointer-manager")
            .join("index.bin"),
    )
    .unwrap();
    assert!(
        !String::from_utf8_lossy(&index).contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
        "{}",
        String::from_utf8_lossy(&index)
    );
    drop(_cwd);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn file_pointer_manager_uses_project_root_across_nested_working_directories() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("file-pointer-project-root");
    let _cwd = enter_temp_cwd(&root);
    write_project_config(&root, "[files]\nremember = true\n");
    let env = root.join(".env");
    std::fs::write(&env, "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n").unwrap();

    let session = Session::open_at(&root, "t").unwrap();
    let masked_path = masked_read_copy(&session, env.to_str().unwrap())
        .unwrap()
        .unwrap();
    let masked = std::fs::read_to_string(masked_path).unwrap();
    let handle = masked_handle_from_assignment(&masked, "OPENAI_API_KEY");
    let root_manager = root.join(".pentect").join("file-pointer-manager");
    assert!(root_manager.join("index.bin").exists());
    assert!(root_manager.join("key.bin").exists());

    let nested = root.join("src").join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::env::set_current_dir(&nested).unwrap();
    let restarted = Session::open_at(&root.join("restart"), "t").unwrap();
    let store = MemoryStore::for_session(&restarted);
    assert_eq!(file_pointer_manager::handle_length(&handle), Some(27));
    assert_eq!(
        store.resolve_all(&handle).unwrap(),
        "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
    );
    assert!(!nested
        .join(".pentect")
        .join("file-pointer-manager")
        .exists());

    drop(_cwd);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn plugin_runtime_storage_uses_project_root_across_nested_working_directories() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("plugin-runtime-project-root");
    let _cwd = enter_temp_cwd(&root);
    std::fs::create_dir_all(root.join(".git")).unwrap();
    let nested = root.join("src/nested");
    std::fs::create_dir_all(&nested).unwrap();
    let plugin = format!("nested-runtime-{}", std::process::id());

    let from_root = plugin_runtime_dirs(&plugin).unwrap();
    std::env::set_current_dir(&nested).unwrap();
    let from_nested = plugin_runtime_dirs(&plugin).unwrap();

    assert_eq!(from_nested.data_dir, from_root.data_dir);
    assert_eq!(from_nested.cache_dir, from_root.cache_dir);
    assert_eq!(from_nested.config_file, from_root.config_file);
    assert!(!nested.join(".pentect").exists());

    let _ = std::fs::remove_dir_all(&from_root.data_dir);
    drop(_cwd);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn file_pointer_manager_refuses_changed_source_file() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("file-pointer-changed");
    let _cwd = enter_temp_cwd(&root);
    write_project_config(&root, "[files]\nremember = true\n");
    let project = PathBuf::from("project");
    std::fs::create_dir_all(&project).unwrap();
    let env = project.join(".env");
    std::fs::write(&env, "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n").unwrap();

    let session = Session::open_at(&root, "t").unwrap();
    let masked_path = masked_read_copy(&session, env.to_str().unwrap())
        .unwrap()
        .unwrap();
    let masked = std::fs::read_to_string(masked_path).unwrap();
    let handle = masked_handle_from_assignment(&masked, "OPENAI_API_KEY");

    std::fs::write(&env, "OPENAI_API_KEY=sk-CHANGEDABCDEFGHIJKLMNOP\n").unwrap();
    let restarted = Session::open_at(&root.join("restart"), "t").unwrap();
    let store = MemoryStore::for_session(&restarted);
    assert_eq!(store.resolve_all(&handle).unwrap(), handle);
    drop(_cwd);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn file_pointer_manager_refuses_grown_source_before_reading_value() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("file-pointer-grown");
    let _cwd = enter_temp_cwd(&root);
    write_project_config(&root, "[files]\nremember = true\n");
    let env = PathBuf::from(".env");
    std::fs::write(&env, "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n").unwrap();

    let session = Session::open_at(&root, "t").unwrap();
    let masked_path = masked_read_copy(&session, env.to_str().unwrap())
        .unwrap()
        .unwrap();
    let masked = std::fs::read_to_string(masked_path).unwrap();
    let handle = masked_handle_from_assignment(&masked, "OPENAI_API_KEY");

    std::fs::write(&env, format!("{}\n{}", "x".repeat(128 * 1024), handle)).unwrap();
    let restarted = Session::open_at(&root.join("restart"), "t").unwrap();
    let store = MemoryStore::for_session(&restarted);
    assert_eq!(store.resolve_all(&handle).unwrap(), handle);
    drop(_cwd);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn file_pointer_manager_save_can_be_disabled() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("file-pointer-disabled");
    let _cwd = enter_temp_cwd(&root);
    write_project_config(&root, "[files]\nremember = false\n");
    let env = PathBuf::from(".env");
    std::fs::write(&env, "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n").unwrap();

    let session = Session::open_at(&root, "t").unwrap();
    let masked_path = masked_read_copy(&session, env.to_str().unwrap())
        .unwrap()
        .unwrap();
    let masked = std::fs::read_to_string(masked_path).unwrap();
    let handle = masked_handle_from_assignment(&masked, "OPENAI_API_KEY");

    let restarted = Session::open_at(&root.join("restart"), "t").unwrap();
    let store = MemoryStore::for_session(&restarted);
    assert_eq!(store.resolve_all(&handle).unwrap(), handle);
    assert!(!Path::new(".pentect")
        .join("file-pointer-manager")
        .join("index.bin")
        .exists());
    assert!(!Path::new(".pentect")
        .join("file-pointer-manager")
        .join("key.bin")
        .exists());
    drop(_cwd);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn file_pointer_manager_skips_non_text_read_inputs() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let root = temp_root("file-pointer-non-text");
    let _cwd = enter_temp_cwd(&root);
    write_project_config(&root, "[files]\nremember = true\n");
    let path = PathBuf::from("image.txt");
    std::fs::write(&path, "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n").unwrap();
    let result = Engine::with_profile(Profile::Strict).mask(
        Input {
            kind: Kind::Env,
            data: std::fs::read_to_string(&path).unwrap(),
        },
        &Config::generate(),
    );
    assert!(result.summary.masked_count > 0);
    assert!(!register_read_file_pointers(
        &path,
        &result.masked,
        &result,
        InputFormat::Image
    ));
    assert!(!Path::new(".pentect")
        .join("file-pointer-manager")
        .join("index.bin")
        .exists());
    drop(_cwd);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pdf_input_is_not_supported() {
    assert!(parse_input_format("pdf").is_err());
}

#[test]
fn pretool_allows_read_many_when_all_files_are_clean() {
    let (root, session) = empty_session("hook-pre-read-many-clean");
    let project = temp_root("pentect-read-many-clean");
    let output = {
        let _lock = TEST_ENV_LOCK.lock().unwrap();
        let _cwd = enter_temp_cwd(&project);
        let first = PathBuf::from("README.txt");
        let second = PathBuf::from("notes.txt");
        std::fs::write(&first, "Settings\n").unwrap();
        std::fs::write(&second, "No credentials here.\n").unwrap();
        let input = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "ReadManyFiles",
            "tool_input": {
                "paths": [first.to_string_lossy(), second.to_string_lossy()]
            }
        });
        handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap()
    };
    assert_eq!(output, json!({}));
    let _ = std::fs::remove_dir_all(project);
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
    assert_eq!(command, r"Get-Content .\.env");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pretool_unwraps_pentect_exec_with_trailing_shell_syntax() {
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
    assert_eq!(
        command,
        "echo ok; Write-Output OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pretool_unwraps_pentect_exec_live_command() {
    let (root, session) = empty_session("hook-pre-exec-live");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": r#"pentect exec --live "Write-Output hi""#
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    let command = output["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap();
    assert_eq!(command, "Write-Output hi");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pretool_unwraps_pentect_exec_without_rewriting_shell_syntax() {
    let (root, session) = empty_session("hook-pre-exec-dollar-substitution");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": r#"pentect exec -- echo $(python exfil.py)"#
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    let command = output["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap();
    assert_eq!(command, "echo $(python exfil.py)");
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
    assert_eq!(command, r"Get-Content .\.env");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pretool_collapses_nested_pentect_read_command() {
    let (root, session) = empty_session("hook-pre-nested-read");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": r#"pentect exec "pentect read .\.env""#
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    let command = output["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap();
    assert_eq!(command, r"pentect read .\.env");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pretool_collapses_nested_pentect_resolve() {
    let (root, session) = empty_session("hook-pre-nested-resolve");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": r#"pentect exec "pentect resolve .\.env.prod""#
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    let command = output["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap();
    assert_eq!(command, r"pentect resolve .\.env.prod");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pretool_does_not_treat_mcp_command_fields_as_shell_commands() {
    let (root, session) = empty_session("hook-pre-mcp-command-field");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__service__invoke",
        "tool_input": {
            "command": "remote-operation",
            "argument": "value"
        }
    });
    let output = handle_hook(HookProvider::Claude, DEFAULT_SESSION, &session, input).unwrap();
    assert_eq!(output, json!({}));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pretool_leaves_camel_case_plain_shell_input_unchanged() {
    let (root, session) = empty_session("hook-pre-camel");
    let input = json!({
        "hookEventName": "PreToolUse",
        "toolName": "shell",
        "toolInput": {
            "command": r"Get-Content .\.env"
        }
    });
    let output = handle_hook(HookProvider::Generic, DEFAULT_SESSION, &session, input).unwrap();
    assert_eq!(output, json!({}));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn claude_pretool_restores_masked_shell_command_directly() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
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
    assert!(command.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"), "{command}");
    assert!(!command.contains("<<OPENAI_API_KEY_"), "{command}");
    assert!(!command.contains("pentect exec"), "{command}");
    assert!(!command.contains("script-b64"), "{command}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn generic_pretool_restores_known_handles_in_nested_mcp_arguments() {
    let _env_guard = TEST_ENV_LOCK.lock().unwrap();
    let (root, session, masked) = masked_session("hook-pre-mcp");
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__example__request",
        "tool_input": {
            "headers": {"authorization": format!("Bearer {masked}")},
            "items": [{"token": masked}]
        }
    });
    let output = handle_hook(HookProvider::Generic, DEFAULT_SESSION, &session, input).unwrap();
    let updated = &output["hookSpecificOutput"]["updatedInput"];
    let rendered = serde_json::to_string(updated).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "allow");
    assert_eq!(
        updated["headers"]["authorization"],
        "Bearer OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n"
    );
    assert_eq!(
        updated["items"][0]["token"],
        "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n"
    );
    assert!(!rendered.contains("<<"), "{rendered}");
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
    assert!(content.contains("<<TOKEN_"), "{content}");
    assert!(
        !content.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
        "{content}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn hook_text_masks_runpod_token_when_keyed() {
    let (root, session) = empty_session("hook-runpod-text");
    let raw = concat!(
        "RUNPOD_API_KEY=",
        "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"
    );
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
    assert!(
        reason.starts_with("Tool completed. Protected output:"),
        "{reason}"
    );
    assert!(reason.contains("<<OPENAI_API_KEY_"), "{reason}");
    assert!(!reason.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"), "{reason}");
    assert!(output.get("hookSpecificOutput").is_none(), "{output}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn codex_mcp_posttool_blocks_with_masked_feedback() {
    let (root, session) = empty_session("hook-post-codex-mcp");
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__node_repl__js",
        "tool_response": {
            "content": [{
                "type": "text",
                "text": "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX"
            }],
            "isError": false
        }
    });
    let output = handle_hook(HookProvider::Codex, "t", &session, input).unwrap();
    assert_eq!(output["decision"], "block");
    let reason = output["reason"].as_str().unwrap();
    assert!(reason.contains("<<OPENAI_API_KEY_"), "{reason}");
    assert!(!reason.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWX"), "{reason}");
    assert!(output.get("hookSpecificOutput").is_none(), "{output}");
    let _ = std::fs::remove_dir_all(root);
}

fn masked_session(name: &str) -> (PathBuf, Session, String) {
    let (root, session) = empty_session(name);
    let result = Engine::with_profile(Profile::Strict).mask(
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
    let root = temp_root(name);
    let session = Session::open_at(&root, "t").unwrap();
    (root, session)
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "pentect-test-{}-{}-{name}",
        std::process::id(),
        unix_millis()
    ))
}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(name: &str) -> Self {
        let path = temp_root(name);
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn assert_directory_empty(path: &Path) {
    assert!(
        std::fs::read_dir(path).unwrap().next().is_none(),
        "hostile ancestor was modified: {}",
        path.display()
    );
}

fn write_project_config(root: &Path, config: &str) {
    let dir = root.join(".pentect");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.toml"), config).unwrap();
}

struct TestHome {
    previous_home: Option<std::ffi::OsString>,
    previous_user_profile: Option<std::ffi::OsString>,
}

impl Drop for TestHome {
    fn drop(&mut self) {
        match self.previous_home.take() {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        match self.previous_user_profile.take() {
            Some(value) => std::env::set_var("USERPROFILE", value),
            None => std::env::remove_var("USERPROFILE"),
        }
    }
}

fn write_user_config(root: &Path, config: &str) -> TestHome {
    let home = root.join("home");
    let dir = home.join(".pentect");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.toml"), config).unwrap();
    let guard = TestHome {
        previous_home: std::env::var_os("HOME"),
        previous_user_profile: std::env::var_os("USERPROFILE"),
    };
    std::env::set_var("HOME", &home);
    std::env::set_var("USERPROFILE", &home);
    guard
}

struct TestCwd {
    previous: PathBuf,
}

impl Drop for TestCwd {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.previous);
    }
}

fn enter_temp_cwd(root: &Path) -> TestCwd {
    std::fs::create_dir_all(root).unwrap();
    let previous = std::env::current_dir().unwrap();
    std::env::set_current_dir(root).unwrap();
    TestCwd { previous }
}

fn strings<const N: usize>(items: [&str; N]) -> Vec<String> {
    items.into_iter().map(str::to_string).collect()
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

fn without_known_opaque_handles(text: &str, store: &MemoryStore) -> String {
    let mut remaining = text;
    let mut visible = String::with_capacity(text.len());
    while let Some(start) = remaining.find("<<") {
        visible.push_str(&remaining[..start]);
        let candidate_start = &remaining[start..];
        let Some(end) = candidate_start.find(">>").map(|offset| offset + 2) else {
            visible.push_str(candidate_start);
            return visible;
        };
        let candidate = &candidate_start[..end];
        let known = parse_placeholder(candidate).is_ok()
            && store
                .resolve_all(candidate)
                .is_ok_and(|resolved| resolved != candidate);
        if known {
            visible.push_str("<KNOWN_OPAQUE_HANDLE>");
        } else {
            visible.push_str(candidate);
        }
        remaining = &candidate_start[end..];
    }
    visible.push_str(remaining);
    visible
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
    let core = match core.rsplit_once("_length_") {
        Some((prefix, suffix))
            if suffix
                .strip_suffix("_chars")
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit())) =>
        {
            prefix
        }
        _ => core,
    };
    let core = match core.rsplit_once("_len") {
        Some((prefix, suffix)) if suffix.bytes().all(|b| b.is_ascii_digit()) => prefix,
        _ => core,
    };
    format!("PENTECT_{core}")
}
#[test]
fn exec_start_errors_never_repeat_the_command_or_os_message() {
    let sensitive_command = "private-command-name";
    let error = std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("localized failure: {sensitive_command}"),
    );
    let diagnostic = command_start_error(&error);
    assert_eq!(
        diagnostic,
        "could not start command: executable was not found; `pentect exec --` requires a program name"
    );
    assert!(!diagnostic.contains(sensitive_command));
    assert!(!diagnostic.contains("localized failure"));
}

#[test]
fn powershell_exec_preamble_forces_utf8_and_sanitizes_missing_commands() {
    let script = "Write-Output '日本語'; private-command-name";
    let prepared = prepare_shell_script(script, ScriptShell::PowerShell);
    assert!(prepared.contains("[Console]::InputEncoding=[Text.UTF8Encoding]"));
    assert!(prepared.contains("[Console]::OutputEncoding=[Text.UTF8Encoding]"));
    assert!(prepared.contains("System.Management.Automation.CommandNotFoundException"));
    assert!(prepared.contains("executable was not found"));
    assert!(prepared.ends_with(script));
}
