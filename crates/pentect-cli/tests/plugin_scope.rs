use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("pentect-{name}-{}-{nonce}", std::process::id()))
}

fn command(home: &Path, cwd: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pentect"));
    command
        .current_dir(cwd)
        .env("HOME", home)
        .env_remove("USERPROFILE");
    command
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn mask(home: &Path, cwd: &Path, input: &str) -> String {
    let mut child = command(home, cwd)
        .arg("mask")
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
    assert_success(&output);
    String::from_utf8(output.stdout).unwrap()
}

fn write_manifest(root: &Path, name: &str, label: &str, pattern: &str) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("plugin.toml"),
        format!(
            "schema = \"pentect.plugin.v1\"\nname = \"{name}\"\n\n[[detector]]\nlabel = \"{label}\"\npattern = '''{pattern}'''\ncategory = \"identifier\"\nconfidence = \"high\"\n"
        ),
    )
    .unwrap();
}

#[test]
fn plugins_are_user_global_by_default_and_project_scope_is_explicit() {
    let root = temp_dir("plugin-scope");
    let home = root.join("home");
    let first_project = root.join("first-project");
    let second_project = root.join("second-project");
    let global_plugin = first_project.join("global-plugin");
    let project_plugin = root.join("project-plugin");
    for path in [&home, &first_project, &second_project] {
        std::fs::create_dir_all(path).unwrap();
    }
    write_manifest(
        &global_plugin,
        "global-test",
        "GLOBAL_TEST",
        r"GLOBAL-[0-9]{6}",
    );
    write_manifest(
        &project_plugin,
        "project-test",
        "PROJECT_TEST",
        r"PROJECT-[0-9]{6}",
    );

    let output = command(&home, &first_project)
        .args(["plugins", "add"])
        .arg("./global-plugin")
        .arg("--yes")
        .output()
        .unwrap();
    assert_success(&output);
    let user_config = home.join(".pentect/config.toml");
    assert!(user_config.is_file());
    assert!(!first_project.join(".pentect/config.toml").exists());

    let output = command(&home, &first_project)
        .args(["plugins", "add"])
        .arg(&project_plugin)
        .args(["--project", "--yes"])
        .output()
        .unwrap();
    assert_success(&output);
    assert!(first_project.join(".pentect/config.toml").is_file());
    let user_config_text = std::fs::read_to_string(&user_config).unwrap();
    assert!(user_config_text.contains(global_plugin.to_str().unwrap()));
    assert!(!user_config_text.contains("./global-plugin"));
    assert!(!user_config_text.contains(project_plugin.to_str().unwrap()));

    let elsewhere = mask(&home, &second_project, "GLOBAL-123456 PROJECT-123456");
    assert!(elsewhere.contains("<<GLOBAL_TEST_"), "{elsewhere}");
    assert!(elsewhere.contains("PROJECT-123456"), "{elsewhere}");

    let inside_project = mask(&home, &first_project, "GLOBAL-123456 PROJECT-123456");
    assert!(
        inside_project.contains("<<GLOBAL_TEST_"),
        "{inside_project}"
    );
    assert!(
        inside_project.contains("<<PROJECT_TEST_"),
        "{inside_project}"
    );

    let nested = first_project.join("src/nested");
    std::fs::create_dir_all(&nested).unwrap();
    let inside_nested = mask(&home, &nested, "GLOBAL-123456 PROJECT-123456");
    assert!(inside_nested.contains("<<GLOBAL_TEST_"), "{inside_nested}");
    assert!(inside_nested.contains("<<PROJECT_TEST_"), "{inside_nested}");
    assert!(!nested.join(".pentect/config.toml").exists());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn project_plugin_directory_is_visible_from_nested_working_directory() {
    let root = temp_dir("plugin-nested-list");
    let home = root.join("home");
    let project = root.join("project");
    let nested = project.join("src/nested");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&nested).unwrap();
    write_manifest(
        &project.join(".pentect/plugins/nested-list"),
        "nested-list",
        "NESTED_LIST",
        r"NESTED-[0-9]{6}",
    );

    let output = command(&home, &nested)
        .args(["plugins", "list"])
        .output()
        .unwrap();
    assert_success(&output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("nested-list: project ok configs=1 binary=no"),
        "{stdout}"
    );
    assert!(!nested.join(".pentect/plugins").exists());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn nearest_nested_pentect_directory_defines_a_separate_project_root() {
    let root = temp_dir("plugin-explicit-nested-root");
    let home = root.join("home");
    let project = root.join("project");
    let nested = project.join("packages/child");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    write_manifest(
        &project.join(".pentect/plugins/outer"),
        "outer",
        "OUTER",
        r"OUTER-[0-9]{6}",
    );
    write_manifest(
        &nested.join(".pentect/plugins/inner"),
        "inner",
        "INNER",
        r"INNER-[0-9]{6}",
    );

    let output = command(&home, &nested)
        .args(["plugins", "list"])
        .output()
        .unwrap();
    assert_success(&output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("inner: project ok configs=1 binary=no"),
        "{stdout}"
    );
    assert!(!stdout.contains("outer:"), "{stdout}");

    std::fs::remove_dir_all(root).unwrap();
}
