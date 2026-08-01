use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("pentect-{name}-{}-{nonce}", std::process::id()))
}

fn read(path: &std::path::Path) -> String {
    read_with_args(&[path.as_os_str()])
}

fn read_with_args(args: &[&std::ffi::OsStr]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_pentect"))
        .arg("read")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn read_as(kind: &str, path: &std::path::Path) -> String {
    read_with_args(&[
        std::ffi::OsStr::new("--kind"),
        std::ffi::OsStr::new(kind),
        path.as_os_str(),
    ])
}

#[test]
fn read_cloudflare_dev_vars_masks_every_value_with_key_labels() {
    let root = temp_dir("dev-vars");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join(".dev.vars");
    std::fs::write(&path, "API_TOKEN=x\nMODE=dev\n").unwrap();

    let output = read(&path);
    assert!(output.contains("API_TOKEN=<<API_TOKEN_"), "{output}");
    assert!(output.contains("MODE=<<MODE_"), "{output}");
    assert!(!output.contains("API_TOKEN=x"), "{output}");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn read_npmrc_masks_auth_but_keeps_public_registry() {
    let root = temp_dir("npmrc");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join(".npmrc");
    std::fs::write(
        &path,
        "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=x\n",
    )
    .unwrap();

    let output = read(&path);
    assert!(
        output.contains("registry=https://registry.npmjs.org/"),
        "{output}"
    );
    assert!(output.contains("_authToken=<<AUTH_TOKEN_"), "{output}");
    assert!(!output.contains("_authToken=x"), "{output}");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn explicit_kinds_cover_arbitrary_dotenv_structured_and_one_secret_files() {
    let root = temp_dir("explicit-kinds");
    std::fs::create_dir_all(&root).unwrap();

    let dotenv = root.join("credentials.custom");
    std::fs::write(&dotenv, "TOKEN=x\nMODE=dev\n").unwrap();
    let output = read_as("env", &dotenv);
    assert!(output.contains("TOKEN=<<TOKEN_"), "{output}");
    assert!(output.contains("MODE=<<MODE_"), "{output}");

    let structured = root.join("settings.custom");
    std::fs::write(&structured, "region: us-east-1\npassword: x\n").unwrap();
    let output = read_as("structured", &structured);
    assert!(output.contains("region: us-east-1"), "{output}");
    assert!(output.contains("password: <<PASSWORD_"), "{output}");

    let secret = root.join("opaque.custom");
    std::fs::write(&secret, "short value with spaces\nand another line").unwrap();
    let output = read_as("secret", &secret);
    assert!(output.trim().starts_with("<<SECRET_"), "{output}");
    assert_eq!(output.matches("<<").count(), 1, "{output}");

    std::fs::remove_dir_all(root).unwrap();
}
