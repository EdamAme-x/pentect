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
    let output = Command::new(env!("CARGO_BIN_EXE_pentect"))
        .arg("read")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
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
