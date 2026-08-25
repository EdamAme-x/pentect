use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../tools/alcatraz-helper/main.go");
    println!("cargo:rerun-if-changed=../../tools/alcatraz-helper/go.mod");
    println!("cargo:rerun-if-changed=../../tools/alcatraz-helper/go.sum");
    println!("cargo:rerun-if-env-changed=PENTECT_ALCATRAZ_HELPER");
    println!("cargo:rerun-if-env-changed=PENTECT_REQUIRE_ALCATRAZ");

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let executable = out.join(
        if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            "pentect-alcatraz.exe"
        } else {
            "pentect-alcatraz"
        },
    );
    let supplied = env::var_os("PENTECT_ALCATRAZ_HELPER").map(PathBuf::from);
    let result = if let Some(path) = supplied {
        fs::copy(path, &executable)
            .map(|_| ())
            .map_err(|error| error.to_string())
    } else {
        build_helper(&executable)
    };

    if let Err(error) = result {
        if env::var_os("PENTECT_REQUIRE_ALCATRAZ").is_some() {
            panic!("Alcatraz helper is required but could not be built: {error}");
        }
        println!("cargo:warning=Alcatraz PII helper disabled: {error}");
        fs::write(&executable, []).expect("write disabled Alcatraz marker");
    }

    let bytes = fs::read(&executable).expect("read Alcatraz helper");
    let compressed =
        zstd::stream::encode_all(bytes.as_slice(), 19).expect("compress Alcatraz helper");
    let compressed_path = out.join("pentect-alcatraz.zst");
    fs::write(&compressed_path, compressed).expect("write compressed Alcatraz helper");
    println!(
        "cargo:rustc-env=PENTECT_ALCATRAZ_ZST={}",
        compressed_path.display()
    );
    println!(
        "cargo:rustc-env=PENTECT_ALCATRAZ_SHA256={:x}",
        Sha256::digest(&bytes)
    );
    println!("cargo:rustc-env=PENTECT_ALCATRAZ_SIZE={}", bytes.len());
}

fn build_helper(output: &Path) -> Result<(), String> {
    let target_os = env::var("CARGO_CFG_TARGET_OS").map_err(|e| e.to_string())?;
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").map_err(|e| e.to_string())?;
    let goos = match target_os.as_str() {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        other => return Err(format!("unsupported target OS {other}")),
    };
    let goarch = match target_arch.as_str() {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => return Err(format!("unsupported target architecture {other}")),
    };
    let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/alcatraz-helper");
    let status = Command::new("go")
        .current_dir(helper)
        .env("CGO_ENABLED", "0")
        .env("GOOS", goos)
        .env("GOARCH", goarch)
        .args([
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags=-s -w -buildid=",
            "-o",
        ])
        .arg(output)
        .arg(".")
        .status()
        .map_err(|e| format!("could not run Go: {e}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("go build exited with {status}"))
}
