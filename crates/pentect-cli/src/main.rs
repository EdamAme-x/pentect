//! Pentect CLI: mask secrets from stdin to stdout. One-way for now; nothing is
//! written to disk.

use pentect_core::{
    Config, DecodeDetector, Engine, EntropyDetector, Input, JsonParser, Kind, NoGuard, Profile,
    ProfilePolicy, RuleDetector, SuspiciousKeyDetector,
};
use std::io::{Read, Write};

/// Refuse oversized input rather than emit partially-masked output (a masked
/// head plus a raw tail would leak the tail).
const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("mask") => cmd_mask(&args),
        _ => usage(),
    }
}

fn usage() {
    eprintln!(
        "pentect mask [--kind text|json|env] [--profile strict|balanced|dev|paranoid] [--length] [--aggressive]\n\
         \x20 mask secrets from stdin to stdout"
    );
}

fn die(msg: &str) -> ! {
    eprintln!("[pentect] {msg}");
    std::process::exit(2);
}

/// Read stdin as bytes (no panic on binary), cap the size, and require UTF-8.
fn read_stdin_capped() -> Result<String, String> {
    let mut buf = Vec::new();
    std::io::stdin()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("could not read stdin: {e}"))?;
    if buf.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "input exceeds {MAX_INPUT_BYTES} bytes; refusing to mask partially"
        ));
    }
    String::from_utf8(buf).map_err(|_| "input is not UTF-8 text (binary not supported)".to_string())
}

fn cmd_mask(args: &[String]) {
    let kind = match arg_value(args, "--kind").as_deref() {
        Some("json") => Kind::Json,
        Some("env") => Kind::Env,
        _ => Kind::Text,
    };
    let profile: Profile = match arg_value(args, "--profile").as_deref() {
        Some(name) => match name.parse() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[pentect] {e}");
                std::process::exit(2);
            }
        },
        None => Profile::Balanced,
    };
    let disclose_length = has_flag(args, "--length");
    let aggressive = has_flag(args, "--aggressive");
    let data = match read_stdin_capped() {
        Ok(s) => s,
        Err(e) => die(&e),
    };

    // Fresh per-run key: mask-only, so the recovery map is not retained and a
    // reproducible key isn't needed (restore is unavailable by design).
    let kind_label = format!("{kind:?}");
    let engine = build_engine(profile, aggressive);
    let cfg = Config {
        disclose_length,
        ..Config::generate()
    };
    let result = engine.mask(Input { kind, data }, &cfg);

    print!("{}", result.masked);
    let _ = std::io::stdout().flush();
    eprintln!(
        "[pentect] profile={profile:?} masked {} value(s), {} warned.",
        result.summary.masked_count,
        result.summary.residual.len()
    );
    if result.summary.parser_fallback {
        eprintln!("[pentect] note: --kind {kind_label} failed to parse; masked as plaintext (key context lost, structure not guaranteed).");
    }
    if !result.summary.collisions.is_empty() {
        eprintln!(
            "[pentect] WARNING: {} placeholder collision(s) — restore may be wrong for the colliding value(s).",
            result.summary.collisions.len()
        );
    }
}

/// `--aggressive` swaps the benign-shape guard for one that spares nothing, so
/// even UUIDs/hashes get masked. Output is then mostly unusable for reasoning.
fn build_engine(profile: Profile, aggressive: bool) -> Engine {
    if !aggressive {
        return Engine::with_profile(profile);
    }
    eprintln!("[pentect] WARNING: --aggressive disables benign-shape guards; output likely unusable for reasoning.");
    let k = profile.knobs();
    Engine::builder()
        .parser(Kind::Json, Box::new(JsonParser))
        .detector(Box::new(RuleDetector::builtin()))
        .detector(Box::new(EntropyDetector::with(
            k.entropy_min_len,
            k.entropy_threshold,
        )))
        .detector(Box::new(
            DecodeDetector::builtin().with_opaque(k.mask_unknown_codec, k.min_opaque_run),
        ))
        .detector(Box::new(SuspiciousKeyDetector))
        .policy(Box::new(ProfilePolicy::new(profile)))
        .guard(Box::new(NoGuard))
        .build()
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
