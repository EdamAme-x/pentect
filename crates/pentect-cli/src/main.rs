//! Pentect CLI: mask secrets from stdin to stdout. One-way for now; nothing is
//! written to disk.

use pentect_core::{load_pack, Config, Engine, Input, Kind, Pack, Profile, RuleDetector};
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
        "pentect mask [--kind text|json|env|har] [--profile strict|balanced|dev|paranoid] [--length] [--aggressive] [--pack FILE]... [--disable LABEL]...\n\
         \x20 mask secrets from stdin to stdout\n\
         \x20 --pack FILE      load extra rules from a TOML pack (repeatable)\n\
         \x20 --disable LABEL  turn off a built-in detector by label (repeatable)\n\
         \x20 --enable LABEL   turn on an off-by-default built-in (e.g. DATE_TIME)\n\
         \x20 --ner            also mask person/location/org via the NER sidecar (needs --features ner)"
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
        Some("har") => Kind::Har,
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
    let packs = match load_packs(args) {
        Ok(p) => p,
        Err(e) => die(&e),
    };
    let data = match read_stdin_capped() {
        Ok(s) => s,
        Err(e) => die(&e),
    };

    // Fresh per-run key: mask-only, so the recovery map is not retained and a
    // reproducible key isn't needed (restore is unavailable by design).
    let kind_label = format!("{kind:?}");
    let engine = build_engine(profile, aggressive, packs, args);
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

/// `--aggressive` disables the benign-shape guard, so even UUIDs/hashes get
/// masked. Output is then mostly unusable for reasoning, but still reversible.
fn build_engine(profile: Profile, aggressive: bool, packs: Vec<Pack>, args: &[String]) -> Engine {
    if aggressive {
        eprintln!("[pentect] WARNING: --aggressive disables benign-shape guards; output likely unusable for reasoning.");
    }
    Engine::with_profile_packs_detectors(profile, packs, ner_detectors(args), aggressive)
}

/// `--ner` adds the semantic NER sidecar (person/location/org/nationality).
/// Built only with `--features ner`; the script defaults to PENTECT_NER_SCRIPT
/// or tools/ner_sidecar.py.
#[cfg(feature = "ner")]
fn ner_detectors(args: &[String]) -> Vec<Box<dyn pentect_core::Detector>> {
    if !has_flag(args, "--ner") {
        return Vec::new();
    }
    let script =
        std::env::var("PENTECT_NER_SCRIPT").unwrap_or_else(|_| "tools/ner_sidecar.py".into());
    match pentect_core::NerDetector::spawn(&script) {
        Ok(d) => vec![Box::new(d)],
        Err(e) => {
            eprintln!(
                "[pentect] --ner: could not start NER sidecar ({e}); continuing without NER."
            );
            Vec::new()
        }
    }
}

#[cfg(not(feature = "ner"))]
fn ner_detectors(args: &[String]) -> Vec<Box<dyn pentect_core::Detector>> {
    if has_flag(args, "--ner") {
        eprintln!("[pentect] --ner requires a build with `--features ner`; ignoring.");
    }
    Vec::new()
}

/// Load each `--pack FILE` as a TOML rule pack. Reading a config file is input,
/// not secret persistence. Errors are reported with the file name so a pack
/// author can see exactly what to fix.
fn load_packs(args: &[String]) -> Result<Vec<Pack>, String> {
    let mut packs = Vec::new();
    for path in arg_values(args, "--pack") {
        let src = std::fs::read_to_string(&path)
            .map_err(|e| format!("could not read pack '{path}': {e}"))?;
        let pack = load_pack(&src).map_err(|e| format!("pack '{path}' is invalid: {e}"))?;
        packs.push(pack);
    }
    // --disable / --enable are a pack with no rules, only toggles.
    let disable = arg_values(args, "--disable");
    let enable = arg_values(args, "--enable");
    if !disable.is_empty() || !enable.is_empty() {
        packs.push(Pack {
            rules: RuleDetector::from_specs(Vec::new())?,
            disable,
            enable,
        });
    }
    Ok(packs)
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// All values following each occurrence of `flag` (so `--pack` can repeat).
fn arg_values(args: &[String], flag: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| a.as_str() == flag)
        .filter_map(|(i, _)| args.get(i + 1).cloned())
        .collect()
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
