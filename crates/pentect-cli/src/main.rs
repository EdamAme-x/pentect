//! Pentect CLI: mask secrets from stdin to stdout. One-way for now; nothing is
//! written to disk.

use pentect_core::{
    Config, Engine, EntropyDetector, Input, Kind, NoGuard, Profile, ProfilePolicy,
    RuleDetector, SuspiciousKeyDetector, DecodeDetector, JsonParser,
};
use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("mask") => cmd_mask(&args),
        _ => usage(),
    }
}

fn usage() {
    eprintln!(
        "pentect mask [--kind text|json] [--profile strict|balanced|dev|paranoid] [--length] [--aggressive]\n\
         \x20 mask secrets from stdin to stdout"
    );
}

fn read_stdin() -> String {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).expect("read stdin");
    s
}

fn cmd_mask(args: &[String]) {
    let kind = match arg_value(args, "--kind").as_deref() {
        Some("json") => Kind::Json,
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
    let data = read_stdin();

    // Fixed dev key for now; a real CSPRNG key + keyfile is an adapter concern.
    eprintln!("[pentect] WARNING: using a fixed insecure dev key (no keyfile yet).");
    let engine = build_engine(profile, aggressive);
    let cfg = Config { disclose_length, ..Config::insecure_testing() };
    let result = engine.mask(Input { kind, data }, &cfg);

    print!("{}", result.masked);
    let _ = std::io::stdout().flush();
    eprintln!(
        "[pentect] profile={profile:?} masked {} value(s), {} warned.",
        result.summary.masked_count,
        result.summary.residual.len()
    );
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
        .detector(Box::new(EntropyDetector::with(k.entropy_min_len, k.entropy_threshold)))
        .detector(Box::new(DecodeDetector::builtin().with_opaque(k.mask_unknown_codec, k.min_opaque_run)))
        .detector(Box::new(SuspiciousKeyDetector))
        .policy(Box::new(ProfilePolicy::new(profile)))
        .guard(Box::new(NoGuard))
        .build()
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}
