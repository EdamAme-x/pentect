//! Pentect CLI: mask secrets from stdin to stdout. One-way for now; nothing is
//! written to disk.

use pentect_core::{mask, Config, Input, Kind};
use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("mask") => cmd_mask(&args),
        _ => usage(),
    }
}

fn usage() {
    eprintln!("pentect mask [--kind text|json]   mask secrets from stdin to stdout");
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
    let data = read_stdin();

    // Fixed dev key for now; a real CSPRNG key + keyfile is an adapter concern.
    eprintln!("[pentect] WARNING: using a fixed insecure dev key (no keyfile yet).");
    let result = mask(Input { kind, data }, &Config::insecure_testing());

    print!("{}", result.masked);
    let _ = std::io::stdout().flush();
    eprintln!("[pentect] masked {} value(s).", result.summary.masked_count);
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}
