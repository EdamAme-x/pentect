//! Pentect CLI: `mask` and `restore` over stdin/stdout. The recovery map is
//! written to ./.pentect/recovery.json (gitignored).

use pentect_core::{mask, restore, Config, Input, Kind, Recovery};
use std::io::{Read, Write};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("mask") => cmd_mask(&args),
        Some("restore") => cmd_restore(),
        Some("resolve") => {
            eprintln!("resolve: not yet implemented.");
            std::process::exit(2);
        }
        _ => usage(),
    }
}

fn usage() {
    eprintln!(
        "pentect <command>   (stdin -> stdout)\n\
         \n\
         commands:\n\
         \x20 mask [--kind text|json]   mask secrets; writes recovery to .pentect/recovery.json\n\
         \x20 restore                   restore placeholders using .pentect/recovery.json\n\
         \x20 resolve                   (not yet)\n"
    );
}

fn read_stdin() -> String {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).expect("read stdin");
    s
}

fn recovery_path() -> PathBuf {
    PathBuf::from(".pentect").join("recovery.json")
}

fn cmd_mask(args: &[String]) {
    let kind = match arg_value(args, "--kind").as_deref() {
        Some("json") => Kind::Json,
        _ => Kind::Text,
    };
    let data = read_stdin();

    // Fixed dev key for now; a real CSPRNG key + keyfile is an adapter concern.
    eprintln!("[pentect] WARNING: using a fixed insecure dev key (no keyfile yet).");
    let cfg = Config::insecure_testing();
    let result = mask(Input { kind, data }, &cfg);

    let path = recovery_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create .pentect dir");
    }
    let json = serde_json::to_string_pretty(&result.recovery).expect("serialize recovery");
    std::fs::write(&path, json).expect("write recovery map");

    print!("{}", result.masked);
    let _ = std::io::stdout().flush();
    eprintln!(
        "[pentect] masked {} value(s); recovery -> {}",
        result.summary.masked_count,
        path.display()
    );
}

fn cmd_restore() {
    let data = read_stdin();
    let path = recovery_path();
    let rec: Recovery = match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).expect("parse recovery map"),
        Err(_) => {
            eprintln!("[pentect] no recovery map at {} — passing through.", path.display());
            Recovery::default()
        }
    };
    let out = restore(&data, &rec).expect("restore");
    print!("{out}");
    let _ = std::io::stdout().flush();
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}
