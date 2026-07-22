use std::collections::VecDeque;
use std::fmt::Write as _;
use std::path::PathBuf;

struct Pattern {
    prefix: String,
    min_length: usize,
    label: String,
}

#[derive(Clone)]
struct State {
    next: [u16; 128],
    fail: usize,
    output: i16,
}

impl State {
    fn new() -> Self {
        Self {
            next: [0; 128],
            fail: 0,
            output: -1,
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/detect/shell_secret_prefixes.tsv");
    let patterns = include_str!("src/detect/shell_secret_prefixes.tsv")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split('\t');
            let prefix = fields.next().expect("prefix").to_string();
            let min_length = fields
                .next()
                .expect("minimum length")
                .parse::<usize>()
                .expect("minimum length is an integer");
            let label = fields.next().expect("label").to_string();
            assert!(fields.next().is_none(), "unexpected prefix table field");
            assert!(prefix.is_ascii() && min_length >= prefix.len());
            Pattern {
                prefix,
                min_length,
                label,
            }
        })
        .collect::<Vec<_>>();
    let mut states = vec![State::new()];
    for (pattern_index, pattern) in patterns.iter().enumerate() {
        let mut state = 0usize;
        for &byte in pattern.prefix.as_bytes() {
            assert!(byte.is_ascii());
            let next = states[state].next[byte as usize];
            state = if next == 0 {
                let next = states.len();
                assert!(next <= u16::MAX as usize);
                states.push(State::new());
                states[state].next[byte as usize] = next as u16;
                next
            } else {
                next as usize
            };
        }
        states[state].output = pattern_index as i16;
    }

    let mut queue = VecDeque::new();
    for byte in 0..128 {
        let child = states[0].next[byte] as usize;
        if child != 0 {
            queue.push_back(child);
        }
    }
    while let Some(state) = queue.pop_front() {
        for byte in 0..128 {
            let child = states[state].next[byte] as usize;
            if child == 0 {
                let fail = states[state].fail;
                states[state].next[byte] = states[fail].next[byte];
                continue;
            }
            let fail = states[state].fail;
            states[child].fail = states[fail].next[byte] as usize;
            if states[child].output < 0 {
                states[child].output = states[states[child].fail].output;
            }
            queue.push_back(child);
        }
    }

    let mut generated = String::new();
    writeln!(
        generated,
        "pub(super) const SHELL_PREFIX_NEXT: [[u16; 128]; {}] = [",
        states.len()
    )
    .unwrap();
    for state in &states {
        writeln!(generated, "    {:?},", state.next).unwrap();
    }
    writeln!(generated, "];").unwrap();
    writeln!(
        generated,
        "pub(super) const SHELL_PREFIX_OUTPUT: [i16; {}] = {:?};",
        states.len(),
        states.iter().map(|state| state.output).collect::<Vec<_>>()
    )
    .unwrap();
    writeln!(
        generated,
        "pub(super) const SHELL_PREFIX_LENGTHS: [usize; {}] = {:?};",
        patterns.len(),
        patterns
            .iter()
            .map(|pattern| pattern.prefix.len())
            .collect::<Vec<_>>()
    )
    .unwrap();
    writeln!(
        generated,
        "pub(super) const SHELL_PREFIX_MIN_LENGTHS: [usize; {}] = {:?};",
        patterns.len(),
        patterns
            .iter()
            .map(|pattern| pattern.min_length)
            .collect::<Vec<_>>()
    )
    .unwrap();
    writeln!(
        generated,
        "pub(super) const SHELL_PREFIX_LABELS: [&str; {}] = {:?};",
        patterns.len(),
        patterns
            .iter()
            .map(|pattern| pattern.label.as_str())
            .collect::<Vec<_>>()
    )
    .unwrap();

    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    std::fs::write(out.join("shell_prefix_automaton.rs"), generated)
        .expect("write generated shell prefix automaton");
}
