progress: https://github.com/setu1421/SecretBench
memo: ui / approve / shell result / prompt

MVP: secret-aware tool boundary for AI agents.

- Rewrite shell tools to `pentect exec "<command>"` from hooks.
- Mask read/shell output before it returns to the agent.
- Do not persist recovery state by default; placeholders are one-way outside the current process.
- Pass literal environment values to child processes with `pentect exec --env NAME=VALUE "<command>"`; stdout/stderr are masked before returning to the agent.
- Stream human terminal output with `pentect exec --live "<command>"`; output is masked line-by-line.
- Gate direct environment-variable reads with `--allow-env NAME` / `--deny-env NAME`.
- Show the terminal approval screen with `pentect approve "<command>"` or gate execution with `pentect exec --approve "<command>"`.
- Block direct AI Read tools; use `pentect exec "<command>"` at the tool boundary.
- Keep `pentect read` as a one-way human masked-preview helper, not the AI path.
- Delete old saved recovery state with `pentect purge`.
- Prompt/TUI masking and external UI logs are out of scope for this MVP.

- Hooks
  - https://developers.openai.com/codex/hooks
  - https://code.claude.com/docs/ja/hooks
  - https://geminicli.com/docs/hooks/reference

Prompt/TUI masking is TODO.

Hostile gap corpus:

```powershell
cargo build -p pentect-cli --release
python tools/eval_hostile_realworld.py --bin target\release\pentect.exe
```

This corpus is intentionally mean: encoded/fractured secrets, low-entropy keyed
values, semantic PII, real-looking logs, and benign near misses. It is for gap
tracking, not a CI pass/fail gate.

For the semantic layer:

```powershell
cargo build -p pentect-cli --release --features semantic
python tools/eval_hostile_realworld.py --bin target\release\pentect.exe --pentect-arg=--semantic
```

Semantic detection is optional and intentionally outside the deterministic core.
It uses the local spaCy sidecar when enabled; keep the AI tool boundary and
reversible masking path as the main Pentect surface.
