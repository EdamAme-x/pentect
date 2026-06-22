progress: https://github.com/setu1421/SecretBench
memo: ui / approve / shell result / prompt

MVP: secret-aware tool boundary for AI agents.

- Rewrite shell tools to `pentect exec "<command>"` from hooks.
- Mask read/shell/MCP-like tool output before it returns to the agent.
- Keep `pentect exec` output clean: normal stdout/stderr, with secrets masked.
- Put the short agent contract in explicit `pentect help`; do not print wrapper hints during normal agent startup.
- Future discoverability should live in agent-native skills/plugins, not terminal output.
- Plain `mask` / `read` stay one-way. `exec` and agent hooks use a local per-directory capability vault so masked handles can be reused without showing plaintext to the AI.
- Masked env values become normal env vars inside later `pentect exec` commands; the agent can use `$env:KEY` on PowerShell or `$KEY` on Unix while stdout/stderr are masked before returning.
- Large opaque masked values carry readable coarse metadata such as `_length_at_least_512_chars`; exact length is not disclosed.
- Materialize known handles into `.env` writes: when a Write-like tool tries to write `KEY=<<HANDLE>>`, Pentect writes the resolved local `.env` itself and blocks the original Write tool so plaintext is not returned in hook JSON.
- Stream human terminal output with `pentect exec --live "<command>"`; output is masked line-by-line.
- Block direct environment-variable reads unless the value was auto-bound from prior masked output.
- Open the terminal control screen with `pentect`; inspect another scope with `pentect dashboard --dir PATH --session NAME`.
- Show the command approval screen with `pentect approve "<command>"` or gate execution with `pentect exec --approve "<command>"`.
- Block direct AI Read tools; use `pentect exec "<command>"` at the tool boundary.
- Keep `pentect read` as a one-way human masked-preview helper, not the AI path.
- Delete local capability state with `pentect purge`.
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
