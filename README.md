progress: https://github.com/setu1421/SecretBench
memo: ui / approve / shell result / prompt

MVP: secret-aware tool boundary for AI agents.

- Rewrite shell tools to `pentect exec "<command>"` from hooks.
- Mask read/shell/MCP-like tool output before it returns to the agent.
- Keep `pentect exec` output clean: normal stdout/stderr, with secrets masked.
- Inject a model-visible agent contract invisibly for supported agents: Codex uses temporary `developer_instructions`, Claude uses `--append-system-prompt`.
- Do not print wrapper hints during normal agent startup; explicit `pentect help` is for humans.
- Canonicalize nested wrappers so `pentect exec "pentect exec ..."` becomes one protected boundary, while `pentect read` remains blocked from AI hooks.
- Plain `mask` / `read` stay one-way. `exec` and agent hooks use a local per-directory capability vault so masked handles can be used without showing plaintext to the AI.
- Every masked handle becomes a normal env var inside later shell commands: `<<LABEL_hash>>` is available as `$env:PENTECT_LABEL_hash` on PowerShell or `$PENTECT_LABEL_hash` on Unix. If the output was `KEY=<<...>>`, `KEY` is also available.
- Printing masked output through `pentect exec` registers capabilities. For `.env`, a normal read command is clearest, and source/export commands also register as hints without exposing plaintext.
- Shell state does not carry between tool calls. If a command sources or exports a `.env` file, Pentect treats that as a registration hint and exposes the resulting capabilities in later `pentect exec` calls.
- `pentect resolve <path>` is only for the file-materialization case; the agent path should prefer env vars inside `pentect exec`.
- Large opaque masked values carry readable coarse metadata such as `_length_at_least_512_chars`; exact length is not disclosed.
- Resolve known handles into `.env` writes: when a Write-like tool tries to write `KEY=<<HANDLE>>`, Pentect writes the resolved local `.env` itself and blocks the original Write tool so plaintext is not returned in hook JSON.
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
