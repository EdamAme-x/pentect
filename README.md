progress: https://github.com/setu1421/SecretBench
memo: ui / approve / shell result / prompt

MVP: secret-aware tool boundary for AI agents.

- Rewrite shell tools to `pentect exec "<command>"` from hooks.
- Mask read/shell output before it returns to the agent.
- Resolve placeholders only inside local tool execution.
- Pass placeholders to child processes as env with `pentect exec --env NAME=<<...>> "<command>"`.
- Block direct AI Read tools; use `pentect exec "<command>"` at the tool boundary.
- Keep `pentect read` as a human masked-preview helper, not the AI path.
- Sessions are directory-local by default via `.pentect-agent/default`.
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
