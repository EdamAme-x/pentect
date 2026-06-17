progress: https://github.com/setu1421/SecretBench
memo: ui / approve / shell result / prompt

MVP: secret-aware tool boundary for AI agents.

- Rewrite shell tools to `pentect exec "<command>"` from hooks.
- Mask read/shell output before it returns to the agent.
- Resolve placeholders only inside local tool execution.
- Block direct reads of likely secret sources; use `pentect read`.
- Sessions are directory-local by default via `.pentect-agent/default`.
- Prompt/TUI masking and external UI logs are out of scope for this MVP.

- Hooks
  - https://developers.openai.com/codex/hooks
  - https://code.claude.com/docs/ja/hooks
  - https://geminicli.com/docs/hooks/reference

Prompt/TUI masking is TODO.
