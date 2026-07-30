Pentect is a local, protocol-aware gateway for AI agents. Existing hosts keep
working with plaintext locally; model-bound requests contain reversible handles,
and completed tool-call inputs are resolved on the way back to the local host.

作り途中

TODO
- [ ] codex issue (plugin, mcp, tool output)
- [ ] host prompt secret (patch...?)
- [ ] starter
- [ ] docs site
- [ ] easy install
- [ ] output fil
- [ ] antigravity cli, pico, https://github.com/usestrix/strix
- [ ] codex app / claude appを各リリースで回帰検証する
- [ ] 止めた後になんか重なる

- [ ] pluginsの責務・配布・権限モデルを再考する
- [ ] local llm mask exts
- [ ] app, http host
- [ ] approval ui?
- [ ] ext apikey get
- [ ] orc layer (api, swarm, langchain)
- [ ] ssl inspection
- [ ] full
- [ ] Input, Output Realtime Masking
- [ ] optional Claude Files API content protection

## HTTP integrations

The Codex and Claude launchers no longer replace terminal input, install host
hooks, or rewrite the local UI. The original host keeps its native UI and
history. Pentect masks model-bound requests and resolves opaque handles only
inside completed client tool-call arguments.

```powershell
pentect codex
pentect claude
```

Both commands preserve an existing upstream with `--upstream URL`. Codex uses
the OpenAI Responses API gateway. Claude Code uses the Anthropic Messages API
gateway.

### Desktop apps

Experimental launchers are available for the installed desktop applications:

```powershell
pentect codex-app
pentect claude-app
```

Use `--dry-run` to show the detected executable, `--app PATH` for a
non-standard installation, and `--upstream URL` to preserve a custom upstream.
Fully quit the target app before launching it through Pentect. Pentect never
kills an existing app or edits its configuration.

`pentect claude-app` uses an in-memory CA scoped to the launched Chromium
process; it does not install a certificate or change the system proxy. Chat
completion bodies are rewritten in memory. Signed Claude Code and Cowork
control-plane events are passed through unchanged, while their child Claude
Code processes inherit the Anthropic gateway.

`pentect codex-app` gives the app's bundled Codex process a loopback-only
Responses API gateway through `OPENAI_BASE_URL`. It currently supports the
built-in OpenAI provider only. A custom `model_provider` or an explicit
`openai_base_url` in `~/.codex/config.toml` is reported as unsupported because
the app exposes no safe one-run config override.

Request and response bodies, query strings, cookies, authorization headers,
and secret values are never logged. Local UI text is intentionally unchanged.

Inline base64 images are scanned before model delivery. Text-extractable PDFs
are inspected, but unsupported or unscannable binary content follows the
configured media policy (blocked by default). Provider file IDs and remote
attachment URLs are not fetched by Pentect and therefore follow the same
policy. Files API uploads themselves are passed through unchanged.
