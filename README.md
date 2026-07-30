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
- [ ] output file
- [ ] antigravity cli, pico, https://github.com/usestrix/strix
- [ ] codex app / claude appを各リリースで回帰検証する
- [ ] PDF・画像・Officeをマスク済みバイナリとして安全に再生成する
- [ ] 前セッションのAnthropic file IDを安全に扱う再アップロード導線
- [x] `pentect codex app`異常終了時のconfig復元
- [ ] OpenAI/Anthropic実providerを使ったFiles・URL・AppのライブE2E
- [ ] HTTPファイル検査の上限をstreaming spoolで512MB級まで拡張する
- [ ] 止めた後になんか重なる

- [x] pluginsの責務・配布・権限モデルを再設計する
- [ ] plugin registry・署名付きpublisher identity・OS sandboxを検討する
- [ ] local llm mask exts
- [ ] app, http host
- [ ] approval ui?
- [ ] ext apikey get
- [ ] orc layer (api, swarm, langchain)
- [ ] ssl inspection
- [ ] full
- [ ] Input, Output Realtime Masking
- [ ] binary Files API rewriting (PDF/image/Office)

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

## Plugins

Plugins can be manifest-only regex detectors or approved executable middleware
written in any language. Executable plugins use a persistent NDJSON stdio
protocol, preserve declared order, and return `next` or `stop`; Pentect keeps
control of the chain and the final masking pass. See
[the plugin guide](guides/plugins.md), [protocol fixtures](protocol/fixtures),
and the lightweight [Rust, Python, TypeScript, and Go SDKs](sdk).

### Desktop apps

Experimental launchers are available for the installed desktop applications:

```powershell
pentect codex app
pentect claude-app
```

`pentect codex-app` remains available as a compatibility alias.

Use `--dry-run` to show the detected executable, `--app PATH` for a
non-standard installation, and `--upstream URL` to preserve a custom upstream.
Fully quit the target app before launching it through Pentect. Pentect never
kills an existing app.

`pentect claude-app` uses an in-memory CA scoped to the launched Chromium
process; it does not install a certificate or change the system proxy. Chat
completion bodies are rewritten in memory. Signed Claude Code and Cowork
control-plane events are passed through unchanged, while their child Claude
Code processes inherit the Anthropic gateway.

`pentect codex app` gives the app's bundled Codex process a loopback-only
Responses API gateway. The built-in provider uses `OPENAI_BASE_URL`. A custom
Responses-compatible `model_provider`, or an explicit `openai_base_url`, gets
a recoverable base-URL override while the App is running; the original
`~/.codex/config.toml` is backed up and restored when the App exits. An
interrupted override is recovered on the next launch. Providers using another
`wire_api` are reported as unsupported.

Request and response bodies, query strings, cookies, authorization headers,
and secret values are never logged. Local UI text is intentionally unchanged.

Inline base64 images are scanned before model delivery. Text-extractable PDFs
are inspected, but unsupported or unscannable binary content follows the
configured media policy (blocked by default). OpenAI and Anthropic Files API
uploads rewrite supported UTF-8 text formats before forwarding and record the
returned file ID. A recorded, fully inspected file ID can be used in later
model requests. Binary uploads are marked as partial coverage and remain
subject to the media policy. Existing OpenAI file IDs used as Responses
`input_file` blocks are downloaded and inspected before model use. Anthropic
uploads that predate the current gateway session cannot generally be
downloaded and must be uploaded again through Pentect.

HTTPS attachment URLs are fetched by Pentect before model delivery and
converted to inspected inline content. Retrieval rejects credentials,
fragments, private/link-local addresses, DNS results containing a non-public
address, excessive redirects, and responses over the configured inspection
budget. Every gateway response reports `X-Pentect-Coverage` as `full`,
`partial`, or `none`; compatible pass-through remains explicit instead of
being presented as complete protection.
