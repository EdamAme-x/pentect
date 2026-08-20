---
title: Compatibility
description: Clients and API formats tested for this release.
---

Pentect tests its gateways with mock provider servers. Each release also
installs and starts every public client launcher with the release binary. A
daily workflow installs current upstream client versions so compatibility
drift is visible before the next release.

| Client | Test | Protected launch |
| --- | --- | --- |
| Codex CLI `0.148.0` | Real launch on Linux and all installer platforms | `pentect codex` |
| Claude Code `2.1.237` | Real launch on Linux and all installer platforms | `pentect claude` |
| OpenCode `1.18.19` | Real launch on Linux and all installer platforms | `pentect opencode` |
| Pi `0.84.2` | Real launch, npm extension, and provider discovery | `pentect pi` or `@pentect/pi` |
| Antigravity CLI `1.1.16` | Real launch plus Cloud Code protocol tests | `pentect antigravity` |
| Aider `0.86.2` | Real launch and OpenAI-compatible route tests | `pentect aider` |
| Continue CLI `1.5.47` | Real launch and Chat/Edit/Apply route tests | `pentect continue` |
| Cline CLI `3.0.55` | Real launch, isolated provider registry, streaming, and tools | `pentect cline` |
| Roo Code `3.54.0` | Real VS Code extension launch and built-in Roo modes | `pentect roo` |
| Zed `1.16.1` | Real launch and isolated Agent/Inline Assistant settings | `pentect zed` |
| Goose CLI `1.46.0` | Real launch and main/fast/planner model routing | `pentect goose` |
| Junie CLI `26.8.17` (`2777.8`) | Real launch and temporary custom model profile | `pentect junie` |
| Gemini CLI `0.56.0` | Real launch plus native Gemini protocol tests | `pentect gemini` |
| ChatGPT desktop app, Codex mode | Executable launch contract and Responses protocol tests | `pentect codex app` |
| Claude Desktop, supported Chat, attachment, and Code routes | Executable launch contract and protocol tests | `pentect claude app` |

API tests cover text, streaming, completed tool calls, structured data, file
links, broken data, custom gateway paths, and Codex zstd-compressed requests.

## Provider contracts

| Launch | Contract Pentect checks | Notes |
| --- | --- | --- |
| `pentect codex` | OpenAI Responses | Includes streaming events and completed tool calls |
| `pentect claude` | Anthropic Messages | Includes streaming content blocks and tool use |
| `pentect antigravity` | Google Cloud Code | Includes streaming content, function calls, inline data, and telemetry JSON |
| `pentect aider` | OpenAI Chat Completions | Main, weak, and editor model routes use the same local gateway |
| `pentect continue` | OpenAI Chat Completions | Covers only the generated Chat, Edit, and Apply model roles |
| `pentect cline` | OpenAI Chat Completions | Covers the local CLI process; detached Zen sessions are rejected |
| `pentect roo` | OpenAI Chat Completions | Covers Roo built-in modes in the isolated VS Code profile |
| `pentect zed` | OpenAI Chat Completions | Covers Agent, Inline Assistant, and compaction; not edit predictions or external agents |
| `pentect goose` | OpenAI Chat Completions | Covers Goose CLI main, fast, and planner routes; not Goose Desktop |
| `pentect junie` | OpenAI Chat Completions or Responses | Selected with `--api chat` or `--api responses`; not Junie IDE |
| `pentect gemini` | Native Gemini API | Covers Gemini API-key mode; not Google sign-in, Vertex, or Code Assist |
| `pentect codex app` | Responses routes used by supported Codex mode | Other ChatGPT modes are outside this claim |
| `pentect claude app` | Supported Claude Chat, attachment, and Code routes | Cowork and Voice are outside this claim |

“Supported” means Pentect recognizes and checks the route and content shapes
documented here. “Tested” means the release suite exercised them with fake
secrets. It does not mean every provider model, account feature, or future
client build has been tested.

The version numbers are release gates, not strict version locks. A newer client
may work, but a new request or stream shape can be blocked until Pentect learns
it. Run `pentect update --check` after a client update.

## API format adapters

You can use an API adapter when a model provider does not offer OpenAI Responses
or Anthropic Messages. The adapter changes the provider API into a format
Pentect supports. Pentect then checks the normal client-side format.

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

[Bifrost](https://docs.getbifrost.ai/cli-agents/overview) can provide both API
formats. Pentect tests its `/openai/v1` and `/anthropic` paths. LiteLLM and other
gateways can also work when they offer the same APIs. Pentect does not test
every gateway release.

See [Custom upstreams](/clients/upstreams/) for setup and recovery steps.

## Desktop testing

Short-lived CI machines do not sign in to or drive the official desktop user
interfaces. Instead, Windows, Linux, and macOS execute process-contract
fixtures that validate the proxy, certificate, and isolated profile arguments,
while protocol tests exercise the supported routes. Pentect therefore does not
list a desktop app version as fully UI-tested. Tests use fake secrets and check
that local handles are not printed.

| Desktop surface | Current scope |
| --- | --- |
| Codex App | Supported Codex mode using the Responses protocol |
| Claude Desktop | Supported Chat, attachment, and Code routes |
| Other app modes | Not claimed unless listed here |

## Not covered

- ChatGPT Chat, Work, and Voice routes outside supported Codex mode
- Remote Claude Cowork execution and Voice
- Continue autocomplete, embeddings, and reranking
- Cline's VS Code extension and detached `--zen` sessions
- Goose Desktop and Junie IDE
- Zed edit predictions and external agents
- Gemini CLI Google sign-in, Vertex AI, and Code Assist OAuth paths
- Copilot, VS Code inline suggestions, and private traffic from other extensions
- Test binary formats
- Unknown future routes
- Every provider and release behind a third-party gateway

Files referenced only by an unknown remote ID are not treated as inspected
just because the surrounding JSON is valid. See
[Files and images](/protection/files-and-images/) for the exact upload, URL,
image, and PDF boundaries.

Pentect blocks unknown or unsupported content by default. It does not claim to
protect content that it cannot check. If you see this error, first try the
default provider, then
follow the [unknown-format recovery steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked).
