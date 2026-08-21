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
| Codex CLI `0.149.0` | Real launch on Linux and all installer platforms | `pentect codex` |
| Claude Code `2.1.238` | Real launch on Linux and all installer platforms | `pentect claude` |
| OpenCode `1.18.20` | Real launch on Linux and all installer platforms | `pentect opencode` |
| Pi `0.84.2` | Real launch, npm extension, and provider discovery | `pentect pi` or `@pentect/pi` |
| ChatGPT desktop app, Codex mode | Executable launch contract and Responses protocol tests | `pentect codex app` |
| Claude Desktop, supported Chat, attachment, and Code routes | Executable launch contract and protocol tests | `pentect claude app` |

## Not implemented

These clients have status pages, but no public launcher in the current
release. The proposed commands return an unknown-command error. Starting the
client normally does not route it through Pentect and provides no Pentect
protection.

| Client | Status page |
| --- | --- |
| Antigravity CLI | [Not implemented](/clients/antigravity/) |
| Aider | [Not implemented](/clients/aider/) |
| Continue CLI | [Not implemented](/clients/continue/) |
| Cline CLI | [Not implemented](/clients/cline/) |
| Roo Code | [Not implemented](/clients/roo-code/) |
| Zed | [Not implemented](/clients/zed/) |
| Goose CLI | [Not implemented](/clients/goose/) |
| Junie CLI | [Not implemented](/clients/junie/) |
| Gemini CLI | [Not implemented](/clients/gemini/) |

API tests cover text, streaming, completed tool calls, structured data, file
links, broken data, custom gateway paths, and Codex zstd-compressed requests.

## Provider contracts

| Launch | Contract Pentect checks | Notes |
| --- | --- | --- |
| `pentect codex` | OpenAI Responses | Includes streaming events and completed tool calls |
| `pentect claude` | Anthropic Messages | Includes streaming content blocks and tool use |
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
