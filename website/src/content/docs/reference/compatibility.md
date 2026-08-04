---
title: Compatibility
description: Release-tested clients, protocols, and explicit coverage limits.
---

Pentect validates its gateways against provider-shaped mock servers. Releases
also launch pinned public CLI builds through the release binary.

| Client | Release gate | Protected launch |
| --- | --- | --- |
| Codex CLI `0.146.0` | Automated on Linux | `pentect codex` |
| Claude Code `2.1.220` | Automated on Linux | `pentect claude` |
| ChatGPT desktop app, Codex mode | Launcher and Responses protocol tests | `pentect codex app` |
| Claude Desktop, supported Chat, attachment, and Code routes | Launcher and protocol tests | `pentect claude app` |

Protocol tests cover text, streaming responses, completed tool calls,
structured content, file references, malformed content, and custom upstream
path preservation.

## API format adapters

Pentect can connect through a protocol adapter when the target model provider
does not expose OpenAI Responses or Anthropic Messages directly. The adapter
converts the API format; Pentect continues to inspect the supported client-side
contract.

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

[Bifrost](https://docs.getbifrost.ai/cli-agents/overview) provides OpenAI and
Anthropic protocol adapters, and Pentect tests its `/openai/v1` and `/anthropic`
path composition. LiteLLM and other gateways can also be used when they expose
the same contracts, but Pentect does not certify each gateway release.

See [Custom upstreams](/clients/upstreams/) for setup and recovery steps.

## Desktop qualification

Ephemeral release runners do not install and drive the signed vendor desktop
apps. Pentect therefore does not describe a desktop app version as fully
release-verified until that automation exists. Windows smoke testing uses
synthetic secrets and verifies launcher, routing, and local-resolution behavior
without printing the value.

## Not covered

- ChatGPT Chat, Work, and Voice routes outside supported Codex mode
- Remote Claude Cowork execution and Voice
- Experimental binary transports
- Unknown future opaque routes
- Every provider and release behind a third-party gateway

Unknown or unsupported content blocks by default rather than silently claiming
protection. If you encounter that error, first retry the default upstream, then
follow the [unknown-format recovery steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked).
