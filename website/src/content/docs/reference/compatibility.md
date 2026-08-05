---
title: Compatibility
description: Clients and API formats tested for this release.
---

Pentect tests its gateways with mock provider servers. Each release also starts
specific public CLI versions with the release binary.

| Client | Test | Protected launch |
| --- | --- | --- |
| Codex CLI `0.146.0` | Automatic test on Linux | `pentect codex` |
| Claude Code `2.1.220` | Automatic test on Linux | `pentect claude` |
| ChatGPT desktop app, Codex mode | Launcher and Responses protocol tests | `pentect codex app` |
| Claude Desktop, supported Chat, attachment, and Code routes | Launcher and protocol tests | `pentect claude app` |

API tests cover text, streaming, completed tool calls, structured data, file
links, broken data, and custom gateway paths.

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

Short-lived CI machines do not install and control the official desktop apps.
Because of this, Pentect does not list any desktop version as fully tested.
Windows tests use fake secrets. They test app launch, routing, and local handle
use without printing the value.

| Desktop surface | Current scope |
| --- | --- |
| Codex App | Supported Codex mode using the Responses protocol |
| Claude Desktop | Supported Chat, attachment, and Code routes |
| Other app modes | Not claimed unless listed here |

## Not covered

- ChatGPT Chat, Work, and Voice routes outside supported Codex mode
- Remote Claude Cowork execution and Voice
- Test binary formats
- Unknown future routes
- Every provider and release behind a third-party gateway

Pentect blocks unknown or unsupported content by default. It does not claim to
protect content that it cannot check. If you see this error, first try the
default provider, then
follow the [unknown-format recovery steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked).
