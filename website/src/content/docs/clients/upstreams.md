---
title: Custom upstreams
description: Route supported OpenAI Responses and Anthropic Messages traffic through another gateway.
---

Pentect can protect a client while forwarding requests to an existing local or
remote gateway.

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

The upstream URL is selected for that launch only. Pentect preserves its base
path when composing provider endpoints.

Pentect sits in front of the gateway; it does not embed or replace it. The
client connects to Pentect locally, and Pentect forwards the transformed
provider request to the upstream you selected.

## Supported contracts

- OpenAI Responses-compatible upstreams for Codex
- Anthropic Messages-compatible upstreams for Claude
- Existing compatible client provider configuration

Bifrost's `/openai/v1` and `/anthropic` paths are included in Pentect's routing
tests. LiteLLM and other gateways can use the same protocol contracts; Pentect
does not certify every gateway provider or release.

## Base paths and authentication

Pass the provider-compatible base URL, not a single model endpoint. For example,
`http://127.0.0.1:8080/openai/v1` remains the base when Pentect composes a
Responses route. Authentication headers and provider credentials continue to
come from the client or gateway configuration.

| Client | Required upstream contract | Example base path |
| --- | --- | --- |
| Codex | OpenAI Responses, including streaming events | `/openai/v1` |
| Claude | Anthropic Messages, including streaming events | `/anthropic` |

## Validate a gateway

1. Confirm the client works with its default provider.
2. Confirm the gateway works directly with the same client and model.
3. Launch once with `--upstream` and a non-sensitive prompt.
4. Run `pentect log` while testing a disposable value.
5. Exercise streaming and one completed tool call—not only plain chat text.

An OpenAI-compatible chat-completions endpoint is not automatically a
Responses endpoint. Likewise, a gateway can accept Messages JSON while emitting
incompatible stream events.

## Unsupported protocols

Pentect rejects an unsupported wire protocol before launching the client. A
provider being OpenAI-like is not sufficient if its request or streaming format
does not match a supported contract. First retry without `--upstream` to confirm
the client works with its default provider. If the custom gateway must be used,
follow the [unknown-format recovery steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
or report its protocol for support.
