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

## Supported contracts

- OpenAI Responses-compatible upstreams for Codex
- Anthropic Messages-compatible upstreams for Claude
- Existing compatible client provider configuration

Bifrost's `/openai/v1` and `/anthropic` paths are included in Pentect's routing
tests. LiteLLM and other gateways can use the same protocol contracts; Pentect
does not certify every gateway provider or release.

## Unsupported protocols

Pentect rejects an unsupported wire protocol before launching the client. A
provider being OpenAI-like is not sufficient if its request or streaming format
does not match a supported contract. First retry without `--upstream` to confirm
the client works with its default provider. If the custom gateway must be used,
follow the [unknown-format recovery steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
or report its protocol for support.
