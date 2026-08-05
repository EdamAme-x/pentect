---
title: Custom upstreams
description: Use Pentect with another gateway or local model server.
---

Pentect can protect a client and send its requests to another local or remote
gateway.

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

The upstream URL applies to that launch only. Pentect keeps the base path when
it builds provider URLs.

Pentect runs in front of the gateway. It does not include or replace the
gateway. The client connects to Pentect, and Pentect sends the protected
request to the gateway you chose.

## Supported API formats

- Gateways that support OpenAI Responses for Codex
- Gateways that support Anthropic Messages for Claude
- Existing compatible client provider configuration

Pentect tests Bifrost's `/openai/v1` and `/anthropic` paths. LiteLLM and other
gateways can also work when they support the same APIs. Pentect does not test
every gateway version.

## Base paths and authentication

Pass the base URL for the provider API, not a URL for one model. For example,
Pentect keeps `http://127.0.0.1:8080/openai/v1` when it builds a Responses API
URL. The client or gateway still sends the login data.

| Client | Required API format | Example base path |
| --- | --- | --- |
| Codex | OpenAI Responses, including streaming events | `/openai/v1` |
| Claude | Anthropic Messages, including streaming events | `/anthropic` |

## Validate a gateway

1. Check that the client works with its normal provider.
2. Check that the gateway works with the same client and model.
3. Start the client with `--upstream` and a safe test prompt.
4. Run `pentect log` and test with a fake secret.
5. Test streaming and one completed tool call, not only normal chat.

An OpenAI-compatible Chat Completions API is not always a Responses API. A
gateway may also accept Messages JSON but return a different stream format.

## Unsupported protocols

Pentect rejects an unsupported API format before it starts the client. An API
that looks similar to OpenAI is not enough. Its requests and stream events must
match a supported API. First try again without `--upstream`. If you still need
the custom gateway, follow the [unknown-format steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
or ask us to support its API format.
