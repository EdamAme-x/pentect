---
title: Custom upstreams
description: Use Pentect with another gateway or local model server.
---

Pentect can protect a client and send its requests to another local or remote
gateway.

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
pentect claude --upstream http://127.0.0.1:8080/anthropic
pentect opencode --model anthropic/claude-sonnet --upstream http://127.0.0.1:8080/openai/v1
pentect pi --model anthropic/claude-sonnet --upstream http://127.0.0.1:8080/openai/v1
```

The upstream URL applies to that launch only. Pentect keeps the base path when
it builds provider URLs.

Pentect runs in front of the gateway. It does not include or replace the
gateway. The client connects to Pentect, and Pentect sends the protected
request to the gateway you chose.

The URL may be local or remote. Treat it as a provider endpoint: Pentect sends
the protected request to it, and the client or gateway supplies authentication.
Pentect does not copy credentials from one provider configuration into another.

## Use Bifrost

Bifrost lets one OpenAI- or Anthropic-compatible gateway route requests to
different model providers. Pentect stays in front of it and protects the
request before Bifrost receives it.

Start a local Bifrost gateway and configure at least one provider:

```sh
npx -y @maximhq/bifrost
```

The default gateway URL is `http://127.0.0.1:8080`. Use the exact model ID
configured in Bifrost, normally in `provider/model` form.

::: code-group

```sh [Codex]
pentect codex --upstream http://127.0.0.1:8080/openai/v1 \
  --model anthropic/claude-sonnet-4-5-20250929
```

```sh [Claude]
pentect claude --upstream http://127.0.0.1:8080/anthropic \
  --model openai/gpt-5
```

```sh [OpenCode]
pentect opencode --upstream http://127.0.0.1:8080/openai/v1 \
  --model anthropic/claude-sonnet-4-5-20250929
```

```sh [Pi]
pentect pi --upstream http://127.0.0.1:8080/openai/v1 \
  --model anthropic/claude-sonnet-4-5-20250929
```

:::

If Bifrost virtual-key authentication is enabled, give Pentect the complete
authorization value before launching the client:

::: code-group

```powershell [PowerShell]
$env:PENTECT_UPSTREAM_AUTHORIZATION = "Bearer bf-your-virtual-key"
```

```sh [Shell]
export PENTECT_UPSTREAM_AUTHORIZATION="Bearer bf-your-virtual-key"
```

:::

Do not put a real virtual key in a project file or command history. Bifrost's
dashboard and request logs remain available at `http://127.0.0.1:8080` and
`http://127.0.0.1:8080/logs`. See the
[Bifrost agent guide](https://docs.getbifrost.ai/cli-agents/overview) for
provider setup, virtual keys, and model IDs.

## Supported API formats

- Gateways that support OpenAI Responses for Codex
- Gateways that support Anthropic Messages for Claude
- Gateways that support OpenAI Chat Completions or Responses for OpenCode and Pi
- Existing compatible client provider configuration

Pentect tests Bifrost's `/openai/v1` and `/anthropic` paths. LiteLLM and other
gateways can also work when they support the same APIs. Pentect does not test
every gateway version.

OpenCode and Pi can use a Chat Completions server directly. Codex still needs
Responses, and Claude still needs Messages. Use a gateway when the server does
not provide the format required by the selected client. Pentect does not
translate arbitrary provider APIs itself.

## Base paths and authentication

Pass the base URL for the provider API, not a URL for one model. For example,
Pentect keeps `http://127.0.0.1:8080/openai/v1` when it builds a Responses API
URL. The client or gateway still sends the login data.

| Client | Required API format | Example base path |
| --- | --- | --- |
| Codex | OpenAI Responses, including streaming events | `/openai/v1` |
| Claude | Anthropic Messages, including streaming events | `/anthropic` |
| OpenCode | OpenAI Chat Completions by default; Responses with `--api responses` | `/openai/v1` |
| Pi | OpenAI Chat Completions by default; Responses with `--api responses` | `/openai/v1` |

## Validate a gateway

1. Check that the client works with its normal provider.
2. Check that the gateway works with the same client and model.
3. Start the client with `--upstream` and a safe test prompt.
4. Run `pentect log` and test with a fake secret.
5. Test streaming and one completed tool call, not only normal chat.
6. Test one attachment if your workflow sends files or images.

An OpenAI-compatible Chat Completions API is not always a Responses API. A
gateway may also accept Messages JSON but return a different stream format.

Do not treat a successful plain-text prompt as full compatibility. Tool calls,
stream events, file references, and errors use additional structures that
Pentect must understand.

## Unsupported protocols

Pentect rejects an unsupported API format before it starts the client. An API
that looks similar to OpenAI is not enough. Its requests and stream events must
match a supported API. First try again without `--upstream`. If you still need
the custom gateway, follow the [unknown-format steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
or ask us to support its API format.
