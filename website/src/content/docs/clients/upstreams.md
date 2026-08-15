---
title: Custom upstreams
description: Use Pentect with another gateway or local model server.
---

Put Pentect in front of a local model server or an existing gateway. The
gateway stays in charge of models, provider credentials, routing, and usage
limits.

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
pentect claude --upstream http://127.0.0.1:8080/anthropic
pentect opencode --model anthropic/claude-sonnet --upstream http://127.0.0.1:8080/openai/v1
pentect pi --model anthropic/claude-sonnet --upstream http://127.0.0.1:8080/openai/v1
pentect goose --model anthropic/claude-sonnet --upstream http://127.0.0.1:8080/openai/v1
pentect junie --model anthropic/claude-sonnet --upstream http://127.0.0.1:8080/openai/v1
pentect antigravity --upstream https://cloud-code.example
pentect gemini --upstream https://generativelanguage.googleapis.com
```

The URL applies to one launch. Pentect keeps its base path, masks the request,
and then sends it to that gateway.

You do not need a custom upstream for normal use. Each protected client route
keeps its usual provider authentication when `--upstream` is not supplied.
Gemini CLI must use its Gemini API-key mode; Google sign-in, Vertex AI, and
Code Assist use different routes and are not covered.

## Use Bifrost

Bifrost lets one OpenAI- or Anthropic-compatible gateway route requests to
different model providers. Pentect stays in front of it and protects the
request before Bifrost receives it.

Start Bifrost and configure at least one provider:

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

### Virtual keys

Keep the key in an environment variable and tell Pentect which request header
should receive it. Only the environment-variable name appears in the command.
Pentect removes that variable from the launched AI client.

::: code-group

```powershell [PowerShell]
$secret = Read-Host "Bifrost virtual key" -AsSecureString
$env:BIFROST_API_KEY = [Net.NetworkCredential]::new('', $secret).Password
pentect codex --upstream http://127.0.0.1:8080/openai/v1 `
  --upstream-header-env x-bf-vk=BIFROST_API_KEY
```

```sh [Shell]
read -rsp "Bifrost virtual key: " BIFROST_API_KEY && echo
export BIFROST_API_KEY
pentect codex --upstream http://127.0.0.1:8080/openai/v1 \
  --upstream-header-env x-bf-vk=BIFROST_API_KEY
```

:::

`x-bf-vk` is Bifrost's dedicated virtual-key header. You can repeat
`--upstream-header-env HEADER=ENV_NAME` when another gateway needs more than
one header. Pentect replaces matching client headers and does not forward the
client's original provider credential when a custom upstream credential is
configured.

Do not put a real key in a project file or command argument. Bifrost's dashboard
and request logs remain available at `http://127.0.0.1:8080` and
`http://127.0.0.1:8080/logs`. See the
[Bifrost agent guide](https://docs.getbifrost.ai/cli-agents/overview) for
provider setup, virtual keys, and model IDs.

## Antigravity and Cloud Code

Normal Antigravity use needs no endpoint setting:

```sh
pentect antigravity
```

If Antigravity already uses a compatible `CLOUD_CODE_URL`, Pentect keeps that
endpoint behind its local gateway. You can override it for one launch with
`--upstream`. This is for existing Cloud Code gateways, not normal Google
sign-in.

Add a custom gateway credential without placing its value in command history:

::: code-group

```powershell [PowerShell]
$secret = Read-Host "Gateway token" -AsSecureString
$env:PENTECT_GATEWAY_AUTH = [Net.NetworkCredential]::new('', $secret).Password
pentect antigravity --upstream https://cloud-code.example `
  --upstream-header-env Authorization=PENTECT_GATEWAY_AUTH
```

```sh [Shell]
read -rsp "Gateway token: " PENTECT_GATEWAY_AUTH && echo
export PENTECT_GATEWAY_AUTH
pentect antigravity --upstream https://cloud-code.example \
  --upstream-header-env Authorization=PENTECT_GATEWAY_AUTH
```

:::

Pentect reads the credential, removes the source variable from `agy`, and adds
the header only when contacting that upstream.

## Existing endpoint settings

Pentect also respects the documented endpoint variable for each supported
client. Examples include `OPENAI_BASE_URL`, `CLOUD_CODE_URL`, and
`GOOGLE_GEMINI_BASE_URL`. You normally do not set them for Pentect. Use
`--upstream` when you want an explicit one-launch override.

## Supported API formats

- Gateways that support OpenAI Responses for Codex
- Gateways that support Anthropic Messages for Claude
- Gateways that support OpenAI Chat Completions or Responses for OpenCode and Pi
- OpenAI-compatible routes used by Continue, Cline, Roo Code, Zed, Goose CLI,
  and Junie CLI
- Native Gemini API routes used by Gemini CLI
- Existing compatible client provider configuration

Pentect tests Bifrost's `/openai/v1` and `/anthropic` paths. LiteLLM and other
gateways can also work when they support the same APIs. Pentect does not test
every gateway version.

OpenCode and Pi can use a Chat Completions server directly. Codex still needs
Responses, and Claude still needs Messages. Use a gateway when the server does
not provide the format required by the selected client. Pentect does not
translate arbitrary provider APIs itself.

## Base paths

Pass the base URL for the provider API, not a URL for one model. For example,
Pentect keeps `http://127.0.0.1:8080/openai/v1` when it builds a Responses API
URL.

| Client | Required API format | Example base path |
| --- | --- | --- |
| Codex | OpenAI Responses, including streaming events | `/openai/v1` |
| Claude | Anthropic Messages, including streaming events | `/anthropic` |
| OpenCode | OpenAI Chat Completions by default; Responses with `--api responses` | `/openai/v1` |
| Pi | OpenAI Chat Completions by default; Responses with `--api responses` | `/openai/v1` |
| Continue, Cline, Roo Code, Zed, Goose | OpenAI Chat Completions | `/openai/v1` |
| Junie | OpenAI Chat Completions by default; Responses with `--api responses` | `/openai/v1` |
| Gemini CLI | Native Gemini `generateContent` API | `/` before `/v1beta/models/...` |

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
