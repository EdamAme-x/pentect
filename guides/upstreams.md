# Custom and local upstreams

Pentect protects the model protocol and leaves provider selection and protocol
translation to an upstream gateway. It supports two upstream contracts:

- OpenAI Responses API for Codex and Codex App
- Anthropic Messages API for Claude Code and Claude App

Pass a compatible base URL without changing the application's permanent
configuration:

```text
pentect codex --upstream http://127.0.0.1:8080/openai/v1
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

Paths already present in the base URL are preserved. The examples above match
Bifrost's OpenAI- and Anthropic-compatible integrations. Bifrost can then route
to hosted providers or local Ollama and vLLM installations. LiteLLM and other
gateways work when they expose the same protocol contracts.

Pentect does not install, embed, configure, or trust an upstream gateway on the
user's behalf. Keep its prompt logging disabled unless storing resolved request
content is intentional, and restrict it to a local or authenticated listener.

## Authentication and enterprise transport

By default, Pentect forwards the client's provider authentication headers. For
a gateway that uses a different bearer credential, set
`PENTECT_UPSTREAM_AUTHORIZATION` to the complete replacement `Authorization`
value. This removes incoming `Authorization`, `x-api-key`, and `api-key`
headers, preventing a vendor credential from being sent to the gateway. Set it
to an empty value to remove those headers without adding a replacement.
Pentect removes this environment variable from the launched agent process.

```powershell
$env:PENTECT_UPSTREAM_AUTHORIZATION = "Bearer $env:MY_GATEWAY_TOKEN"
pentect codex --upstream https://gateway.example/openai/v1
```

For a trusted local gateway that requires no client authentication:

```powershell
$env:PENTECT_UPSTREAM_AUTHORIZATION = ""
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

The transport also supports:

| Environment variable | Meaning |
| --- | --- |
| `PENTECT_UPSTREAM_CA_CERT` | PEM bundle containing additional trusted root certificates |
| `PENTECT_UPSTREAM_IDENTITY` | PEM containing the mTLS client certificate and private key |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | Standard outbound proxy selection |

Remote plaintext HTTP upstreams are rejected. Loopback HTTP is allowed for
local gateways. `PENTECT_ALLOW_INSECURE_UPSTREAM=1` is an explicit escape hatch
for isolated development networks, not a production setting.

Pentect rejects URL-embedded credentials and fragments. It does not print the
upstream URL, query string, proxy credentials, or authorization value when a
connection fails.

## Compatibility boundary

An OpenAI-compatible Chat Completions endpoint is not enough for Codex: the
gateway must implement `/responses`, including streaming events and tool calls.
Claude requires `/v1/messages` and its streaming/tool-use semantics. Unknown
provider endpoints and content formats follow Pentect's global compatibility
policy and are blocked by default.
