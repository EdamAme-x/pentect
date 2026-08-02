# Compatibility

Pentect validates its HTTP gateways against provider-shaped mock servers in
the Rust test suite. Every release also launches these exact public CLI builds
through the release binary:

| Client | Release gate | Protected mode |
| --- | --- | --- |
| Codex CLI `0.146.0` | automated on Linux | `pentect codex` |
| Claude Code `2.1.220` | automated on Linux | `pentect claude` |
| ChatGPT desktop app (Codex mode) | launcher and Responses protocol tests | `pentect codex app` |
| Claude Desktop (supported Chat, attachment, and Claude Code routes) | launcher and protocol tests | `pentect claude app` |

The CLI gate proves that the vendor executable still starts under Pentect.
Mock protocol tests cover text, streaming responses, completed tool calls,
structured content, file references, malformed content, and custom upstream
path preservation without sending repository secrets to a model provider.

Desktop vendor apps are not installed on ephemeral release runners, so their
full signed-GUI flow is not yet a release gate. Pentect does not claim an App
version as verified until that automation exists.

The App rows do not imply protection for ChatGPT Chat or Work, remote Claude
Cowork execution, Voice, experimental binary transports, or unknown future
opaque routes. Current Claude multipart attachment flows are protected as
described in [desktop apps](guides/apps.md).

## Upstreams

Codex Responses-compatible and Anthropic Messages-compatible upstreams can be
selected with `--upstream URL`. Existing Codex provider configuration and
Claude's managed/user endpoint configuration are preserved as the upstream
when Pentect inserts its local gateway. Unsupported wire protocols are rejected
before launch.

Bifrost's `/openai/v1` and `/anthropic` integration base paths are covered by
the URL-routing tests. This verifies Pentect's protocol boundary and path
composition; it does not certify every Bifrost provider or release. LiteLLM and
other gateways are supported through the same contracts rather than
provider-specific code. See [custom upstreams](guides/upstreams.md).
