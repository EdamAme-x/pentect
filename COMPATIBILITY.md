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

## Manual live smoke tests

The protected client behavior carried into v0.0.22 was exercised on Windows on
2026-08-03 against the v0.0.17 release binary, using synthetic secrets only.
The gateway code did not change between those releases:

| Client | Version | Result |
| --- | --- | --- |
| Codex CLI | `0.145.0` | The provider received a handle; a completed shell tool call was restored locally to the exact synthetic value. |
| Claude Code | `2.1.220` | A tool result reached the model as a handle; a later PowerShell tool call using that handle was restored locally to the exact synthetic value. |
| ChatGPT desktop app (Codex mode) | `26.721.4979.0` | Installation, running-process detection, and protected Responses routing preflight passed. No signed-GUI message was sent. |
| Claude Desktop | `1.24012.9` | The signed app launched through Pentect with the local proxy, certificate pin, and memory store attached. No signed-GUI message was sent. |

The CLI checks compare the final local file with the original synthetic value
without printing the value. They cover a real provider round trip in addition
to the deterministic mock protocol suite. Desktop message submission remains a
manual release task until a dedicated signed-GUI runner is available.

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
