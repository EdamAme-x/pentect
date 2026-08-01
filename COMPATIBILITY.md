# Compatibility

Pentect validates its HTTP gateways against provider-shaped mock servers in
the Rust test suite. Every release also launches these exact public CLI builds
through the release binary:

| Client | Release gate | Protected mode |
| --- | --- | --- |
| Codex CLI `0.146.0` | automated on Linux | `pentect codex` |
| Claude Code `2.1.220` | automated on Linux | `pentect claude` |
| Codex App | launcher and protocol tests | `pentect codex app` |
| Claude App | launcher and protocol tests | `pentect claude app` |

The CLI gate proves that the vendor executable still starts under Pentect.
Mock protocol tests cover text, streaming responses, completed tool calls,
structured content, file references, malformed content, and custom upstream
path preservation without sending repository secrets to a model provider.

Desktop vendor apps are not installed on ephemeral release runners, so their
full signed-GUI flow is not yet a release gate. Pentect does not claim an App
version as verified until that automation exists.

## Upstreams

Codex Responses-compatible and Anthropic Messages-compatible upstreams can be
selected with `--upstream URL`. Existing Codex provider configuration and
Claude's managed/user endpoint configuration are preserved as the upstream
when Pentect inserts its local gateway. Unsupported wire protocols are rejected
before launch.
