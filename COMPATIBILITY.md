# Compatibility

Pentect validates its HTTP gateways against provider-shaped mock servers in
the Rust test suite. Every release also launches these exact public CLI builds
through the release binary:

The current official coding-client scope is four clients: **Codex CLI, Claude
Code, OpenCode, and Pi**. Pentect is concentrating compatibility work on these
four rather than adding more client launchers. Desktop rows below are separate
surfaces within the Codex and Claude client families, not additional core
clients.

| Client | Release gate | Protected mode |
| --- | --- | --- |
| Codex CLI `0.149.0` | real launch on Linux and all installer platforms | `pentect codex` |
| Claude Code `2.1.238` | real launch on Linux and all installer platforms | `pentect claude` |
| OpenCode `1.18.20` | real launch on Linux and all installer platforms | `pentect opencode` |
| Pi `0.84.2` | real launch, npm extension, and provider discovery | `pentect pi` or `@pentect/pi` |
| ChatGPT desktop app (Codex mode) | launcher and Responses protocol tests | `pentect codex app` |
| Claude Desktop | protocol tests; signed app `1.24012.9` was manually launch-tested, while `1.34493.1` is known incompatible | `pentect claude app` only on an explicitly compatible build |

Release pins are intentionally separate from the daily current-client
monitor. The latest successful monitor on 2026-09-03 exercised the published
Pentect binary and the then-current downloadable clients on Windows, macOS,
and Linux:

| Client | Current-client evidence | Installed handle path |
| --- | --- | --- |
| Codex CLI `0.153.0` | passed on Windows, macOS, and Linux | OpenAI Responses request, local shell tool arguments, cancellation recovery, and image redaction |
| Claude Code `2.1.259` | passed on Windows, macOS, and Linux | Anthropic Messages request and local Bash tool arguments |
| OpenCode `1.18.27` | passed on Windows, macOS, and Linux | configured OpenAI Chat request and local tool arguments |
| Pi `0.84.4` | passed on Windows, macOS, and Linux | configured OpenAI Chat request and local Bash tool arguments |

These current-client results are compatibility observations, not retroactive
changes to a release's pinned gate. A client name alone also does not imply
coverage of every provider, transport, hosted tool, or execution location.

The CLI gate proves that the vendor executable still starts under Pentect.
Mock protocol tests cover text, streaming responses, completed tool calls,
structured content, file references, malformed content, and custom upstream
path preservation without sending repository secrets to a model provider.
The installed handle-flow test goes further: a real client reads two synthetic
local keys, receives only distinct handles from a localhost provider fixture,
uses those handles in local tool calls, and reaches the fixture service with
the exact originals. The provider requests and persistent diagnostics must not
contain either plaintext value. It does not make a paid provider request.

Desktop vendor apps are not installed on ephemeral release runners, so their
full signed-GUI flow is not yet a release gate. Pentect does not claim an App
version as verified until that automation exists.

## Manual live smoke tests

The v0.0.23 release binary was exercised on Windows on 2026-08-03 UTC
(2026-08-04 JST) using synthetic secrets only. The reusable probe is
`tools/release_live_e2e.ps1`:

| Client | Version | Result |
| --- | --- | --- |
| Codex CLI | `0.145.0` | A completed shell tool call was restored locally to the exact synthetic value. |
| Claude Code | `2.1.220` | A later PowerShell tool call using the opaque value was restored locally to the exact synthetic value; final output did not contain it. |
| ChatGPT desktop app (Codex mode) | `26.721.4979.0` | v0.0.23 installation, running-process detection, and protected Responses routing preflight passed. No signed-GUI message was sent. |
| Claude Desktop | `1.24012.9` | The signed app launched through v0.0.23 with the local proxy, certificate pin, and memory store attached. No signed-GUI message was sent. |

Claude Desktop `1.34493.1` on Windows was tested on 2026-08-24 and deliberately
refused Pentect's required `--ignore-certificate-errors-spki-list` switch. The
proxy switch alone is accepted, but Pentect does not disable certificate
verification or install its ephemeral CA into the system trust store. That
build is therefore incompatible with `pentect claude app`; updating is not a
remedy. Use `pentect claude` for Claude Code. The exact first incompatible
Claude Desktop version is not known, so `1.24012.9` is an observed compatible
point, not a claimed version ceiling.

The CLI probe compares the final local file with the original synthetic value
without printing the value and deletes its temporary files. It covers a real
provider round trip in addition to the deterministic mock protocol suite.
Desktop message submission remains a manual release task until a dedicated
signed-GUI runner is available.

The App rows do not imply protection for ChatGPT Chat or Work, remote Claude
Cowork execution, Voice, experimental binary transports, or unknown future
opaque routes. Current Claude multipart attachment flows are protected; unknown
or unsupported attachment formats are blocked by default.

## Upstreams

Codex Responses-compatible, OpenAI Chat Completions-compatible, and Anthropic Messages-compatible upstreams can be
selected with `--upstream URL`. Existing Codex provider configuration and
Claude user endpoint configuration are preserved as the upstream when Pentect
inserts its local gateway. Claude supports the Anthropic Messages HTTP route
with normal Anthropic authentication and gateways implementing that contract.
Claude Code's Bedrock, Vertex AI, Foundry, and Mantle transports are rejected
before launch; they require separate authenticated transport designs. Managed
policy/configuration remains compatible only when it does not select one of
those transports, override the enforced route, or use a policy helper whose
route cannot be verified.

Bifrost's `/openai/v1` and `/anthropic` integration base paths are covered by
the URL-routing tests. This verifies Pentect's protocol boundary and path
composition; it does not certify every Bifrost provider or release. LiteLLM and
other gateways are supported through the same contracts rather than
provider-specific code.
