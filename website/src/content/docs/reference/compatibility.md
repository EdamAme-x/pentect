---
title: Compatibility
description: Clients and API formats tested for this release.
---

Pentect tests its gateways with mock provider servers. Each release also
installs and starts every public client launcher with the release binary. A
daily workflow installs current upstream client versions so compatibility
drift is visible before the next release.

Pentect currently supports four core AI coding clients: **Codex CLI, Claude
Code, OpenCode, and Pi**. Compatibility work is focused on these four rather
than on adding more client launchers. Codex App and Claude Desktop entries are
separate desktop surfaces within those client families, not additional core
clients.

On Unix, the four protected CLI launchers supervise the native client process
group. If the shell-facing Pentect process is forcibly killed, a separate
guardian stops ordinary descendants that remain in that group. Normal exit
status and terminal job control are preserved. This is a lifecycle boundary,
not a sandbox: a process that deliberately creates a new session or process
group is outside the guarantee, and forcibly killing the guardian itself can
leave the client running. Desktop launchers have separate lifecycle contracts.

| Client | Test | Protected launch |
| --- | --- | --- |
| Codex CLI `0.149.0` | Real launch on Linux and all installer platforms | `pentect codex` |
| Claude Code `2.1.238` | Real launch on Linux and all installer platforms | `pentect claude` |
| OpenCode `1.18.20` | Real launch on Linux and all installer platforms | `pentect opencode` |
| Pi `0.84.2` | Real launch, npm extension, and provider discovery | `pentect pi` or `@pentect/pi` |
| ChatGPT desktop app, Codex mode | Executable launch contract and Responses protocol tests, including computer-use screenshots | `pentect codex app` |
| Claude Desktop | Protocol tests; Windows current-user trust-store launch path awaiting real-account release verification | `pentect claude app` with explicit certificate confirmation |

Release pins are separate from the daily current-client monitor. The latest
successful monitor on 2026-09-03 exercised the published Pentect binary on
Windows, macOS, and Linux:

| Client | Current-client evidence | Installed handle path |
| --- | --- | --- |
| Codex CLI `0.153.0` | Passed on all three platforms | OpenAI Responses, local shell tool arguments, cancellation recovery, and image redaction |
| Claude Code `2.1.259` | Passed on all three platforms | Anthropic Messages and local Bash tool arguments |
| OpenCode `1.18.27` | Passed on all three platforms | Configured OpenAI Chat and local tool arguments |
| Pi `0.84.4` | Passed on all three platforms | Configured OpenAI Chat and local Bash tool arguments |

These are compatibility observations, not retroactive changes to a release's
pinned gate. The installed test uses real client binaries and a localhost
provider fixture; it does not make a paid provider request.

## Not implemented

These clients have status pages, but no public launcher in the current
release. The proposed commands return an unknown-command error. Starting the
client normally does not route it through Pentect and provides no Pentect
protection.

| Client | Status page |
| --- | --- |
| Antigravity CLI | [Not implemented](/clients/antigravity/) |
| Aider | [Not implemented](/clients/aider/) |
| Continue CLI | [Not implemented](/clients/continue/) |
| Cline CLI | [Not implemented](/clients/cline/) |
| Roo Code | [Not implemented](/clients/roo-code/) |
| Zed | [Not implemented](/clients/zed/) |
| Goose CLI | [Not implemented](/clients/goose/) |
| Junie CLI | [Not implemented](/clients/junie/) |
| Gemini CLI | [Not implemented](/clients/gemini/) |

API tests cover text, streaming, completed tool calls, structured data, file
links, broken data, custom gateway paths, and Codex zstd-compressed requests.

## Provider contracts

| Launch | Contract Pentect checks | Notes |
| --- | --- | --- |
| `pentect codex` | OpenAI Responses | Includes streaming events and completed tool calls |
| `pentect claude` | Anthropic Messages | Includes streaming content blocks and tool use |
| `pentect opencode` | Selected OpenAI Responses, OpenAI Chat, or Anthropic Messages adapter | The current installed-client E2E uses OpenAI Chat; unrelated OpenCode providers are not implied |
| `pentect pi` | Selected OpenAI Responses, OpenAI Chat, or Anthropic Messages adapter | The current installed-client E2E uses OpenAI Chat; other Pi API adapters are not implied |
| `pentect codex app` | Responses routes used by supported Codex mode, including documented `computer_call_output` screenshots | Other ChatGPT modes are outside this claim |
| `pentect claude app` | Supported Claude Chat and attachment routes on a compatible app build | Claude Code should use `pentect claude`; Cowork and Voice are outside this claim |

“Supported” means Pentect recognizes and checks the route and content shapes
documented here. “Tested” means the release suite exercised them with fake
secrets. It does not mean every provider model, account feature, or future
client build has been tested.

The version numbers are release gates, not strict version locks. A newer client
may work, but a new request or stream shape can be blocked until Pentect learns
it. Run `pentect update --check` after a client update.

## API format adapters

You can use an API adapter when a model provider does not offer OpenAI Responses
or Anthropic Messages. The adapter changes the provider API into a format
Pentect supports. Pentect then checks the normal client-side format.

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

[Bifrost](https://docs.getbifrost.ai/cli-agents/overview) can provide both API
formats. Pentect tests its `/openai/v1` and `/anthropic` paths. LiteLLM and other
gateways can also work when they offer the same APIs. Pentect does not test
every gateway release.

See [Custom upstreams](/clients/upstreams/) for setup and recovery steps.

## Desktop testing

Short-lived CI machines do not sign in to or drive the official desktop user
interfaces. Instead, Windows, Linux, and macOS execute process-contract
fixtures that validate the proxy, certificate, and isolated profile arguments,
while protocol tests exercise the supported routes. Pentect therefore does not
list a desktop app version as fully UI-tested. Tests use fake secrets and check
that local handles are not printed.

| Desktop surface | Current scope |
| --- | --- |
| Codex App | Supported Codex mode using the Responses protocol; signed-in UI execution remains a manual release check |
| Claude Desktop | Protocol support exists, but current build compatibility is restricted as described below |
| Other app modes | Not claimed unless listed here |

Current Claude Desktop builds on Windows reject Chromium's certificate-pin
switch. Pentect instead asks before installing a session-specific public CA in
the current user's trust store, launches Claude with its local proxy setting,
and removes the certificate on exit. The CA private key stays process-local.
Windows may also show its own Root-store security confirmation, which Pentect
does not suppress or bypass.
Crash residue is journaled and removed before the next protected launch. This
gateway is also monitored after startup; an unexpected gateway exit terminates
the protected Desktop process and releases its temporary trust state. This
command reports protection as active only after Claude Desktop accepts the
session certificate and establishes an inspected connection. If that does not
happen within 30 seconds, Pentect warns without terminating an app that may
still be waiting for login or user input. This path still requires a
real-account release verification before it is listed as
fully supported; use `pentect claude` for Claude Code when Desktop coverage is
not acceptable.

## Not covered

- ChatGPT Chat, Work, and Voice routes outside supported Codex mode
- Codex cloud tasks and the Codex Remote control channel; a Remote task is
  covered only if its connected-computer worker actually uses a separately
  verified local Pentect path
- Remote Claude Cowork execution; Claude Voice content is not inspected (the
  exact Voice WebSocket can only be relayed after the user enables unknown
  format pass-through)
- Independent web-search, hosted-tool, browser, and MCP connections that do
  not pass through a listed provider contract
- Copilot, VS Code inline suggestions, and private traffic from other extensions
- Test binary formats
- Unknown future routes
- Every provider and release behind a third-party gateway

Files referenced only by an unknown remote ID are not treated as inspected
just because the surrounding JSON is valid. See
[Files and images](/protection/files-and-images/) for the exact upload, URL,
image, and PDF boundaries.

Pentect blocks unknown or unsupported content by default. It does not claim to
protect content that it cannot check. If you see this error, first try the
default provider, then
follow the [unknown-format recovery steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked).
