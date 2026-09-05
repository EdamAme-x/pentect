---
title: Claude
description: Use Claude with Pentect.
---

::: code-group

```sh [Claude Code]
pentect claude
```

```sh [Claude Desktop]
pentect claude app
```

:::

Pentect protects the Claude session it starts. Normal Claude Code arguments
pass through, and `app` opens Claude Desktop without changing the official app.
Cloud sessions, self-hosted cloud environments, Remote Control, teleport, and
cloud-hosted ultrareview run outside this local gateway and are rejected.

Prerequisites:

- Claude Code or Claude Desktop is already installed and starts normally.
- An Anthropic login/API key, or credentials for an Anthropic
  Messages-compatible custom gateway, already works.
- Run `pentect doctor` after installing or updating Claude.

`pentect claude` does not currently route Claude Code's Bedrock, Vertex AI,
Foundry, or Mantle transports. Pentect rejects those switches before launch.
A centrally managed policy is supported when it leaves the Anthropic Messages
route available; "managed policy" does not mean that managed cloud-provider
transports are supported. If your organization requires one of those
transports, use Claude Code without `pentect claude` and do not assume that the
remote session passes through Pentect's local gateway.

| Launch | Scope |
| --- | --- |
| `pentect claude` | One Claude Code process and its children |
| `pentect claude app` | One supported Claude Desktop launch |
| `pentect claude --plugins NAME` | One launch with the selected plugin set |

## Use a clickable App launcher

For regular use, create a separate protected launcher:

```sh
pentect claude app --install-launcher
```

Windows adds `Claude via Pentect` under Start menu → Pentect. macOS adds it to
`~/Applications`. Pin that launcher and use it for protected Desktop sessions.
It starts the same `pentect claude app` gateways in the background and does not
modify the official App.

Quit Claude Desktop first. If it is already running, Pentect stops and asks you
to close it so the new process can receive the proxy settings.

```sh
pentect claude app --remove-launcher
```

The launcher uses normal App discovery and the default provider. Use the
terminal command when you need a one-time `--app` or `--plugins` option.

Normal Claude Code arguments pass through directly:

```sh
pentect claude --model sonnet
pentect claude --permission-mode plan
```

## Protected flow

`pentect claude` checks supported Claude Code requests before they reach the
selected provider. On an explicitly compatible Desktop build,
`pentect claude app` checks the supported Chat and attachment routes. Local tool
calls can use handles without showing the real values to the model.

Pentect adds short session instructions that explain handle use and local
environment bindings. The instructions contain labels and syntax, not real
secret values. Claude can use a binding directly in a tool call instead of
rereading the source file.

Local `tool_use`, MCP input/result, and supported execution-result plaintext is
checked before conversation history is sent again. Detected values in those
rewriteable fields become handles.

Anthropic server-tool history has a different constraint. Tool-search
references and encrypted result state must be returned unchanged for a paused
turn to resume. Pentect leaves those protocol fields byte-stable. It checks the
model-visible narration and tool-search error message, web-search title and URL,
and web-fetch plaintext document fields without changing them. If one contains a detected value,
Pentect stops the request with `provider history blocked` and names the field;
it does not include the value in the error. Unknown-format compatibility does
not bypass this decision or allow unknown nested provider-history blocks.

## Custom gateways

```sh
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

The selected provider manages login and model routing. Pentect keeps the
Anthropic Messages API format and protects supported requests, response events,
and completed tool calls.

Supported combinations are Anthropic's Messages endpoint with normal Claude
login/API-key authentication, or a custom upstream that implements the same
Messages and streaming contract with credentials supplied as described in the
custom-upstream guide. Native Bedrock, Vertex AI, Foundry, and Mantle protocols
are different transports and are rejected even when Claude Code can authenticate
to them directly.

An endpoint that accepts similar JSON but does not implement Anthropic Messages
and its streaming events is not supported. Put a compatible adapter in front of
that endpoint and pass the adapter base URL with `--upstream`.

See [Custom upstreams](/clients/upstreams/) for compatible gateway setup,
credentials, and troubleshooting.

## Claude Desktop

::: warning
On Windows, `pentect claude app` asks before adding a session-specific public
CA certificate to the current user's trust store. Its private key remains in
the Pentect process, and Pentect removes the certificate when Claude Desktop
exits. If Pentect or Claude crashes, the next `pentect claude app` launch
removes the stale certificate before doing anything else; `pentect doctor
--fix` can also remove it. Declining makes no trust-store change. Use `--yes`
only to skip Pentect's own prompt. Windows can still show its security
confirmation for the Root store; Pentect does not bypass it, so this launch
path is not suitable for unattended automation.
:::

Pentect monitors the local Claude App gateway for the entire Desktop session.
If the gateway stops unexpectedly, Pentect terminates the Desktop process tree
instead of leaving a broken protected session running, removes the temporary
Windows certificate, and records `warning/claude-app` with
`reason=gateway-stopped` in `pentect log`.

Desktop protection affects only the launch started by Pentect. Test app
discovery first. If Pentect cannot find the app, pass its path:

```sh
pentect claude app --check
pentect claude app --app /path/to/claude
pentect claude app
```

Run `pentect log` in another terminal and test with a fake secret. Check that it
becomes a handle before you use real data. Desktop features can use different
network routes, so Pentect protects only the listed features.

Test one completed tool call as well as chat. This confirms that Claude can use
the protected reference locally without the provider learning the value.

::: warning
Pentect does not protect remote Cowork tasks, Voice, test binary formats, or
unknown future routes. Voice remains blocked by default. With the user-level
`compatibility.unknown_formats = "ignore"` setting, Pentect can relay the exact
`claude.ai` Voice WebSocket, but that opaque stream is **not inspected or
masked** and is logged as `inspected=no`. See the
[unknown-format steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
for safer options and the pass-through setting. Real-account Voice UI
verification is not currently claimed.
:::
