---
title: Claude
description: Run Claude Code and supported Claude Desktop routes through Pentect.
---

::: code-group

```sh [Claude Code]
pentect claude
```

```sh [Claude Desktop]
pentect claude app
```

:::

Arguments after `claude` are forwarded to Claude Code. The app command launches
the installed app with a local Messages-compatible gateway and an isolated
certificate configuration for that process.

| Launch | Scope |
| --- | --- |
| `pentect claude` | One Claude Code process and its children |
| `pentect claude app` | One supported Claude Desktop launch |
| `pentect claude --upstream URL` | One CLI launch using a Messages-compatible upstream |
| `pentect claude --plugins NAME` | One launch with the selected plugin set |

Normal Claude Code arguments pass through directly:

```sh
pentect claude --model sonnet
pentect claude --permission-mode plan
```

## Protected flow

Supported Chat, attachment, and Claude Code traffic is inspected before it
reaches the Anthropic-compatible upstream. Completed local tool calls can use
opaque handles without exposing their plaintext to the model.

```sh
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

The upstream owns authentication and model routing. Pentect preserves the
Anthropic Messages contract and protects supported request content, response
events, and completed tool calls.

## Claude Desktop

Desktop support is opt-in for each launch. Validate discovery first, or select
an executable explicitly when automatic discovery is not enough:

```sh
pentect claude app --check
pentect claude app --app /path/to/claude
```

Run `pentect log` in another terminal to verify that a test secret becomes a
handle before relying on the setup. Desktop features can use different network
routes, so coverage is feature-specific rather than a claim about every screen
in the app.

::: warning
Pentect does not claim coverage for remote Cowork execution, Voice,
experimental binary transports, or unknown future opaque routes. Unsupported
formats follow the configured compatibility policy. See the
[unknown-format recovery steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
for protected alternatives and the explicit pass-through setting.
:::
