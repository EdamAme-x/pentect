---
title: Claude
description: Run Claude Code and supported Claude Desktop routes through Pentect.
---

::: code-group

```text [Claude Code]
pentect claude
```

```text [Claude Desktop]
pentect claude app
```

:::

Arguments after `claude` are forwarded to Claude Code. The app command launches
the installed app with a local Messages-compatible gateway and an isolated
certificate configuration for that process.

## Protected flow

Supported Chat, attachment, and Claude Code traffic is inspected before it
reaches the Anthropic-compatible upstream. Completed local tool calls can use
opaque handles without exposing their plaintext to the model.

```text
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

::: warning
Pentect does not claim coverage for remote Cowork execution, Voice,
experimental binary transports, or unknown future opaque routes. Unsupported
formats follow the configured compatibility policy. See the
[unknown-format recovery steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
for protected alternatives and the explicit pass-through setting.
:::
