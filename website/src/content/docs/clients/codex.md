---
title: Codex
description: Run Codex CLI and Codex App through Pentect.
---

::: code-group

```sh [CLI]
pentect codex
```

```sh [App]
pentect codex app
```

:::

Arguments after `codex` are forwarded to the Codex CLI. The app command
launches the installed desktop app with Pentect routing for that process; it
does not permanently change the app's global configuration.

## Protected flow

Pentect inserts a local Responses-compatible gateway for the launched client.
It protects supported prompt content, tool results, file inputs, and completed
tool-call arguments while preserving streaming responses.

## Existing providers

Existing Codex provider configuration is retained as the upstream when its wire
protocol is supported. You can also select an upstream for one launch:

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
```

::: warning
Codex App coverage applies to its supported Codex mode. Pentect does not claim
protection for ChatGPT Chat, Work, Voice, or unknown future opaque routes. If a
request is blocked, follow the [unknown-format recovery steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
instead of disabling Pentect for the whole app.
:::
