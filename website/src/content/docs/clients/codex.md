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

| Launch | Scope |
| --- | --- |
| `pentect codex` | One Codex CLI process and its children |
| `pentect codex app` | One Codex App launch |
| `pentect codex --upstream URL` | One CLI launch using a compatible upstream |
| `pentect codex --plugins NAME` | One launch with the selected plugin set |

Client flags do not need a separator:

```sh
pentect codex exec --full-auto
pentect codex --model o3
```

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

Pentect preserves the configured base path when it composes Responses API
routes. Authentication remains owned by Codex and the upstream; Pentect does
not replace provider credentials.

## Codex App

Use `--check` to validate discovery and routing without keeping an app session
open. If automatic discovery does not find the executable, pass it explicitly:

```sh
pentect codex app --check
pentect codex app --app /path/to/codex
```

This is opt-in per launch. Opening Codex App normally does not silently install
a global proxy or change unrelated ChatGPT traffic.

## Verify protection

Run `pentect log` in another terminal, then ask Codex to read a test dotenv file.
The model-visible text should contain a handle and the log should show a masked
event. Do not use a production credential for the first check.

::: warning
Codex App coverage applies to its supported Codex mode. Pentect does not claim
protection for ChatGPT Chat, Work, Voice, or unknown future opaque routes. If a
request is blocked, follow the [unknown-format recovery steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
instead of disabling Pentect for the whole app.
:::
