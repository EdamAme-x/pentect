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

Pentect passes arguments after `codex` to the Codex CLI. The app command starts
the installed desktop app through Pentect. It does not make a permanent change
to the app.

| Launch | Scope |
| --- | --- |
| `pentect codex` | One Codex CLI process and its children |
| `pentect codex app` | One Codex App launch |
| `pentect codex --upstream URL` | One CLI launch using a compatible gateway |
| `pentect codex --plugins NAME` | One launch with the selected plugin set |

Client flags do not need a separator:

```sh
pentect codex exec --full-auto
pentect codex --model o3
```

## Protected flow

Pentect starts a local gateway that supports the Responses API. It protects
prompts, tool results, files, and completed tool-call arguments. Streaming
responses still work.

## Existing providers

Pentect keeps your current Codex provider when it uses a supported API format.
You can also choose a provider or gateway for one launch:

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
```

Pentect keeps the base path when it builds Responses API URLs. Codex and the
selected provider still manage login details and credentials.

## Codex App

Use `--check` to test app discovery and routing without leaving the app open.
If Pentect cannot find the app, pass its path:

```sh
pentect codex app --check
pentect codex app --app /path/to/codex
```

This affects only the launch started by Pentect. Opening Codex App normally
does not use Pentect or change other ChatGPT traffic.

## Verify protection

Run `pentect log` in another terminal. Then ask Codex to read a test dotenv
file. The model should see a handle, and the log should show a mask event. Use
a test value, not a real production credential.

::: warning
Pentect protects the supported Codex mode in the app. It does not protect
ChatGPT Chat, Work, Voice, or unknown future routes. If Pentect blocks a
request, follow the [unknown-format steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked).
Do not turn off Pentect for the whole app.
:::
