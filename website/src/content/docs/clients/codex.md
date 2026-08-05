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

Prerequisites:

- Codex CLI or Codex App is already installed and can start normally.
- The selected provider login already works. Pentect does not replace Codex
  authentication.
- Run `pentect doctor` after installing or updating Codex.

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

For each protected request, Pentect adds short session instructions that tell
Codex how to use handles and their local environment bindings. These
instructions contain no real secret values. They prevent the agent from
rereading a file only because it sees a handle.

## Existing providers

Pentect keeps your current Codex provider when it uses a supported API format.
You can also choose a provider or gateway for one launch:

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
```

Pentect keeps the base path when it builds Responses API URLs. Codex and the
selected provider still manage login details and credentials.

An OpenAI Chat Completions endpoint is not enough. Codex needs the Responses
request and streaming event format. Use an API adapter such as Bifrost when the
model server exposes a different contract.

## Codex App

Use `--check` to test app discovery and routing without leaving the app open.
If Pentect cannot find the app, pass its path:

```sh
pentect codex app --check
pentect codex app --app /path/to/codex
```

This affects only the launch started by Pentect. Opening Codex App normally
does not use Pentect or change other ChatGPT traffic.

Pentect makes a temporary provider override for the protected app process and
restores the previous configuration when that launch ends. `--check` exercises
discovery and routing without sending a model prompt.

## Verify protection

Run `pentect log` in another terminal. Then ask Codex to read a test dotenv
file. The model should see a handle, and the log should show a mask event. Use
a test value, not a real production credential.

Also test one local tool call that uses the handle. A complete check proves both
directions: the provider does not receive the value, and the local tool still
receives it.

::: warning
Pentect protects the supported Codex mode in the app. It does not protect
ChatGPT Chat, Work, Voice, or unknown future routes. If Pentect blocks a
request, follow the [unknown-format steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked).
Do not turn off Pentect for the whole app.
:::
