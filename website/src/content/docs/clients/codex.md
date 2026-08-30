---
title: Codex
description: Use Codex with Pentect.
---

::: code-group

```sh [CLI]
pentect codex
```

```sh [App]
pentect codex app
```

:::

Pentect protects the Codex session it starts. Normal CLI arguments pass
through, and `app` opens Codex App without changing the official app.

Prerequisites:

- Codex CLI or Codex App is already installed and can start normally.
- The selected provider login already works. Pentect does not replace Codex
  authentication.
- Run `pentect doctor` after installing or updating Codex.

| Launch | Scope |
| --- | --- |
| `pentect codex` | One Codex CLI process and its children |
| `pentect codex app` | One Codex App launch |
| `pentect codex --plugins NAME` | One launch with the selected plugin set |

## Use a clickable App launcher

For regular use, create a separate protected launcher:

```sh
pentect codex app --install-launcher
```

Windows adds `Codex via Pentect` under Start menu → Pentect. macOS adds it to
`~/Applications`. Pin that launcher and use it for protected App sessions. It
starts the same `pentect codex app` gateway in the background and does not
modify the official App.

Quit ChatGPT/Codex first. If it is already running, Pentect stops and asks you
to close it so the new process can receive the protected routing.

```sh
pentect codex app --remove-launcher
```

The launcher uses normal App discovery and your current Codex provider. Use the
terminal command when you need a one-time `--app` or `--plugins` option.

Client flags do not need a separator:

```sh
pentect codex exec --full-auto
pentect codex --model o3
```

## Protected flow

Pentect starts a local gateway that supports the Responses API. It protects
prompts, tool results, files, and completed tool-call arguments. Streaming
responses still work.

Responses computer-use screenshots returned as
`computer_call_output.output` are checked through the same local image and OCR
path as other supported inline images. Pentect keeps the computer-call IDs and
safety fields intact, replaces sensitive pixels in the screenshot, and adds a
separate user text item containing only the corresponding handles. A malformed,
unknown, or unscannable computer screenshot follows the configured
`image.unscanned` policy; allowing unknown JSON formats does not by itself skip
the image check.

For each protected request, Pentect adds short session instructions that tell
Codex how to use handles and their local environment bindings. These
instructions contain no real secret values. They prevent the agent from
rereading a file only because it sees a handle.

## Custom gateways

Pentect keeps your current Codex provider when it uses a supported API format.
You can also choose a provider or gateway for one launch:

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
```

Pentect keeps the base path when it builds Responses API URLs. Codex and the
selected provider still manage login details and credentials.

An OpenAI Chat Completions endpoint is not enough. Codex needs the Responses
request and streaming event format. Use an API adapter such as Bifrost when the
model server exposes a different contract. See
[Custom upstreams](/clients/upstreams/) for setup, credentials, and
troubleshooting.

## Codex App

Use `--check` to test app discovery and routing without leaving the app open.
If Pentect cannot find the app, pass its path:

```sh
pentect codex app --check
pentect codex app --app /path/to/codex
```

This affects only the launch started by Pentect. Opening Codex App normally
does not use Pentect or change other ChatGPT traffic. Pentect gives the child
App a session-only Codex configuration; it never points your shared
`~/.codex/config.toml` at the temporary gateway. Running `codex` directly still
uses your normal provider, even while the protected App is open.

`--check` exercises discovery and routing without sending a model prompt.

CI exercises the Codex App process boundary and the documented Responses
computer-use request shape with mock services and fake secrets. It does not sign
in to a real OpenAI account or drive the released App UI, so that end-to-end UI
step remains a release verification item.

`pentect codex app` stays attached for the full App session. If the launcher
hands off to another App process, Pentect keeps the gateway alive until that
process exits. `pentect log` includes value-free Codex App lifecycle and crash
events from previous sessions as well as live protection events.

After launch, use a non-sensitive test prompt first. Pentect reports active
protection only after the App sends a supported request through the gateway. A
listening gateway by itself is not proof that the App is routed through it.
See [Compatibility](/reference/compatibility/) for the routes and client modes
covered by this status.

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
