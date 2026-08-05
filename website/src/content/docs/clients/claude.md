---
title: Claude
description: Run Claude Code and supported Claude Desktop features through Pentect.
---

::: code-group

```sh [Claude Code]
pentect claude
```

```sh [Claude Desktop]
pentect claude app
```

:::

Pentect passes arguments after `claude` to Claude Code. The app command starts
Claude Desktop with a local gateway that supports the Messages API. It uses a
separate certificate setup for that process.

| Launch | Scope |
| --- | --- |
| `pentect claude` | One Claude Code process and its children |
| `pentect claude app` | One supported Claude Desktop launch |
| `pentect claude --upstream URL` | One CLI launch using a gateway that supports Messages |
| `pentect claude --plugins NAME` | One launch with the selected plugin set |

Normal Claude Code arguments pass through directly:

```sh
pentect claude --model sonnet
pentect claude --permission-mode plan
```

## Protected flow

Pentect checks supported Chat, attachment, and Claude Code requests before they
reach the selected provider. Local tool calls can use handles without showing
the real values to the model.

```sh
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

The selected provider manages login and model routing. Pentect keeps the
Anthropic Messages API format and protects supported requests, response events,
and completed tool calls.

## Claude Desktop

Desktop protection affects only the launch started by Pentect. Test app
discovery first. If Pentect cannot find the app, pass its path:

```sh
pentect claude app --check
pentect claude app --app /path/to/claude
```

Run `pentect log` in another terminal and test with a fake secret. Check that it
becomes a handle before you use real data. Desktop features can use different
network routes, so Pentect protects only the listed features.

::: warning
Pentect does not protect remote Cowork tasks, Voice, test binary formats, or
unknown future routes. Unsupported formats use your compatibility setting. See
the [unknown-format steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
for safer options and the pass-through setting.
:::
