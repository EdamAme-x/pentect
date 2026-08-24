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

Prerequisites:

- Claude Code or Claude Desktop is already installed and starts normally.
- The selected Anthropic or managed-provider login already works.
- Run `pentect doctor` after installing or updating Claude.

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

## Custom gateways

```sh
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

The selected provider manages login and model routing. Pentect keeps the
Anthropic Messages API format and protects supported requests, response events,
and completed tool calls.

An endpoint that accepts similar JSON but does not implement Anthropic Messages
and its streaming events is not supported. Put a compatible adapter in front of
that endpoint and pass the adapter base URL with `--upstream`.

See [Custom upstreams](/clients/upstreams/) for compatible gateway setup,
credentials, and troubleshooting.

## Claude Desktop

::: danger
Claude Desktop `1.34493.1` on Windows rejects the certificate-pin switch that
Pentect requires for its ephemeral local CA, so that build cannot be protected
with `pentect claude app`. Pentect will not bypass certificate verification or
install a system CA. Version `1.24012.9` is an older observed-compatible point,
not a guaranteed version ceiling. Use `pentect claude` for Claude Code and see
the [compatibility matrix](/reference/compatibility/#desktop-testing) before
using Desktop mode.
:::

Desktop protection affects only the launch started by Pentect. Test app
discovery first. If Pentect cannot find the app, pass its path:

```sh
pentect claude app --check
pentect claude app --app /path/to/claude
```

Run `pentect log` in another terminal and test with a fake secret. Check that it
becomes a handle before you use real data. Desktop features can use different
network routes, so Pentect protects only the listed features.

Test one completed tool call as well as chat. This confirms that Claude can use
the protected reference locally without the provider learning the value.

::: warning
Pentect does not protect remote Cowork tasks, Voice, test binary formats, or
unknown future routes. Unsupported formats use your compatibility setting. See
the [unknown-format steps](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
for safer options and the pass-through setting.
:::
