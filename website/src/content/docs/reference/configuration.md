---
title: Configuration
description: Change Pentect settings for a user or project.
---

Pentect reads user settings from `~/.pentect/config.toml` and project settings
from `.pentect/config.toml`. Project settings win when allowed. A repository
cannot lower the user's protection for unknown formats.

You can leave both files absent. Pentect uses safe defaults. Restart a protected
client after changing a setting.

## Which file wins

Pentect loads settings in this order:

1. built-in defaults;
2. `~/.pentect/config.toml` for the current user;
3. `.pentect/config.toml` for the current project.

Project values normally win. Two security rules are different: a project
cannot change `compatibility.unknown_formats` to `ignore`, and
`agent.required` becomes true when either file requires it. Plugin approval
state is managed by the plugin commands, not by copying another user's config.

Unknown keys and invalid values cause an error instead of being silently
ignored.

## Settings at a glance

| Setting | Default | Purpose |
| --- | --- | --- |
| `handles.scope` | `device` | Choose how stable handle IDs are |
| `compatibility.unknown_formats` | `error` | Block request formats Pentect cannot inspect |
| `image.ocr` | `on` | Check supported images locally |
| `image.redaction` | `black` | Cover detected image regions |
| `image.unscanned` | `block` | Stop when image or document content cannot be checked |
| `files.remember` | `true` | Remember safe local file-to-handle information |
| `activity.share` | `true` | Share events with compatible local Pentect processes |
| `agent.required` | `false` | Require supported agents to start through Pentect |
| `output.restore` | `false` | Restore known handles in assistant text shown by supported clients |

## Handle identity

```toml
[handles]
scope = "device"
```

| Value | Behavior |
| --- | --- |
| `device` | Default. The same value gets the same handle ID on this device. |
| `project` | The same value gets a different handle ID in each project. |
| `session` | The same value gets a new handle ID in each session. |

Pentect creates handle hashes with a private key. They are stable references,
not simple fingerprints of the real value.

## Unknown provider formats

```toml
[compatibility]
unknown_formats = "error" # default
```

Set `ignore` only in the user config. It sends an unknown request without
checking it. Restart the client after changing this value. Change it back to
`error` to restore the default.

Project config can require `error`, but it cannot set `ignore`. See
[Unknown provider format troubleshooting](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
for copyable Windows, macOS, and Linux steps.

## Images

```toml
[image]
ocr = "on"
redaction = "black"
unscanned = "block"
max_edge = 2048
max_pixels = 64000000
max_images = 64
max_total_bytes = 536870912
max_seconds = 20
max_image_bytes = 67108864
fetch_seconds = 8
```

`redaction` accepts `black` or `blur`. `unscanned` accepts `block` or `allow`.
Size values are bytes except `max_edge` and `max_pixels`. Keep the defaults
unless a trusted file is larger than a limit.

## Encoded values

Pentect can inspect common encoded text and compressed data before detection:

```toml
[decode]
enabled = true
max_depth = 3
min_bytes = 16
max_bytes = 262144
max_inflate_bytes = 8388608
mask_unknown = false
unknown_min_bytes = 24
```

Use `"unlimited"` for `max_depth`, `max_bytes`, or `max_inflate_bytes` only
when another limit controls the input. `mask_unknown = true` also masks long
opaque encoded values that Pentect cannot identify. It can create false
positives, so it is off by default.

## Files and activity

```toml
[files]
remember = true

[activity]
share = true
```

`files.remember` keeps local information that helps restore handles from files.
`activity.share` lets compatible Pentect processes share protection events.

Project values normally override user values. `agent.required` is stricter: if
either file sets it to `true`, the effective value is true.

## Assistant output restoration

By default, assistant text keeps protected handles visible. To restore known
handles in assistant text locally, opt in from the user config:

```toml
[output]
restore = true
```

This affects supported JSON and streaming responses for Codex, Claude,
OpenCode, and Pi. It does not send plaintext back to the model provider, but it
does place the restored value in the client UI and may place it in terminal
scrollback, screenshots, or client logs. Unknown and expired handles remain
unchanged.

A project config cannot enable this wider output boundary by itself. It may set
`output.restore = false` to disable a user-level opt-in for that project. Restart
the protected client after changing the setting.

## Require the agent to start through Pentect

```toml
[agent]
required = true
```

Use this when the project must stop if the agent was not started by Pentect.

::: info
Environment variables for handles always start with `PENTECT_`. You cannot
change this prefix.
:::

## Plugin settings

Do not edit plugin state by hand. Use the CLI so values stay valid:

```sh
pentect plugins config PLUGIN policy.level=strict
pentect plugins config PLUGIN --unset policy.level
pentect plugins setup PLUGIN
```

`plugins add` records an enabled source in the user config by default. Add
`--project` to use the project config instead. Wasm and Command access is
approved separately and tied to the selected scope, manifest, and binary or
command-file hashes.
