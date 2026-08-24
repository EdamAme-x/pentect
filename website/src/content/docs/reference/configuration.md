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
| `output.restore` | `true` | Restore known handles in assistant text shown by supported clients |
| `update.check` | `true` | Check in the background for a newer Pentect release |

## Update notification

```toml
[update]
check = true
```

Pentect checks GitHub Releases at most once every 24 hours and caches the latest
known version in the local Pentect state directory. The check runs in the
background and never blocks protected client startup. Set `check = false` to
disable it. Installing an update remains explicit through `pentect update`.

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

Detection scans both the original text and bounded decoded representations.
Supported text layers include standard and URL-safe Base64, dense `%XX`
percent encoding, hexadecimal text, Base32, Base58, and the documented Base85
forms. Mixed layers are allowed up to `max_depth`. A detected encoded value is
masked as one outer handle, so Pentect keeps the exact encoded source for local
recovery and never writes decoded plaintext to the activity log.

Hard safety budgets apply even when a configurable limit is `"unlimited"`: at
most 256 successful decode candidates, 1 MiB of aggregate decoded bytes, a 32x
per-transform expansion ratio, and 100 ms of decode work per detector pass.
When one is reached, the persistent log records only `candidate-limit`,
`decoded-byte-limit`, `expansion-limit`, or `elapsed-limit`. It does not record
the candidate or decoded value. Dense percent encoding is required; ordinary
URL paths are not decode candidates. Encoding can make benign text resemble a
credential, so review false positives before enabling `mask_unknown`.

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

By default, Pentect restores known handles in assistant text shown to the local
user. To keep handles visible instead, opt out in either the user config or a
project config:

```toml
[output]
restore = false
```

This affects supported JSON and streaming responses for Codex, Claude,
OpenCode, and Pi. It does not send plaintext back to the model provider, but it
does place the restored value in the client UI and may place it in terminal
scrollback, screenshots, or client logs. Unknown and expired handles remain
unchanged.

A `false` in either scope wins, so a project cannot override a user-level
opt-out. Set `output.restore = true` explicitly only when recording the desired
default in managed configuration. Restart the protected client after changing
the setting.

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
