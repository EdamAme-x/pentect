---
title: Configuration
description: Change Pentect settings for a user or project.
---

Pentect reads user settings from `~/.pentect/config.toml` and project settings
from `.pentect/config.toml`. Project settings win when allowed. A repository
cannot lower the user's protection for unknown formats.

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

## Files and activity

```toml
[files]
remember = true

[activity]
share = true
```

`files.remember` keeps local information that helps restore handles from files.
`activity.share` lets compatible Pentect processes share protection events.

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
