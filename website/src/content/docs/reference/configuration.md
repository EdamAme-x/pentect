---
title: Configuration
description: Pentect user and project configuration with secure defaults.
---

import { Aside } from '@astrojs/starlight/components';

Pentect reads user configuration from `~/.pentect/config.toml` and project
configuration from `.pentect/config.toml`. Project values take precedence where
allowed, but a repository cannot weaken user-level unknown-format protection.

## Handle identity

```toml
[handles]
scope = "device"
```

| Value | Behavior |
| --- | --- |
| `device` | Default. The same value produces the same handle identity on this device. |
| `project` | Derives a distinct identity for each project on this device. |
| `session` | Generates a new identity for each session. |

Handle hashes are keyed. They are stable references, not unsalted fingerprints
of the plaintext.

## Unknown provider formats

```toml
[compatibility]
unknown_formats = "error" # default
```

Set `ignore` only in the user configuration to continue past provider content
Pentect does not understand.

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

`files.remember` keeps local recovery hints for file-backed handles.
`activity.share` allows compatible local Pentect processes to share protection
events.

## Require the Pentect agent boundary

```toml
[agent]
required = true
```

Use this when the project must not silently continue without a Pentect-launched
agent session.

<Aside type="note">
  Handle environment bindings always use the `PENTECT_` prefix. The prefix is
  intentionally not configurable.
</Aside>
