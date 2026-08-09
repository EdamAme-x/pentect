---
title: Configuration
description: Change Pentect settings for a user or project.
---

Pentect reads user settings from `~/.pentect/config.toml` and project settings
from `.pentect/config.toml`. Project settings win when allowed. A signed team
policy, when configured by the user, wins over both. A repository cannot lower
the user's protection for unknown formats.

You can leave both files absent. Pentect uses safe defaults. Restart a protected
client after changing a setting.

## Which file wins

Pentect loads settings in this order:

1. built-in defaults;
2. `~/.pentect/config.toml` for the current user;
3. `.pentect/config.toml` for the current project.
4. a verified signed team policy configured by the current user.

Project values normally win. Two security rules are different: a project
cannot change `compatibility.unknown_formats` to `ignore`, and
`agent.required` becomes true when either file requires it. Plugin approval
state is managed by the plugin commands, not by copying another user's config.

Unknown keys and invalid values cause an error instead of being silently
ignored.

## Signed team policy

Phase 1 supports offline policy bundles. Add the trust root only to the user
config; project config cannot select a key or bundle:

```toml
[team_policy]
bundle = "/absolute/path/to/pentect-policy.json"
issuer = "example-security"
public_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

`public_key` is a pinned Ed25519 verification key in lowercase hexadecimal.
The JSON bundle uses this schema:

```json
{
  "schema": "pentect.team-policy.v1",
  "issuer": "example-security",
  "sequence": 42,
  "issued_at": "2026-08-01T00:00:00Z",
  "expires_at": "2026-09-01T00:00:00Z",
  "payload_sha256": "64-lowercase-hex-characters",
  "payload": "[agent]\nrequired = true\n",
  "signature": "128-lowercase-hex-characters"
}
```

The signature is Ed25519 over `pentect:team-policy:v1\0`, followed by each
length-prefixed field (`schema`, `issuer`, little-endian `sequence`,
`issued_at`, `expires_at`, and the 32-byte payload digest). The exact format is
implemented in `crates/pentect-runtime/src/team_policy.rs`.

Pentect rejects invalid signatures, expired bundles, reused sequence numbers
with different content, and sequence rollback. A verified copy is atomically
cached as
`~/.pentect/team-policy-cache/team-policy.last-known-good-<trust-id>.json` and is used
when the configured bundle is temporarily missing. The trust ID separates
issuers and pinned keys, so an intentional key change starts a new rollback
history. Cache files contain the signed policy but no private key. On a shared
machine, protect the user config and account: changing the pinned public key
intentionally changes the trust root.

Automatic download, key rotation, TUF, and Sigstore are not part of Phase 1.
Distribute the bundle and rotate the pinned key through an authenticated
administrative channel.

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

`plugins add` records an enabled source in the project config. Wasm access is
approved separately and tied to the manifest and binary hashes.
