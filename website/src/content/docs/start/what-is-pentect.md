---
title: What is Pentect?
description: Protect sensitive data before an AI request leaves your computer.
---

Pentect runs locally between an AI coding tool and its model provider. It
replaces secrets and sensitive data with handles before a request leaves your
computer. A handle is a safe reference such as `<<DATABASE_URL_...>>`.

Use Pentect when an agent needs a credential or sensitive file. The agent can
use the handle without receiving the real value.

## Why normal masking is not enough

Normal masking hides both the value and its name:

```dotenv
DATABASE_URL=[REDACTED]
```

The model cannot use this value in a command. Pentect keeps a named reference:

```dotenv
DATABASE_URL=<<DATABASE_URL_4ce8a3b0a6f64e12>>
```

The model can copy this handle into a tool call. Pentect restores the real value
just before the local tool runs. The model provider does not need to see it.

## Scope

Pentect protects supported AI requests. It is not a password manager or secret
vault. Keep using normal permissions, sandboxes, and access controls.

Pentect does not give an agent new access. It only changes what the model
provider can see. Local tools still use the permissions of the current user.

## One request, end to end

| Step | What Pentect does |
| --- | --- |
| Local input | Finds supported sensitive values and creates handles |
| Request to the provider | Sends handles instead of known real values |
| Model response | Keeps handles in text and tool arguments |
| Before a local tool runs | Restores handles that the current session knows |
| Tool result | Checks and masks output before the next request |

The client UI stays the same. Pentect starts the client with a local gateway for
that process only.

## Supported surfaces

Pentect supports Codex CLI, Claude Code, Codex App, and selected Claude Desktop
features. It also offers local masking commands, custom gateways, and safe
plugins.

See [Compatibility](/reference/compatibility/) for the release-tested matrix.
