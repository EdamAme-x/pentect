---
title: What is Pentect?
description: A local security boundary between AI coding tools and model providers.
---

Pentect is a local security boundary for AI coding tools. It replaces secrets
and sensitive data with opaque handles before requests reach a model provider,
then resolves those handles only at trusted local tool boundaries.

## The problem with redaction

Conventional redaction protects a value by removing its meaning:

```text
DATABASE_URL=[REDACTED]
```

The model can no longer use that value in a command. Pentect preserves a typed,
stable reference instead:

```text
DATABASE_URL=<<DATABASE_URL_4ce8a3b0a6f64e12>>
```

The model can copy the handle into a completed tool call. Pentect resolves it
immediately before the trusted local client executes that call. The provider
never needs the plaintext.

## What Pentect is not

- It is not a replacement chat application.
- It is not a password manager or secret vault.
- It does not grant tools permission to use a secret.
- It cannot guarantee detection of every future or unknown sensitive format.

Pentect reduces exposure at the provider boundary. Existing client permissions,
sandboxing, account controls, and least-privilege credentials still matter.

## Supported surfaces

Pentect currently integrates with Codex CLI, Claude Code, Codex App, and
supported Claude Desktop routes. It also provides standalone masking and
execution commands, custom upstream routing, and sandboxed plugins.

See [Compatibility](/reference/compatibility/) for the release-tested matrix.
