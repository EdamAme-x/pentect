---
title: What is Pentect?
description: A local security boundary between AI coding tools and model providers.
---

Pentect is a local security boundary for AI coding tools. It replaces secrets
and sensitive data with opaque handles before requests reach a model provider,
then resolves those handles only at trusted local tool boundaries.

Use it when a coding agent needs to work with configuration, credentials, or
sensitive files without sending their plaintext to the model provider.

## The problem with redaction

Conventional redaction protects a value by removing its meaning:

```dotenv
DATABASE_URL=[REDACTED]
```

The model can no longer use that value in a command. Pentect preserves a typed,
stable reference instead:

```dotenv
DATABASE_URL=<<DATABASE_URL_4ce8a3b0a6f64e12>>
```

The model can copy the handle into a completed tool call. Pentect resolves it
immediately before the trusted local client executes that call. The provider
never needs the plaintext.

## Scope

Pentect protects supported AI client traffic; it is not a password manager or
secret vault. It complements existing permissions, sandboxing, and access controls.

Pentect does not grant an agent access to a secret. It changes how already
accessible content crosses the model boundary. The local client and its tools
still run with the permissions of the user who launched them.

## One request, end to end

| Boundary | What Pentect does |
| --- | --- |
| Local input | Detects supported sensitive values and creates handles |
| Provider request | Sends the transformed content, not the known plaintext |
| Model response | Preserves handles in text and completed tool arguments |
| Local tool boundary | Resolves only handles known to the current store |
| Tool result | Inspects and masks sensitive output before the next request |

The client UI stays the same. Pentect launches the existing client with a local
provider-compatible gateway for that process.

## Supported surfaces

Pentect currently integrates with Codex CLI, Claude Code, Codex App, and
supported Claude Desktop routes. It also provides standalone masking and
execution commands, custom upstream routing, and sandboxed plugins.

See [Compatibility](/reference/compatibility/) for the release-tested matrix.
