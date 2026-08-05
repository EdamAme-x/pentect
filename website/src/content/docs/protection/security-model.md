---
title: Security model
description: What Pentect protects, what it trusts, and where its limits are.
---

Pentect protects supported content between a local AI client and a model
provider. It trusts the local user and approved local tools to use credentials
they already have.

## Security properties

- Pentect replaces sensitive values before supported requests leave the local
  process.
- Data needed to restore a handle stays in the local Pentect session. It is not
  added to the model request.
- Pentect restores known handles only before supported local tools run.
- Tool output is masked before it returns to the provider.
- Unknown provider formats and unsupported content are blocked by default.
- Wasm plugins cannot directly use WASI, files, environment variables,
  processes, or network sockets.

## What Pentect does not guarantee

- Finding every possible secret or type of personal data
- Safety after a trusted local tool sends a credential to another service
- Protection for unsupported clients, hidden binary traffic, or future routes
- A replacement for limited permissions, key changes, network rules, or client
  sandboxes

## Compatibility mode

Pentect returns an error for unknown provider formats by default. Only the user
config can change this:

```toml
[compatibility]
unknown_formats = "ignore"
```

A project cannot make this setting less safe. This stops a repository from
silently turning off the default check.

See [Unknown provider format troubleshooting](/reference/troubleshooting/#an-unknown-provider-format-was-blocked)
for protected alternatives, copyable setup commands, restart instructions, and
how to restore the default.

::: danger
Compatibility mode can send content that Pentect does not understand. Do not
turn it on only to hide an error that you have not checked.
:::

## Reporting a vulnerability

Do not open a public issue for a possible security problem. Use the private
steps in the repository's
[security policy](https://github.com/EdamAme-x/pentect/security/policy).
