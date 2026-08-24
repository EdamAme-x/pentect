---
title: Security model
description: What Pentect protects, what it trusts, and where its limits are.
---

Pentect protects supported content between a local AI client and a model
provider. It trusts the local user and approved local tools to use credentials
they already have.

The main boundary is the provider request. Pentect reduces which sensitive
values leave the computer without trying to remove the local tool's existing
permissions.

## Security properties

- Pentect replaces sensitive values before supported requests leave the local
  process.
- Data needed to restore a handle stays in the local Pentect session. It is not
  added to the model request.
- Pentect restores known handles only before supported local tools run.
- Tool output is masked before it returns to the provider.
- Supported MCP and connector text and structured data are checked before they
  enter the next provider request. Media follows the configured OCR and
  `unscanned` policy; allowing unchecked media can bypass inspection.
- Unknown provider formats and unsupported content are blocked by default.
- Wasm plugins cannot directly use WASI, files, environment variables,
  processes, or network sockets.

## Local state

Recovery data lives in the active local Pentect flow. The handle identity key
is stored with restricted local permissions and is used only to create stable,
keyed handle IDs. A handle ID is not enough to recover a value.

Optional file-pointer metadata is encrypted locally and is useful only while
the source still matches. Activity logs store actions, labels, counts, and safe
context—not real protected values.

Pentect control environment variables carry local process-host addresses and
tokens. They are filtered from normal tool environment exposure. Wasm plugins
do not receive them.

When a command explicitly references a recovered environment binding, Pentect
passes only that binding to the command process. The operating system then
makes it part of that process environment, so child processes can inherit it
and other processes running as the same user may be able to inspect it. Bash
same-shell execution runs in a temporary subshell. PowerShell same-shell
execution restores every previous environment value in a `finally` block, but
a child deliberately started by the command can still retain its inherited
copy. Pentect cannot distinguish an intended child from a daemon started by
the same command.

## Trust boundaries

| Component | Boundary |
| --- | --- |
| Local user | Chooses providers, plugins, and compatibility settings |
| Supported client launcher | Starts the protected process with the local gateway |
| Pentect gateway and memory store | Holds recovery data and applies protection at supported boundaries |
| Model provider | Receives the protected request; it is not trusted with original values |
| Approved local tool | Receives restored values and runs with the user's existing permissions |
| Wasm plugin | Receives only hook input and the host access shown during approval |

## Where Pentect must run

Pentect must run on the same machine as the client process that sends the model
request. A loopback gateway on your laptop cannot protect an extension host,
background agent, container, SSH session, or cloud task running elsewhere.

For remote development, install Pentect on the remote host and start the agent
through Pentect there. Do not expose Pentect's loopback URL or session token as
a remote service.

## What Pentect does not guarantee

- Finding every possible secret or type of personal data
- Safety after a trusted local tool sends a credential to another service
- Protection for a browser or MCP server's direct network side effects
- Protection for unsupported clients, hidden binary traffic, or future routes
- A replacement for limited permissions, key changes, network rules, or client
  sandboxes
- Protection from a malicious local process running as the same user with
  access to the same files or debugging rights
- Revoking a secret already inherited by a child or daemon started by an
  approved command
- Proof that every OCR engine or detector will find every sensitive value

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

For concrete prompt, MCP, browser, and screenshot flows, read
[Prompts and tool results](/protection/prompts-and-tools/).

::: danger
Compatibility mode can send content that Pentect does not understand. Do not
turn it on only to hide an error that you have not checked.
:::

## Reporting a vulnerability

Do not open a public issue for a possible security problem. Use the private
steps in the repository's
[security policy](https://github.com/EdamAme-x/pentect/security/policy).
