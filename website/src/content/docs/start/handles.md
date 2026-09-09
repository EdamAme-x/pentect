---
title: Handles
description: Understand handle names, local restoration, lifetime, and recovery.
---

A handle is a local reference to a sensitive value:

```text
<<DATABASE_URL_4ce8a3b0a6f64e12>>
```

The provider can see and copy this string. It cannot derive the value from it.
Pentect restores a known handle only inside the protected local flow.
Assistant prose restores known handles in the local client display by default.
Set [`output.restore = false`](/reference/configuration/#assistant-output-restoration)
when a user or project must keep handles visible.

## Anatomy

| Part | Example | Purpose |
| --- | --- | --- |
| Label | `DATABASE_URL` | Tells the agent what the value is for |
| ID | `4ce8a3b0a6f64e12` | Distinguishes values without exposing them |

Pentect prefers a label taken from a trusted structure, such as a dotenv key,
JSON field, Terraform variable, or Kubernetes Secret key. For plain text, the
detector supplies the label. If equally strong detectors disagree, Pentect uses
a general `SECRET` or `PII` label.

The ID is a keyed hash. It is not a plain checksum of the value. The private
identity key stays on the local device.

IDs normally use 16 hexadecimal characters. If two different values ever
produce the same short ID under the same label, Pentect keeps the first compact
handle and gives the other value a 64-character full-width ID. This preserves
exact recovery instead of publishing an ambiguous mapping.

## Force a value to become a handle

Wrap a value in `pentect(...)` or its shorter alias `mask(...)` when it must be
protected even if it is short, low-entropy, or unknown to the built-in detectors:

```text
sudo password is pentect(passsword123)
```

Pentect removes the wrapper before the request leaves the device and sends a
`KEYED_SECRET` handle in its place. If that handle is later used by a local tool,
Pentect restores only `passsword123`; the annotation is not part of the value.
Both markers are case-sensitive, must be balanced, and are ignored when empty.

## Intentionally leave a prompt value visible

Use `unpentect(...)` or `unmask(...)` when a value in your own prompt must be
sent without masking:

```text
public fixture is unmask(sk-example-not-a-real-key)
```

Pentect removes the wrapper and leaves only its contents. Unmask markers are
recognized only in user prompt text. They are deliberately ignored in tool
results, browser output, files, and other external content so an external source
cannot disable protection. All four marker names are case-sensitive and require
balanced parentheses.

## How a tool uses a handle

The model copies the complete handle into a tool argument. Before the local
client executes the completed tool call, Pentect replaces every known handle in
its string arguments with the original value. This applies recursively to shell
commands, file writes and edits, connector arguments, and MCP arguments.

Pentect does not parse or rewrite shell syntax. It performs exact replacement
of known handles and leaves every other byte unchanged. The client and shell
therefore keep their normal semantics. If a value contains shell metacharacters,
the agent must place the handle in syntax appropriate for that command, just as
it would for any other argument.

This boundary protects provider traffic, not the local client process. A
restored value may be visible in local tool-call history, process arguments,
debuggers, or terminal scrollback. Tool output is checked and masked again
before the next provider request.

## Lifetime and stability

Two different things have different lifetimes:

- **Handle identity** controls whether the displayed ID stays the same.
- **Recovery data** lets the active local flow restore the value.

With the default `handles.scope = "device"`, the same value normally gets the
same ID on the same device. The file-pointer index does not persist secret
values. When `files.remember = true`, an explicit trusted file read can retain
a local pointer that lets a later session verify and reread an unchanged source
file.

| Scope | ID behavior |
| --- | --- |
| `device` | Stable on this device; default |
| `project` | Different in each project on this device |
| `session` | New for every protected session |

See [Configuration](/reference/configuration/#handle-identity) to change the
scope.

## Known and unknown handles

Pentect restores only handles present in the active recovery store or recovered
from a verified trusted-file pointer. Text that looks like a handle but was
invented or belongs to another identity scope stays inert.

If an old handle no longer works, read the original file or input again inside
the current protected client. Do not replace its ID by hand.

Inspect the safe parts of a handle with:

```sh
pentect view '<<DATABASE_URL_4ce8a3b0a6f64e12>>'
```

`view` prints the label, ID, and a length hint when available. It never prints
the real value.

## Files and recovery

With `files.remember = true`, `pentect read PATH` can remember where a handle
came from. A later Claude Code, Codex, OpenCode, or Pi HTTP client session may
then use that old handle in a completed, recognized tool input.
Pentect restores it only when the registered path is still a regular readable
file, its complete size and content hash are unchanged, and the current device
or project identity reproduces the handle. The index contains encrypted local
file metadata and byte ranges, not secret values.

With `handles.scope = "session"`, a restarted session has a different identity,
so an old handle is not recovered even when the file is unchanged.

Standard input (`pentect read -`), image input, arbitrary paths named by a
model, and generic native-tool output are not registered. Read the file through
an explicit trusted entry point first. Missing, changed, inaccessible,
out-of-scope, malformed, or oversized recovery sources reject the complete tool
response before any buffered call is released.

The same completed-tool validation applies after recovery: ordinary handles are
the primary representation, `|base64` is explicit and optional, and unsupported
Code or Patch representations remain rejected rather than guessed or escaped.

Supported protected clients restore handles in completed tool calls
automatically. `pentect exec` remains available for manual terminal workflows.
Use `pentect resolve` only when you intentionally need plaintext written to
standard output or a file:

```sh
pentect exec 'command --token <<API_TOKEN_...>>'
pentect resolve config.masked.toml
```

If a program supports credentials on stdin, keep the value out of both argv
and the environment:

```sh
pentect exec --secret-stdin '<<SUDO_PASSWORD_...>>' -- sudo -S -p '' command
```

`resolve` changes the data boundary. Review its destination and permissions
before running it.
