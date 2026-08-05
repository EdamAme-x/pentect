---
title: Handles
description: Understand handle names, environment bindings, lifetime, and recovery.
---

A handle is a local reference to a sensitive value:

```text
<<DATABASE_URL_4ce8a3b0a6f64e12>>
```

The provider can see and copy this string. It cannot derive the value from it.
Pentect restores a known handle only inside the protected local flow.

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

## How a tool uses a handle

Protected launches provide an environment binding for each handle. The binding
name is `PENTECT_` followed by the text inside the handle:

::: code-group

```powershell [PowerShell]
# Handle: <<DATABASE_URL_4ce8a3b0a6f64e12>>
irm https://api.example.test/status `
  -Headers @{ Authorization = "Bearer $env:PENTECT_DATABASE_URL_4ce8a3b0a6f64e12" }
```

```sh [Bash / Zsh]
# Handle: <<DATABASE_URL_4ce8a3b0a6f64e12>>
curl https://api.example.test/status \
  -H "Authorization: Bearer $PENTECT_DATABASE_URL_4ce8a3b0a6f64e12"
```

:::

Pentect also resolves a handle copied directly into completed tool-call
arguments. The environment form is useful for shell commands because it avoids
placing the real value in the command text.

Do not assign the binding to a normal variable in one tool call and expect a
later tool call to keep it. Agent shells may be separate processes. Reference
the binding in each command that needs it.

## Lifetime and stability

Two different things have different lifetimes:

- **Handle identity** controls whether the displayed ID stays the same.
- **Recovery data** lets the active local flow restore the value.

With the default `handles.scope = "device"`, the same value normally gets the
same ID on the same device. This does not store the value forever. After the
protected session ends, a later session must read the source again before it
can restore that handle.

| Scope | ID behavior |
| --- | --- |
| `device` | Stable on this device; default |
| `project` | Different in each project on this device |
| `session` | New for every protected session |

See [Configuration](/reference/configuration/#handle-identity) to change the
scope.

## Known and unknown handles

Pentect restores only handles present in the active recovery store. Text that
looks like a handle but was invented, copied from another device, or created by
an old session stays inert.

If an old handle no longer works, read the original file or input again inside
the current protected client. Do not replace its ID by hand.

Inspect the safe parts of a handle with:

```sh
pentect view '<<DATABASE_URL_4ce8a3b0a6f64e12>>'
```

`view` prints the label, ID, and a length hint when available. It never prints
the real value.

## Files and recovery

With `files.remember = true`, Pentect can remember where a handle came from and
recover it only if the file still matches the recorded location and content.
This is local metadata, not a copy of every secret.

Use `pentect exec` when a command needs a handle. Use `pentect resolve` only
when you intentionally need plaintext written to standard output or a file:

```sh
pentect exec 'command --token <<API_TOKEN_...>>'
pentect resolve config.masked.toml
```

`resolve` changes the data boundary. Review its destination and permissions
before running it.
