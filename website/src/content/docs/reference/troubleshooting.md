---
title: Troubleshooting
description: Diagnose launch, compatibility, handle, and installation problems.
---

## Start with doctor

```text
pentect doctor
```

For automation or an issue report:

```text
pentect doctor --json
```

Use `pentect doctor --fix` only after reviewing the proposed repair.

## A handle cannot be resolved

Handles resolve through the running Pentect session that registered them. If a
handle came from another session, re-read the source through the current
Pentect-launched client instead of copying a stale handle.

Stable handle identity does not make recovery data global or persistent. It
prevents confusing handle churn; the plaintext mapping remains constrained to
the active local protection context or an explicitly remembered file pointer.

## The client does not launch

1. Run `pentect doctor`.
2. Confirm the unwrapped `codex` or `claude` command starts normally.
3. If you use a custom upstream, confirm it implements the required Responses
   or Messages contract.
4. Retry with the default upstream to separate client discovery from gateway
   compatibility.

## An unknown format was blocked

This is the default security behavior. Capture the ordinary error details and
open a compatibility issue if the format should be supported. User-level
compatibility mode exists, but may expose content Pentect cannot inspect.

## Follow protection events

```text
pentect log
pentect log --json
```

Logs report actions and counts, not plaintext protected values.

::: warning
Do not paste real credentials into a public issue. Reproduce with a synthetic
value that has the same format.
:::
