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

## An unknown provider format was blocked

This error means the client sent a provider request or content block that
Pentect does not know how to inspect. The request was not sent upstream.

### Try the protected path first

1. Run `pentect doctor`, then check for a fix with `pentect update --check`.
   Install it with `pentect update` if one is available.
2. Retry without `--upstream`. If that works, the custom gateway is using a
   different wire format from OpenAI Responses or Anthropic Messages.
3. If the error followed a client update, retry the last known working client
   version or report the new format so Pentect can add support.
4. Use `pentect log` to capture the route and error category. Logs do not
   include plaintext protected values.

### Temporarily pass the request through

If you trust the destination and need compatibility immediately, add this to
the **user** configuration at `~/.pentect/config.toml`:

```toml
[compatibility]
unknown_formats = "ignore"
```

Create the directory and open the file with:

::: code-group

```powershell [Windows]
New-Item -ItemType Directory -Force "$HOME\.pentect" | Out-Null
notepad "$HOME\.pentect\config.toml"
```

```sh [macOS / Linux]
mkdir -p ~/.pentect
${EDITOR:-vi} ~/.pentect/config.toml
```

:::

If `[compatibility]` already exists, change its `unknown_formats` value instead
of adding a second table. Then close and relaunch the Pentect-launched client.
There is intentionally no per-project or one-launch bypass: a repository must
not be able to weaken this user decision.

With `ignore`, an unknown request can reach the upstream without Pentect
inspecting or masking that request. Supported requests remain protected. To
restore the default, change the value back to `"error"` and relaunch the
client.

### Report a format Pentect should support

Open a [compatibility report](https://github.com/EdamAme-x/pentect/issues/new?template=bug_report.yml)
with the Pentect version, client and version, command, upstream type, route, and
the complete error text. Replace credentials and private content with synthetic
values before attaching a request sample.

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
