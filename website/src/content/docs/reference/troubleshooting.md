---
title: Troubleshooting
description: Fix common launch, API, handle, and install problems.
---

## Start with doctor

```sh
pentect doctor
```

For scripts or an issue report:

```sh
pentect doctor --json
```

Read the suggested fix before you run `pentect doctor --fix`.

Also record the versions involved:

```sh
pentect version
codex --version
claude --version
```

## A handle cannot be resolved

The Pentect session that created a handle also restores it. If a handle came
from an old session, read the source again in the current Pentect client. Do
not copy an old handle.

A stable handle ID does not save the real value forever or share it everywhere.
It only keeps the displayed handle from changing too often. The real value
stays in the current local session or in a file location that Pentect remembers.

Check these points:

1. Use the exact handle produced in the current protected launch.
2. If the handle came from a file, read that file again in the same launch.
3. Do not remove or edit the handle ID.
4. Do not expect a handle copied from another device to resolve.
5. Run the command through the protected client or `pentect exec`, not a normal
   terminal with no active Pentect recovery store.

See [Handles](/start/handles/) for the difference between stable identity and
live recovery data.

## A `PENTECT_...` environment binding is empty

These bindings exist in protected tool processes. They are not permanent user
environment variables and normally do not exist in a separate terminal.

Use the complete name from the current handle. For example:

```text
<<KAGGLE_API_TOKEN_b818890b85f7482a>>
PENTECT_KAGGLE_API_TOKEN_b818890b85f7482a
```

In PowerShell, reference it as
`$env:PENTECT_KAGGLE_API_TOKEN_b818890b85f7482a`. In Bash or Zsh, use
`$PENTECT_KAGGLE_API_TOKEN_b818890b85f7482a`.

If the command output shows another handle instead of the value, masking worked.
Do not use `echo` as a test. Test the intended API call with a fake credential
and check its ordinary status result.

## A handle ID changed

- `handles.scope = "session"` changes IDs every protected launch.
- `handles.scope = "project"` changes IDs between project roots.
- `device` IDs change after the local identity key is removed or on another
  device.
- Different normalized values always produce different IDs.

Changing the ID does not change the source value. Copy the newly produced
handle instead of trying to keep an old one alive.

## The client does not launch

1. Run `pentect doctor`.
2. Check that normal `codex` or `claude` starts without Pentect.
3. If you use a custom gateway, check that it supports the required Responses
   or Messages API.
4. Try the default provider. This shows whether the problem is the client or
   the gateway.

For a desktop app, check discovery without keeping the app open:

```sh
pentect codex app --check
pentect claude app --check
```

If auto-discovery fails, pass the executable with `--app PATH`.

## A file or image was blocked

1. Check whether the file is UTF-8 text, a supported image, or a supported PDF.
2. For text, pipe it through `pentect mask` to isolate the problem.
3. For an image, check its size against the `[image]` limits and keep OCR on.
4. Convert an unknown binary format before sending it.

`image.unscanned = "allow"` is available for content already checked by
another trusted system. It sends unchecked content and should not be the first
fix. See [Files and images](/protection/files-and-images/).

## A plugin does not run

```sh
pentect plugins inspect NAME
pentect plugins test NAME
pentect plugins setup NAME
```

`inspect` shows requested hooks and access. `test` checks the manifest and
Wasm exports. Run `setup` after a reviewed plugin update changes its approved
access. For a required plugin, a plugin error stops the protected action.

## An unknown provider format was blocked

This error means Pentect does not know how to check part of the request. Pentect
did not send the request to the provider.

### Try the protected path first

1. Run `pentect doctor`, then run `pentect update --check`. If an update is
   available, install it with `pentect update`.
2. Try again without `--upstream`. If this works, the custom gateway uses a
   different API format.
3. If the error started after a client update, try the last working client
   version. You can also report the new format.
4. Run `pentect log` to record the route and error type. Logs do not include
   real protected values.

### Temporarily pass the request through

If you trust the provider and must continue now, add this to your **user**
config at `~/.pentect/config.toml`:

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

If `[compatibility]` already exists, change its `unknown_formats` value. Do not
add the table twice. Then close and restart the client through Pentect. A
project cannot change this setting because only the user should make this
choice.

With `ignore`, Pentect sends an unknown request without checking or masking it.
Known request types stay protected. To restore the default, change the value to
`"error"` and restart the client.

### Report a format Pentect should support

Open a [compatibility report](https://github.com/EdamAme-x/pentect/issues/new?template=bug_report.yml).
Include the Pentect version, client version, command, gateway type, route, and
full error. Replace credentials and private data with fake values before you
attach a request sample.

## Follow protection events

```sh
pentect log
pentect log --json
```

Logs show actions and counts, not real protected values.

::: warning
Do not paste real credentials into a public issue. Use a fake value with the
same format.
:::
