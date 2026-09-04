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

## A handle was not restored in a tool call

Copy the complete `<<LABEL_ID>>` handle into the tool argument. Do not convert
it to a `PENTECT_...` environment variable name. Pentect restores exact known
handles recursively in completed local shell, file, connector, and MCP inputs.

If the value contains shell metacharacters, the surrounding command still has
to use syntax valid for that shell. Pentect replaces the handle but does not
parse, quote, or escape the command. Test the intended operation with a fake
credential and inspect its ordinary status result instead of printing the
credential.

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

## Provider history was blocked

This error means a provider-owned history block contains detected plaintext,
but the block must remain unchanged for a paused server-tool turn to resume.
Pentect did not send the request and reports only the block and field name.

Start a new turn without the affected server-tool history, or remove the value
at its original source before retrying. `compatibility.unknown_formats =
"ignore"` does not disable this block because the format is known and the
plaintext check already found a value. Tool-search references and encrypted
provider state are not decoded or rewritten.

Pentect also uses this error for an unknown nested server-history shape, even in
unknown-format compatibility mode. Pentect cannot safely rewrite or inspect an
unrecognized provider-owned block while preserving resumable history.

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
pentect log --once --tail 100
pentect log --json --once --tail 100
pentect log --path
```

Pentect persists process starts, exit codes, gateway activity, and panic
diagnostics to `~/.pentect/logs/pentect.log`. `pentect log` reads that history
before following live events, `--once` prints a bounded snapshot and exits,
`--tail` selects 1 to 10,000 records (`--once` defaults to 100), `--json` keeps
the JSONL representation, and `--path` prints the exact file location. Use
`--follow` to request the existing live-follow behavior explicitly. Panic entries include the Pentect
version, OS, architecture, PID, source location, and a backtrace so a crash can
be investigated after the process exits.

Gateway warnings include a fixed endpoint class, HTTP method, retry hint, PID,
OS, and architecture, and can include an HTTP status. OCR entries report the
backend and a fixed outcome such as `scan-complete`, `scan-failed kind=decode`,
or `scan-unavailable-blocked`. They never include URLs, image bytes, recognized
text, or raw provider/OCR errors.

Repeated diagnostics with the same safe fields are combined into one entry
every five seconds. The entry's count and `span_ms` show how many times it
occurred and over what interval, so a retry loop remains visible without
writing one line per attempt.

Writes are handled by a bounded background queue and flushed in batches of up
to 64 events, 64 KiB, or 250 ms. The file rotates at 128 MiB and keeps 31
older generations (`pentect.log.1` through `pentect.log.31`), for a maximum of
about 4 GiB. A saturated queue never blocks protection work; the log records
the number of dropped diagnostic events when writing catches up.

The entries contain command categories and status metadata only. Pentect does
not persist command arguments, environment variables, request or response
bodies, prompts, protected values, or panic payload text. Codex App also keeps
its value-free lifecycle history, so the combined view shows why a previous
protected App session ended.

Logs show actions and counts, not real protected values.

::: warning
Do not paste real credentials into a public issue. Use a fake value with the
same format.
:::
