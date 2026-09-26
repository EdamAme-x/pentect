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

## Source code is masked too aggressively

If ordinary assignments, counters, or expressions become handles after a file
contains a credential-like assignment, update to **v0.0.85 or later**:

```sh
pentect update
pentect version
```

Earlier versions could classify an entire source snippet as dotenv after
finding one sensitive assignment. Version 0.0.85 checks the complete text
before treating it as an environment-variable dump. Mixed source code uses
normal text detection, so a detected secret remains masked without promoting
unrelated assignments to environment values.

Restart the client through Pentect and reread the original source. Updating
does not rewrite content already stored in a client's conversation history.
If the problem persists, include a minimal example with fake values, the
Pentect and client versions, and bounded diagnostics:

```sh
pentect log --json --once --tail 100
```

Do not disable protection or share a real session transcript to report this
bug. A short synthetic example is enough to show which safe text was masked.

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

In Claude Code, Codex/OpenAI Responses, OpenAI Chat Completions, Gemini, and
Google Cloud Code model requests, an unavailable handle, a changed/unreadable
source, or a malformed/unsupported handle representation triggers a recovery
notice to the model. Pentect withholds the complete response and asks the model
to reread the source or use the documented data representation.
No rejected client tool is executed. Recovery makes at most two additional model
requests, which may consume provider usage. If recovery keeps failing, Pentect
returns a normal explanatory message instead of a retrying 502 API error.

These model responses are buffered until validation completes, including streaming
responses. This prevents partial output or tools from escaping before recovery,
but means the response is displayed after generation and validation finish.
Malformed protocol input, plugin denials and other protection failures are not
retried as missing handles. An unsupported tool surface produces an explanatory
message; it does not enable compatibility settings or bypass validation.
Claude App also withholds rejected output and returns an explanatory message,
but does not automatically replay its stateful conversation POSTs, which could
duplicate server-side turns. It therefore does not perform the automatic
model-feedback retry used by the stateless provider adapters.

For diagnosis, run `pentect log --json --once --tail 100`. Look for
`sse-tool-rejected` or `json-tool-rejected` and their `kind`, followed by
`handle-recovery-attempt-1`, `handle-recovery-attempt-2`,
`handle-recovery-completed`, or `handle-recovery-exhausted`.
The categories `handle-view-malformed`, `handle-view-unsupported`, and
`handle-surface-unsupported` distinguish invalid syntax, an unsupported value
representation, and an unsupported input surface without recording the value.
`tool-input-rejected` identifies a fixed tool category; `restore-code-rejected`,
`restore-file-rejected` and related events identify the input surface. Events
include timestamps, PID and version, but never handle IDs, values, file paths,
arbitrary MCP names, or raw resolver errors. These are local diagnostics, not
automatic uploads of your conversations.

Copy the complete `<<LABEL_ID>>` handle into a supported local tool argument.
Do not invent a `PENTECT_...` environment binding. Pentect validates completed
tool inputs before restoring known values; it does not blindly substitute
credentials into arbitrary executable text.

In code or patch text, keep the handle as one complete quoted data argument or
string. If Pentect cannot safely represent the original value there, use the
documented `|base64` view and decode it locally through a data API. Never use a
handle as syntax or `eval` input. See [How a tool uses a handle](/start/handles/#how-a-tool-uses-a-handle).

For Claude's “unsafe or invalid protected tool input” error, collect
`pentect log --json --once --tail 100` and check the fixed `kind` on
`event=sse-tool-rejected`. The [Claude troubleshooting guide](/clients/claude/#streamed-tool-input-errors)
explains the categories. A client's “permission denied” summary alone does not
establish whether its permissions, Pentect validation, or plugin policy caused
the failure. Test with a fake credential; do not print the original value.

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

## Codex logs an initial HTTP 426 error

With Codex CLI 0.153.0, an initial Responses WebSocket attempt can receive HTTP
426 from Pentect and be logged by Codex as an error before Codex retries the
same turn through protected HTTP/SSE. This negotiation message is expected when
the retry succeeds. Pentect keeps Codex's built-in provider identity so saved
threads remain resumable; that verified client version does not expose a
working built-in-provider setting to suppress only the initial attempt.

Do not ignore a failed `POST /responses`, a turn that never retries, or a final
gateway error. Those indicate a genuine request failure and still need the
normal diagnostics from `pentect doctor` and `pentect log --once --tail 100`.
Future Codex versions may add a supported HTTP-only control, so check current
Pentect compatibility guidance after upgrading.

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

Unknown-format pass-through is the default. If strict blocking is reported,
check both user and project configuration for an explicit `error` or `block`.
Malformed supported structures, unsafe handles, and image-policy failures may
still be rejected in pass-through mode; do not treat `ignore` as a way to disable
those checks.

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
project cannot set `ignore`. An explicit project `error` still requires strict
blocking, even when the user config says `ignore`.

With `ignore`, Pentect sends an unknown request without checking or masking it.
Known request types stay protected. To enable strict blocking, change the value
to `"error"` and restart the client. Remove an explicit policy to inherit the
default (`ignore` unless the other config requires `error`).

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
`--follow` to request the existing live-follow behavior explicitly. A bounded
read is best effort during concurrent writes or rotation; it can omit or repeat
an event across files rather than claiming an atomic multi-file snapshot. Human
follow output marks the transition to waiting for live events; JSONL contains
events only. Panic entries include the Pentect
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
