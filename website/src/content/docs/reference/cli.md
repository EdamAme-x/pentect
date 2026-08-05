---
title: CLI reference
description: Pentect commands and what they do.
---

Run `pentect help` for the short list installed with your version. Pentect
returns a non-zero exit code when it blocks input, cannot start a client, or
cannot complete a requested change.

## Launch clients

| Command | Purpose |
| --- | --- |
| `pentect codex` | Launch Codex CLI through Pentect |
| `pentect claude` | Launch Claude Code through Pentect |
| `pentect codex app` | Launch Codex App for this protected session |
| `pentect claude app` | Launch Claude Desktop for this protected session |

Use `--upstream URL` to choose a compatible gateway for one launch. Use
`--plugins SOURCE` to add a plugin for one launch. App commands also support
`--app PATH` and `--check`.

Codex and Claude arguments are forwarded directly:

```sh
pentect codex exec --full-auto
pentect claude --model sonnet
```

`--check` validates app discovery and routing without leaving the app open.
`--plugins` accepts a local plugin directory or a
`github:@OWNER/REPOSITORY/path` source. Separate multiple sources with commas.

## Protect local input and execution

| Command | Purpose |
| --- | --- |
| `pentect mask [TEXT]` | Mask arguments or UTF-8 stdin |
| `pentect read PATH` | Print a masked preview of a file |
| `pentect exec "COMMAND"` | Restore known handles, run the command, and mask its output |
| `pentect view HANDLE` | Show handle details without revealing its value |
| `pentect resolve [PATH...]` | Restore known handles from stdin or selected files |
| `pentect log [--json]` | Follow local protection events |

Use `resolve` with care. It writes real values to the selected file or output.
Use `exec` instead when a command can take a handle directly.

`mask` accepts text as arguments or reads UTF-8 standard input:

::: code-group

```sh [macOS / Linux]
printf '%s' 'TOKEN=example' | pentect mask
```

```powershell [Windows]
'TOKEN=example' | pentect mask
```

:::

## Installation health

| Command | Purpose |
| --- | --- |
| `pentect doctor` | Check readiness |
| `pentect doctor --json` | Print results as JSON |
| `pentect doctor --fix` | Show and apply approved fixes |
| `pentect doctor --fix --yes` | Apply all offered fixes without another prompt |
| `pentect update [VERSION]` | Install a verified GitHub Release binary |
| `pentect update --check` | Check without installing |
| `pentect update --force` | Reinstall even when the selected version is already present |
| `pentect uninstall` | Remove Pentect but keep project data |
| `pentect version` | Print the installed version |

## Plugins

| Command | Purpose |
| --- | --- |
| `plugins search [QUERY]` | Search the first-party catalog |
| `plugins inspect SOURCE` | Show the manifest, hooks, binary, and requested access |
| `plugins add SOURCE [--yes]` | Verify, approve, and enable a plugin in this project |
| `plugins remove NAME` | Disable a plugin in this project |
| `plugins list [--json]` | Show enabled and installed plugins |
| `plugins config NAME KEY=VALUE` | Save one JSON setting for a plugin |
| `plugins config NAME --unset KEY` | Remove one plugin setting |
| `plugins setup NAME [--yes]` | Review changed hooks or access again |
| `plugins test SOURCE [--json]` | Validate a manifest or installed binary |
| `plugins update [NAME] [--yes]` | Fetch and verify a newer release |
| `plugins new NAME` | Create a Rust Wasm plugin project |
| `plugins dev PATH [--yes]` | Build, approve, and activate a local development build |
| `plugins publish PATH` | Build a release bundle in `dist` |

`SOURCE` can be a local directory or `github:@OWNER/REPOSITORY/path`. Use
`--plugins SOURCE` on a client or mask command when you need a plugin for only
one launch.

Approval flags skip an interactive confirmation; they do not skip checksum,
build-record, manifest, or sandbox checks.

See [Plugins](/plugins/overview/) for the full workflow.
