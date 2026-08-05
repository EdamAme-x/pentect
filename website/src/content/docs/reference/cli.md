---
title: CLI reference
description: Pentect commands and what they do.
---

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

## Installation health

| Command | Purpose |
| --- | --- |
| `pentect doctor` | Check readiness |
| `pentect doctor --json` | Print results as JSON |
| `pentect doctor --fix` | Show and apply approved fixes |
| `pentect update [VERSION]` | Install a verified GitHub Release binary |
| `pentect update --check` | Check without installing |
| `pentect uninstall` | Remove Pentect but keep project data |
| `pentect version` | Print the installed version |

## Plugins

```sh
pentect plugins new NAME
pentect plugins dev PATH
pentect plugins publish PATH
pentect plugins add SOURCE [--yes]
pentect plugins remove NAME
pentect plugins list [--json]
pentect plugins search [QUERY] [--json]
pentect plugins inspect NAME [--json]
pentect plugins test NAME [--json]
pentect plugins config NAME [KEY=VALUE | --unset KEY]
pentect plugins setup NAME [--yes]
pentect plugins update [NAME] [--yes]
```
