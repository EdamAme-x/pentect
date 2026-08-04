---
title: CLI reference
description: User-facing Pentect commands and their purpose.
---

## Launch clients

| Command | Purpose |
| --- | --- |
| `pentect codex` | Launch Codex CLI through Pentect |
| `pentect claude` | Launch Claude Code through Pentect |
| `pentect codex app` | Launch Codex App for this protected session |
| `pentect claude app` | Launch Claude Desktop for this protected session |

Client launchers accept `--upstream URL` for a compatible upstream and
`--plugins SOURCE` for a one-off plugin addition. App launchers also accept
`--app PATH` and `--check`.

Codex and Claude arguments are forwarded directly:

```text
pentect codex exec --full-auto
pentect claude --model sonnet
```

## Protect local input and execution

| Command | Purpose |
| --- | --- |
| `pentect mask [TEXT]` | Mask arguments or UTF-8 stdin |
| `pentect read PATH` | Print a masked preview of a file |
| `pentect exec "COMMAND"` | Resolve known handles locally, run the command, and mask stdout/stderr |
| `pentect view HANDLE` | Show handle metadata without revealing its value |
| `pentect resolve [PATH...]` | Resolve known handles from stdin or in selected files |
| `pentect log [--json]` | Follow local protection events |

Use `resolve` carefully: resolving a file writes plaintext to its destination.
Prefer `exec` when a command can consume a handle directly.

## Installation health

| Command | Purpose |
| --- | --- |
| `pentect doctor` | Check readiness |
| `pentect doctor --json` | Emit machine-readable diagnostics |
| `pentect doctor --fix` | Offer safe repairs |
| `pentect update [VERSION]` | Install a verified GitHub Release binary |
| `pentect update --check` | Check without installing |
| `pentect uninstall` | Remove the binary while retaining project data |
| `pentect version` | Print the installed version |

## Plugins

```text
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
