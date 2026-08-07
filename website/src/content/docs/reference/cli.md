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
| `pentect opencode` | Launch OpenCode with a temporary Pentect provider |
| `pentect pi` | Launch Pi with a temporary Pentect provider |
| `pentect codex app` | Launch Codex App for this protected session |
| `pentect claude app` | Launch Claude Desktop for this protected session |

For Codex and Claude, `--set-default` adds a reviewed function to the current
shell's user profile. The normal `codex` or `claude` command then launches
through Pentect. `--unset-default` removes only the block Pentect added.

```sh
pentect codex --set-default
pentect codex --unset-default
```

PowerShell, Bash, Zsh, and Fish are supported. Add `--yes` only in automation
where you have already reviewed the profile change.

### App launchers

Add an optional clickable launcher for a desktop App:

```sh
pentect codex app --install-launcher
pentect claude app --install-launcher
```

| Option | Result |
| --- | --- |
| `--install-launcher` | Add or refresh the current user's Pentect launcher |
| `--remove-launcher` | Remove only the launcher owned by Pentect |
| `--yes` | Skip the confirmation in reviewed automation |

Windows and macOS are supported. Both commands show the exact target and ask
before changing it. The launcher does not store a custom `--app`, `--upstream`,
or `--plugins` value; use the normal terminal launch for those one-time options.

Use `--upstream URL` to choose a compatible gateway for one launch. Use
`--upstream-header-env HEADER=ENV_NAME` to add a gateway credential without
putting its value in command arguments. The source variable is removed from the
launched client process. Use `--plugins SOURCE` to add a plugin for one launch.
App commands also support
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
| `pentect mask` | Mask UTF-8 text from stdin |
| `pentect read PATH` | Print a masked preview of a file |
| `pentect exec "COMMAND"` | Restore known handles, run the command, and mask its output |
| `pentect view HANDLE` | Show handle details without revealing its value |
| `pentect resolve [PATH...]` | Restore known handles from stdin or selected files |
| `pentect log [--json]` | Follow local protection events |

Use `resolve` with care. It writes real values to the selected file or output.
Use `exec` instead when a command can take a handle directly.

### `mask`

Mask UTF-8 standard input. It infers structured formats from content when no
path is available.

```sh
printf '%s' 'TOKEN=fake-value' | pentect mask
cat .env | pentect mask
printf '%s' 'CASE-12345678' | pentect mask --plugins ./company-policy
```

### `read`

Read a path with filename-aware format detection and print only the protected
preview:

```sh
pentect read .env
pentect read terraform.tfvars
```

When file remembering is enabled, `read` also records safe local recovery
metadata for handles found in that file.

### `exec`

`exec` restores known handles before execution and masks stdout and stderr:

| Form | Behavior |
| --- | --- |
| `pentect exec "COMMAND"` | Run through the native shell |
| `pentect exec -- PROGRAM ARG...` | Run a program directly without shell parsing |
| `pentect exec --stdin` | Read the shell script from UTF-8 stdin |
| `pentect exec --live "COMMAND"` | Stream masked output instead of buffering it |
| `--script-shell native\|bash\|powershell` | Choose the shell for script forms |
| `--session NAME` | Use an explicit local session instead of the current-directory session |

```sh
pentect exec -- curl -H 'Authorization: Bearer <<API_TOKEN_...>>' https://api.example.test/me
printf '%s' 'tool <<API_TOKEN_...>>' | pentect exec --stdin
```

Use the direct program form when possible. It avoids another layer of shell
quoting. `--live` keeps interactive progress visible but still masks output in
chunks before it is written.

### `view` and `resolve`

`view` parses a handle and prints its label, ID, and safe length hint. It does
not require or reveal the real value.

`resolve` reads stdin when no path is given. With paths, it replaces known
handles in each file in place. Unknown handle-shaped text causes an error
instead of being guessed.

```sh
pentect view '<<DATABASE_URL_4ce8a3b0a6f64e12>>'
cat masked.txt | pentect resolve > plaintext.txt
pentect resolve config.masked.toml
```

Treat redirected or in-place resolved output as plaintext secret material.

`mask` reads UTF-8 standard input:

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

## Output for scripts

Commands with `--json` produce machine-readable JSON. Human output can change
for clarity, so scripts should use JSON where offered. Pentect uses a non-zero
exit code for invalid arguments, blocked content, launch failures, and failed
updates. A launched program keeps its own exit code.

See [Plugins](/plugins/overview/) for the full workflow.
