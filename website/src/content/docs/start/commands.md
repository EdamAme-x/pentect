---
title: Command guide
description: Choose the Pentect command that matches the data flow you need.
---

Pentect commands differ mainly in where plaintext is allowed to appear. Use
this guide before reaching for the advanced `resolve` command.

## Mask text or read a file

| Task | Command | Plaintext destination |
| --- | --- | --- |
| Mask UTF-8 stdin | `pentect mask` | Nowhere; protected text is printed |
| Read and mask a file | `pentect read PATH` | Nowhere; the file is not changed |
| Inspect a handle | `pentect view HANDLE` | Nowhere; only safe metadata is printed |

`read` uses the filename to recognize formats and can retain safe recovery
metadata in the active local store. `mask` is a one-run stdin filter.

::: code-group

```sh [macOS / Linux]
cat .env | pentect mask
pentect read ./config.json
pentect view '<<API_TOKEN_0123456789abcdef>>'
```

```powershell [PowerShell]
Get-Content .env -Raw | pentect mask
pentect read .\config.json
pentect view '<<API_TOKEN_0123456789abcdef>>'
```

:::

See [Handles](/start/handles/) and
[Files and images](/protection/files-and-images/) for the protection details.

## Run a local command

`pentect exec` requires a real command. It does not treat arbitrary text as a
secret, filename, or handle lookup. Pentect restores known handles only at the
local execution boundary, then masks stdout and stderr before displaying them.

Prefer the direct form after `--`; it avoids another quoting layer:

::: code-group

```sh [macOS / Linux]
pentect exec -- git status --short
pentect exec 'printf "%s\n" "hello"'
```

```powershell [PowerShell]
pentect exec -- git status --short
pentect exec 'Write-Output "hello"'
```

:::

The shell form is one command string. The direct form is a program name
followed by separate arguments. A missing executable produces a fixed Pentect
diagnostic; Pentect does not repeat the potentially sensitive command text.

For a program that reads one credential from stdin:

::: code-group

```sh [macOS / Linux]
pentect exec --secret-stdin '<<SUDO_PASSWORD_0123456789abcdef>>' -- sudo -S -p '' command
```

```powershell [PowerShell]
pentect exec --secret-stdin '<<API_TOKEN_0123456789abcdef>>' -- .\consumer.exe
```

:::

The restored value reaches the child process through stdin, but not the
terminal or Pentect log. Pentect does not append a newline. Use
`--allow-secret-argv` only when a target program cannot accept a safer channel;
same-user processes may be able to inspect process arguments.

## Resolve plaintext only when required

`pentect resolve` is advanced because its output is plaintext. With no path it
reads stdin and prints plaintext. With paths it replaces known handles in each
file in place.

```sh
pentect resolve config.masked.toml
cat masked.txt | pentect resolve > plaintext.txt
```

Both destination files now contain plaintext secret material. Prefer `exec`
when a command can consume a handle without creating a plaintext file.

## Diagnose and maintain the installation

| Task | Command | Notes |
| --- | --- | --- |
| View persistent diagnostics | `pentect log` | Values, bodies, headers, and URLs are not logged |
| Locate the log file | `pentect log --path` | Prints the local path |
| Machine-readable diagnostics | `pentect log --json` | Suitable for support tooling |
| Check readiness | `pentect doctor` | Does not change configuration |
| Offer safe repairs | `pentect doctor --fix` | Confirms changes interactively |
| Check for an update | `pentect update --check` | Does not install |
| Update Pentect | `pentect update` | Uses the recorded package-manager scope when available |
| Remove Pentect | `pentect uninstall` | Keeps project data |

For failures, include the value-free reason shown by `pentect log --json` and
follow [Troubleshooting](/reference/troubleshooting/). Installation-specific
commands are documented in [Install](/start/install/), and the complete option
list is in the [CLI reference](/reference/cli/).
