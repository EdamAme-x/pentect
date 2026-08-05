---
title: What Pentect can do
description: A full list of what you can do with Pentect.
---

## Clients

| Capability | Entry point |
| --- | --- |
| Protect Codex CLI | `pentect codex` |
| Protect Claude Code | `pentect claude` |
| Launch a protected Codex App session | `pentect codex app` |
| Launch a protected Claude Desktop session | `pentect claude app` |
| Pass normal client arguments | Add them normally, for example `pentect codex exec --full-auto` |
| Select a compatible gateway for one launch | `--upstream URL` |
| Add a plugin for one launch | `--plugins SOURCE` |
| Check an app setup without launching it | `pentect codex app --check` or `pentect claude app --check` |

Pentect changes only the process it starts. It does not create a permanent
proxy for the whole system or replace the client UI.

## Protected content

| Capability | Behavior |
| --- | --- |
| Prompts and tool results | Replaces sensitive text before supported requests are sent |
| Completed tool calls | Restores known handles just before a trusted local tool runs |
| Command output | Masks stdout and stderr before they return to the model |
| Structured config | Uses field names and syntax to create useful labels |
| UTF-8 uploads | Checks and rewrites supported Files API content |
| Documents | Checks supported document formats sent in a request |
| Images | Runs local OCR and covers sensitive areas |
| QR codes and barcodes | Checks the text found in codes inside images |
| Unknown provider structures | Returns an error by default |

Pentect checks for secrets and personal data. Supported config formats include
dotenv, Terraform, Kubernetes Secrets, kubeconfig, AWS, npm, PyPI, JSON, and
other key/value formats.

## Handles

- Keep a useful label such as `DATABASE_URL` or `KAGGLE_API_TOKEN`.
- Use a private key when creating the handle ID.
- Can stay the same per device or project, or change each session.
- Are restored only when the current local session knows them.
- Do not restore unknown or invented handle-like text.
- Show handle details through `pentect view` without printing the value.

## Local CLI

| Command | What it does |
| --- | --- |
| `pentect mask [TEXT]` | Mask arguments or UTF-8 stdin |
| `pentect read PATH` | Print a masked file preview |
| `pentect exec "COMMAND"` | Restore known handles and mask command output |
| `pentect view HANDLE` | Show handle details without revealing the real value |
| `pentect resolve [PATH...]` | Restore known handles from stdin or selected files |
| `pentect log [--json]` | Follow local protection events without secret values |
| `pentect doctor [--json]` | Check the installation and supported clients |
| `pentect doctor --fix` | Offer repairable configuration changes |
| `pentect update [VERSION]` | Install a checksummed GitHub Release binary |
| `pentect update --check` | Check for an update without installing it |
| `pentect uninstall` | Remove Pentect but keep project data |

```sh
cat .env | pentect mask
cat terraform.tfvars | pentect mask
```

## Custom gateways

Pentect can use an existing compatible gateway for one launch:

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

It supports the OpenAI Responses API used by Codex and the Anthropic Messages
API used by Claude. It keeps the base path from your gateway URL.

## Configuration and local state

| Capability | Setting |
| --- | --- |
| Stable handle identity on one device | `[handles] scope = "device"` |
| Separate handle identity per project | `[handles] scope = "project"` |
| New handle identity per session | `[handles] scope = "session"` |
| Remember where file-based handles came from | `[files] remember = true` |
| Share protection events between compatible local processes | `[activity] share = true` |
| Require the agent to start through Pentect | `[agent] required = true` |
| Allow unknown provider formats after a user choice | `[compatibility] unknown_formats = "ignore"` |

Pentect reads user settings from `~/.pentect/config.toml` and project settings
from `.pentect/config.toml`. A project cannot lower the user's protection for
unknown formats.

For exact recovery and rollback steps, see
[Unknown provider format troubleshooting](/reference/troubleshooting/#an-unknown-provider-format-was-blocked).

## Plugins

| Capability | Command or format |
| --- | --- |
| Regex detector | Regex rules in `plugin.toml` |
| Plugin code with more logic | Sandboxed WebAssembly |
| Create and run locally | `plugins new`, `plugins dev` |
| Validate behavior | `plugins test`, `plugins inspect` |
| Install from GitHub | `plugins add github:@owner/repository/path` |
| Configure and approve access | `plugins config`, `plugins setup` |
| Discover and maintain | `plugins search`, `plugins list`, `plugins update`, `plugins remove` |
| Publish | `plugins publish` |
| Local model example | First-party OpenAI Privacy Filter adapter |

Wasm plugins cannot directly use WASI, files, environment variables, processes,
or network sockets. Optional HTTP access needs approval and has limits for
hosts, methods, request count, and data size.

See [Plugins](/plugins/overview/) for the full workflow and
[Official plugins](/plugins/official/) for ready examples.

## Installation and distribution

You can install Pentect with PowerShell, a shell script, Homebrew, apt, Nix,
npm, or Cargo. The binary installers check SHA-256 checksums. They support
version choice, updates, and uninstall. They also find installs managed by
another package manager.

Continue with [Install](/start/install/) or the [Quick start](/start/quick-start/).
