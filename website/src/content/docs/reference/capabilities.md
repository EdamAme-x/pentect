---
title: What Pentect can do
description: Every user-facing Pentect capability, grouped by the job it performs.
---

## Clients

| Capability | Entry point |
| --- | --- |
| Protect Codex CLI | `pentect codex` |
| Protect Claude Code | `pentect claude` |
| Launch a protected Codex App session | `pentect codex app` |
| Launch a protected Claude Desktop session | `pentect claude app` |
| Forward normal client arguments | Pass them normally, for example `pentect codex exec --full-auto` |
| Select a compatible upstream for one launch | `--upstream URL` |
| Load an additional plugin for one launch | `--plugins SOURCE` |
| Check an app setup without launching it | `pentect codex app --check` or `pentect claude app --check` |

Pentect changes only the process it launches. It does not enable a permanent
system-wide proxy or replace the client interface.

## Protected content

| Capability | Behavior |
| --- | --- |
| Prompts and tool results | Sensitive spans are replaced before supported provider requests |
| Completed tool calls | Known handles are resolved immediately before trusted local execution |
| Command output | stdout and stderr are masked before returning to the model |
| Structured configuration | Uses key and syntax context for useful labels |
| UTF-8 uploads | Inspects and rewrites supported Files API content |
| Documents | Inspects supported inline document formats |
| Images | Runs local OCR and redacts detected regions |
| QR codes and barcodes | Inspects decoded payloads during image protection |
| Unknown provider structures | Returns an error by default |

Detection covers secret and PII categories. Recognized structured sources
include dotenv, Terraform, Kubernetes Secrets,
kubeconfig, AWS, npm, PyPI, JSON, and other supported key/value formats.

## Handles

- Preserve a useful label such as `DATABASE_URL` or `KAGGLE_API_TOKEN`.
- Use a keyed identity instead of an unsalted plaintext fingerprint.
- Can stay stable per device, per project, or change per session.
- Resolve only when the current local protection context knows the handle.
- Keep unknown or invented handle-shaped text inert.
- Expose metadata through `pentect view` without printing the value.

## Local CLI

| Command | What it does |
| --- | --- |
| `pentect mask [TEXT]` | Mask arguments or UTF-8 stdin |
| `pentect read PATH` | Print a masked file preview |
| `pentect exec "COMMAND"` | Resolve known handles locally and mask command output |
| `pentect view HANDLE` | Show handle metadata without revealing plaintext |
| `pentect resolve [PATH...]` | Resolve known handles from stdin or selected files |
| `pentect log [--json]` | Follow local protection events without secret values |
| `pentect doctor [--json]` | Check the installation and supported clients |
| `pentect doctor --fix` | Offer repairable configuration changes |
| `pentect update [VERSION]` | Install a checksummed GitHub Release binary |
| `pentect update --check` | Check for an update without installing it |
| `pentect uninstall` | Remove the binary while retaining project data |

`mask` works in ordinary pipelines; no `--kind` flag is required:

```sh
cat .env | pentect mask
cat terraform.tfvars | pentect mask
```

## Custom gateways

Pentect can sit in front of an existing compatible gateway for a single
launch:

```text
pentect codex --upstream http://127.0.0.1:8080/openai/v1
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

It supports the OpenAI Responses contract used by Codex and the Anthropic
Messages contract used by Claude while preserving the configured upstream base
path.

## Configuration and local state

| Capability | Setting |
| --- | --- |
| Stable handle identity on one device | `[handles] scope = "device"` |
| Separate handle identity per project | `[handles] scope = "project"` |
| New handle identity per session | `[handles] scope = "session"` |
| Remember local file-backed recovery hints | `[files] remember = true` |
| Share protection events between compatible local processes | `[activity] share = true` |
| Require a Pentect-launched agent boundary for a project | `[agent] required = true` |
| Allow unknown provider formats explicitly | `[compatibility] unknown_formats = "ignore"` |

Pentect reads user configuration from `~/.pentect/config.toml` and project
configuration from `.pentect/config.toml`. A project cannot weaken the user's
unknown-format policy.

For exact recovery and rollback steps, see
[Unknown provider format troubleshooting](/reference/troubleshooting/#an-unknown-provider-format-was-blocked).

## Plugins

| Capability | Command or format |
| --- | --- |
| Declarative detector | Regex rules in `plugin.toml` |
| Context-aware middleware | Sandboxed WebAssembly |
| Create and run locally | `plugins new`, `plugins dev` |
| Validate behavior | `plugins test`, `plugins inspect` |
| Install from GitHub | `plugins add github:@owner/repository/path` |
| Configure and approve access | `plugins config`, `plugins setup` |
| Discover and maintain | `plugins search`, `plugins list`, `plugins update`, `plugins remove` |
| Publish | `plugins publish` |

Wasm plugins have no ambient WASI, filesystem, environment, process, or raw
socket access. Optional HTTP access is limited by declared origins, methods,
request counts, and byte limits, and requires approval.

## Installation and distribution

Pentect provides PowerShell and POSIX installers plus Homebrew, apt, Nix, npm,
and Cargo installation paths. Direct binary installers verify SHA-256 checksums,
support version selection, updating, and uninstalling, and detect installations
owned by another package manager.

Continue with [Install](/start/install/) or the [Quick start](/start/quick-start/).
