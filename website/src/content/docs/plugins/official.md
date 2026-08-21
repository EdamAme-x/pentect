---
title: Official plugins
description: First-party plugins and examples maintained with Pentect.
---

Pentect's built-in engine works without plugins. Plugins add user-wide or
project-specific rules and optional local models.

## Built-in protection

The Pentect binary includes CredSweeper-derived secret rules, structured labels
for dotenv, Terraform, Kubernetes, JSON, and other config formats, plus checks
for supported documents and images. Plugins cannot disable these checks.

## Plugin catalog

| Plugin | Type | Best for |
| --- | --- | --- |
| `example-regex` | Manifest | Learning and fixed company patterns |
| `openai-privacy-filter` | Command | Context-aware English PII with a local model |

```sh
pentect plugins search
```

## Example regex

```sh
pentect plugins add github:@EdamAme-x/pentect/plugins/example-regex
```

Its
[`plugin.toml`](https://github.com/EdamAme-x/pentect/blob/main/plugins/example-regex/plugin.toml)
is a complete one-file example.

## OpenAI Privacy Filter

This plugin runs [OpenAI Privacy Filter](https://github.com/openai/privacy-filter)
on your computer. Pentect starts it as a managed Command process and exchanges
JSONL over stdin/stdout. There is no local HTTP server.

The model is large and mainly targets English. It can still miss private text
or mark safe text, so built-in detection stays enabled.

### 1. Install the model

The commands create the location that the plugin automatically detects.

::: code-group

```powershell [Windows]
$root = "$HOME\.pentect\openai-privacy-filter"
py -m venv "$root\venv"
& "$root\venv\Scripts\python.exe" -m pip install `
  "git+https://github.com/openai/privacy-filter.git@f7f00ca7fb869683eb732c010299d901457f19c3"
& "$root\venv\Scripts\python.exe" -c `
  "from opf import OPF; OPF(device='cpu', output_mode='typed', output_text_only=False).get_runtime()"
```

```sh [macOS / Linux]
root="$HOME/.pentect/openai-privacy-filter"
python3 -m venv "$root/venv"
"$root/venv/bin/python" -m pip install \
  "git+https://github.com/openai/privacy-filter.git@f7f00ca7fb869683eb732c010299d901457f19c3"
"$root/venv/bin/python" -c \
  "from opf import OPF; OPF(device='cpu', output_mode='typed', output_text_only=False).get_runtime()"
```

:::

### 2. Add the plugin

```sh
pentect plugins add github:@EdamAme-x/pentect/plugins/openai-privacy-filter
```

Review the exact Python command, `server.py` hash, `inspect` hook, and required
status. Pentect starts the process only when protected text needs inspection.
The install command prepares the model runtime so the first protected request
does not have to download it.

Test with fake data:

```sh
echo "Email Alice at alice@example.test" | pentect mask
```

### How it connects

```text
Pentect engine
  -> managed Python Command process over JSONL
  -> local OpenAI Privacy Filter model
  -> byte ranges and labels
  -> Pentect handles
```

The plugin returns ranges and labels, not copies of matched values. Pentect
still creates and owns the handles. Because Command is native, it has the same
OS access as the user; enable only plugins you trust.

### Common problems

| Symptom | What to do |
| --- | --- |
| Python or `opf` is missing | Repeat the managed-environment install step |
| First request times out | Let the checkpoint finish downloading, then retry |
| CPU use is high | Remove the plugin when the local model is not needed |
| Plugin file or command changed | Inspect it, then run `pentect plugins setup` |

Remove the user-wide installation:

```sh
pentect plugins remove openai-privacy-filter
```

You may then delete `~/.pentect/openai-privacy-filter`. OpenAI Privacy Filter is
Apache-2.0. The Pentect integration is MIT and is not maintained by OpenAI.
