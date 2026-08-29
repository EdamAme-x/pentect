---
title: Official plugins
description: First-party plugins and examples maintained with Pentect.
---

Pentect's built-in engine works without plugins. Plugins add user-wide or
project-specific rules and optional local models.

## Built-in protection

The Pentect binary includes a native implementation driven by pinned
CredSweeper assets, Pentect-maintained structured secret checks, and a bundled
Alcatraz helper for selected personal-data types. These sources have different
evidence and must not be described as one upstream detector. See
[Detectors and evidence](/protection/detectors/) for the exact inventory and
limits. Plugins cannot disable the built-in checks.

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

### Install

```sh
pentect plugins add github:@EdamAme-x/pentect/plugins/openai-privacy-filter
```

Pentect shows the expected transfer and disk cost, asks once, detects a
compatible NVIDIA driver, and installs the complete managed environment. The
automatic profile chooses CUDA when a supported NVIDIA driver is visible and
CPU otherwise. Linux and Windows CPU installation use PyTorch's official
CPU-only wheel index, so they do not pull CUDA runtimes. macOS uses PyTorch's
official default package and the CPU device because OPF currently exposes
`cpu` and `cuda`, not an MPS profile. Unsupported architectures do not select
an x86-only CUDA wheel.

Force a profile when automatic selection is not what you want:

```sh
pentect plugins add github:@EdamAme-x/pentect/plugins/openai-privacy-filter --profile cpu
pentect plugins setup openai-privacy-filter --profile cuda
```

The selected profile is stored in
`~/.pentect/openai-privacy-filter/setup.json`. Updates keep an explicit choice;
run `plugins setup --profile auto` to return to driver-based selection. CPU and
CUDA environments share the same roughly 2.8 GB checkpoint. Switching profiles
therefore replaces PyTorch and the managed virtual environment, not the model.

Review the exact runtime and environment setup commands, downloaded file
hashes, `inspect` hook, and required status. Pentect prepares the model before
enabling the plugin, so the first protected request does not unexpectedly start
a multi-gigabyte download. The first process start has a five-minute model-load
budget; later requests retain the normal 60-second inference limit.

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
| `opf` is missing | Run `pentect plugins setup openai-privacy-filter` |
| Python is missing | Install a supported Python executable, then run `pentect plugins setup openai-privacy-filter` |
| CUDA setup is unavailable | Update the NVIDIA driver or select `--profile cpu` |
| CPU use is high | Select CUDA, or remove the plugin when it is not needed |
| Plugin file or command changed | Inspect it, then run `pentect plugins setup` |

Remove the user-wide installation:

```sh
pentect plugins remove openai-privacy-filter
```

You may then delete `~/.pentect/openai-privacy-filter`. OpenAI Privacy Filter is
Apache-2.0. The Pentect integration is MIT and is not maintained by OpenAI.
