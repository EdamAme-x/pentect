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
| `gliner-pii-small` | Command | Experimental lightweight local PII detection |
| `local-llm-masking` | Command | Experimental local LLM extraction of secrets and PII |

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

## GLiNER PII Small

An experimental first-party bridge for
[GLiNER PII small](https://huggingface.co/knowledgator/gliner-pii-small-v1.0).
Install it explicitly to add PII detection; it is not enabled by default.

```sh
pentect plugins add github:@EdamAme-x/pentect/plugins/gliner-pii-small --profile cpu
```

Setup downloads pinned weights and a managed Python environment. Runtime
inspection is offline, over stdin/stdout, with no model API or HTTP listener.
Python 3.10–3.13 is required. CPU is the default; `--profile cuda` selects NVIDIA
CUDA 12.4 wheels. macOS uses CPU. Allow several GB for the runtime and weights.

The detector is primarily English and can both miss private text and mask safe
text. Input is processed in overlapping 1,000-character windows, so long values
or dependencies across windows remain a limitation. Built-in secret checks stay
enabled. Installing the plugin opts into its PII detection independently of the
built-in PII switches.

This plugin is marked required: inference and protocol failures block the
request. An empty but incorrect prediction is still a possible false negative.
The native process has the user's OS permissions; review it before approval.

Bridge unit tests cover byte offsets and response validation, not real-model
quality. See the [integration README](https://github.com/EdamAme-x/pentect/tree/main/plugins/gliner-pii-small)
for setup, limitations, and removal.

## Local LLM Masking

An experimental first-party plugin maintained in the separate
[Local LLM Masking repository](https://github.com/EdamAme-x/pentect-local-llm-masking-plugin).
It supplements built-in detection with **Gemma 4 E2B IT** and is off by default.

### Install

Install the tested revision with Python 3.10–3.13 available:

```sh
pentect plugins add github:@EdamAme-x/pentect-local-llm-masking-plugin/plugin.toml@5759a22be3fd8440c9e9442d6112443ef6168639 --profile cpu
```

For a compatible NVIDIA GPU, replace `--profile cpu` with `--profile cuda`.
Allow 25 GB of disk space and 24 GB of RAM for CPU inference, or roughly 11 GB
of GPU memory for CUDA. Setup downloads pinned weights and a managed Python
environment. Inference runs offline over stdin/stdout, without a model API or
HTTP listener. Review the native process before approving its OS access.

### How it masks

The prompt asks the model to extract exact values into a JSON array, labeled
as secrets, names, email addresses, phone numbers, addresses, or account numbers.
It excludes public URLs, code identifiers, hashes, UUIDs, and placeholders.
Local code validates that each extracted value occurs in the original text and
converts it into UTF-8 byte ranges. **Pentect creates and restores the handles**;
the model does not rewrite your text or generate handles.

Built-in checks stay enabled. Installing this plugin also enables its PII
detection independently of the built-in PII switches.

### Measured performance and limits

On a Windows RTX 5080, the initial 41-case synthetic test measured a median
inference time of **1.71 seconds**, with full coverage of **30 of 31 annotated
entities** and false positives in **2 of 10 clean cases**. Peak GPU allocation
was about 10.4 GB. These are small synthetic tests, not a production accuracy
guarantee. See the [benchmark report](https://github.com/EdamAme-x/pentect-local-llm-masking-plugin/blob/main/BENCHMARKS.md)
for datasets, CPU results, and model comparisons.

Input is split into 3,500-character windows with 500-character overlap. Long
inputs need multiple inference calls and can exceed the 60-second request
timeout; entities or context crossing windows can be missed. Exact substring
validation does not prevent semantic mistakes or prompt injection.

This plugin is required: malformed output and inference failures block the
request. A valid but incorrect prediction, including `[]`, can still miss
secrets. Use it as supplemental detection, not your only protection.

Pentect 0.0.94 has a [Command-plugin update issue](https://github.com/EdamAme-x/pentect/issues/1506).
Use an explicitly reviewed, pinned revision rather than relying on a moving
branch to refresh cached files; see the repository's installation instructions.

Remove the user-wide installation with:

```sh
pentect plugins remove local-llm-masking
```

Downloaded weights and environments remain in `~/.pentect/local-llm-masking`.

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

### What CI verifies

Plugin-sensitive pull requests run the installed plugin lifecycle on Linux,
macOS, and Windows. That required CI uses deterministic manifest, Command, and
Wasm fixtures to cover installation, approval, setup, update, removal,
required and optional failures, process cleanup, scope isolation, and
value-free diagnostics. It also runs the OpenAI Privacy Filter bridge unit
tests with fixture setup state.

Pull-request CI does **not** download the multi-gigabyte OpenAI Privacy Filter
checkpoint, install its real managed Python environment, run model inference,
test CUDA, or sign in to an AI provider. A green pull request therefore does
not claim that those heavyweight boundaries were exercised.

The repository includes a separate
[`live_e2e.py`](https://github.com/EdamAme-x/pentect/blob/main/plugins/openai-privacy-filter/tests/live_e2e.py)
for the real model. It verifies real setup and checkpoint state, the direct
plugin protocol including a warm second request, cold and restarted Pentect
masking, worker cleanup, removal, and an installed Codex flow against a
localhost recorder without sending a request to OpenAI.

The `OpenAI Privacy Filter live smoke` workflow runs this test weekly with the
CPU profile and also supports manual CPU runs. The managed Python environment
and checkpoint are cached by the setup revision and runtime identity. Its
bounded artifact contains timing evidence and persistent logs only after a
fixture-plaintext scan succeeds. A manually selected CUDA profile targets a
separately managed self-hosted Linux runner labeled `gpu` and `nvidia`; CUDA is
not a pull-request or scheduled-release gate.

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
