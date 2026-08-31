# OpenAI Privacy Filter for Pentect

This first-party plugin adds local, context-aware PII detection from
[OpenAI Privacy Filter](https://github.com/openai/privacy-filter). The model and
the plugin process run on your computer. Pentect communicates with it over
stdin/stdout and does not expose a local HTTP port.

The model is not bundled with Pentect. During plugin approval, Pentect displays
the expected cost and creates the managed environment at
`~/.pentect/openai-privacy-filter/venv`. Automatic setup selects a compatible
NVIDIA CUDA wheel when available, the official CPU-only PyTorch index on Linux
and Windows otherwise, and PyTorch's official default package on macOS. See the
[setup guide](https://pentect.dev/plugins/official/#openai-privacy-filter).

```sh
pentect plugins add github:@EdamAme-x/pentect/plugins/openai-privacy-filter --profile cpu
```

To change the profile later, run
`pentect plugins setup openai-privacy-filter --profile cuda`.

On CPU, Pentect bounds the Privacy Filter model's internal MoE working set to
avoid excessive temporary memory traffic. Set
`PENTECT_OPF_CPU_MOE_BATCH_SIZE` to a positive integer to tune this for a
specific machine, or to `0` to use the upstream checkpoint setting unchanged.
This setting does not apply to CUDA.

The server returns byte ranges and labels. It does not return the matched text.
Pentect turns those ranges into normal handles such as
`<<PRIVATE_EMAIL_...>>`.

## Live end-to-end test

The live test runs setup without fixture mode, loads the real model, verifies
the plugin protocol directly against that model, masks synthetic PII through
Pentect, then repeats the mask in a new Pentect process. It also launches the
installed Codex CLI through Pentect and a local Responses API recorder. The
recorder verifies that synthetic PII reached the upstream as a handle, never as
plaintext, and returns a complete local response that Codex must consume
without a plugin timeout. No OpenAI request is made by that step. It may
download several gigabytes when the managed environment is not ready.

```sh
python3 plugins/openai-privacy-filter/tests/live_e2e.py \
  --pentect ./target/debug/pentect \
  --codex "$(command -v codex)" \
  --profile cpu
```

Use `--skip-codex` only when validating the model integration without an
installed Codex CLI.

## Performance benchmark

The benchmark keeps one real plugin process alive, records model startup and
warm request latency, and rejects runs that fail to detect the synthetic PII.
It does not contact OpenAI.

```sh
python3 plugins/openai-privacy-filter/tests/benchmark.py \
  --iterations 5 --sizes 64 256 1024
```

Pass `--batch-size 0` to measure the pinned upstream model configuration as a
baseline. The command prints a versioned JSON report with all samples, p50,
p95, and maximum latency. Add `--compare-unchunked` to start a second baseline
process after the optimized run and require byte ranges and labels to match
exactly for every requested input size.

OpenAI Privacy Filter is an OpenAI project released under Apache-2.0. This
plugin is maintained by Pentect and released under MIT. OpenAI does not
maintain or support this plugin.
