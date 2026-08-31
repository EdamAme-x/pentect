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

OpenAI Privacy Filter is an OpenAI project released under Apache-2.0. This
plugin is maintained by Pentect and released under MIT. OpenAI does not
maintain or support this plugin.
