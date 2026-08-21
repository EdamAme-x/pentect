# OpenAI Privacy Filter for Pentect

This first-party plugin adds local, context-aware PII detection from
[OpenAI Privacy Filter](https://github.com/openai/privacy-filter). The model and
the plugin process run on your computer. Pentect communicates with it over
stdin/stdout and does not expose a local HTTP port.

The model is not bundled with Pentect. During plugin approval, Pentect displays
the expected cost and creates the managed environment at
`~/.pentect/openai-privacy-filter/venv`. Automatic setup selects a compatible
NVIDIA CUDA wheel when available and the official CPU-only PyTorch wheel
otherwise. See the
[setup guide](https://pentect.dev/plugins/official/#openai-privacy-filter).

```sh
pentect plugins add github:@EdamAme-x/pentect/plugins/openai-privacy-filter
pentect plugins setup openai-privacy-filter --profile cpu
```

The server returns byte ranges and labels. It does not return the matched text.
Pentect turns those ranges into normal handles such as
`<<PRIVATE_EMAIL_...>>`.

OpenAI Privacy Filter is an OpenAI project released under Apache-2.0. This
plugin is maintained by Pentect and released under MIT. OpenAI does not
maintain or support this plugin.
