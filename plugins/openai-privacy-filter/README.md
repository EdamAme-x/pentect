# OpenAI Privacy Filter for Pentect

This first-party plugin adds local, context-aware PII detection from
[OpenAI Privacy Filter](https://github.com/openai/privacy-filter). The model and
the bridge run on your computer. The Wasm plugin can connect only to
`http://127.0.0.1:8787`.

The model is not bundled with Pentect. Install and start it before enabling the
plugin. See the [Pentect guide](https://pentect.dev/plugins/official/) for full
setup steps, limits, and removal instructions.

```sh
python server.py --device cpu
pentect plugins add github:@EdamAme-x/pentect/plugins/openai-privacy-filter
```

The server returns byte ranges and labels. It does not return the matched text.
Pentect turns those ranges into normal handles such as
`<<PRIVATE_EMAIL_...>>`.

OpenAI Privacy Filter is an OpenAI project released under Apache-2.0. This
adapter is maintained by Pentect and released under MIT. OpenAI does not
maintain or support this adapter.
