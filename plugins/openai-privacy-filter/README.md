# OpenAI Privacy Filter for Pentect

This first-party plugin adds local, context-aware PII detection from
[OpenAI Privacy Filter](https://github.com/openai/privacy-filter). The model and
the plugin process run on your computer. Pentect communicates with it over
stdin/stdout and does not expose a local HTTP port.

The model is not bundled with Pentect. Install its Python dependency in the
documented managed environment before enabling the plugin. Pentect starts the
process only when it is needed.

```sh
pentect plugins add github:@EdamAme-x/pentect/plugins/openai-privacy-filter
```

The server returns byte ranges and labels. It does not return the matched text.
Pentect turns those ranges into normal handles such as
`<<PRIVATE_EMAIL_...>>`.

OpenAI Privacy Filter is an OpenAI project released under Apache-2.0. This
plugin is maintained by Pentect and released under MIT. OpenAI does not
maintain or support this plugin.
