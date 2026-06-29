Pentect is a local secret-capability boundary for AI agents: it masks tool/file/MCP/browser output before the model sees it.
Masked handles can be reused inside `pentect exec` as local env capabilities, with stdout/stderr remasked afterward.

Extensions:
- Rules packs for company-specific literals and syntax: `examples/extensions/company/pack.toml`
- Model adapters for local NER/classifier spans: `examples/extensions/ner/adapter.toml`
- Spec: `docs/EXTENSIONS.md`

TODO
- dirty log
- staring
- docs site
- easy install
