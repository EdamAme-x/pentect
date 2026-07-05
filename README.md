[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/EdamAme-x/pentect?utm_source=oss&utm_medium=github&utm_campaign=EdamAme-x%2Fpentect&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)](https://coderabbit.ai)

Pentect is a local secret-capability boundary for AI agents: it masks tool/file/MCP/browser output before the model sees it.
Masked handles can be reused inside `pentect exec` as local env capabilities, with stdout/stderr remasked afterward.

作り途中

Extensions:
- Rules packs for company-specific literals and syntax: `examples/extensions/company/pack.toml`
- Model adapters for local NER/classifier spans: `examples/extensions/ner/adapter.toml`

TODO
- codex issue
- host prompt secret (patch...?)
- pdf as exts, image as exts, etc...
- dirty log
- staring
- docs site
- easy install

- opencode, antigravity cli, pico, https://github.com/usestrix/strix
