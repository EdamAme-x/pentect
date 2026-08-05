# Plugins

Pentect supports manifest-only regex detectors and sandboxed WebAssembly
middleware. Native executable plugins and postscripts are not supported.

Use a regex plugin for a stable value pattern. Use Wasm when you need context,
policy logic, provider JSON, or an approved HTTP call. Normal Pentect secret
and structured-data checks are built in and cannot be disabled by a plugin.

Install and enable a plugin for the current project:

```text
pentect plugins add github:@owner/repository/path
```

The same configured plugin set is used by `mask`, `read`, Codex,
Claude Code, and their desktop-app launchers. Use `--plugins SOURCE` only for a
one-off addition.

```text
pentect plugins new NAME
pentect plugins dev PATH
pentect plugins publish PATH
pentect plugins list
pentect plugins inspect NAME
pentect plugins config NAME key=value
pentect plugins test NAME
pentect plugins update NAME
pentect plugins remove NAME
```

`pentect plugins new` creates a Rust `cdylib`, `plugin.toml`, tests, and a
GitHub release workflow. `plugins dev` builds it for
`wasm32-unknown-unknown`, shows its requested access, and activates the local
build after approval. `plugins publish` creates the Wasm and SHA-256 files in
`dist`; it does not push them.

Wasm plugins run without WASI. They cannot directly read files or environment
variables, start a program, or open a socket. Optional HTTP access must list
exact origins and methods in `plugin.toml`. Pentect checks this access and asks
the user to approve it.

First-party examples are listed by `pentect plugins search`:

- `example-regex` is a complete one-file detector.
- `openai-privacy-filter` connects a sandboxed adapter to OpenAI Privacy Filter
  running on `127.0.0.1`. It is optional and is not enabled automatically.

Remote manifests are pinned locally. They change only through an explicit
`add`, `setup`, or `update`, never merely because a cache timer expired.
Run `pentect plugins update` without a name to update every enabled plugin.

The complete guide covers regex plugins, the Rust SDK, every manifest field,
local development, publishing, and the first-party OpenAI Privacy Filter
adapter: https://pentect.dev/plugins/overview/
