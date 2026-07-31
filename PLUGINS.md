# Plugins

Pentect supports manifest-only regex detectors and sandboxed WebAssembly
middleware. Native executable plugins and postscripts are not supported.

Install and enable a plugin for the current project:

```text
pentect plugins add github:@owner/repository/path
```

The same configured plugin set is used by `mask`, `read`, `scan`, Codex,
Claude Code, and their desktop-app launchers. Use `--plugins SOURCE` only for a
one-off addition.

```text
pentect plugins list
pentect plugins inspect NAME
pentect plugins config NAME key=value
pentect plugins test NAME
pentect plugins update NAME
pentect plugins remove NAME
```

Remote manifests are pinned locally. They change only through an explicit
`add`, `setup`, or `update`, never merely because a cache timer expired.
Run `pentect plugins update` without a name to update every enabled plugin.

See [the plugin guide](guides/plugins.md) for the manifest, WebAssembly ABI,
network approval, publishing, and SDK documentation.
