---
title: Plugins
description: Extend Pentect with declarative detectors or sandboxed Wasm middleware.
---

Pentect plugins come in two forms:

1. Manifest-only regex detectors for compact pattern matching.
2. WebAssembly middleware for logic that cannot be expressed as an automaton.

Native executable plugins and postscripts are not supported.

## Install a plugin

```sh
pentect plugins add github:@owner/repository/path
```

The configured plugin set applies consistently to `mask`, local execution,
Codex, Claude, and supported desktop-app launchers.

## Manage plugins

```sh
pentect plugins list
pentect plugins inspect NAME
pentect plugins config NAME key=value
pentect plugins test NAME
pentect plugins update NAME
pentect plugins remove NAME
```

Remote manifests are pinned locally. They change only after an explicit add,
setup, or update operation—not because a cache timer expired.

## Sandbox and permissions

Wasm middleware runs without WASI. It has no ambient filesystem, environment,
process, or socket access. Network destinations and permissions that can change
payloads require explicit user approval.
