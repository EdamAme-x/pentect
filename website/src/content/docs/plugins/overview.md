---
title: Plugins
description: Extend Pentect with declarative detectors or sandboxed Wasm middleware.
---

Pentect plugins come in two forms:

1. Manifest-only regex detectors for compact pattern matching.
2. WebAssembly middleware for logic that cannot be expressed as an automaton.

Native executable plugins and postscripts are not supported.

| Form | Best for | Runtime |
| --- | --- | --- |
| Manifest detector | Deterministic pattern and label rules | Built into Pentect's detection pass |
| Wasm middleware | Context, branching, configuration, request or response control | Fuel- and memory-bounded WebAssembly sandbox |

A manifest detector is the default choice. Use Wasm only when a regular
expression cannot express the required behavior.

## Install a plugin

```sh
pentect plugins add github:@owner/repository/path
```

The configured plugin set applies consistently to `mask`, local execution,
Codex, Claude, and supported desktop-app launchers.

Plugins may also be selected for a single client launch:

```sh
pentect codex --plugins jp-pii
pentect claude --plugins jp-pii,company-policy
```

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

## Installation lifecycle

1. `add` resolves the source and stores the manifest.
2. `setup` downloads and verifies a Wasm binary when the plugin has one.
3. Pentect shows the discovered hooks and requested access for approval.
4. A binary digest, manifest state, and approval are locked together locally.
5. `update` fetches a newer version explicitly. Changed binary or hook access requires approval again.

Use `inspect` before approval and `test` after setup. A modified installed
binary is rejected until it is verified again.

## Sandbox and permissions

Wasm middleware runs without WASI. It has no ambient filesystem, environment,
process, or socket access. Network destinations and permissions that can change
payloads require explicit user approval.

Available hooks are `prepare`, `inspect`, `finalize`, `request`, `response`,
`tool_call`, and `file`. A successful hook continues to the next plugin
automatically. A plugin can block at any hook; only the request hook can return
a response directly. Outbound HTTP is limited to approved origins, methods,
sizes, request counts, and timeouts. Private or insecure origins require
additional explicit approval.
