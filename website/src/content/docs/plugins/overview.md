---
title: Plugins
description: Add custom checks with regex rules or safe Wasm code.
---

Pentect plugins come in two forms:

1. Regex rules in a manifest for simple pattern checks.
2. WebAssembly (Wasm) code for checks that need more logic.

Native executable plugins and postscripts are not supported.

| Form | Best for | Runtime |
| --- | --- | --- |
| Manifest detector | Clear pattern and label rules | Runs as part of Pentect's normal checks |
| Wasm middleware | Context, choices, settings, or request and response control | Runs in a Wasm sandbox with time and memory limits |

Start with a manifest detector. Use Wasm only when a regular expression cannot
do the job.

## Install a plugin

```sh
pentect plugins add github:@owner/repository/path
```

Your plugin setup works with `mask`, local commands, Codex, Claude, and
supported desktop apps.

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

Pentect saves the exact remote manifest locally. It changes only when you run
an add, setup, or update command. A cache timer cannot change it.

## Installation lifecycle

1. `add` finds the source and saves the manifest.
2. `setup` downloads and verifies a Wasm binary when the plugin has one.
3. Pentect shows the plugin hooks and requested access for your approval.
4. Pentect links the binary hash, manifest, and approval together.
5. `update` gets a newer version. You must approve a changed binary or new access again.

Use `inspect` before approval and `test` after setup. If an installed binary
changes, Pentect blocks it until you check it again.

## Sandbox and permissions

Wasm code runs without WASI. It cannot directly use files, environment
variables, processes, or network sockets. You must approve network targets and
any access that can change data.

Plugins can use these hooks: `prepare`, `inspect`, `finalize`, `request`,
`response`, `tool_call`, and `file`. After a hook succeeds, Pentect runs the
next plugin. Any hook can block an action. Only `request` can return a response
directly. HTTP calls have limits for approved hosts, methods, size, number of
requests, and time. Private or insecure hosts need extra approval.
