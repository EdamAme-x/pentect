---
title: Plugins
description: Add your own detection rules and request checks to Pentect.
---

A plugin can find sensitive text or change how Pentect handles a request. You
can write a small regex plugin with only `plugin.toml`. For more control, write
a WebAssembly (Wasm) plugin with the Rust SDK. A local model or existing tool
can use the language-neutral Command protocol.

Plugins are not enabled by default. You choose each plugin and review its
access before you use it.

Pentect's normal secret and structured-data checks do not depend on plugins.
See [Official plugins](/plugins/official/#built-in-protection) for what is
already included.

## Choose a plugin type

| Type | Use it for | Files you write |
| --- | --- | --- |
| Manifest | Company IDs, internal names, or tokens with a clear regex | `plugin.toml` |
| Wasm | Context-aware checks, request changes, local model integrations, or custom policy | `plugin.toml`, Wasm source, and tests |
| Command | Python, native tools, local models, or Docker | `plugin.toml` and an executable speaking JSONL |

Start with Manifest. Use Wasm when the plugin needs sandboxed logic or approved
host access. Use Command when the workload already needs Python, native code,
or Docker.

## Find and install plugins

Search the small first-party catalog:

```sh
pentect plugins search
pentect plugins search privacy
```

Inspect a released version before you add it:

```sh
pentect plugins inspect github:@EdamAme-x/pentect/plugins/example-regex@v0.1.0
```

Add it for your user account on this computer:

```sh
pentect plugins add github:@EdamAme-x/pentect/plugins/example-regex@v0.1.0
```

This writes the source to `~/.pentect/config.toml` and pins downloaded source
bytes in `~/.pentect/pentect.plugins.lock`. The plugin is then available from
every project on this computer. A Wasm plugin
also downloads its release file, checks its SHA-256 checksum and GitHub build
record, and asks you to approve its hooks and network access.

The `@VERSION` suffix selects a tag or full commit. When an older unversioned
source uses `main`, Pentect treats the lockfile's content hashes—not `main`—as
its approved identity. Only `plugins update` can replace those locked bytes.

Released Wasm plugins need
[GitHub CLI](https://cli.github.com/) v2.51.0 or newer for build-record checks.
Regex plugins do not need it.

Use a plugin for only one launch without changing saved configuration:

```sh
pentect codex --plugins github:@owner/repository/path@0123456789abcdef0123456789abcdef01234567
pentect claude --plugins ./my-plugin
```

Separate more than one plugin with commas. A one-off remote plugin must use a
full 40-character commit. Tags can move, so tag-based sources must first be
added and pinned by a lockfile.

For a repository-owned plugin set, add `--project`. This writes
`.pentect/config.toml` and `pentect.plugins.lock`; commit both project files.

```sh
pentect plugins add github:@owner/repository/path@v1.2.3 --project
```

The same `--project` switch selects project scope for `remove`, `config`,
`setup`, and `update`. Existing project plugin settings stay project-scoped
after upgrading; Pentect does not silently promote their permissions.

## How plugins run

Pentect runs user plugins first, followed by project plugins and one-off
plugins, preserving the order within each config. A hook returns
normally to continue to the next plugin. It can also block the action. The
`request` hook can return a response without calling the provider.

```text
client input
  → prepare
  → inspect
  → Pentect detection and handles
  → finalize
  → request
  → provider
  → response
  → completed tool_call
```

The `file` hook runs when Pentect handles supported file information. Built-in
checks still run. A regex plugin cannot turn them off.

## What a plugin can see

A hook receives only the data for its point in the flow. Text hooks receive a
text value and its kind. Provider hooks receive the supported request or
response JSON. The file hook receives the filename, media type, and size; it
does not receive arbitrary file bytes.

A Wasm plugin does not inherit the user's environment or filesystem. Settings
added with `pentect plugins config` are available only when the plugin asks for
that key. File, environment, storage, command, and HTTP access must be declared
and is performed by Pentect.

A Command plugin is a native process. It receives one request and returns one
response per JSONL line. It runs with the user's OS permissions, so Pentect
shows its exact argv, files, and hooks before activation.

## Sandbox and approval

Wasm plugins run without WASI. They cannot directly read files, read environment
variables, start programs, or open network sockets. Optional `[permissions]`
entries expose only the listed operations through the Pentect host.

A plugin can ask Pentect to make an HTTP request for it. The manifest must list
the exact origins and methods. Pentect shows this access during setup. Private
addresses and plain HTTP need extra settings and extra approval.

Pentect links approval to the manifest hash, Wasm hash, release, and exported
hooks. If any of these change, you must review the plugin again.

Command plugins do not receive the Wasm sandbox. Their downloaded files are
hash-locked, their argv is never passed through a shell, and access changes
require approval. A Command plugin may declare one explicit native environment
setup command and bounded profiles. Pentect displays its argv and expected
cost, locks its distributed files, and runs it only as part of approval; it
does not support hidden package lifecycle scripts.

## Manage installed plugins

```sh
pentect plugins list
pentect plugins inspect NAME
pentect plugins test NAME
pentect plugins config NAME key=value
pentect plugins update NAME
pentect plugins remove NAME
```

`remove` disables the user plugin. Use `remove NAME --project` for a project
plugin. Neither form runs cleanup code from the plugin.

## Next steps

- Follow [Build a plugin](/plugins/build/) for a working regex and Wasm example.
- Understand ordering and failure behavior in [Middleware lifecycle](/plugins/lifecycle/).
- Copy complete patterns from [Plugin recipes](/plugins/recipes/).
- See [Plugin manifest](/plugins/manifest/) for every `plugin.toml` field.
- See [Rust SDK](/plugins/sdk/) for hooks and context methods.
- See [Command plugins](/plugins/command/) for Python, JavaScript, native, and Docker integrations.
- See [Test and publish](/plugins/publish/) for releases and updates.
- Browse [Official plugins](/plugins/official/), including OpenAI Privacy Filter.
