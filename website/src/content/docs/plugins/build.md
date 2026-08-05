---
title: Build a plugin
description: Create a Pentect plugin and test it on your computer.
---

1. Create a plugin project.

   ```sh
   pentect plugins new my-plugin
   ```

2. Run it from the local directory.

   ```sh
   pentect plugins dev ./my-plugin
   ```

3. Test its behavior and requested access.

   ```sh
   pentect plugins test my-plugin
   pentect plugins inspect my-plugin
   ```

4. Publish the plugin when it is ready.

   ```sh
   pentect plugins publish ./my-plugin
   ```

## Choose the smallest plugin form

Use a manifest-only regex detector when you only need to find and label text.
Use Wasm when you need context, choices, settings, or control over what runs
next.

The Rust SDK is published as
[`pentect-plugin`](https://crates.io/crates/pentect-plugin).

## Manifest-only detector

The smallest plugin is one `plugin.toml` file:

```toml
schema = "pentect.plugin.v1"
name = "example-regex"
description = "Detect ACME case identifiers."

[[detector]]
label = "ACME_CASE"
pattern = '''\bACME-[0-9]{8}\b'''
category = "identifier"
confidence = "high"
```

This form needs no binary, build step, setup script, or native library.

## Wasm middleware

Add the SDK to a `cdylib` crate and export only the hooks you implement:

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
pentect-plugin = "0.1"
```

```rust
use pentect_plugin::{Finding, Inspect, PluginResult};

fn inspect(context: &mut Inspect) -> PluginResult {
    if let Some(start) = context.input().text.find("ACME-") {
        context.add_finding(Finding::new(start, start + 5, "ACME_ID"))?;
    }
    Ok(())
}

pentect_plugin::export!(inspect);
```

Finding positions use UTF-8 byte offsets. The `inspect` hook adds results but
does not change its input. `prepare`, `finalize`, `request`, `response`, and
`tool_call` may change data. `request` may return a response directly. Every
hook may block. `Ok(())` moves to the next step, so you do not need to call
`next()`.

Build the portable module:

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

Set `binary = "my-plugin.wasm"` in `plugin.toml`. Pentect finds hooks from the
module exports. It rejects native apps and binary paths that leave the plugin
folder.

## Configuration and network access

Plugins do not receive the user's environment variables. Pentect stores plugin
settings and gives them to the SDK only after approval. HTTP access also goes
through Pentect and can reach only approved hosts. Plugins do not get raw
network sockets.

Before publishing, run:

```sh
pentect plugins dev ./my-plugin
pentect plugins test my-plugin
pentect plugins inspect my-plugin
```

Test empty input, non-ASCII text, overlapping results, the largest allowed
input, and every block path. Put the manifest, Wasm file, and checksum in the
same tagged release. This lets users approve one exact build.

::: info
Plugin permissions protect the user. Ask only for the access your plugin needs.
Approval during install does not make broad permissions safe.
:::
