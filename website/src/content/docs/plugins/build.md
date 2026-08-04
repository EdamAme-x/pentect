---
title: Build a plugin
description: Start a Pentect plugin and test it locally.
---

1. Create a plugin project.

   ```sh
   pentect plugins new my-plugin
   ```

2. Run it from the local directory.

   ```sh
   pentect plugins dev ./my-plugin
   ```

3. Test its declared behavior and permissions.

   ```sh
   pentect plugins test my-plugin
   pentect plugins inspect my-plugin
   ```

4. Publish the prepared plugin.

   ```sh
   pentect plugins publish ./my-plugin
   ```

## Choose the smallest plugin form

Use a manifest-only regex detector when matching and labeling spans is enough.
Choose Wasm middleware only when you need context, branching, configuration, or
control over whether the next middleware runs.

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

This form needs no binary, build step, postscript, or native dependency.

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

Finding offsets are UTF-8 byte offsets. The inspect hook adds findings; it does
not replace its input. `prepare`, `finalize`, `request`, `response`, and
`tool_call` may replace payloads. `request` may respond directly. Every hook may
block. Returning `Ok(())` continues automatically, so simple middleware does
not need boilerplate `next()` calls.

Build the portable module:

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

Set `binary = "my-plugin.wasm"` in `plugin.toml`. Pentect discovers hooks from
the module exports and rejects native executables or path-traversing binary
names.

## Configuration and network access

Plugins do not inherit the user's environment. Configuration is stored by
Pentect and exposed through the SDK only when approved. HTTP access likewise
uses a Pentect host function with an origin allowlist; the module receives no
raw socket access.

Before publishing, run:

```sh
pentect plugins dev ./my-plugin
pentect plugins test my-plugin
pentect plugins inspect my-plugin
```

Test empty input, non-ASCII offsets, overlapping findings, maximum-size input,
and every stop path. Keep the manifest, Wasm artifact, and release checksum in
the same tagged release so users can approve an immutable build.

::: info
Plugin permissions are part of the user-facing security contract. Declare
only the access the plugin needs; installation approval is not a substitute
for narrow permissions.
:::
