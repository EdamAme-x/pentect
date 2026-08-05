---
title: Build a plugin
description: Create your first regex or Wasm plugin.
---

## A regex plugin in one file

Create `my-plugin/plugin.toml`:

```toml
schema = "pentect.plugin.v1"
name = "acme-case-id"
description = "Protect ACME support case IDs."

[[detector]]
label = "ACME_CASE_ID"
pattern = '''\bACME-[0-9]{8}\b'''
category = "identifier"
confidence = "high"
```

Try it without installing anything:

```sh
echo "case ACME-12345678" | pentect mask --plugins ./my-plugin
```

The result contains a handle:

```text
case <<ACME_CASE_ID_...>>
```

Check and enable the plugin:

```sh
pentect plugins test ./my-plugin
pentect plugins add ./my-plugin
```

Regex plugins have no binary and need no setup step. See
[Plugin manifest](/plugins/manifest/#regex-detectors) for capture groups,
prefilters, checksums, categories, and confidence values.

## Create a Wasm plugin

The CLI can create a Rust project, a manifest, and a release workflow:

```sh
pentect plugins new company-policy
cd plugins/company-policy
```

The generated hook looks like this:

```rust
use pentect_plugin::{Category, Confidence, Finding, Inspect, PluginResult};

fn inspect(c: &mut Inspect) -> PluginResult {
    for (start, _) in c.input().text.match_indices("INTERNAL-") {
        c.add_finding(Finding {
            start,
            end: start + "INTERNAL-".len(),
            label: "INTERNAL_ID".into(),
            category: Some(Category::Identifier),
            confidence: Some(Confidence::High),
        })?;
    }
    Ok(())
}

pentect_plugin::export!(inspect);
```

Build and check it:

```sh
rustup target add wasm32-unknown-unknown
pentect plugins dev .
pentect plugins test .
```

`plugins dev` builds, tests, and activates that local build after you approve
its hooks and access. It does not require a GitHub release. Run it again after
you change the Wasm code.

`plugins dev` currently builds Rust projects with Cargo. Other languages can
produce a plugin if they export the same Wasm ABI, but Pentect does not provide
an SDK for them yet.

## Use plugin settings

Set a value outside the plugin:

```sh
pentect plugins config company-policy prefix=INTERNAL-
```

Read it from any hook:

```rust
let prefix = c
    .config("prefix")?
    .and_then(|value| value.as_str().map(str::to_owned))
    .unwrap_or_else(|| "INTERNAL-".to_string());
```

The plugin receives only the key it asks for. It does not receive the user's
environment variables.

## Block an action

Every hook can stop the current action:

```rust
fn inspect(c: &mut Inspect) -> PluginResult {
    if c.input().text.contains("DO_NOT_SEND") {
        c.block("company policy blocked this text");
    }
    Ok(())
}
```

Set `required = true` in `plugin.toml` when a plugin error must also stop the
action. Leave it false when Pentect may continue after a plugin error.

## Continue learning

- [Rust SDK](/plugins/sdk/) explains all seven hooks.
- [Plugin manifest](/plugins/manifest/) lists settings and hard limits.
- [Test and publish](/plugins/publish/) covers unit tests, tags, and updates.
