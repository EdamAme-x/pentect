# pentect-plugin

Small Rust SDK for sandboxed [Pentect](https://github.com/EdamAme-x/pentect)
WebAssembly plugins. Export only the hooks the plugin needs; Pentect discovers
them from the module.

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
pentect-plugin = "0.1"
```

```rust
use pentect_plugin::{Finding, Inspect, PluginResult};

fn inspect(context: &mut Inspect) -> PluginResult {
    if let Some(start) = context.input.text.find("ACME-") {
        context.add_finding(Finding::new(start, start + 5, "ACME_ID"));
    }
    Ok(())
}

pentect_plugin::export!(inspect);
```

Available hooks are `prepare`, `inspect`, `finalize`, `request`, `response`,
`tool_call`, and `file`. A successful handler continues automatically. It only
needs to call `block`, `replace`, `respond`, or `add_finding` when changing the
result.

Finding offsets are UTF-8 byte offsets. Overlapping findings become one masked
union and one handle; edge-adjacent findings remain separate. When labels
conflict at otherwise equal strength, Pentect falls back to the canonical
category label (for example, `SECRET` or `PII`) instead of depending on plugin
execution order.

Build with:

```text
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

The module receives no WASI, filesystem, environment, process, or raw socket
access. Configuration and outbound HTTP are available only through explicitly
approved Pentect host functions.
