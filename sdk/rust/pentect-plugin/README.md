# pentect-plugin

Rust helpers for sandboxed Pentect WebAssembly plugins.

Start with the [plugin guide](https://pentect.dev/plugins/build/) and use the
[SDK reference](https://pentect.dev/plugins/sdk/) for all hooks and methods.

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
pentect-plugin = "0.1"
```

```rust
use pentect_plugin::{Category, Confidence, Finding, Inspect, PluginResult};

fn inspect(c: &mut Inspect) -> PluginResult {
    if let Some(start) = c.input().text.find("ACME-12345678") {
        c.add_finding(Finding {
            start,
            end: start + "ACME-12345678".len(),
            label: "ACME_ID".into(),
            category: Some(Category::Identifier),
            confidence: Some(Confidence::High),
        })?;
    }
    Ok(())
}

pentect_plugin::export!(inspect);
```

Build it with:

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

## Hooks

The SDK provides `prepare`, `inspect`, `finalize`, `request`, `response`,
`tool_call`, and `file`. Export only the hooks you use. Returning `Ok(())`
continues to the next plugin.

- Use `add_finding` from `inspect`.
- Use `replace` from `prepare`, `finalize`, `request`, `response`, or
  `tool_call`.
- Use `respond` from `request`.
- Use `block` from any hook.
- Use `config` and `fetch` from any hook when the manifest allows them.

Finding positions are UTF-8 byte positions. Pentect checks every range before
it masks the input.

The module has no WASI, file, environment, process, or raw socket access.
Pentect provides settings and HTTP only after the user approves them.

See the first-party
[OpenAI Privacy Filter plugin](https://github.com/EdamAme-x/pentect/tree/main/plugins/openai-privacy-filter)
for a complete local-service example.
