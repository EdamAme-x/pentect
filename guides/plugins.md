# Plugins

Pentect plugins have two forms:

1. A declarative `plugin.toml` can add regex detectors without executable code.
2. Executable plugins are portable WebAssembly modules running inside Pentect's
   sandbox.

There is no native executable plugin mode. A `.wasm` module receives no
filesystem, environment, process, or socket access. Optional network requests
go through a narrow Pentect host function and only after explicit approval.

## Manifest

```toml
schema = "pentect.plugin.v1"
name = "company-policy"
binary = "company-policy.wasm"
repository = "owner/company-policy"
required = true

[execution]
timeout_ms = 10000
max_input_bytes = 262144
max_output_bytes = 1048576

```

`execution.runtime = "wasm"` and `execution.mode = "oneshot"` are accepted for
older manifests but are unnecessary. Any other runtime or mode is rejected.
Hooks are discovered from the signed WebAssembly exports; they are not repeated
in `plugin.toml`. Reading hook input is implicit. The publisher workflow defaults to
`.github/workflows/release.yml`; declare `[publisher].workflow` only when a
different workflow publishes the release. `[assets]` is needed only when the
Release asset name differs from `binary`.

Simple detectors need no binary:

```toml
schema = "pentect.plugin.v1"
name = "company-identifiers"

[[detector]]
label = "ACME_CASE"
pattern = '''\bACME-[0-9]{8}\b'''
category = "identifier"
confidence = "high"
```

## Network access

Network access is off by default. A plugin that needs HTTP declares exactly
which origins and methods it wants:

```toml
[network]
allow = ["https://api.example.com"]
methods = ["GET", "POST"]
max_request_bytes = 262144
max_response_bytes = 1048576
max_requests = 4
```

An allowed origin is only `scheme://host[:port]`; paths, queries, fragments,
and embedded credentials are rejected. Requests cannot follow redirects.
Pentect pins the approved DNS result for each request and rejects loopback,
private, link-local, multicast, documentation, and reserved addresses.
DNS resolution, requests, and response reads share the plugin's wall-clock
deadline. A plugin can make at most four requests per invocation by default
and never more than sixteen.

Local services require visibly stronger approval:

```toml
[network]
allow = ["http://127.0.0.1:8080"]
methods = ["GET"]
private_network = true
allow_insecure = true
```

Private-network approval applies only to literal private or loopback IP
origins. A public hostname is never allowed to resolve into a private network,
which prevents DNS rebinding from turning an approved public origin into an
internal target.

The module imports only:

```text
pentect:http/request(i32, i32, i32, i32) -> i32
```

The Rust SDK exposes this as `context.fetch(...)`. Pentect performs
the request on behalf of the module; the module never receives a raw socket.
Unknown imports and network imports without a matching `[network]` section are
rejected before execution.

## Plugin configuration

Configuration remains outside the module and is read one key at a time through
Pentect:

```text
pentect plugins config PATH model.threshold=0.8
```

The Rust SDK exposes `context.config("model.threshold")`. Pentect imports
`pentect:config/read` only for the plugin's own isolated configuration. The module
never receives a configuration file path or general filesystem access.
Mutable plugin cache access is not currently supported.

## WebAssembly ABI

The module exports:

```text
memory
pentect_alloc(i32) -> i32
one or more of:
pentect_prepare(i32, i32) -> i64
pentect_inspect(i32, i32) -> i64
pentect_finalize(i32, i32) -> i64
pentect_request(i32, i32) -> i64
pentect_response(i32, i32) -> i64
pentect_tool_call(i32, i32) -> i64
pentect_file(i32, i32) -> i64
```

The high 32 bits of a hook result are the response pointer and the low 32 bits
are its byte length. A plugin exports only the hooks it implements. Successful
handlers continue automatically:

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

Finding offsets are UTF-8 byte offsets into `context.input.text`. Overlapping
findings are one sensitive value: Pentect masks their complete union with one
handle and selects the strongest finding's label. If equally strong findings
disagree only on the label, Pentect uses their canonical category label such as
`SECRET` or `PII`; plugin order never decides the result. This also prevents a
lower-priority finding's prefix or suffix from remaining visible. Findings that
only touch at an edge remain separate. Structural labels such as a `.env` key
name are applied after merging and remain authoritative.

Build a Rust plugin as a `cdylib`:

```text
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
wasm-tools validate target/wasm32-unknown-unknown/release/company_policy.wasm
```

`wasm-tools` is recommended for validation and inspection. The ABI remains a
small Core WebAssembly interface today so Pentect can keep the lightweight
`wasmi` runtime. WIT is the intended source format for a future Component Model
revision once that migration does not require replacing the lightweight host.

## Security and approval

Every module has a 64 MiB memory ceiling, fuel scheduling, a real wall-clock
deadline, input/output limits, and a bounded detector-span count. No WASI
interfaces are linked. Manifests cannot raise execution past 60 seconds,
4 MiB input, 4 MiB output, or 4096 spans.

`pentect plugins setup` shows the release, publisher workflow, discovered hooks,
and requested network access before approval. Approval records the complete
manifest SHA-256. Any manifest change requires approval again.

Arbitrary postscripts are rejected. Executable assets must be GitHub Release
assets with Sigstore build provenance matching both the publisher repository
and `[publisher].workflow`; attestations from self-hosted runners are rejected.

Reading hook input is implicit. Hook-specific context types constrain which
operations are available; local responses are valid only in the `request` hook. The
deterministic Pentect masking engine remains the final authority for detector
spans.

There is intentionally no post-resolution hook: plugins can inspect and
transform opaque handles at `tool_call`, but Pentect does not hand their
plaintext values to third-party middleware.

## Lifecycle

```text
pentect plugins add SOURCE
pentect plugins list
pentect plugins inspect PATH
pentect plugins setup PATH
pentect plugins test PATH
pentect plugins update PATH
pentect plugins remove SOURCE
```

`add` installs, approves, pins, and enables a plugin for the current project.
`remove` disables it for that project. Shared installed data remains available
to other projects. `setup` remains as a lower-level compatibility command that
approves without enabling. Remote manifests remain pinned until `add`, `setup`,
or `update` is explicitly run.
Run `pentect plugins update` without a name to update every enabled plugin.

Add a plugin for one run without changing the project:

```text
pentect claude --plugins PATH
pentect codex --plugins PATH
```

Or preserve an ordered project list in `.pentect/config.toml`:

```toml
plugins = ["./plugins/company-policy", "company-identifiers"]
```

The signed built-in registry is searchable with:

```text
pentect plugins search [QUERY]
```

Registry inclusion is optional. Any publisher can distribute a
`github:@owner/repository/path` plugin when its `.wasm` release asset has
matching provenance.
