# Plugins

Pentect plugins have three deliberately small forms:

1. A declarative `plugin.toml` can add regex detectors without executable code.
2. A sandboxed WebAssembly plugin uses a tiny request/response ABI and receives
   no host imports.
3. A publisher-trusted native plugin exchanges one JSON object per line over
   stdin/stdout.

The host owns ordering and the core masking pass. A plugin returns `next` to
continue, or `stop` with `block`, `respond`, or `handled`. Plugins never call
the next plugin themselves.

## Manifest

```toml
schema = "pentect.plugin.v1"
name = "company-policy"
binary = "company-policy"
repository = "owner/company-policy"

[publisher]
workflow = ".github/workflows/release.yml"

[execution]
runtime = "native" # use "wasm" for capability-sandboxed modules
mode = "persistent" # default; "oneshot" is supported
timeout_ms = 10000
max_input_bytes = 262144
max_output_bytes = 1048576

[middleware]
stages = ["provider_request", "tool_call"]
permissions = ["input:read", "payload:write", "pipeline:block"]
required = true

[assets]
windows-x86_64 = "company-policy-windows-x86_64.exe"
linux-x86_64 = "company-policy-linux-x86_64"
macos-aarch64 = "company-policy-macos-aarch64"
```

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

Explicit plugin order is preserved. The persistent process receives an
`initialize` request, then `event` requests. It must return exactly one NDJSON
response for each request and flush stdout. The canonical schema and fixtures
live in [`protocol/`](../protocol/); small Rust, Python, TypeScript, and Go
helpers live in [`sdk/`](../sdk/).

For an untrusted third-party plugin, publish one portable `.wasm` asset:

```toml
binary = "company-policy.wasm"
repository = "owner/company-policy"

[publisher]
workflow = ".github/workflows/release.yml"

[execution]
runtime = "wasm"
mode = "oneshot"
```

The module exports `memory`, `pentect_alloc(i32) -> i32`, and
`pentect_handle(i32, i32) -> i64`. The high 32 bits of the result are the
response pointer and the low 32 bits are its byte length. The Rust SDK's
`export_wasm_plugin!` macro implements this ABI. WebAssembly plugins cannot
request `config:read` or `cache:write`; future host capabilities can be added
without granting ambient filesystem or network access.

Rust publishers set `crate-type = ["cdylib"]`, use
`pentect_plugin::export_wasm_plugin!(handler)`, and build with:

```text
cargo build --release --target wasm32-unknown-unknown
```

## Security and approval

WebAssembly plugins run in a capability sandbox with a 64 MiB memory ceiling,
fuel metering, and no filesystem, environment, process, or network imports.
Native plugins remain an explicit publisher-trusted compatibility path for
workloads such as local ONNX inference.

`pentect plugins setup` shows the binary source, runtime, middleware stages,
permissions, and destination before approval. Approval records the manifest
SHA-256; changing any manifest content requires approval again. Arbitrary
postscripts are rejected—setup output must be a release asset.

Plugin children receive a cleared environment plus a small platform allowlist.
They never inherit Pentect's memory-store credentials. `PENTECT_PLUGIN_CONFIG`
is exposed only with `config:read`; `PENTECT_PLUGIN_CACHE_DIR` only with
`cache:write`. `PENTECT_PLUGIN_DATA_DIR` is always scoped to that plugin.
Approval files, installed binaries, configuration, cache, and mutable data live
in project-scoped OS user data outside the repository, so a clone cannot
pre-seed an approved executable.

`input:read` is mandatory. Payload replacement requires `payload:write`;
blocking requires `pipeline:block`; local responses require
`pipeline:respond`. The deterministic Pentect masking engine remains the final
authority for detector spans.

There is intentionally no post-resolution stage: plugins can inspect and
transform opaque handles at `tool_call`, but Pentect does not hand their
plaintext values to third-party middleware.

## Lifecycle

```text
pentect plugins inspect PATH
pentect plugins setup PATH
pentect plugins test PATH
pentect plugins config PATH key='"value"'
pentect plugins update PATH
```

`setup` installs and approves executable parts; it does not silently enable a
plugin for every command. Activate it explicitly for one agent run:

```text
pentect claude --plugins PATH
pentect codex --plugins PATH
```

To keep an ordered project-wide list, add it to `.pentect/config.toml`:

```toml
plugins = ["./plugins/company-policy", "company-identifiers"]
```

Native release binaries are selected by OS and architecture; a WebAssembly
asset is portable. Unsupported native platforms produce an explicit
missing-asset error rather than compiling on the user's machine.

Every executable asset must carry GitHub artifact provenance. Setup and update
verify its Sigstore attestation with `gh`, pinning both the publisher repository
and the workflow declared in `[publisher]`, and reject attestations from
self-hosted runners. SHA-256 is still checked for transport corruption.
`plugins update` only replaces the release binary described by the exact
approved manifest.

The registry shipped inside the signed Pentect binary is searchable with
`pentect plugins search [QUERY]`. A plugin does not need to be in that registry:
any publisher can distribute a `github:@owner/repository/path` spec, provided
its executable assets carry matching provenance.

The protocol exposes masking, provider, tool, file, finding, and reporting
stages. HTTP provider requests, JSON responses, completed streaming and
non-streaming tool calls, and multipart file discovery/decoding/detection/
transformation are connected. Streaming provider text is not dispatched as a
`provider_response` event per token; only its completed tool calls are held and
dispatched before local handle restoration.
