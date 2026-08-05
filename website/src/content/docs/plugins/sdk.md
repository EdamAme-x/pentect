---
title: Rust SDK
description: Write Pentect Wasm hooks with the pentect-plugin crate.
---

Add the SDK and build a `cdylib`:

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
pentect-plugin = "0.1"
```

The SDK is published on crates.io. Keep the dependency on the same supported
API family as the host release. Commit `Cargo.lock` for release builds.

Export only the hooks you use:

```rust
pentect_plugin::export!(prepare, inspect, request);
```

Pentect reads the exports from the Wasm file. You do not list hooks in
`plugin.toml`.

## Hooks

| Hook | Input | Allowed result |
| --- | --- | --- |
| `prepare` | Text | Replace text or block |
| `inspect` | Text | Add findings or block |
| `finalize` | Text | Replace text after detection or block |
| `request` | Provider JSON | Replace, return a response, or block |
| `response` | Provider JSON | Replace or block |
| `tool_call` | Completed tool-call JSON | Replace or block |
| `file` | Filename, media type, and size | Block or continue |

Return `Ok(())` to continue. You do not call `next()`. If a hook blocks, later
plugins and the normal action do not run. Only `request` can call `respond`.

See [Middleware lifecycle](/plugins/lifecycle/) for the exact order around
built-in detection and provider calls.

### Text input

`prepare`, `inspect`, and `finalize` receive:

```rust
pub struct Text {
    pub kind: String,
    pub text: String,
}
```

Read it with `c.input()`. The `kind` tells you where the text came from, such
as user input or a tool result. Do not use it as the only security check;
future Pentect versions may add new kinds.

`metadata()` provides safe context for the current surface when available. Its
JSON fields can grow. Treat every field as optional and do not block only
because a new field appears.

### Provider JSON

`request`, `response`, and `tool_call` receive `serde_json::Value`. Check only
the fields you understand and leave other fields unchanged. This helps the
plugin keep working when a provider adds an optional field.

```rust
fn request(c: &mut Request) -> PluginResult {
    let Some(model) = c.input().get("model").and_then(|v| v.as_str()) else {
        return Ok(());
    };
    if model == "blocked-model" {
        c.block("this model is not allowed by company policy");
    }
    Ok(())
}
```

### File information

The `file` hook receives `filename`, optional `media_type`, and `size`. It can
approve or block the file before the normal action continues. It cannot read
the file from disk.

## Add a finding

```rust
use pentect_plugin::{Category, Confidence, Finding, Inspect, PluginResult};

fn inspect(c: &mut Inspect) -> PluginResult {
    if let Some(start) = c.input().text.find("EMP-") {
        c.add_finding(Finding {
            start,
            end: start + 4,
            label: "EMPLOYEE_ID".into(),
            category: Some(Category::Identifier),
            confidence: Some(Confidence::High),
        })?;
    }
    Ok(())
}

pentect_plugin::export!(inspect);
```

Positions are UTF-8 byte positions, not character numbers. Both ends must be on
a valid character boundary. `add_finding` returns an error for an empty or bad
range.

When findings overlap, Pentect joins their ranges. It chooses the label by
source, confidence, range, and detector type. See
[Structured data](/protection/structured-data/#when-detectors-disagree).

## Replace data

Text hooks use `replace` with a string:

```rust
fn prepare(c: &mut Prepare) -> PluginResult {
    c.replace(c.input().text.replace("old", "new"));
    Ok(())
}
```

JSON hooks use `replace` with `serde_json::Value`. The `inspect` hook cannot
replace its input. It should add findings instead.

Only the `request` hook can return a complete response without calling the
provider:

```rust
fn request(c: &mut Request) -> PluginResult {
    let use_local = c.input()
        .get("pentect_mock")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if use_local {
        c.respond(serde_json::json!({"output": []}));
    }
    Ok(())
}
```

Use `respond` only when the returned JSON follows the provider contract that
the client expects.

## Read plugin settings

Every hook can read an approved plugin setting:

```rust
let value = c.config("policy.level")?;
```

Users set values with:

```sh
pentect plugins config NAME policy.level=strict
pentect plugins config NAME --unset policy.level
```

Settings are JSON values inside the Wasm hook. A missing key returns `None`.
The SDK call can fail, so use `?` or handle the error explicitly. Do not confuse
a missing key with invalid JSON.

## Make an approved HTTP request

First list the origin and method in `plugin.toml`. Then ask the Pentect host to
make the request:

```rust
use pentect_plugin::HttpRequest;

let response = c.fetch(
    &HttpRequest::get("https://policy.example.com/status"),
    64 * 1024,
)?;
```

The URL and method must match the manifest. Pentect checks request counts,
sizes, DNS results, and private addresses. The Wasm module never receives a raw
socket.

`HttpResponse.status` can be absent when the host request fails. Check
`response.error` before parsing the body. Set the response capacity no larger
than your manifest limit.

## Errors and required plugins

Returning `Err` marks the hook as failed. With `required = true`, the action
stops. With the default `false`, Pentect reports partial plugin coverage and may
continue according to the current request policy.

Use `c.block("message")` for an expected policy decision. Use `Err` for a
broken response or internal plugin error.

## API types

The main public types are:

- `Prepare`, `Inspect`, `Finalize`, `Request`, `Response`, `ToolCall`, and `File`
- `Text` and `FileInfo`
- `Finding`, `Category`, and `Confidence`
- `HttpRequest` and `HttpResponse`
- `PluginResult`

The SDK source and examples live in
[`sdk/rust/pentect-plugin`](https://github.com/EdamAme-x/pentect/tree/main/sdk/rust/pentect-plugin).

Copy complete patterns from [Plugin recipes](/plugins/recipes/).

## Keep plugins compatible

- Ignore JSON fields you do not use.
- Return `Ok(())` for input that is outside your plugin's job.
- Use UTF-8 byte positions for findings.
- Set tight limits in `plugin.toml`.
- Test empty text, Unicode, malformed JSON, network errors, and size limits.
- Use `required = true` only when running without the plugin would be unsafe.
