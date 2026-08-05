---
title: Plugin recipes
description: Complete patterns for detection, policy, settings, HTTP, and tests.
---

Start with the smallest recipe that solves the problem. Use fake values in
tests and examples.

## Protect a fixed company identifier

This plugin needs only `plugin.toml`:

```toml
schema = "pentect.plugin.v1"
name = "case-id"
description = "Protect internal support case IDs."

[[detector]]
label = "CASE_ID"
pattern = '''\bCASE-[0-9]{8}\b'''
category = "identifier"
confidence = "high"
prefilter = ["CASE-"]
```

```sh
echo 'Open CASE-12345678' | pentect mask --plugins ./case-id
```

Add a `prefilter` when the pattern has a stable literal. Pentect skips the regex
when none of the prefilter strings appear.

## Protect every match in a Wasm hook

`match_indices` returns UTF-8 byte positions, which is exactly what Pentect
expects:

```rust
use pentect_plugin::{Category, Confidence, Finding, Inspect, PluginResult};

fn inspect(c: &mut Inspect) -> PluginResult {
    for (start, value) in c.input().text.match_indices("EMP-") {
        c.add_finding(Finding {
            start,
            end: start + value.len(),
            label: "EMPLOYEE_ID".into(),
            category: Some(Category::Identifier),
            confidence: Some(Confidence::High),
        })?;
    }
    Ok(())
}

pentect_plugin::export!(inspect);
```

Real identifier formats should extend the range past the prefix. Check every
start and end with `is_char_boundary` if you calculate positions manually.

## Read a user setting

The user stores a JSON value through the CLI:

```sh
pentect plugins config company-policy policy.level=strict
```

The hook reads only that key:

```rust
let level = c
    .config("policy.level")?
    .and_then(|value| value.as_str().map(str::to_owned))
    .unwrap_or_else(|| "normal".to_string());
```

Do not use settings as a path to environment variables. A plugin never receives
the user's environment automatically.

## Block a provider request

Check only fields your plugin owns and ignore new optional fields:

```rust
use pentect_plugin::{PluginResult, Request};

fn request(c: &mut Request) -> PluginResult {
    if c.input()
        .get("model")
        .and_then(|value| value.as_str())
        .is_some_and(|model| model == "blocked-model")
    {
        c.block("company policy does not allow this model");
    }
    Ok(())
}

pentect_plugin::export!(request);
```

Do not require a field that the provider contract marks optional. Return
normally when the request is outside your plugin's job.

## Call an approved local service

Declare the exact origin and the smallest limits:

```toml
[network]
allow = ["http://127.0.0.1:8787"]
methods = ["POST"]
private_network = true
allow_insecure = true
max_request_bytes = 65536
max_response_bytes = 65536
max_requests = 1
```

Then use the host API. The Wasm module does not open a socket:

```rust
use pentect_plugin::HttpRequest;

let mut request = HttpRequest::get("http://127.0.0.1:8787/check");
request.method = "POST".into();
request.headers.insert("content-type".into(), "application/json".into());
request.body = r#"{"text":"fake sample"}"#.into();

let response = c.fetch(&request, 64 * 1024)?;
if response.error.is_some() || response.status != Some(200) {
    return Err("policy service failed".into());
}
```

Use HTTPS for remote services. Plain HTTP and private addresses require the
extra manifest fields because they expand access.

## Test the behavior, not only the manifest

```sh
pentect plugins test .
pentect plugins dev .
echo 'CASE-12345678' | pentect mask --plugins .
```

Your normal unit tests should include:

- one expected match and one safe near-match;
- empty text and Unicode before the match;
- every configuration value and the missing-value default;
- malformed service data, timeouts, and size limits;
- every block path and a request that must continue;
- more findings than expected and input near the configured limits.

Use `pentect log` during one real protected flow. Confirm that the plugin runs
where expected and that no real test credential appears in output.

See [Middleware lifecycle](/plugins/lifecycle/) for ordering and failure rules,
then [Test and publish](/plugins/publish/) for release assets and updates.
