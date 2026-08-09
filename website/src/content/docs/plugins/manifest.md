---
title: Plugin manifest
description: Reference for every supported plugin.toml field.
---

Every plugin starts with `plugin.toml` and this schema:

```toml
schema = "pentect.plugin.v1"
name = "my-plugin"
description = "What the plugin protects."
```

Unknown fields cause an error. This helps catch spelling mistakes.

## Basic fields

| Field | Required | Meaning |
| --- | --- | --- |
| `schema` | Yes | Must be `pentect.plugin.v1` |
| `name` | Recommended | Lowercase plugin name shown by the CLI |
| `description` | Recommended | Short text shown before approval |
| `binary` | For Wasm | Release filename ending in `.wasm` |
| `repository` | For released Wasm | GitHub repository in `OWNER/REPO` form |
| `required` | No | Stop when the plugin cannot run; default is `false` |

`postscript` is not supported. A plugin cannot run an installer or native setup
program.

## What users approve

Before activation, Pentect shows the plugin identity, hooks, required status,
execution limits, network origins, HTTP methods, and private or insecure
network access. The approval is tied to the manifest and verified Wasm binary.

| Change | Result |
| --- | --- |
| Regex, hook, access, or manifest changes | Review and approval are required again |
| New verified binary with the same approved access | Update can continue without wider permission |
| Checksum or GitHub build record does not match | Installation stops |
| Required plugin fails at runtime | The protected action stops |
| Optional plugin fails at runtime | Pentect reports partial plugin coverage and continues |

`--yes` accepts the displayed approval without another prompt. It never turns
off validation, checksums, build-record verification, or sandbox limits.

## Regex detectors

Add one or more detector tables:

```toml
[[detector]]
label = "CUSTOM_TOKEN"
pattern = '''\bct_[A-Za-z0-9]{24}\b'''
category = "secret"
confidence = "high"
prefilter = ["ct_"]
capture = 0
```

| Field | Default | Meaning |
| --- | --- | --- |
| `pattern` | — | Rust regular expression; required in `plugin.toml` |
| `label` | `CUSTOM` | Label used in the handle |
| `category` | `secret` | `secret`, `identifier`, `endpoint`, `pii`, or `other` |
| `confidence` | `high` | `high`, `medium`, or `low` |
| `capture` | `0` | Regex capture group to protect; `0` means the full match |
| `prefilter` | none | Plain text that must exist before the regex runs |
| `validator` | none | `luhn`, `iban_mod97`, `verhoeff`, or another built-in validator |

Inline regex plugins can add checks. They cannot disable built-in Pentect
checks.

## Wasm binary and publisher

```toml
binary = "my-plugin.wasm"
repository = "owner/my-plugin"

[publisher]
workflow = ".github/workflows/release.yml"
```

Pentect downloads the binary and its `.sha256` file from the latest GitHub
Release. It also checks the GitHub build record against `publisher.workflow`.
The workflow path must stay inside the repository.

Most plugins use the binary name as the release asset. An older manifest can
override the portable asset name with `assets.wasm32`, but new plugins should
use the same name in both places.

## Execution limits

```toml
[execution]
runtime = "wasm"
mode = "oneshot"
timeout_ms = 10000
max_input_bytes = 262144
max_output_bytes = 1048576
max_spans = 512
```

Only `wasm` and `oneshot` are supported. The largest allowed values are 60
seconds, 4 MiB input, 4 MiB output, and 4,096 findings. The Wasm file itself
must be 32 MiB or smaller.

Use small limits. They protect the user from a slow or broken plugin.

Pentect also applies one shared ceiling to the complete plugin chain for a
protected action: 60 seconds, 16 MiB total input, 16 MiB total output, 8,192
findings, and 32 brokered HTTP requests. These host limits need no manifest
settings. A plugin's own limits can only make its invocation stricter.

Wasm modules are checked before compilation with `wasmi`'s strict untrusted
module limits. At runtime Pentect permits one memory, one table, and one
instance, caps memory at 64 MiB and table size at 4,096 elements, and uses a
fuel budget for Wasm instructions. Memory or table growth beyond those host
caps traps the plugin. The chain deadline is also used by brokered
HTTP calls. Fuel bounds compute work; it is not a general thread preemption
mechanism for host code.

## Network access

Do not add this table when the plugin needs no network:

```toml
[network]
allow = ["https://policy.example.com"]
methods = ["POST"]
max_request_bytes = 262144
max_response_bytes = 1048576
max_requests = 4
```

Each item in `allow` must be an exact origin. It can contain a scheme, host,
and port, but no path, query, credentials, or fragment. A plugin cannot use a
different origin at runtime.

Local services need clear extra access:

```toml
[network]
allow = ["http://127.0.0.1:8787"]
methods = ["POST"]
private_network = true
allow_insecure = true
```

Network limits cannot be larger than 64 origins, 16 requests per hook, 1 MiB
per request, or 4 MiB per response. Pentect also blocks unsafe address changes
during DNS lookup.

## Full Wasm example

```toml
schema = "pentect.plugin.v1"
name = "company-policy"
description = "Apply our local text policy."
binary = "company-policy.wasm"
repository = "example/company-policy"
required = true

[publisher]
workflow = ".github/workflows/release.yml"

[execution]
runtime = "wasm"
mode = "oneshot"
timeout_ms = 5000
max_input_bytes = 262144
max_output_bytes = 262144
max_spans = 256
```
