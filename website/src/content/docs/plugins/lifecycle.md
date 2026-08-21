---
title: Middleware lifecycle
description: See when plugin hooks run, what they receive, and how the chain stops.
---

Pentect plugins form an ordered middleware chain around the built-in protection
engine. A hook returns normally to continue. It can replace its current payload,
block the action, or—in the request hook—return a response without contacting
the provider.

You do not call `next()` in the Rust SDK. Returning `Ok(())` is the equivalent
of continuing to the next plugin.

## Text flow

```text
input
  → prepare plugins
  → inspect plugins
  → built-in Pentect detection
  → merge findings and create handles
  → finalize plugins
  → protected text
```

| Hook | Use it for | Can replace? | Can block? |
| --- | --- | --- | --- |
| `prepare` | Normalize text before detection | Yes | Yes |
| `inspect` | Add byte ranges and labels | No | Yes |
| `finalize` | Apply a final text policy after masking | Yes | Yes |

`inspect` findings join the same conflict-resolution process as built-in
findings. Plugin order does not decide which overlapping label wins.

## Provider flow

```text
protected client request
  → request plugins
  → provider
  → response plugins
  → completed tool_call plugins
  → restore known handles locally
  → run tool
  → mask tool result
```

| Hook | Payload | Special action |
| --- | --- | --- |
| `request` | Supported provider request JSON | `respond(...)` can skip the provider |
| `response` | Supported non-stream or completed response JSON | Replace or block |
| `tool_call` | One completed tool-call JSON object | Replace or block before local execution |
| `file` | Filename, media type, and size | Block before the normal file action |

Streaming provider responses are reassembled only where a completed structure
is needed. A plugin does not receive arbitrary transport bytes.

## Continue, replace, block, and respond

| SDK action | Chain behavior |
| --- | --- |
| Return `Ok(())` | Continue with the current payload |
| `replace(value)` then return | Continue with the replacement |
| `block(message)` then return | Stop later plugins and the normal action |
| `respond(value)` in `request` | Stop the chain and return that provider-shaped response |
| Return `Err(...)` | Mark this plugin run as failed |

Use `block` for an expected policy decision. Use `Err` for an internal failure
such as invalid service output.

## Required and optional plugins

`required = true` means the protected action must stop when the plugin cannot
run. This fits company policy or a detector that must always be present.

With the default `required = false`, Pentect records partial plugin coverage.
For a provider request, the normal unknown-format policy can still block partial
coverage. Optional does not mean that Pentect silently claims the plugin ran.

## Order and scope

User plugins run first in the order stored in `~/.pentect/config.toml`, then
project plugins from `.pentect/config.toml`. A one-off plugin passed with
`--plugins` is added for that command or client launch.

```sh
pentect codex --plugins ./plugins/company-policy
echo 'sample' | pentect mask --plugins first,second
```

Use one plugin for one job. Small plugins are easier to approve, test, update,
and remove than one plugin with unrelated access.

`pentect plugins remove NAME` removes the user-wide reference. Add `--project`
to remove a project reference. A protected client
that is already running keeps its loaded middleware until that client exits;
its supervised Command process is then stopped and reaped. Start a new client
to use the updated project list. Pentect may retain verified shared cache and
private plugin storage as appropriate for its scope.

## Sandbox boundary

Wasm plugins have no WASI. They cannot directly read files, environment
variables, processes, or sockets. They receive only the hook payload and the
specific settings they request.

An HTTP request is made by the Pentect host after it checks the approved origin,
method, address, count, and size limits. Changing the manifest, binary, exported
hooks, or approved access can require setup approval again.

Continue with [Plugin recipes](/plugins/recipes/) or the
[Rust SDK](/plugins/sdk/).
