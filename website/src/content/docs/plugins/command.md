---
title: Command plugins
description: Connect Python, JavaScript, native programs, and Docker over JSONL.
---

Use Command when a plugin needs a local model, native library, or container.
Pentect starts one process and keeps it alive for the protected session.

## Manifest

```toml
schema = "pentect.plugin.v1"
name = "my-model"
command = ["python", "{plugin}/server.py"]
hooks = ["inspect"]
required = true
```

The first item is the executable. Pentect resolves its exact path and executes
the argv directly without a shell. `{plugin}/server.py` marks a distributed
file: Pentect downloads it, stores its SHA-256, and checks the hash before
launch. A plugin-owned native executable can use the same prefix:

```toml
command = ["{plugin}/scanner", "--stdio"]
hooks = ["inspect"]
```

Python, native programs, and Docker use the same field:

```toml
command = ["docker", "run", "--rm", "-i", "example/policy@sha256:..."]
```

Docker images are not a separate plugin type. Pin the image digest and review
the mounts and network flags in the displayed argv.

If executable names differ by OS, replace `command` with a small platform map:

```toml
hooks = ["inspect"]

[commands]
windows = ["py", "{plugin}/server.py"]
macos = ["python3", "{plugin}/server.py"]
linux = ["python3", "{plugin}/server.py"]
```

Only the current OS command runs. If its entry is missing, Pentect reports the
plugin as unsupported instead of guessing another executable.

## Protocol

Read one JSON object per line from stdin and write one response per line to
stdout. Requests include `schema`, `id`, `hook`, `payload`, optional `metadata`,
and the plugin's own `config` object. Pentect discards stderr so an untrusted plugin cannot copy values
into the protected client's terminal; use value-free Pentect activity logs for
runtime diagnostics.

```json
{"schema":"pentect.plugin.v1","id":1,"hook":"inspect","payload":{"kind":"text","text":"hello"},"metadata":null,"config":{}}
```

The response must repeat the schema and id:

```json
{"schema":"pentect.plugin.v1","id":1,"type":"result","action":"next","spans":[]}
```

Pentect stops and restarts a process after invalid JSON, a wrong id, a timeout,
an oversized response, or an unexpected exit.

## Python

Install the small helper or copy its dependency-free source:

```sh
python -m pip install pentect-plugin
```

```python
from pentect_plugin import serve

def inspect(request):
    text = request["payload"]["text"]
    return {"spans": []}

serve(inspect)
```

## JavaScript

```sh
npm install @pentect/plugin
```

```js
import {serve} from '@pentect/plugin';

await serve(request => ({spans: []}));
```

Both helpers preserve the request id and turn an uncaught handler error into a
protocol error. They do not add a web server or network dependency.

Set Command plugin configuration with the normal CLI:

```sh
pentect plugins config my-model model.threshold=0.8
```

The handler reads it from `request["config"]` in Python or `request.config` in
JavaScript. Command is native, so it receives the complete plugin-specific
configuration object. Wasm keeps the narrower key-by-key `c.config(...)` API.

## Managed environment setup

Command plugins that need a model, virtual environment, or device-specific
runtime can declare `[setup]` in `plugin.toml`. The command is displayed as part
of the native approval and runs during `plugins add` and `plugins setup`.
Platform-specific commands use `[setup.commands]`.

```toml
[setup]
command = ["python", "{plugin}/setup.py"]
profiles = ["auto", "cpu", "cuda"]
profile_arg = "--profile"
download = "CPU: about 3 GB; CUDA: about 6 GB"
disk = "CPU: about 5 GB; CUDA: about 8 GB"
```

```sh
pentect plugins add ./my-model --profile auto
pentect plugins setup my-model --profile cpu
```

Setup is still native code, not a sandboxed package hook. Pentect never invokes
a shell, locks every distributed `{plugin}/...` setup file, and rolls managed
command state back when setup fails. The setup program should stage and replace
its own external environment atomically.

## Security boundary

Command is native. It runs with the current user's OS permissions. Pentect
clears most inherited environment variables, avoids a shell, locks distributed
files and the resolved executable into the approval, limits protocol I/O, and
enforces a deadline, but it is not a sandbox.

Use Wasm when Pentect must enforce exact file, environment, storage, command,
or network permissions. Use Command only for code you trust and inspect the
complete argv before approval.
