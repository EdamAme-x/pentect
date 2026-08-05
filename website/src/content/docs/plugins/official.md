---
title: Official plugins
description: First-party plugins and examples maintained with Pentect.
---

Pentect has built-in protection and a small plugin catalog. Built-in protection
is ready without setup. Catalog plugins are optional and are never enabled
without your choice.

## Built-in protection

You do not need a plugin for common secrets and config files. The Pentect
engine is always available and includes:

- secret patterns generated from CredSweeper rules;
- field-aware labels for dotenv, Terraform, Kubernetes, kubeconfig, JSON, AWS,
  npm, PyPI, and other key/value data;
- local checks for supported text files, documents, images, QR codes, and
  barcodes;
- handles that are restored only inside the protected local flow.

Built-in protection is part of the Pentect binary. It does not appear in
`pentect plugins list`, and it cannot be removed by a plugin.

## Plugin catalog

The catalog currently contains these first-party choices:

| Plugin | Type | Best for | Extra service |
| --- | --- | --- | --- |
| `example-regex` | Manifest only | Learning and custom fixed patterns | No |
| `openai-privacy-filter` | Wasm + local model | Context-aware English PII | Yes |

```sh
pentect plugins search
```

## Example regex

`example-regex` is the smallest complete plugin. It protects values such as
`ACME-12345678` with one regex in `plugin.toml`.

```sh
pentect plugins add github:@EdamAme-x/pentect/plugins/example-regex
```

Use its
[`plugin.toml`](https://github.com/EdamAme-x/pentect/blob/main/plugins/example-regex/plugin.toml)
as a starting point for company IDs and custom tokens.

## OpenAI Privacy Filter

`openai-privacy-filter` adds context-aware PII checks with OpenAI's local
Privacy Filter model. The model can find account numbers, private addresses,
emails, names, phone numbers, URLs, dates, and secrets.

The model does not run inside the Wasm sandbox. A small local bridge runs it on
your computer. The Wasm plugin can connect only to `127.0.0.1:8787`. It sends
no text to an OpenAI API or another remote service.

::: info
The first setup downloads the OpenAI model weights. It needs much more disk,
memory, and startup time than a normal regex plugin. The model mainly targets
English and can still miss or over-mask text.
:::

### 1. Install the local model

The commands use the official OpenAI repository at a reviewed commit.

::: code-group

```powershell [Windows]
$root = "$HOME\.pentect\openai-privacy-filter"
New-Item -ItemType Directory -Force $root | Out-Null
py -m venv "$root\venv"
& "$root\venv\Scripts\python.exe" -m pip install `
  "git+https://github.com/openai/privacy-filter.git@f7f00ca7fb869683eb732c010299d901457f19c3"
irm "https://github.com/EdamAme-x/pentect/releases/latest/download/openai-privacy-filter-server.py" `
  -OutFile "$root\openai-privacy-filter-server.py"
irm "https://github.com/EdamAme-x/pentect/releases/latest/download/openai-privacy-filter-server.py.sha256" `
  -OutFile "$root\openai-privacy-filter-server.py.sha256"
$expected = (Get-Content "$root\openai-privacy-filter-server.py.sha256").Split()[0]
$actual = (Get-FileHash "$root\openai-privacy-filter-server.py" -Algorithm SHA256).Hash
if ($actual.ToLower() -ne $expected.ToLower()) { throw "checksum mismatch" }
```

```sh [macOS / Linux]
root="$HOME/.pentect/openai-privacy-filter"
mkdir -p "$root"
python3 -m venv "$root/venv"
"$root/venv/bin/python" -m pip install \
  "git+https://github.com/openai/privacy-filter.git@f7f00ca7fb869683eb732c010299d901457f19c3"
curl -fsSL \
  "https://github.com/EdamAme-x/pentect/releases/latest/download/openai-privacy-filter-server.py" \
  -o "$root/openai-privacy-filter-server.py"
curl -fsSL \
  "https://github.com/EdamAme-x/pentect/releases/latest/download/openai-privacy-filter-server.py.sha256" \
  -o "$root/openai-privacy-filter-server.py.sha256"
if command -v sha256sum >/dev/null; then
  (cd "$root" && sha256sum -c openai-privacy-filter-server.py.sha256)
else
  (cd "$root" && shasum -a 256 -c openai-privacy-filter-server.py.sha256)
fi
```

:::

### 2. Start the model

The first start downloads the official checkpoint. Later starts use the local
copy.

::: code-group

```powershell [Windows · CPU]
& "$HOME\.pentect\openai-privacy-filter\venv\Scripts\python.exe" `
  "$HOME\.pentect\openai-privacy-filter\openai-privacy-filter-server.py" --device cpu
```

```sh [macOS / Linux · CPU]
"$HOME/.pentect/openai-privacy-filter/venv/bin/python" \
  "$HOME/.pentect/openai-privacy-filter/openai-privacy-filter-server.py" --device cpu
```

:::

Use `--device cuda` on a supported NVIDIA setup. Keep this terminal open.

Check the local bridge in another terminal:

```sh
curl http://127.0.0.1:8787/health
```

### 3. Enable the Pentect plugin

Install [GitHub CLI](https://cli.github.com/) v2.51.0 or newer if it is not
already available. Pentect uses it to check the plugin's release build.

```sh
pentect plugins add github:@EdamAme-x/pentect/plugins/openai-privacy-filter
```

Pentect shows that the plugin can make one plain HTTP request to the local
bridge. Review and approve it. The plugin is marked as required, so a protected
action stops if the local model is not ready.

Test with fake private data before using it with a client:

```sh
echo "Email Alice at alice@example.test" | pentect mask
```

### How the parts connect

```text
Pentect engine
  -> sandboxed Wasm adapter
  -> HTTP on 127.0.0.1:8787
  -> local OpenAI Privacy Filter model
  -> byte ranges and labels
  -> normal Pentect handles
```

The bridge returns positions and labels, not copies of the matched values.
Pentect still creates and owns the handles.

### Common problems

| Message or symptom | What to do |
| --- | --- |
| `not available on 127.0.0.1:8787` | Start the bridge and check `/health` |
| The first start is slow | Wait for the model download and initialization |
| CPU use is too high | Stop the bridge when you do not need this plugin |
| A value is missed | Keep built-in checks enabled and add a focused regex plugin when the format is stable |
| Safe text is masked | Test with fake samples and report the model label and sentence without real private data |
| The plugin changed | Run `pentect plugins inspect`, then `pentect plugins setup` after review |

### Remove it

Disable it in the current project:

```sh
pentect plugins remove openai-privacy-filter
```

Then stop the local server. You can remove
`~/.pentect/openai-privacy-filter` when you no longer need its environment or
downloaded checkpoint.

OpenAI Privacy Filter is released by OpenAI under Apache-2.0. The Pentect Wasm
adapter and bridge are maintained by the Pentect project under MIT. OpenAI does
not maintain this integration.
