# Pentect

Pentect is a local security boundary for AI coding tools. It replaces secrets
and sensitive data with opaque handles before requests reach a model provider,
then resolves those handles only at trusted client tool boundaries.

Pentect currently supports Codex CLI, Claude Code, Codex App, and Claude
Desktop. It also provides standalone masking commands and sandboxed WebAssembly
plugins.

> Pentect is pre-1.0 security software. Unknown provider formats are blocked by
> default, but no filter can promise perfect detection. Keep provider and tool
> permissions narrow and review the documented limitations before production
> use.

## Install

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.ps1 | iex
```

Linux and macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.sh | sh
```

The installers detect the platform, download a GitHub Release asset, and verify
its SHA-256 checksum. Run `pentect doctor` after installation. Version-specific
installation is supported with `-Version 0.0.14` in PowerShell or
`--version 0.0.14` for `install.sh`.

## Use

Launch a supported CLI through Pentect:

```text
pentect codex
pentect claude
```

Launch a desktop app only when explicitly requested:

```text
pentect codex app
pentect claude app
```

Mask text from stdin while preserving opaque handles:

```sh
cat .env | pentect mask
cat terraform.tfvars | pentect mask
```

PowerShell:

```powershell
Get-Content .env -Raw | pentect mask
```

Common maintenance commands:

```text
pentect doctor [--json | --fix [--yes]]
pentect update [VERSION] [--check | --force]
pentect uninstall
pentect log [--json]
```

## What is protected

- Prompts and local tool results sent through supported model gateways
- Completed model tool-call arguments, resolved only for the local client tool
- dotenv, Terraform, Kubernetes, kubeconfig, AWS, npm, PyPI, JSON, and other
  recognized structured configuration
- Inline images and documents that Pentect can inspect safely
- Supported UTF-8 Files API uploads

Binary uploads that Pentect cannot inspect or safely rewrite are blocked. File
IDs and remote URLs are accepted only when Pentect can establish safe coverage;
otherwise the configured unscanned-content policy applies.

Unknown provider endpoints, content blocks, and malformed provider JSON are
blocked by default. A user may explicitly select compatibility mode in the
global configuration, but project configuration cannot weaken this policy.

See [configuration](guides/configuration.md) for policies and limits.
See [compatibility](COMPATIBILITY.md) for the release-tested client matrix.

## Plugins

Plugins are either declarative regex rules or portable WebAssembly middleware.
Wasm plugins run without WASI, filesystem, environment, process, or raw socket
access. Network destinations and payload-changing permissions require explicit
approval.

```text
pentect plugins new NAME
pentect plugins dev PATH
pentect plugins publish PATH
pentect plugins add github:@owner/repository/path
pentect plugins list
pentect plugins inspect NAME
pentect plugins test NAME
pentect plugins update NAME
```

See [PLUGINS.md](PLUGINS.md) and the [plugin authoring guide](guides/plugins.md).
The Rust SDK is published as
[`pentect-plugin`](https://crates.io/crates/pentect-plugin).

## Security and development

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

Pentect is licensed under the MIT License.
