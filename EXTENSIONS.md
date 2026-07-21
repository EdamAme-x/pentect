# Extensions

An extension can be selected by name, local path, GitHub URL, or the compact
GitHub form:

```text
github:@EdamAme-x/pentect/extensions/jp-pii
```

The compact form resolves the path from the repository's `main` branch.

## Metadata and setup

Optional metadata lives in `extension.toml`:

```toml
schema = "pentect.extension.v1"
name = "example"
description = "Example extension"

[[postscript]]
name = "install helper"
command = ["cargo", "install", "example-helper", "--locked"]
platforms = ["windows", "macos", "linux"]
permissions = ["network", "filesystem", "process"]
timeout_ms = 120000
```

Postscripts never run while loading an extension. They only run through
`pentect extensions setup NAME`. Pentect prints every command and its declared
permissions first, then requires an interactive `y`/`yes` confirmation. CI can
provide the same explicit approval with `--yes`. The process receives only a
small allowlist of operating-system environment variables plus its isolated
Pentect extension paths; credentials from the parent process are not inherited.

Release-hosted helper binaries use a declarative artifact entry instead of a
postscript:

```toml
[[artifact]]
name = "example-helper"
repository = "owner/repository"
destination = "bin/example-helper"

[artifact.assets]
windows-x86_64 = "example-helper-windows-x86_64.exe"
linux-x86_64 = "example-helper-linux-x86_64"
macos-x86_64 = "example-helper-macos-x86_64"
macos-aarch64 = "example-helper-macos-aarch64"
```

`pentect extensions setup NAME` installs the platform asset from the latest
stable GitHub Release after verifying its sibling `.sha256` asset.
`pentect extensions update NAME` repeats the verified lookup and replaces the
binary only when its hash changed.

## Configuration

Adapters receive the path to their config file in `PENTECT_EXTENSION_CONFIG`.
Arbitrary TOML values can be managed without printing their values:

```text
pentect extensions config example threshold=0.8
pentect extensions config example model.name=small
pentect extensions config example
pentect extensions config example --unset model.name
```

The no-value form prints the config path and key names only. Configuration is
stored under `.pentect/extensions-data/<extension>/config.toml`.
