# Plugins

A plugin can be selected by name, local path, GitHub URL, or the compact
GitHub form:

```text
github:@EdamAme-x/pentect/plugins/pii-ner
```

The compact form resolves the path from the repository's `main` branch.

## Metadata and setup

Optional metadata lives in `plugin.toml`:

```toml
schema = "pentect.plugin.v1"
name = "example"
description = "Example plugin"

[[postscript]]
name = "install helper"
command = ["cargo", "install", "example-helper", "--locked"]
platforms = ["windows", "macos", "linux"]
permissions = ["network", "filesystem", "process"]
timeout_ms = 120000
```

A regex-only plugin needs no other file. Put one or more detectors directly in
`plugin.toml`; metadata and detector definitions can coexist:

```toml
schema = "pentect.plugin.v1"
name = "internal-identifiers"
description = "Masks internal ticket identifiers"

[[detector]]
pattern = '''TICKET-[0-9]{6}'''
prefilter = ["TICKET-"]
label = "INTERNAL_TICKET"
category = "secret"
confidence = "high"
```

Inline manifest rules may only add detectors. They cannot disable Pentect's
built-in detectors.

Executable plugins only declare their binary name:

```toml
binary = "example-helper"
```

Pentect infers the GitHub repository from a `github:@OWNER/REPO/PATH` source and
looks for `{binary}-{os}-{arch}` in its latest stable Release, adding `.exe` on
Windows. For example, Linux x86-64 resolves to
`example-helper-linux-x86_64`. Local manifests can declare
`repository = "OWNER/REPO"` because they have no remote source to infer.

Non-standard Release asset names can be overridden without listing every
platform:

```toml
[assets]
windows-x86_64 = "example-helper-win64.exe"
```

A missing asset is reported as unsupported. Pentect verifies the sibling
`.sha256`, then installs the executable at the deterministic
`.pentect/plugins-data/<plugin>/bin/<binary>` path and records its repository,
version, asset, and digest in `binary.lock`. Optional process limits and
arguments can be placed under `[execution]`, but the defaults require no extra
configuration.

Postscripts never run while loading a plugin. They only run through
`pentect plugins setup NAME`. Pentect prints every command and its declared
permissions first, then requires an interactive `y`/`yes` confirmation. CI can
provide the same explicit approval with `--yes`. The process receives only a
small allowlist of operating-system environment variables plus its isolated
Pentect plugin paths; credentials from the parent process are not inherited.

`pentect plugins setup NAME` installs the platform asset from the latest
stable GitHub Release after verifying its sibling `.sha256` asset.
`pentect plugins update NAME` repeats the verified lookup and replaces the
binary only when its hash changed.

## Configuration

Executable plugins receive the path to their config file in
`PENTECT_PLUGIN_CONFIG`.
Arbitrary TOML values can be managed without printing their values:

```text
pentect plugins config example threshold=0.8
pentect plugins config example model.name=small
pentect plugins config example
pentect plugins config example --unset model.name
```

The no-value form prints the config path and key names only. Configuration is
stored under `.pentect/plugins-data/<plugin>/config.toml`.
