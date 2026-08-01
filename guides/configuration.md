# Configuration

Pentect needs no configuration for its default protection. Project settings
live in `.pentect/config.toml`; global defaults live in
`~/.pentect/config.toml`. Project values override global values.
`agent.required` is the exception: a project cannot turn off a global
requirement. `compatibility.unknown_formats = "ignore"` is also global-only,
so a repository cannot silently weaken provider inspection. The `plugins` list
is project-only.

Start from [`templates/config.toml`](../templates/config.toml). The everyday
settings are:

| Setting | Default | Meaning |
| --- | --- | --- |
| `plugins` | `[]` | Ordered plugins enabled for the project |
| `handles.scope` | `"device"` | Stable handles per `device`, `project`, or `session` |
| `agent.required` | `false` | Refuse an unprotected agent launch |
| `image.ocr` | `true` | Inspect text in images |
| `image.redaction` | `"black"` | Use `black` boxes or `blur` for image secrets |
| `image.unscanned` | `"block"` | `block` or `allow` images Pentect could not inspect |
| `files.remember` | `true` | Restore file-backed handles across Pentect restarts |

Handle environment variables always begin with `PENTECT_`; the prefix is not
configurable.

## Advanced limits

These settings are optional. Defaults are deliberately omitted from the starter
file so most users do not need to learn them.

| Setting | Default | Meaning |
| --- | ---: | --- |
| `compatibility.unknown_formats` | `"error"` | Error on provider formats Pentect cannot safely inspect; `"ignore"` is a global-only escape hatch |
| `image.max_edge` | `2048` | Largest OCR image edge in pixels |
| `image.max_pixels` | `64000000` | Largest decoded image area |
| `image.max_images` | `64` | Images inspected per request |
| `image.max_total_bytes` | `536870912` | Total image bytes per request |
| `image.max_seconds` | `20` | Total image inspection time |
| `image.max_image_bytes` | `67108864` | Bytes allowed for one image |
| `image.fetch_seconds` | `8` | Timeout for a remote image fetch |
| `decode.enabled` | `true` | Inspect encoded text |
| `decode.max_depth` | `3` | Nested decoding steps, or `"unlimited"` |
| `decode.min_bytes` | `16` | Smallest encoded candidate |
| `decode.max_bytes` | `262144` | Largest encoded candidate, or `"unlimited"` |
| `decode.max_inflate_bytes` | `8388608` | Largest decompressed result, or `"unlimited"` |
| `decode.mask_unknown` | profile-dependent | Mask opaque decoded data without a known secret signature |
| `decode.unknown_min_bytes` | profile-dependent | Smallest unknown opaque value |
| `activity.share` | `true` | Keep `pentect log` continuous across process-host handoffs |

Byte and time limits must be positive integers. Boolean settings should use
TOML booleans (`true` or `false`).

Pentect v0.0.x intentionally does not preserve old configuration names.
Errors name the replacement setting directly.

## Repair

`pentect doctor` checks the executable, PATH, configuration, memory store,
plugins, OCR support, and supported agent commands. Run `pentect doctor --fix`
to receive an English confirmation prompt for each safe repair Pentect can
perform. It currently adds the installed binary directory to the user PATH and
migrates known removed configuration names after writing a backup.

Use `pentect doctor --fix --yes` only in automation where those repairs are
already approved. `--json` is always read-only and cannot be combined with
`--fix`.
