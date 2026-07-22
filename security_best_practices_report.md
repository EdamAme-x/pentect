# Pentect security review

Date: 2026-07-22
Scope: Rust workspace, shell/runtime IPC, masking pipeline, plugins, installers/updater, and GitHub Actions.

## Executive summary

Four clear security issues were fixed in this review: an unsafe UTF-8 mutation reachable through the public detector API, local memory-store connection/request exhaustion, a project-controlled remote plugin cache, and mutable GitHub Actions dependencies. Dependencies with current actionable RustSec/OSV advisories were upgraded. Targeted tests and `cargo check -p pentect-cli` pass.

The largest remaining risk is the plugin execution trust model. A remote adapter can currently select a command from `PATH`, and plugin binaries are stored below the current project's `.pentect` directory. Fixing that safely changes plugin compatibility and storage semantics, so it is intentionally held for an explicit product decision.

## Fixed findings

### PNT-SEC-001 — Invalid detector spans could violate Rust string invariants (high)

`Detector` is a public safe trait, but the masking pipeline previously trusted detector byte ranges and mutated `String` bytes through `unsafe`. A plugin or custom detector could return a range inside a multibyte UTF-8 code point, producing invalid UTF-8 through a safe API.

Fixed in `crates/pentect-core/src/pipeline/mod.rs`: ranges are validated for ordering, bounds, and UTF-8 character boundaries, and replacement now uses safe `replace_range`. A regression test covers a deliberately invalid span.

### PNT-SEC-002 — Local memory-store resource exhaustion (high)

An unauthenticated loopback client could keep spawning threads, send an unbounded line, or repeatedly submit a bad token on one connection. This could exhaust memory, threads, or CPU for the local Pentect session.

Fixed in `crates/pentect-runtime/src/memory_store.rs`: concurrent clients are capped at 32, the first request has a five-second timeout, request lines are capped at 8 MiB, and a bad-token response closes the connection. Authenticated persistent clients retain their intended behavior.

### PNT-SEC-003 — Remote plugin cache was controlled by the opened project (high)

Remote plugin manifests were cached under `.pentect/plugin-cache`. A malicious repository could pre-populate fresh cache entries and substitute plugin configuration loaded under a trusted remote plugin name.

Fixed in `crates/pentect-cli/src/plugins.rs`: remote cache data now lives in the OS user cache (`LOCALAPPDATA`, `~/Library/Caches`, or `XDG_CACHE_HOME`/`~/.cache`). Unix cache directories are restricted to mode `0700`.

### PNT-SEC-004 — Known vulnerable dependencies (high)

The lockfile contained actionable advisories affecting `lopdf`, `quick-xml`, `crossbeam-epoch`, and `anyhow`. In particular, affected PDF/XML parsers could be driven into excessive resource use by hostile documents.

Fixed by upgrading `pdf-extract`/`lopdf`, `phonenumber`/`quick-xml`, `crossbeam-epoch`, and `anyhow`. A follow-up OSV scan found no remaining known actionable vulnerability advisories. Informational unmaintained transitive packages remain: `atomic-polyfill`, `paste`, `proc-macro-error2`, and `ttf-parser`.

References: <https://rustsec.org/advisories/RUSTSEC-2026-0187.html>, <https://rustsec.org/advisories/RUSTSEC-2026-0190.html>, <https://rustsec.org/advisories/RUSTSEC-2026-0194.html>, <https://rustsec.org/advisories/RUSTSEC-2026-0195.html>, <https://rustsec.org/advisories/RUSTSEC-2026-0204.html>.

### PNT-SEC-005 — Mutable CI action references (medium)

CI and release workflows used mutable action tags. A compromised or moved upstream tag could inject code into builds or releases.

Fixed in `.github/workflows/ci.yml` and `.github/workflows/release.yml`: third-party actions are pinned to full commit SHAs, CI defaults to read-only repository permissions, and checkout credentials are not persisted.

## Decisions required

### PNT-SEC-D01 — Remote adapters can execute arbitrary commands (high)

`adapter_program` falls back to a relative command or `PATH`. A remote TOML plugin can therefore name `powershell`, `sh`, or another installed executable and receive unmasked input through stdin without going through the setup approval used for downloaded binaries. Clearing the child environment reduces exposure but is not a sandbox.

Recommended decision: TOML-only remote plugins may define regex detectors, but executable/model adapters must resolve to an explicitly installed, checksum-verified plugin artifact or an explicitly trusted local absolute path. A less restrictive alternative is a per-source/digest approval store.

Relevant code: `crates/pentect-cli/src/plugins_cmd.rs` and `crates/pentect-runtime/src/plugin_adapter.rs` (`adapter_program`).

### PNT-SEC-D02 — Plugin executables are project-controlled (high)

Installed binaries are resolved from `.pentect/plugins-data/<plugin>/bin`. A cloned repository can pre-place a same-named executable, which may then be selected before an approved setup artifact.

Recommended decision: keep project plugin configuration in the repository, but move executable artifacts and mutable plugin data to an OS user-data directory keyed by plugin identity and artifact digest. This needs migration and re-setup behavior to be chosen.

### PNT-SEC-D03 — Postscript permissions are descriptive, not enforced (medium/high)

The setup prompt displays declared permissions, but approved postscript commands run with the user's normal filesystem, process, and network access. `--yes` intentionally removes the interactive gate.

Recommended decision: either implement enforceable platform sandboxes/capabilities, or rename the field/UI to `declared_permissions` and clearly state that approval grants full user-level execution.

### PNT-SEC-D04 — Release checksums are not independent signatures (medium/high)

Install, update, and plugin downloads verify SHA-256, but the checksum and binary come from the same GitHub release. This detects corruption, not compromise of the repository, release workflow, or release token.

Recommended decision: add Sigstore keyless signing/attestations, or choose an offline Ed25519 release key with an explicit rotation and recovery policy.

### PNT-SEC-D05 — Stable machine-scoped handles allow equality correlation (medium/privacy)

The default machine hash scope intentionally makes equal values produce equal handles across sessions and projects for the same user cache. This improves usability but reveals equality and can preserve identity if the key is copied in a machine backup.

Recommended decision: retain the requested default but document the tradeoff, and optionally protect the stable key with DPAPI/Keychain/libsecret. Project or session scope remains preferable for stronger unlinkability.

### PNT-SEC-D06 — File-pointer manager state is project-controlled (medium)

Encrypted file-pointer state and its local key are stored below `.pentect/file-pointer-manager`. A malicious repository can pre-populate this state; the exact impact depends on which recovery actions the user invokes.

Recommended decision: move mutable manager state to OS user storage keyed by canonical project identity, with a migration policy matching plugin data.

### PNT-SEC-D07 — Activity metadata is shared by default (low/privacy)

Concurrent Pentect sessions for the same OS user can share masked counts, labels, and safe relative filenames. Secret values are not shared, but cross-project metadata is visible to another Pentect process holding the local control channel.

Recommended decision: scope activity sharing by project or default it off if cross-project status aggregation is not required.

## Validation

- `cargo check -p pentect-cli`
- Targeted `pentect-runtime` memory-store tests: 11 passed
- Invalid UTF-8 detector regression: passed
- Remote plugin cache regression: passed
- Phone detector test after dependency upgrade: passed
- `cargo fmt --all -- --check`
- `git diff --check`
- Post-upgrade OSV query: no known actionable vulnerability advisories

No tracked private keys or obvious committed credential values were found. This review is code- and configuration-focused; it does not replace a third-party penetration test or an audit of the GitHub organization and release credentials.
