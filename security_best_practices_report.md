# Pentect security review

Date: 2026-07-22
Scope: Rust workspace, shell/runtime IPC, masking pipeline, plugins, installers/updater, and GitHub Actions.

## Executive summary

Seven clear security issues were fixed in this review: an unsafe UTF-8 mutation reachable through the public detector API, local memory-store connection/request exhaustion, a project-controlled remote plugin cache, mutable GitHub Actions dependencies, the dependency advisories known at the time of the review, executable-plugin approval bypasses, and project-controlled plugin runtime artifacts. Targeted tests and `cargo check -p pentect-cli` pass.

Executable plugins now use a WebAssembly-only runtime with bounded memory, fuel metering, wall-clock deadlines, and no ambient filesystem, environment, process, or socket access. Optional network access is restricted to explicitly approved origins and methods, with redirect denial, pinned DNS resolution, private-address filtering, and byte limits. Native plugin execution and arbitrary postscripts are rejected. Plugin release assets are verified with GitHub's Sigstore artifact attestations, pinned to the publisher repository and workflow, in addition to SHA-256.

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

The vulnerable dependency versions found by this review were removed or upgraded, including `phonenumber`/`quick-xml`, `crossbeam-epoch`, and `anyhow`. PDF inspection was subsequently restored as a product requirement using a newer parser stack; it remains subject to normal lockfile audit and input-size limits and must not be described as dependency-free. A follow-up OSV scan at the time found no remaining known actionable vulnerability advisories. Informational unmaintained transitive packages remained: `atomic-polyfill`, `paste`, and `proc-macro-error2`.

References: <https://rustsec.org/advisories/RUSTSEC-2026-0187.html>, <https://rustsec.org/advisories/RUSTSEC-2026-0190.html>, <https://rustsec.org/advisories/RUSTSEC-2026-0194.html>, <https://rustsec.org/advisories/RUSTSEC-2026-0195.html>, <https://rustsec.org/advisories/RUSTSEC-2026-0204.html>.

### PNT-SEC-005 — Mutable CI action references (medium)

CI and release workflows used mutable action tags. A compromised or moved upstream tag could inject code into builds or releases.

Fixed in `.github/workflows/ci.yml` and `.github/workflows/release.yml`: third-party actions are pinned to full commit SHAs, CI defaults to read-only repository permissions, and checkout credentials are not persisted.

### PNT-SEC-006 — Executable plugin activation could bypass setup (high)

The retired adapter runtime could fall back to a relative command or `PATH`. A remote TOML file could therefore select an installed interpreter and receive input without the release-binary setup path.

Fixed in the plugin middleware runtime: TOML-only plugins may add regex detectors, while executable plugins resolve only to the project-scoped installed release artifact or a Pentect sidecar. Runtime startup requires an exact SHA-256 match with the approved `plugin.toml`, including repository, command, stages, permissions, and postscripts. Plugin updates preserve that approval instead of rewriting it.

Relevant code: `crates/pentect-cli/src/plugins_cmd.rs` and `crates/pentect-runtime/src/plugin_middleware.rs`.

### PNT-SEC-007 — Plugin executables were project-controlled (high)

Installed binaries and approval files previously lived below `.pentect/plugins-data/<plugin>`. A cloned repository could pre-place both a same-named executable and unauthenticated approval metadata.

Fixed by moving approval, binaries, configuration, cache, and mutable plugin data to an OS user-data directory outside the repository, scoped by the canonical project identity and plugin ID. Unix plugin data directories are restricted to mode `0700`. Existing project-local approvals are intentionally not migrated; executable plugins require setup once under the new layout.

## Decisions required

### PNT-SEC-D03 — Postscript permissions were descriptive, not enforced (resolved)

Resolved by rejecting arbitrary postscripts. Plugin setup is limited to host-owned installation of a signed release asset.

### PNT-SEC-D04 — Plugin release checksums were not independent signatures (resolved)

Resolved with GitHub Actions keyless artifact attestations. Verification pins the expected repository and signer workflow and denies self-hosted runners; SHA-256 remains a transport-integrity check.

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
