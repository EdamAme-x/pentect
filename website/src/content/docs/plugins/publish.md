---
title: Test and publish
description: Check a plugin, publish a Wasm release, and update it safely.
---

## Test locally

Check the manifest or installed Wasm file:

```sh
pentect plugins test ./my-plugin
pentect plugins inspect ./my-plugin
```

For a Rust Wasm plugin, build it through Pentect:

```sh
pentect plugins dev ./my-plugin
```

This activates a local development build after approval. Pentect locks its
hash, but it has no GitHub build record. Use this mode only for code you are
developing on your computer.

These commands check the manifest, Wasm format, exports, and basic hook calls.
They do not prove that your detection rule is correct. Add normal unit tests for
expected matches, safe text, UTF-8 input, empty input, size limits, errors, and
every block path.

## Test in a real flow

Use fake values, not real credentials:

```sh
echo "ACME-12345678" | pentect mask --plugins ./my-plugin
pentect codex --plugins ./my-plugin
```

Run `pentect log` in another terminal. Check both a match and a value that must
stay visible.

## Create a release bundle

The project made by `pentect plugins new` includes a GitHub Actions release
workflow. Before the first release:

1. Set `repository = "OWNER/REPOSITORY"` in `plugin.toml`.
2. Commit `Cargo.lock`.
3. Keep the generated workflow at `.github/workflows/release.yml`, or update
   `publisher.workflow`.
4. Run the local checks.

Prepare the same files locally:

```sh
pentect plugins publish .
```

This builds `dist/PLUGIN.wasm` and `dist/PLUGIN.wasm.sha256`. It does not push
code or create a GitHub release.

## Publish from GitHub

Push the repository, then create a version tag:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The generated workflow builds the Wasm file with `--locked`, creates its
checksum, adds a GitHub build record, and uploads both files to a release.

Users can then install it with:

```sh
pentect plugins add github:@OWNER/REPOSITORY
```

Binary installation needs [GitHub CLI](https://cli.github.com/) v2.51.0 or
newer. Pentect uses it to check the release build record.

For a plugin inside a larger repository, add the path:

```sh
pentect plugins add github:@OWNER/REPOSITORY/plugins/my-plugin
```

The release asset still comes from `repository` in the manifest.

## Updates and approval

```sh
pentect plugins update NAME
```

Pentect checks the new checksum and GitHub build record. It asks for approval
again when the manifest or exported hooks change. A binary with the same
approved access can update without changing the saved manifest approval.

Do not replace files in an old release. Publish a new tag so users can review
and roll back versions clearly.

## Add a plugin to the Pentect catalog

The built-in catalog is intentionally small. A plugin can work without being
listed there. Users can install any GitHub source directly.

To request a catalog entry, open a Pentect pull request that adds one item to
`plugins/registry.toml`. The source publisher must match the repository owner.
Include a clear README, license, tests, release workflow, and security contact.
