# Contributing to Pentect

Thanks for contributing. Keep changes focused, explain the user problem, and avoid committing secrets or private data.

## Before opening a change

- Use a bug report for reproducible incorrect behavior and a feature request for new behavior.
- Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/EdamAme-x/pentect/security/advisories/new).
- For larger design changes, open an issue before investing in an implementation.

## Pull requests

1. Create a branch from `main`.
2. Make one focused change and include relevant tests or documentation.
3. Run the smallest useful local checks; the full suite runs in CI.
4. Open a pull request and describe what changed, why, and how it was validated.

Useful checks:

```sh
cargo fmt --all --check
cargo check --locked -p pentect-cli
```

Run focused tests for the crate or behavior you changed. Please do not add unrelated cleanup to the same pull request.

## Releases

Maintainers only need to merge a version bump and create the matching `vX.Y.Z`
tag from `main`. GitHub Actions then builds immutable release assets, tests the
install and uninstall lifecycle, signs and publishes the APT repository, updates
package metadata through an auto-merge pull request, creates the matching
`nix-vX.Y.Z` tag, and tests the Homebrew formula on Intel and Apple Silicon before
publishing it.

Never reuse a release tag. A workflow retry may fill in a missing prerelease
asset only when every already-published asset has the same SHA-256 digest.
