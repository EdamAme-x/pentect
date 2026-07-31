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
