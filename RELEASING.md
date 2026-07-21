# Releasing Pentect

Pentect releases are driven by a `v<version>` tag on `main`. The version must
match both `pentect-cli` and `pentect-pii-ner` in their Cargo manifests.

Pushing the tag runs `.github/workflows/release.yml`, which builds and uploads:

- `pentect` for Windows x64, Linux x64, macOS Intel, and macOS Apple Silicon;
- `pentect-pii-ner` for the same platforms;
- one `.sha256` file beside every binary.

The workflow rejects a tag that does not match the Cargo version or does not
point at `origin/main`. It creates the GitHub Release after every platform build
succeeds. Re-running the workflow replaces the assets on the same release.

Users update the main executable with:

```text
pentect update
```

`pentect update --check` only reports availability. Downloads are accepted only
when the release asset size and its sibling SHA-256 file match. On Windows, a
detached copy of the verified new executable performs the replacement after the
running updater exits.

First-time installation automatically selects the OS and CPU architecture:

```sh
curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.ps1 | iex
```

Set `PENTECT_INSTALL_DIR` to override the default destination. The installers
download the matching latest-release binary and its `.sha256` file before
installing anything.

Release-backed extension binaries are installed or refreshed with:

```text
pentect extensions setup pii-ner
pentect extensions update pii-ner
```
