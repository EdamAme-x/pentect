# Benchmarks

## CredData

CredData is the first external secret-detection benchmark target.
It is tracked as a Git submodule, but generated data is not vendored.

On Windows, generate and run the dataset inside WSL. CredData's downloader
requires Linux-compatible paths, and copying the generated data to NTFS can
trigger Defender quarantine or path handling differences. The benchmark runner
scores files in parallel with deterministic path-order merging, so repeated runs
keep the same metrics and example order while finishing much faster.

```powershell
git submodule update --init --depth 1 benchmarks/CredData
wsl bash -lc "cp -a /mnt/c/Users/$env:USERNAME/Desktop/pentect/benchmarks/CredData ~/pentect-creddata"
wsl bash -lc "cd ~/pentect-creddata/CredData && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
wsl bash -lc "cd ~/pentect-creddata/CredData && .venv/bin/python download_data.py --jobs 8"
wsl bash -lc "cd /mnt/c/Users/$env:USERNAME/Desktop/pentect && CARGO_TARGET_DIR=~/pentect-linux-target cargo build -p pentect-cli --release"
wsl bash -lc "~/pentect-linux-target/release/pentect bench creddata ~/pentect-creddata/CredData --json"
```

Useful runs:

```powershell
wsl bash -lc "~/pentect-linux-target/release/pentect bench creddata ~/pentect-creddata/CredData --json"
wsl bash -lc "~/pentect-linux-target/release/pentect bench creddata ~/pentect-creddata/CredData --limit 1000"
wsl bash -lc "~/pentect-linux-target/release/pentect bench creddata ~/pentect-creddata/CredData --repo 02dfa7ec"
wsl bash -lc "~/pentect-linux-target/release/pentect bench creddata ~/pentect-creddata/CredData --min-precision 0.80 --min-recall 0.70"
```

Scoring:

- `T` rows are positives.
- `F` and `X` rows are negatives by default, matching CredData's benchmark.
- `--ignore-x` removes `X` rows.
- `ValueStart` and `ValueEnd` are treated as zero-based, end-exclusive columns.
- A positive is `tp` when a Pentect secret span overlaps the value range.
- A detection on a positive line but outside the value range is `line_only`.
- Detections outside labeled rows are reported as `unlabeled`, not counted as `fp`.
- `--examples N` emits local diagnostic examples for `fn`, `line_only`, `fp`,
  and `unlabeled` rows, capped at `N`.
- Category summaries split CredData category strings on `:`.

Previous baseline before the current false-positive hardening:

```text
CredData commit: 9a55c40
Pentect command: ~/pentect-linux-target/release/pentect bench creddata ~/pentect-creddata/CredData --json
Rows: 66898
Files: 10865
True rows: 15104
False rows: 51794
TP: 6967
FP: 27635
FN: 8137
Line only: 278
Unlabeled: 196201
Missing files: 0
Precision: 0.201
Recall: 0.461
F1: 0.280
Elapsed: 153352 ms
```

Current working result after structural false-positive reductions, source
name/reference and fixture filtering, generic-key name filtering, RFC
documentation-value handling, plaintext GitHub node-id entropy suppression, and
C-family ternary syntax suppression. Keyed detection now recovers unquoted
hex-like values under `*_key`, `*_secret`, and explicit `hex*` fields by
structure rather than by a vendor/corpus regex. Canonical cryptographic fixture
hex patterns such as sequential bytes, repeated bytes, and visual
`012345...`/`001122...` test vectors stay negative. `KEYED_SECRET` identity
sweep is disabled: key-value detections require local key context, while
stronger rule/entropy/structural detections still drive global identity sweep.

```text
CredData commit: 9a55c40
Pentect command: ~/pentect-linux-target/release/pentect bench creddata ~/pentect-creddata/CredData --json
Rows: 66898
Files: 10865
True rows: 15104
False rows: 51794
TP: 10294
FP: 13280
FN: 4810
Line only: 220
Unlabeled: 69500
Missing files: 0
Precision: 0.437
Recall: 0.682
F1: 0.532
Elapsed: 29026 ms
```

Weak groups:

- `Key`: recall improved substantially from hex material detection; remaining precision work is mostly `KEYED_SECRET` source/config metadata collisions.
- `Password`: many false positives from weak fixture/default-looking values that are still real credentials in production.
- `Token` and `Auth`: recall is strong, but precision still needs vendor/context validators.
- `LIKELY_SECRET`: broad entropy recall still catches source identifiers and opaque non-secret blobs.
- Plaintext GitHub API captures now suppress Base64 `node_id` metadata after validating the decoded `type:id` shape; arbitrary Base64 secrets still fire.
- `URL_CREDENTIAL`: now keeps token-as-username recall; documentation hosts are suppressed only for RFC-reserved examples.
- RFC 2606/6761 domains, RFC 5737 IPv4 ranges, and RFC 3849/9637 IPv6 ranges are shared by URL and placeholder suppression so sample hosts do not need ad hoc literals.
- Structured JSON now suppresses UI/localization prose for password/token message keys and avoids sweeping low-information UI labels, but compact values under real secret keys still fire.
- Generic JSON `"key"` values that are identifier names such as `smtpDomain`, `Authorization`, or `grant_type` are treated as metadata; digit/symbol-bearing key material and sensitive single words still fire.
- Code/reference literals under sensitive-looking keys are suppressed only when syntax proves they are not values: PascalCase type annotations require a code delimiter, and env lookups require explicit Jinja/Ansible `lookup('env', ...)` shape.
- Additional source/metadata literals are shape-gated: protobuf tag descriptors require `protobuf_key` context, key algorithm labels require known algorithm-size syntax, fingerprints require explicit fingerprint keys and colon-hex shape, and command/mock fragments require invocation syntax.
- Synthetic hex fixture strings are suppressed when the whole value is built from canonical visual patterns, sequential byte runs, or repeated bytes; arbitrary hex under sensitive key context still fires.
- `KEYED_SECRET` identity sweep keeps anchored detections only. Context-free propagation is left to stronger rule, entropy, and structural detections.
- Source fixture literals require both source-code shape and fixture key context, so `expectedPassword = "pass"` is skipped while plain `password = "pass"` still fires.
- `UUID`: low recall.
- `AWS S3 Bucket`, `Firebase Domain`, and `Tencent WeChat API App ID`: currently missed.

CredData source: https://github.com/Samsung/CredData
