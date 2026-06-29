# Benchmarks

## CredData

CredData is the first external secret-detection benchmark target.
It is tracked as a Git submodule, but generated data is not vendored.

On Windows, generate and run the dataset inside WSL. CredData's downloader
requires Linux-compatible paths, and copying the generated data to NTFS can
trigger Defender quarantine or path handling differences.

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

Current working result after structural false-positive reductions and recall
hardening:

```text
CredData commit: 9a55c40
Pentect command: ~/pentect-linux-target/release/pentect bench creddata ~/pentect-creddata/CredData --json
Rows: 66898
Files: 10865
True rows: 15104
False rows: 51794
TP: 7043
FP: 16992
FN: 8061
Line only: 259
Unlabeled: 133090
Missing files: 0
Precision: 0.293
Recall: 0.466
F1: 0.360
Elapsed: 219429 ms
```

Weak groups:

- `Key`: low precision and low recall; mostly `KEYED_SECRET` and source/config metadata collisions.
- `Password`: many false positives from weak fixture/default-looking values that are still real credentials in production.
- `Token` and `Auth`: recall is strong, but precision still needs vendor/context validators.
- `LIKELY_SECRET`: broad entropy recall still catches source identifiers and opaque non-secret blobs.
- `URL_CREDENTIAL`: now keeps token-as-username recall; documentation hosts are suppressed only for RFC-reserved examples.
- Structured JSON now suppresses UI/localization prose for password/token message keys, but compact values under real secret keys still fire.
- `UUID`: low recall.
- `AWS S3 Bucket`, `Firebase Domain`, and `Tencent WeChat API App ID`: currently missed.
- Identity sweep intentionally does not propagate very short `KEYED_SECRET` values; this avoids widespread false positives but can miss repeated weak credentials outside their anchored assignment.

CredData source: https://github.com/Samsung/CredData
