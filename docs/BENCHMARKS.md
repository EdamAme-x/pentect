# Benchmarks

## CredData

CredData is the first external secret-detection benchmark target.
It is not vendored into this repository.

```powershell
git clone https://github.com/Samsung/CredData.git target/CredData
cd target/CredData
python download_data.py
cd ../..
pentect bench creddata target/CredData
```

Useful runs:

```powershell
pentect bench creddata target/CredData --json
pentect bench creddata target/CredData --limit 1000
pentect bench creddata target/CredData --repo 02dfa7ec
pentect bench creddata target/CredData --min-precision 0.80 --min-recall 0.70
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

CredData source: https://github.com/Samsung/CredData
