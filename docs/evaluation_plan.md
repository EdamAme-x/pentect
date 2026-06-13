# Pentect evaluation plan

## Evaluation goal

Evaluate whether Pentect lets users safely use AI on sensitive technical data.

The main question is not "does Pentect anonymize all prose PII?" The main question is:

> Can AI still do useful technical work while raw secrets never leave the local machine?

## Primary metrics

- `leak_count`: raw protected values that survive in the masked text. Target: 0.
- `overmask_count`: benign values masked when they should remain visible. Target: 0 for the precision ratchet corpus.
- `utility`: whether the masked prompt still preserves enough structure for the task.
- `task_success`: whether the AI can complete the intended debugging, review, or security reasoning task.
- `resolve_correctness`: masked text resolves byte-for-byte through the local recovery map.
- `remask_correctness`: resolved secrets echoed by tools are hidden again before returning to the AI.

## Corpora

### SecretBench export

This is the primary external benchmark for deterministic secret detection.

SecretBench is gated and must be requested from its authors. Do not copy its
rows into this repository. After access is granted, export the BigQuery table to
CSV, JSON, or JSONL, then run:

Access status: request sent to the authors; wait for their reply and any data
protection agreement instructions before exporting or running the dataset.

```sh
python tools/eval_secretbench.py path/to/secretbench_export.jsonl --bin target/release/pentect
```

The runner consumes external labeled rows and reports candidate-level precision,
recall, F1, false-positive rate, and failures by SecretBench category/comment.
It does not contain a hand-authored corpus, so the result cannot be made 100%
by adjusting local fixtures.

### External regex packs

External regex sources can be used as broad-recall detector packs without
locking Pentect to a specific benchmark. SecretBench's public regular-expression
workbook is one useful source, but the same builder also accepts CSV, TSV, XLSX,
JSON, and JSONL inputs with explicit column mappings.

Generate chunked Pentect packs from the SecretBench public workbook:

```sh
python tools/build_regex_pack.py --source secretbench-public --out-dir target/secretbench-public-regex
```

Generate packs from another source by mapping its columns:

```sh
python tools/build_regex_pack.py rules.csv \
  --pattern-col regex \
  --label-col type \
  --id-col id \
  --origin-col source \
  --capture-col capture \
  --label-prefix EXT \
  --out-dir target/external-regex
```

The builder skips entries that are templates, malformed, or not supported by the
Rust regex engine, and writes a `*-skipped.tsv` report.

Generated packs can set `capture = N` per detector. `capture = 0` masks the full
regex match; `capture = 1` masks only the first capture group. This matters for
third-party rules shaped like `keyword ... (actual_secret)`, where masking the
whole match would erase useful context. The SecretBench public preset enables a
conservative capture inference pass for common context-window and delimiter
patterns.

The CLI can load the whole generated directory directly:

```sh
pentect mask --pack-dir target/secretbench-public-regex
```

Use generated regex packs as temporary broad-recall detector packs. Keep them
reported separately from the curated core rules because third-party regexes are
often context-heavy and can overmask surrounding text.

### ai4privacy export

This is the external benchmark path for structured PII and the boundary between
structured PII and semantic PII.

Use it from an external Hugging Face export. Do not copy the dataset rows into
this repository.

```sh
python tools/eval_ai4privacy.py path/to/ai4privacy.jsonl --bin target/release/pentect
python tools/eval_ai4privacy.py path/to/ai4privacy.jsonl --preset core-structured --bin target/release/pentect
python tools/eval_ai4privacy.py path/to/ai4privacy.jsonl --preset semantic --extra-arg --ner --bin target/release/pentect
```

The runner consumes `source_text`, `privacy_mask`, and `span_labels` style rows.
It reports detection-only recall by label: a labeled value counts as concealed
when the raw value is absent from Pentect's masked output. It does not report
type accuracy, because Pentect placeholders use Pentect labels rather than the
ai4privacy label taxonomy.

Use the presets deliberately:

- `core-structured`: email, phone, card, IBAN, passport, tax/social numbers,
  account numbers, usernames, IP-like and URL-like identifiers.
- `semantic`: names, addresses, organizations, locations, titles, dates, and
  time-like prose labels. This should be used to measure optional NER/date
  layers, not to judge the deterministic core.

### Technical corpus

This is the primary corpus.

It should include hand-authored and synthetic samples for:

- `.env` files
- JSON/YAML/TOML config snippets
- logs and stack traces
- HAR and HTTP traces
- curl commands and API examples
- code review prompts with embedded secrets
- pentest or security investigation notes

Each sample should mark:

- values that must be hidden
- values that must remain visible
- the task the AI should still be able to perform

### Negative corpus

This prevents overmasking.

It should include benign UUIDs, hashes, IDs, public endpoints, version strings, code constants, product names, and prose that look superficially secret-like but are safe to keep.

The ceiling for false positive masking in this corpus should remain zero unless explicitly changed.

### Prose PII corpus

This is secondary.

TAB/ECHR and similar prose anonymization datasets are useful only for measuring optional semantic PII layers such as NER or date detection. They should not be used as the headline score for the deterministic core.

ai4privacy is more useful than TAB for Pentect because it contains many
structured identifiers mixed into natural text. Still, the headline Pentect
score should separate `core-structured` from `semantic`; combining them into one
PII number hides the actual product boundary.

## Why TAB is not the primary benchmark

TAB/ECHR is mostly legal prose with PERSON, ORG, LOC, DATETIME, and case-code style entities. It contains little to none of the technical secret material Pentect's deterministic core targets.

A low deterministic-core score on TAB is expected domain mismatch, not a core failure.

Use TAB only to demonstrate:

- date detection when `DATE_TIME` is explicitly enabled
- NER sidecar behavior
- the boundary between deterministic core and semantic PII

## Acceptance scenarios

### Debugging scenario

Input: `.env`, config, and error log.

Accept when:

- all secrets are masked
- repeated values use stable placeholders
- benign debugging context remains readable
- resolve returns the exact original input

### Agent execution scenario

Input: masked command containing placeholders.

Accept when:

- resolve before execution yields the real command locally
- tool output is remasked before it is shown to the AI
- unknown or hallucinated placeholders do not reveal anything

### Security trace scenario

Input: HAR or HTTP trace.

Accept when:

- credential-bearing values are masked
- request/response structure remains valid enough for analysis
- endpoint and vulnerability-relevant context is preserved by default

## Reporting

Report results by workflow, not only by detector label.

Recommended reporting table:

- scenario
- leak count
- overmask count
- resolve pass/fail
- remask pass/fail
- task success
- notes on utility loss

This keeps the evaluation tied to the product promise rather than to generic PII benchmark coverage.
