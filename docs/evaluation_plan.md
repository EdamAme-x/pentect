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
