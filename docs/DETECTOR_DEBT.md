# Detector Debt Inventory

This inventory tracks detector logic that can look like coverage-driven
hardcoding. Each item has an intended disposition: `keep`, `replace`,
`extension`, or `remove`.

## Failure Groups

These are the groups to use when presenting what is still weak. Do not collapse
them into one aggregate "false positive" number; each group needs a different
fix and a different claim.

### Structure-blind keyed secrets

- Symptom: natural language such as "secret capability" or docs about password
  fields is treated as a secret value.
- Root cause: a regex captures key vocabulary, separators, and values without
  first proving that the line is a real key/value structure.
- Current fix: `KeyValueDetector` owns plaintext key/value parsing and emits
  only the value span.
- Readiness gate: all positive keyed corpora pass while benign docs/prose,
  counters, and public labels stay at zero masks.

### Entropy overreach

- Symptom: long source identifiers, regex character classes, path fragments, and
  checksum/hash strings become `LIKELY_SECRET`.
- Root cause: Shannon entropy alone is not a detector; it needs a candidate
  shape gate before scoring.
- Current fix: entropy now rejects source identifiers, regex character-class
  fragments, lowercase charset/digest-like runs, benign assignments, and
  slash-delimited source paths. URL/path secrets are scored by segment.
- Readiness gate: `LIKELY_SECRET` in application source should be explainable as
  fake secret fixtures or real opaque values, not ordinary identifiers.

### Reference-data and fixture echo

- Symptom: BIP39 wordlists, detector implementation text, and benchmark fixtures
  are counted as real findings when scanning the repository.
- Root cause: scanner reports lack scope, and detectors do not distinguish
  reference material from runtime/user data.
- Current fix: scan output groups findings by `runtime`, `application_source`,
  `detector_source`, `test_fixture`, `evaluation`, and `docs_examples`; BIP39
  ignores official one-word-per-line reference wordlists.
- Readiness gate: demos and papers report scope-separated precision/recall, not
  one blended scan count.

### Vendor-token catalog debt

- Symptom: adding one more provider regex improves recall but makes core look
  like an unbounded secret-pattern pack.
- Root cause: vendor-specific syntax has no stable ownership boundary.
- Current fix: deterministic high-signal vendor tokens stay in core for now;
  long-tail and org-specific rules move to extension packs.
- Readiness gate: every built-in vendor rule has a reason, validator where
  possible, and a negative collision test.

### Extension-boundary misses

- Symptom: person names, organizations, postal addresses, and other natural
  language PII are missed by core.
- Root cause: deterministic core is intentionally not an NER/NN privacy filter.
- Current fix: core owns secrets, tokens, structured PII, local paths, and URLs;
  NER/NN belongs in extensions.
- Readiness gate: benchmark tables split `core` from `extension_pii`, and demos
  do not imply core handles language-heavy PII without an extension.

### Benchmark overfitting

- Symptom: a detector exists only because one benchmark contains a recognizable
  sample shape.
- Root cause: headline recall was optimized without paired negative corpora and
  ablation.
- Current fix: negative corpora include source, fixtures, detector text,
  wordlists, docs, logs, and near-miss tokens.
- Readiness gate: each detector change ships with positive/negative deltas and
  an ablation note showing why the rule is not corpus-specific.

## Presentation Readiness Gates

The current answer to "is this ready to present as production-grade?" is still
`no`. It becomes defensible for MSAI 2026 when these gates are met:

- Reproducible eval: one command produces precision/recall/F2/utility by scope
  and by detector family.
- No hidden hardcoding: built-ins are documented as deterministic core, extension
  packs, or debt with owner and migration path.
- Precision story: repo scan reports are grouped by scope and top labels, with
  source/fixture false positives separated from runtime risk.
- Recall story: secrets, tokens, structured PII, URLs, local paths, BIP39, and
  `.env`/JSON/header values have positive corpora and no-survivor tests.
- Extension story: NER/NN PII is explicitly out of core and demonstrated through
  an extension boundary if claimed.
- Performance story: release-build throughput is measured on adversarial and
  realistic corpora, not only unit tests.
- Ablation story: KeyValue, BIP39, entropy, vendor rules, and structural
  detectors can be evaluated independently.

Latest local release-build snapshot:

- `python tools/bench_adversarial.py --bin target/release/pentect.exe --profile strict --json`: all cases pass; benign and near-miss storms produce zero masks.
- `python tools/eval_hostile_realworld.py --bin target/release/pentect.exe --profile strict --json --sample-limit 8`: overall coverage 0.786, utility 1.000, all deterministic core categories 1.000, `extension_pii` 0.000 by design.
- `pentect scan . --json --no-fail`: 438 findings across 67 scanned files;
  scope split is test fixtures 203, application source 114, detector source
  89, evaluation 27, docs examples 5.
- `pentect scan C:/Users/yun40/Desktop/codex-continuer --json --no-fail`: 0
  findings across 2 scanned files after rejecting source self-references,
  function-call RHS values, and Rust namespace separators.
- Application-source `LIKELY_SECRET` dropped from 403 to 16 after entropy
  candidate gating. Application-source `KEYED_SECRET` dropped from 364 to 39
  after quote/type-expression/source-expression tightening; remaining hits are mostly fixture-like
  source samples and need a narrower source-scope precision pass.

## Replace

### Generic keyed secret regex

- Status: `replace`
- Location: formerly `RuleDetector` captured rule labelled `KEYED_SECRET`
- Why it was debt: one large capture regex mixed key vocabulary, separators,
  value shape, and sentence handling. Small regex edits could improve a fixture
  while still masking prose such as "secret capability" or "token budget".
- Replacement: `KeyValueDetector`, which parses `key / separator / quote /
  value / line boundary` and then applies key-name and value-shape features.
- Migration tests: positive plaintext assignments (`password is summer-2026`,
  `client_secret: tenant-7-trial`, `otp=100482`, copied auth headers) and
  negative prose/counters (`secret capability`, `token budget`, `api design`,
  `password field docs`, `port=5432`).

### BIP-39 mnemonic word runs

- Status: `replace`
- Location: `Bip39Detector`
- Why it was debt: checksum alone is strong for a single phrase, but scanning a
  whole source tree can still flag official wordlists, detector source, and
  fixture literals.
- Replacement: keep checksum validation, but require evidence that the window
  is a real user mnemonic: standalone phrase, explicit seed/recovery/mnemonic
  context, or numbered-list structure. Ignore large one-word-per-line reference
  wordlists.
- Migration tests: official wordlist and source-test-vector literals are
  negative; standalone, labelled, multilingual, and numbered phrases remain
  positive.

### Context-free entropy scoring

- Status: `replace`
- Location: `EntropyDetector`
- Why it was debt: a long token with high Shannon entropy was enough to produce
  `LIKELY_SECRET`, so normal code identifiers and regex source text could be
  masked.
- Replacement: use `structure first, entropy second`: validate the candidate
  shape, split slash paths into segments, reject source identifiers and regex
  character classes, and then apply Shannon scoring.
- Migration tests: source identifiers, regex character classes, benign
  assignments, source paths, and lowercase charset constants are negative; an
  opaque mixed-case token and a secret-looking URL path segment remain positive.

## Keep

### Anchored vendor token rules

- Status: `keep`
- Location: `RuleDetector` built-ins
- Why it is acceptable for now: unique prefixes and fixed vendor grammars such
  as `AKIA...`, `github_pat_...`, Slack webhook URLs, and SendGrid keys are
  deterministic and high-signal.
- Required discipline: each new rule needs a reason, a validator when available,
  and at least one negative test for plausible collisions.
- Migration tests: labelled vendor recall corpus plus precision corpus on logs,
  prose, JSON, Rust snippets, and benchmark/source text.

### Checksum-gated structured identifiers

- Status: `keep`
- Location: `RuleDetector` checked rules and `validate.rs`
- Why it is acceptable for now: regex finds candidates, but validators such as
  Luhn, IBAN mod-97, Verhoeff, and country-specific checks decide acceptance.
- Required discipline: ambiguous identifiers without checksums must be
  context-gated or low-confidence.
- Migration tests: reference vectors in `validate.rs` and no-overmasking corpus
  in pipeline tests.

### Protocol structural masking

- Status: `keep`
- Location: `StructuralDetector`, `SensitiveKeyDetector`, `EnvValueDetector`
- Why it is acceptable for now: these fire from parser- or protocol-supplied
  structure, not from open-ended text guessing.
- Required discipline: keep adapter context explicit. Do not infer arbitrary
  natural-language entities here.
- Migration tests: JSON value context, `.env` value regions, cookies, and auth
  headers.

## Extension

### Vendor long tail

- Status: `extension`
- Location: currently split between built-ins and user rule packs
- Why it is debt in core: a growing vendor catalog turns core into a large
  regex pack and encourages benchmark-by-benchmark additions.
- Alternative: keep only high-signal deterministic defaults in core. Move
  organization-specific and lower-confidence vendor rules to `.pentect/extensions`
  rule packs.
- Migration tests: extension packs may add detectors but must not disable
  built-ins unless explicitly loaded as packs with `disable`.

### Dynamic regexp generation

- Status: `extension`
- Location: not in core
- Why it would be debt in core: generating regexes from examples can overfit
  user samples and silently promote benchmark-specific patterns.
- Alternative: implement as an extension that stores generated regex with
  positive examples, negative examples, and a validator/prefilter where possible.
- Migration tests: generated rules must reject supplied negatives and should not
  be auto-promoted into built-ins.

### NN / NER privacy filters

- Status: `extension`
- Location: not in core
- Why it would be debt in core: person names, addresses, organizations, and
  natural-language PII require language/model policy and deployment choices.
- Alternative: use an extension boundary such as
  `pentect --extensions openai-privacy-filter` for NER/NN detection.
- Migration tests: core benchmark tables should list these as extension scope,
  not core misses.

## Remove

### Benchmark-only win conditions

- Status: `remove`
- Location: any test, fixture, scan prefilter, or pack-builder output that
  exists only to win one corpus
- Why it is debt: it improves headline recall while making real scans noisy.
- Alternative: use labelled precision/recall deltas, with benign source and
  fixture corpora included.
- Migration tests: `pentect scan . --no-fail` top labels and false-positive
  counts should be compared before and after detector changes.

### Inferred prefilters without ownership

- Status: `remove`
- Location: regex pack builder outputs when literals are inferred mechanically
- Why it is debt: a prefilter can hide rule behavior and make a generated regex
  look cheaper or more precise than it is.
- Alternative: require explicit prefilters in extension packs, documented next
  to the rule and covered by tests.
- Migration tests: pack loading should preserve captures and validators; absent
  prefilter literals must skip only the intended extension rule.
