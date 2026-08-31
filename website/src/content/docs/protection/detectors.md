---
title: Detectors and evidence
description: The source, scope, version, and verification boundary of every built-in detector.
---

Pentect does not have one detector that recognizes every kind of private data.
The standard masking engine combines the detectors below. `pentect mask` and
supported AI request and tool-result paths construct this same engine; parsers
may add trusted field and format context before the detectors run.

This inventory describes the default built-in engine. A plugin can add rules,
but plugin findings are plugin-provided evidence and are not part of the
built-in coverage claims.

## Credential-class boundaries

Detection depends on both the value and its trusted context. A short string can
be a real password and an ordinary word at the same time, so Pentect does not
claim that every credential is recognizable from the value alone.

| Class | Default behavior | Evidence boundary |
| --- | --- | --- |
| Low-entropy password | Built in when a parser supplies a password field or plaintext has a supported password assignment/prose shape | A bare common word or very short string is intentionally not treated as a secret without context. A structured value identical to its key, such as `"password": "Password"`, is also left visible because that shape is common localization UI text. Use `pentect(...)` or `mask(...)` when the intended meaning is known only to the user. |
| Cookie | Built in for parser-identified cookie values and `Cookie`/`Set-Cookie` headers; supported keyed plaintext forms are also detected | A bare cookie value has no unique syntax and is not a separate value-only claim. |
| Session ID or session token | Built in for sensitive structured keys, supported key/value text, and structurally valid token formats such as JWT | A bare UUID remains visible unless trusted cookie, session, or identifier-bearing context says otherwise. UUID shape alone is not proof of a credential. |
| Refresh, access, or CSRF token | Built in for sensitive structured keys, supported key/value text, credential-bearing URL fields, and token-specific formats | A bare word or public identifier is not automatically classified as a token. |
| JWT or JWE | Built in through `JwtDetector` when compact JOSE structure validates | Structural validation does not prove that the token is live or accepted by a service. |
| Editor-extension credential | No product-name-wide claim. Built-in detectors protect supported generic token formats and sensitive fields regardless of which editor produced them | An extension-specific storage envelope needs a verified parser or plugin before Pentect can claim full coverage for that extension. |

The same standard engine handles `pentect mask`, supported AI prompt and tool
result paths, and text extracted from logs. HTTP adapters add only the protocol
fields they explicitly recognize, including credential-bearing headers,
cookies, and protected JSON fields. OCR sends recognized text through the same
engine, but this proves only masking after successful text recognition; OCR
accuracy and unscanned-image policy are separate boundaries.

Plugins may add extra formats or rules. They do not turn a heuristic or an
intentionally unsupported bare value into built-in coverage. Explicit
`pentect(...)` and `mask(...)` markers are user instructions, not automatic
detections, and are the safe control for an ambiguous value.

## Upstream-derived detectors

| Detector | Source and pinned version | Enabled coverage | Evidence and limit |
| --- | --- | --- | --- |
| `CredSweeperNativeDetector` | Samsung CredSweeper `v1.17.4`, commit `c7ad63b95ce0941954465a3b759046b14b88807b`; rule, keyword, allowlist, and ML assets are pinned in the binary | Credential and secret rules represented by the pinned assets | Pull requests regenerate the complete official rule/filter inventory, exercise every official filter through its upstream tests and deterministic boundary inputs, and compare one pinned CredData repository end to end. A 16-shard weekly or manually dispatched job compares all 333 CredData repositories, including rule identity, value and variable spans, path and line context, entropy, and bounded ML probability. This remains corpus and fixture evidence, not proof of general CredSweeper parity. |
| `AlcatrazDetector` | Hoop Alcatraz `0.20.2`, commit `cd2e19b7d0f08b113c52ef52d3485c64a0871455`, compiled as a static Go helper and compressed into the Pentect binary | `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `IBAN_CODE`, `UK_NINO`, `IN_PAN`, `IT_FISCAL_CODE`, `ES_NIF`, `ES_NIE`, `SG_FIN`, `KR_RRN`, and `FI_PERSONAL_IDENTITY_CODE` | Helper tests cover each enabled entity and release smoke tests check representative findings on supported release platforms. Other Alcatraz entities are disabled. Alcatraz can still miss valid values or produce false positives. |

Pentect does not call the CredSweeper Python package at runtime. The native
implementation consumes pinned upstream assets and reimplements their behavior
in Rust. “CredSweeper-derived” therefore does not mean that every future,
unseen, or unsupported input is proven identical to official CredSweeper.

The binary embeds unchanged copies of the pinned upstream rule and scanner
configuration, keyword and morpheme checklists, ONNX model and model
configuration, and license. Rust code independently performs rule parsing,
keyword-pattern expansion, candidate and line construction, regular-expression
matching, filter-group expansion and filter execution, path and target checks,
multiline and PEM handling, ML feature extraction and inference, and output-span
construction. The official Python implementation is an Actions oracle; it is
not installed or used by the released binary.

The version-bound compatibility inventory records every source rule, its
expanded runtime state, filter and filter group, rule type, ML-gated rule, model
configuration, and configured candidate and line-data output field. Automated
upstream updates regenerate that inventory and must pass the native/oracle gates
before opening a pull request.

Every stable release also runs the full 333-repository comparison and the
complete filter/inventory and whole-pipeline fixture gates against the exact
tagged commit. A value-free `pentect-credsweeper-compatibility.json` release
asset records the tagged Pentect commit, pinned CredSweeper and CredData
revisions, test date, runner platform, finding totals, bounded ML difference,
and per-rule gaps. Release publication stops if the evidence does not match the
tag or either implementation reports a finding the other one does not.

## CredSweeper disagreement and rollback

A native/official mismatch is a security regression even when it is only an
extra finding. Do not silently accept it, weaken the fixture, or describe a
successful corpus run as proof for unseen input. Before release, the parity
gate blocks publication. If a mismatch is discovered after release, identify
the newest earlier Pentect release whose
`pentect-credsweeper-compatibility.json` evidence names the intended
CredSweeper version and reports no missing or extra findings, then validate and
install that exact Pentect version:

```sh
pentect update v0.0.69 --check
pentect update v0.0.69
pentect version
```

This restores the complete known release binary, not only its rule assets, so
independently implemented scanner behavior is rolled back as well. Exact
published tags are selectable even when GitHub marks an older release as a
prerelease; drafts remain unavailable and artifact checksum verification is
unchanged. Startup checks only notify, so the selected version is not
automatically replaced. Package-manager installations must select that exact
version through their package manager if Pentect cannot replace it directly.

## Pentect-maintained detectors

These detectors are maintained in this repository. They must not be attributed
to CredSweeper or Alcatraz. They ship at the Pentect release version and do not
have separate component versions.

| Detector | Finding category | What it masks by default | Evidence boundary |
| --- | --- | --- | --- |
| `ExplicitSecretDetector` | Secret | Non-empty values deliberately wrapped in `pentect(...)` or `mask(...)` | Unit and end-to-end handle tests; explicit user instruction, not inference |
| `UrlDetector` | Secret, identifier, or endpoint | Credential-bearing URL and URI components; password/token/secret, OAuth/OIDC callback, signature/session, and one-time-code query fields; `curl -u/-U` credentials; and selected cloud endpoint identifiers | Syntax, HTTP/WebSocket query, navigation-metadata, and mask/restore regressions in the detector module |
| `CliCredentialDetector` | Secret | Plaintext password arguments in supported PowerShell command shapes | Shell-token and command-shape regression fixtures |
| `JwtDetector` | Secret | Structurally valid compact JWT and JWE values | JOSE structure, JSON header/payload, and size-bound tests; it does not establish token validity |
| `KeyValueDetector` | Secret | Values in plaintext `key=value`, `key: value`, similar secret-key contexts, and leaf XML element text whose element name is sensitive, when key, boundary, and value checks agree | Positive, benign-corpus, malformed-XML, and mask/restore regression fixtures; independently maintained heuristics |
| `AuthCodeDetector` | Secret | Contextual authentication, verification, recovery, and one-time codes | Pattern, boundary, and known metadata false-positive tests |
| `Bip39Detector` | Secret | Checksum-valid 12, 15, 18, 21, or 24-word BIP-39 mnemonics from the bundled language lists | Checksum and boundary tests; ordinary names and prose are not its scope |
| `DecodeDetector` | Secret | An outer encoded or compressed value when bounded decoding reveals a finding from its inner secret detectors; optionally opaque encoded blobs when configured | Codec, nesting, expansion, byte, candidate, and time-budget tests |
| `SensitiveKeyDetector` | Secret | Parser-provided structured values under a sensitive key or path | Structured-format and key-context tests |
| `EnvValueDetector` | Secret | Values in parser-confirmed dotenv/secret-value regions and sensitive shell environment assignments | Dotenv, structured parser, POSIX shell, and PowerShell tests |
| `StructuralDetector` | Secret | Cookie values and values in a closed list of credential-bearing HTTP headers | Protocol-position and benign-value tests |

`RuleDetector` and `PatternMatchDetector` are building blocks used by compiled
rules and plugins. They are not additional default detector registrations.
Likewise, `EnvParser`, JSON parsers, and structured-format parsers provide
regions and context; they are parsers, not detectors.

## Labels are not provenance

A placeholder label describes how Pentect will present and recover a value. A
trusted parser can replace a generic detector label with a more useful field or
environment-key label. For example, a credential found inside a `DATABASE_URL`
field can use `DATABASE_URL` in its handle even when a different detector first
recognized the value. The label alone therefore does not prove that an upstream
CredSweeper rule, Alcatraz, or a particular Pentect detector produced the
finding.

Plugin findings and explicit `pentect(...)` or `mask(...)` directives have
their own sources. They must not be counted as upstream-detector evidence.

## What the checks prove

A passing unit fixture proves only that the named case works. The pinned
filter comparison proves agreement on the recorded filter invocations, and the
CredData comparison proves agreement on the exact corpus fields it compares.
Release smoke tests prove that representative detector behavior is present in
the produced binaries. None of these proves complete secret detection,
complete personal-data detection, or identical behavior on every input.

When describing coverage, use the narrowest supported statement:

- name the detector or enabled entity;
- name the client boundary or command that was tested;
- name the corpus or fixture when claiming measured compatibility;
- do not turn a passing sample into a general accuracy or parity claim.

The [Security model](/protection/security-model/) describes boundaries that
detectors cannot cover.
