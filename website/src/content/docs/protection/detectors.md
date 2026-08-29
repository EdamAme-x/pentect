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

## Upstream-derived detectors

| Detector | Source and pinned version | Enabled coverage | Evidence and limit |
| --- | --- | --- | --- |
| `CredSweeperNativeDetector` | Samsung CredSweeper `v1.17.4`, commit `c7ad63b95ce0941954465a3b759046b14b88807b`; rule, keyword, allowlist, and ML assets are pinned in the binary | Credential and secret rules represented by the pinned assets | Pull requests compare the native result with official Python CredSweeper on one pinned CredData repository. A 16-shard weekly or manually dispatched job is configured to compare all 333 CredData repositories, including rule identity, value and variable spans, path and line context, entropy, and bounded ML probability. This is corpus evidence, not proof of general CredSweeper parity. |
| `AlcatrazDetector` | Hoop Alcatraz `0.20.2`, commit `cd2e19b7d0f08b113c52ef52d3485c64a0871455`, compiled as a static Go helper and compressed into the Pentect binary | `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `IBAN_CODE`, `UK_NINO`, `IN_PAN`, `IT_FISCAL_CODE`, `ES_NIF`, `ES_NIE`, `SG_FIN`, `KR_RRN`, and `FI_PERSONAL_IDENTITY_CODE` | Helper tests cover each enabled entity and release smoke tests check representative findings on supported release platforms. Other Alcatraz entities are disabled. Alcatraz can still miss valid values or produce false positives. |

Pentect does not call the CredSweeper Python package at runtime. The native
implementation consumes pinned upstream assets and reimplements their behavior
in Rust. “CredSweeper-derived” therefore does not mean that every future,
unseen, or unsupported input is proven identical to official CredSweeper.

## Pentect-maintained detectors

These detectors are maintained in this repository. They must not be attributed
to CredSweeper or Alcatraz. They ship at the Pentect release version and do not
have separate component versions.

| Detector | Finding category | What it masks by default | Evidence boundary |
| --- | --- | --- | --- |
| `ExplicitSecretDetector` | Secret | Non-empty values deliberately wrapped in `pentect(...)` or `mask(...)` | Unit and end-to-end handle tests; explicit user instruction, not inference |
| `UrlDetector` | Secret, identifier, or endpoint | Credential-bearing URL and URI components, selected sensitive query values, `curl -u/-U` credentials, and selected cloud endpoint identifiers | Syntax and regression fixtures in the detector module |
| `CliCredentialDetector` | Secret | Plaintext password arguments in supported PowerShell command shapes | Shell-token and command-shape regression fixtures |
| `JwtDetector` | Secret | Structurally valid compact JWT and JWE values | JOSE structure, JSON header/payload, and size-bound tests; it does not establish token validity |
| `KeyValueDetector` | Secret | Values in plaintext `key=value`, `key: value`, and similar secret-key contexts when key, separator, boundary, and value checks agree | Positive and benign-corpus regression fixtures; independently maintained heuristics |
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
