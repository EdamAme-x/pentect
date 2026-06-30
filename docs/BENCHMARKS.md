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
C-family ternary syntax suppression. Entropy detection suppresses RFC 7468
public PEM bodies, OpenSSH public-key blobs, and `public_key`-style fields while
leaving private-key and ordinary opaque blobs detectable. Keyed detection now recovers unquoted
hex-like values under `*_key`, `*_secret`, and explicit `hex*` fields by
structure rather than by a vendor/corpus regex. Canonical cryptographic fixture
hex patterns such as sequential bytes, repeated bytes, and visual
`012345...`/`001122...` test vectors stay negative. `KEYED_SECRET` identity
sweep is disabled: key-value detections require local key context, while
stronger rule/entropy/structural detections still drive global identity sweep.
Generic `key` fields that name code members and parser-cut source fragments
(`Type{Field:`, minified `{key:"...", value:function...}` tails, strict ISO date
bucket keys) are treated as metadata/source syntax, not credential values. RFC
7617 Basic Authorization is captured through a token68 validator that decodes
to `user:password` shape. Identity sweep now rejects short syntax-only
representatives, and keyed locator/resource metadata suppresses values such as
`secretName`, `secret.type`, and URL/path references only when the value is not
credential-bearing. Generic `"key"` values now include common public field names
such as `token`, `code`, `signature`, and `unknown` as metadata-only names.
Generic `"key"` metadata also covers common public schema/tag names,
human-readable tag labels, and file-name references while preserving
credential-shaped values such as `sk-test-token`. Keyed detection also treats
AWS SigV4's `AWS4-HMAC-SHA256` as a public algorithm identifier, suppresses
documentation `<code>` samples only when the code value is a UUID or non-secret
resource name, and treats Kubernetes `TopologyKey` as public topology metadata.
Structured/keyed detection suppresses narrow i18n lookup references such as
`$t(passwordLabel):`, and UI setup/instruction prose for 2FA/auth fields.
Keyed detection treats whole-value printf templates such as `%[3]s` and Java
builder-chain tails such as `).append(getApiKey()).append(` as source syntax,
not credential bytes.
Core benign gating treats public crypto test-vector identifiers such as
`KAS-ECC-CDH_P-192_C0`, `KAS-ECC-CDH_K-163_C0`, `ALICE_secp112r1_PUB`, and
`ED25519-1-PUBLIC` as case/curve labels, not key material.
Keyed detection also skips generated documentation fragments such as
`Key: CreatedTime</p>` and Go struct tag metadata such as `key:"name,string"`.
Generated documentation key-name suppression also covers public condition keys
and enum-style names such as `resource-groups:Name`, `NAME_PREFIX`, and
`OBJECT_EXTENSION`, while keeping credential-shaped doc samples visible.
Placeholder matching treats explicit `fake_*` values as non-secret examples,
without suppressing weak real-world values such as `pass` or `secret`.
Default keyed detection also suppresses public ASN.1 object identifier DER
bodies in `OBJ_*` tables, standalone NIST/RFC curve/test-case labels such as
`P-256` and `SECP224R1_RFC5114`, RSA mode labels such as `RSA-PSS`, and
localized UI password copy only when the key name is a UI text/message field.
Generic JSON `"key"` metadata covers public schema names, CORS header names,
metasyntactic numbered names, and dotted config paths such as
`idle_timeout.timeout_seconds` while rejecting dotted paths with sensitive
components such as `secret.value`.
Entropy detection suppresses embedded media blobs under MIME keys such as
`image/png`, W3C/npm `integrity` digests, and OpenSSL `OBJ_*=` assignment-name
fragments. JWT detection requires a three-segment compact token boundary so a
five-segment JWE is not cut into a fake JWT.
Keyed detection also suppresses JSON-escaped HTML/source fragments, generic
`key` resource-name metadata such as lower-kebab public labels, and URI
template/redaction userinfo such as `[user[:password]@]` or `***:***` while
keeping concrete URL/DB credentials. Entropy handling is RFC 7517/7518-aware
for JWK: public `kid`/`n`/`e`/`x`/`y` members are metadata, while private or
symmetric `d`/`k`/`p`/`q`/`dp`/`dq`/`qi` members are allowed through even when
their base64url shape resembles a source identifier.

```text
CredData commit: 9a55c40
Pentect command: ~/pentect-linux-target/release/pentect bench creddata ~/pentect-creddata/CredData --json
Rows: 66898
Files: 10865
True rows: 15104
False rows: 51794
TP: 10285
FP: 6704
FN: 4819
Line only: 227
Unlabeled: 54129
Missing files: 0
Precision: 0.605
Recall: 0.681
F1: 0.641
Elapsed: 27838 ms
```

Weak groups:

- `Key`: recall improved substantially from hex material detection; remaining precision work is mostly `KEYED_SECRET` source/config metadata collisions.
- `Password`: many false positives from weak fixture/default-looking values that are still real credentials in production.
- `Token` and `Auth`: recall is strong, but precision still needs vendor/context validators.
- `LIKELY_SECRET`: broad entropy recall still catches source identifiers and opaque non-secret blobs.
- Plaintext GitHub API captures now suppress Base64 `node_id` metadata after validating the decoded `type:id` shape; arbitrary Base64 secrets still fire.
- Public key material is suppressed only when the public role is structurally visible: OpenSSH key prefixes, RFC 7468 public/certificate armor, or `public_key`-style field names. Private-key contexts still fire.
- `URL_CREDENTIAL`: now keeps token-as-username recall; documentation hosts are suppressed only for RFC-reserved examples.
- RFC 2606/6761 domains, RFC 5737 IPv4 ranges, and RFC 3849/9637 IPv6 ranges are shared by URL and placeholder suppression so sample hosts do not need ad hoc literals.
- Structured JSON now suppresses UI/localization prose for password/token message keys and avoids sweeping low-information UI labels, but compact values under real secret keys still fire.
- Generic JSON `"key"` values that are identifier names such as `smtpDomain`, `Authorization`, or `grant_type` are treated as metadata; digit/symbol-bearing key material and sensitive single words still fire.
- Generic `"key"` metadata also suppresses public schema/tag names such as `offset`, `host`, `cost-center`, display labels such as `Dev Gateway Region`, and file references such as `HappyFace.jpg`; credential-shaped values such as `sk-test-token` still fire.
- Generic `"key"` metadata also covers public CORS header names, schema type names such as `string`, numbered metasyntactic names such as `foo2`, and dotted config paths without sensitive components.
- Protocol/documentation metadata suppression is shape-gated: AWS SigV4 algorithm labels, Kubernetes `TopologyKey` values, and HTML `<code>` UUID/resource-name samples are skipped, but credential-shaped code samples still fire.
- UI/i18n suppression is syntax-gated: `$t(...)`/`i18n.t(...)` references and setup/instruction prose under auth/2FA keys are skipped; ordinary weak password/token literals still fire.
- Source-template suppression is syntax-gated: whole-value printf templates and method-chain fragments are skipped, but mixed literal values such as `abc%[3]s` still fire.
- Public crypto test-vector identifiers are shape-gated: NIST KAS-ECC P/K/B case IDs, role+named-curve labels, and ED25519/ED448 test case labels are skipped; operational handles such as `tenant-7-trial` and `ALICE_prod_key_2026` still fire.
- Public crypto metadata now also covers standalone named-curve/RFC test-case labels and RSA mode labels used in published vector tables; actual hex/scalar/key bytes remain detectable.
- ASN.1 OID tables are suppressed only for `OBJ_*`/OID key context and DER-body octet syntax; arbitrary escaped binary under ordinary secret keys still fires.
- Entropy suppression also treats `OBJ_*=` as source assignment syntax, so the identifier before an escaped OID body is not masked as an opaque value.
- Entropy suppression for embedded media and SRI/package integrity is key-scoped: media requires MIME keys such as `image/png`, and SRI requires `integrity` plus `sha256`/`sha384`/`sha512` digest syntax.
- JWT rule matching is compact-serialization bounded: three-segment JWTs still fire, while five-segment JWEs are not partially captured as JWTs.
- JWK handling follows RFC 7517/7518 member roles: public key IDs/coordinates are suppressed as metadata, but private/symmetric members are treated as secret-bearing values.
- URI userinfo template suppression is marker-gated: bracket/brace/angle and literal `*` redactions are skipped, while concrete `user:password@host` connection strings still fire.
- JSON-escaped HTML/source snippets are suppressed only when escaped markup/source syntax proves the captured value is a parser fragment; compact credential-shaped examples still fire.
- Localized UI password/token prose is suppressed only when the key name also carries UI text context such as label/error/invalid/message; ordinary `password = "..."` and compact credential values still fire.
- Generated documentation fragments and Go struct tag values are syntax-gated: HTML doc fragments require documentation/HTML on the left side, and struct tags require backtick-delimited `key` metadata.
- Documentation metadata names are shape-gated: public namespaced condition keys, uppercase enum names, inline `key=value` help text, shell command substitutions, and source prefix constants are skipped; `sk-test-token</p>` and `secret:` still fire.
- Explicit placeholder markers include `fake_*`; weak literals such as `pass`, `secret`, `abc123`, and `changeme` remain detectable unless a separate fixture/source context proves they are examples.
- Code/reference literals under sensitive-looking keys are suppressed only when syntax proves they are not values: PascalCase type annotations require a code delimiter, and env lookups require explicit Jinja/Ansible `lookup('env', ...)` shape.
- Additional source/metadata literals are shape-gated: protobuf tag descriptors require `protobuf_key` context, key algorithm labels require known algorithm-size syntax, fingerprints require explicit fingerprint keys and colon-hex shape, and command/mock fragments require invocation syntax.
- Generic `key` code-member names and parser-cut source fragments are suppressed only when source syntax proves they are metadata, keeping concrete key material under `api_key`/`client_secret` unaffected.
- Generic `"key"` field values such as `token`, `code`, `signature`, and `unknown` are metadata names only in that generic-key context; `password` and `secret` still fire.
- Synthetic hex fixture strings are suppressed when the whole value is built from canonical visual patterns, sequential byte runs, or repeated bytes; arbitrary hex under sensitive key context still fires.
- `KEYED_SECRET` identity sweep keeps anchored detections only. Context-free propagation is left to stronger rule, entropy, and structural detections.
- `BASIC_AUTH` is RFC 7617-gated: the captured token68 must decode to a non-empty `user:password` pair, so `Basic something` style prose is not counted.
- Locator/resource metadata suppression is policy-gated: secret object names and URL/path references are skipped only when no userinfo/query/fragment or webhook/signed-url key suggests the locator itself carries a credential. This improves precision with a small recall tradeoff on path-like positive labels.
- Source fixture literals require both source-code shape and fixture key context, so `expectedPassword = "pass"` is skipped while plain `password = "pass"` still fires.
- `UUID`: low recall.
- `AWS S3 Bucket`, `Firebase Domain`, and `Tencent WeChat API App ID`: currently missed.

CredData source: https://github.com/Samsung/CredData
