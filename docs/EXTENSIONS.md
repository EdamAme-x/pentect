# Pentect Extensions

Pentect has two extension types. Keep them separate.

1. Rules packs: simple TOML data for company-specific literals or regex rules.
2. Model adapters: local executable adapters for NER, classifiers, or other models.

Rules packs are deterministic core inputs. Model adapters are runtime boundary
inputs. Do not turn model output into built-in regex rules.

## Layout

Project extensions live under:

```text
.pentect/extensions/<name>/
  pack.toml
  packs/*.toml
  adapter.toml
  adapters/*.toml
```

Examples live under:

```text
examples/extensions/<name>/
```

Use them with:

```powershell
pentect codex --extensions company
pentect exec --extensions company "Get-Content .env"
pentect exec --extensions company,ner "service-cli export"
```

Default project extensions:

```toml
# .pentect/config.toml
extensions = ["company", "./.pentect/extensions/local-ner"]
```

Named extensions resolve in this order:

1. `.pentect/extensions/<name>`
2. `examples/extensions/<name>`

Path extensions can point to an extension directory. A direct `.toml` path is a
rules pack unless the file is named `adapter.toml` or is inside an `adapters`
directory.

## Rules Packs

Use rules packs for stable local patterns:

- internal hostnames
- project codenames
- employee or customer ID formats
- vendor tokens with a documented syntax
- lightweight organization-specific PII formats

Minimal pack:

```toml
[[detector]]
keywords = ["Project Titan", "vault.acme.internal"]
label = "COMPANY_SECRET"
category = "secret"
```

Regex pack:

```toml
[[detector]]
pattern = '\bEMP-[0-9]{6}\b'
label = "EMPLOYEE_ID"
category = "identifier"
confidence = "high"
```

Rules pack fields:

- `keywords`: literal strings, case-insensitive, no regex knowledge required
- `pattern`: regex for power users
- `label`: placeholder label; normalized to `UPPER_SNAKE`
- `category`: `secret`, `pii`, `identifier`, `endpoint`, or `other`
- `confidence`: `high`, `medium`, or `low`
- `validator`: optional checksum gate such as `luhn`, `iban_mod97`, `verhoeff`
- `capture`: optional regex capture group to mask
- `prefilter`: optional literal gates before running a regex

Extension-loaded packs may add detectors but may not disable built-ins. Direct
`pentect mask --pack file.toml` remains the local tuning escape hatch for
`disable = [...]`.

## Model Adapters

Use model adapters for language-heavy detection:

- person names
- street addresses
- company or organization names
- natural-language PII
- local ML/NER models

Model adapters run only at the agent/tool boundary in this version:

- `pentect exec --extensions ner ...`
- `pentect codex --extensions ner`
- `pentect claude --extensions ner`

They are intentionally outside core. `pentect scan` stays deterministic and
rules-pack based.

Adapter file:

```toml
schema = "pentect.model_adapter.v1"
kind = "model"
name = "ner"
command = ["python", "adapter.py"]
timeout_ms = 3000
max_input_bytes = 262144
max_spans = 512
```

Pentect sends one JSON object to adapter stdin:

```json
{
  "schema": "pentect.model_adapter.v1",
  "kind": "text",
  "text": "Alice Smith lives in Seattle.",
  "context": null
}
```

The adapter returns JSON on stdout:

```json
{
  "spans": [
    {
      "start": 0,
      "end": 11,
      "label": "PERSON_NAME",
      "category": "pii",
      "confidence": "high"
    }
  ]
}
```

Span offsets are UTF-8 byte offsets into `text`. `label` is normalized to
`UPPER_SNAKE`. `category` defaults to `pii`; `confidence` defaults to `medium`.

Order:

1. Existing handles are remasked.
2. Model adapters return spans.
3. Pentect renders adapter spans into handles and stores recovery in memory.
4. Built-in detectors and rules packs run over the masked output.
5. Final stdout/stderr/tool result is returned to the agent.

Adapter safety contract:

- Do not print raw input to stdout or stderr.
- Return spans only.
- Keep models and logs local.
- Use bounded input size and timeout.
- Treat adapter failure as extension failure.

## Choosing One

Use a rules pack when a human can write the rule as data. Use a model adapter
when the signal is language-heavy or model-owned. If both apply, keep the stable
syntax in a pack and the fuzzy language detection in an adapter.
