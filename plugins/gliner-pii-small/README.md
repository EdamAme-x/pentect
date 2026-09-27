# GLiNER PII Small for Pentect

Experimental first-party integration of
[GLiNER PII small](https://huggingface.co/knowledgator/gliner-pii-small-v1.0).
It adds local, primarily English PII detection. Installation is explicit opt-in;
it does not enable Pentect's optional built-in PII rules or replace secret detection.

```sh
pentect plugins add github:@EdamAme-x/pentect/plugins/gliner-pii-small --profile cpu
```

Python 3.10–3.13 is required. Setup downloads pinned model weights and a managed Python
environment to `~/.pentect/gliner-pii-small`. CPU is the default; `--profile cuda`
selects NVIDIA CUDA 12.4 wheels and requires a compatible driver. macOS uses CPU.
Setup verifies offline inference before writing the selected profile. Runtime
does not download weights, contact a model API, or open an HTTP port.

The plugin uses a native Command process with the user's OS permissions, not a
Wasm sandbox. It returns UTF-8 byte ranges, labels, and confidence, never matched
values. Pentect creates the actual handles. Inspect its code before approving it.

## Behavior and limitations

- Names, email addresses, phone numbers, addresses, account numbers, passwords,
  and API keys are queried at threshold 0.3.
- Input is inspected in 1,000-character windows with 250 characters of overlap.
  Long entities and context spanning windows can be missed.
- This is a statistical detector: false positives and missed values remain.
  Japanese performance must not be inferred from English model claims.
- `required = true`: model/protocol failures block the protected request, rather
  than silently disabling this detector. A successful empty prediction can still
  be a false negative; required status cannot detect semantic mistakes.
- Installation affects the selected Pentect scope. Installing this PII plugin is
  consent to its PII detection even when built-in PII options are off.
- The bridge does not echo inference exceptions or input text in error responses.

```sh
echo "Contact Alice at alice@example.test" | pentect mask
pentect plugins remove gliner-pii-small
```

Removal leaves the downloaded environment at `~/.pentect/gliner-pii-small`.
Delete that directory separately if its cached assets are no longer needed.

Bridge tests require no model downloads:

```sh
python -m unittest discover plugins/gliner-pii-small/tests -v
```

These tests validate protocol/offset handling, not model recall. The model is
Apache-2.0; this integration follows Pentect's MIT license.
