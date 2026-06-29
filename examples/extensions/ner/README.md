# NER Adapter

This directory is a model-adapter example.

Run it through an agent boundary:

```powershell
pentect exec --extensions ner "Write-Output 'Alice Smith opened CASE-20260101'"
```

Files:

- `adapter.toml`: Pentect adapter declaration
- `adapter.py`: minimal local process using the adapter JSON protocol

`adapter.py` is not production NER. Replace `detect()` with a local model call
and keep stdout limited to `{ "spans": [...] }`.

Rules packs are for stable patterns. Model adapters are for language-heavy PII.
