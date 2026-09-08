# Production handle-view E2E invocation

[`tools/handle_views_e2e.py`](../../tools/handle_views_e2e.py) exercises a supplied normal Pentect binary through installed Claude, Codex, OpenCode, and Pi clients. Each run uses an isolated home/configuration and a bounded localhost deterministic provider; it makes no paid model request.

Run the successful roundtrip matrix one client at a time:

```sh
python3 tools/handle_views_e2e.py --pentect /absolute/path/to/pentect --client claude --scenario roundtrip --execute --output result-claude.json
python3 tools/handle_views_e2e.py --pentect /absolute/path/to/pentect --client codex --scenario roundtrip --execute --output result-codex.json
python3 tools/handle_views_e2e.py --pentect /absolute/path/to/pentect --client opencode --scenario roundtrip --execute --output result-opencode.json
python3 tools/handle_views_e2e.py --pentect /absolute/path/to/pentect --client pi --scenario roundtrip --execute --output result-pi.json
```

Repeat with `--scenario late-invalid` to emit one response containing an ordinary valid input followed by an unsupported view. A trustworthy negative result requires `read_handle_captured`, `invalid_batch_issued`, absent batch tool-result IDs, and no output files or counter. A retrying client that reaches the 60-second process-group kill remains incomplete (`passed: false`) even when those safety observations hold.

The measured installed versions were Claude Code 2.1.263, Codex CLI 0.153.0, OpenCode 1.18.20, and Pi 0.84.2. The test server only emits calls and inspects requests; it never resolves or remasks a value. The roundtrip checks ordinary-handle bytes, strict base64 decoding, one side-effect counter, provider-request absence, and remasked tool output. It does not establish live-model correction, arbitrary edge-byte handling, or byte-exact `apply_patch` behavior.
