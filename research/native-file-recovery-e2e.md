# Native file recovery E2E

`tools/native_file_recovery_e2e.py` is a bounded, deterministic localhost
probe. It does not contact a paid model. Session A runs `pentect read` against
an unchanged trusted text file with `[files] remember = true`, records only the
emitted opaque handle, and exits. Session B starts a fresh installed client and
receives only that old handle in a local command. The provider never reads the
source file and never resolves or remasks a value.

```sh
python3 tools/native_file_recovery_e2e.py \
  --pentect /absolute/path/to/pentect \
  --client claude --registration pentect-read \
  --execute --output result.json
```

Run the unchanged case for Claude, Codex, OpenCode, and Pi. The optional
`--value low-entropy` representative case first proves that its bare fixture
phrase is not detected, then uses the `PASSWORD=` file context to register it;
Session B writes and echoes the recovered value so the next provider request
also tests remasking. `--source-state changed|deleted`, `--remember disabled`,
and `--scope different-project` are focused fail-closed cases; they need not be
multiplied across every client because the persisted-file resolver is shared.
The default `--expect auto` selects `recovered` for the unchanged registered
case, `blocked` for those fail-closed cases, and `registration-missing` for the
native-client boundary check. An expected block requires the old-handle call to
be issued while observing no tool result and no destination side effect.

`--registration client` is a negative boundary check. Native client tool output
is generic masked output and is not itself a trusted file-registration path.
Do not interpret its missing pointer index as a restart-resolver failure.
The different-project case deliberately does not copy the first project's
index; it tests an unregistered project reference, not an identity-key mismatch.
