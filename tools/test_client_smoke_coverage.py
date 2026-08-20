#!/usr/bin/env python3
"""Keep the real-client smoke inventory aligned with public descriptors."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "client_smoke", ROOT / "tools" / "client_smoke.py"
)
assert SPEC is not None and SPEC.loader is not None
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


def main() -> None:
    descriptor = (ROOT / "crates/pentect-cli/src/client_descriptor.rs").read_text(
        encoding="utf-8"
    )
    declared = set(
        re.findall(
            r"pub\(crate\) const [A-Z_]+: ClientDescriptor = ClientDescriptor \{\s*name: \"([^\"]+)\"",
            descriptor,
        )
    )
    exercised = {name for name, _ in SMOKE.PORTABLE_CLIENTS + SMOKE.NATIVE_CLIENTS}
    assert exercised == declared, (
        f"real-client smoke mismatch: missing={sorted(declared - exercised)}, "
        f"stale={sorted(exercised - declared)}"
    )
    assert set(SMOKE.APP_SURFACES) == {"codex-app", "claude-app"}


if __name__ == "__main__":
    main()
