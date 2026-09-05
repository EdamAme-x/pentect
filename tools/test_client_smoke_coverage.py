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
    public_block = re.search(
        r"pub\(crate\) const CLIENTS: &\[ClientDescriptor\] = &\[(.*?)\];",
        descriptor,
        re.DOTALL,
    )
    assert public_block is not None
    constants = re.findall(r"\b[A-Z][A-Z_]+\b", public_block.group(1))
    declared = {
        re.search(
            rf"pub\(crate\) const {constant}: ClientDescriptor = ClientDescriptor \{{\s*name: \"([^\"]+)\"",
            descriptor,
        ).group(1)
        for constant in constants
    }
    exercised = {name for name, _ in SMOKE.PORTABLE_CLIENTS + SMOKE.NATIVE_CLIENTS}
    assert exercised == declared, (
        f"real-client smoke mismatch: missing={sorted(declared - exercised)}, "
        f"stale={sorted(exercised - declared)}"
    )
    assert set(SMOKE.APP_SURFACES) == {"codex-app", "claude-app"}

    workflow = (ROOT / ".github/workflows/current-clients.yml").read_text(
        encoding="utf-8"
    )
    for boundary in (
        "crates/pentect-cli/src/main.rs",
        "crates/pentect-cli/src/openai_clients.rs",
        "crates/pentect-cli/src/secure_temp.rs",
        "crates/pentect-cli/src/claude_settings_session.rs",
        "crates/pentect-cli/src/*supervisor*.rs",
        "crates/pentect-cli/tests/client_store_isolation.rs",
        "crates/pentect-cli/tests/native_interrupt.rs",
        "crates/pentect-cli/tests/*claude*.rs",
        "tools/installed_agent_e2e.py",
    ):
        assert f"- '{boundary}'" in workflow, (
            f"current-client workflow does not watch launch boundary {boundary}"
        )
    assert "--claude-parent-kill" in workflow

    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "claude_supervisor: ${{ steps.filter.outputs.claude_supervisor }}" in ci
    supervisor_filter = re.search(
        r"^            claude_supervisor:\n(?P<body>(?:              - .+\n)+)",
        ci,
        re.MULTILINE,
    )
    assert supervisor_filter is not None
    for boundary in (
        ".github/workflows/ci.yml",
        "Cargo.lock",
        "Cargo.toml",
        "crates/pentect-cli/Cargo.toml",
        "crates/pentect-cli/src/main.rs",
        "crates/pentect-cli/src/claude_settings_session.rs",
        "crates/pentect-cli/src/claude_windows_supervisor.rs",
        "crates/pentect-cli/tests/*claude*.rs",
    ):
        assert f"- '{boundary}'" in supervisor_filter.group("body"), (
            f"Windows Claude supervisor tests do not watch {boundary}"
        )
    supervisor_guard = "needs.changes.outputs.claude_supervisor == 'true'"
    # Checkout, toolchain, linker, cache, and the test itself share the same
    # positive change predicate. The no-op step carries the inverse predicate.
    assert ci.count(supervisor_guard) == 5
    assert (
        "cargo test -p pentect-cli --no-default-features --bin pentect "
        "claude_windows_supervisor::tests --locked"
    ) in ci


if __name__ == "__main__":
    main()
