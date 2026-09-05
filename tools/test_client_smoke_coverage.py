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
        "crates/pentect-cli/tests/native_unix_supervisor.rs",
        "crates/pentect-cli/tests/native_windows_supervisor.rs",
        "crates/pentect-cli/tests/*claude*.rs",
        "tools/installed_agent_e2e.py",
    ):
        assert f"- '{boundary}'" in workflow, (
            f"current-client workflow does not watch launch boundary {boundary}"
        )
    assert "--claude-parent-kill" in workflow
    assert "--codex-parent-kill" in workflow
    assert "--test claude_guardian_loss" in workflow

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
        "crates/pentect-cli/src/claude_unix_supervisor.rs",
        "crates/pentect-cli/src/claude_windows_supervisor.rs",
        "crates/pentect-cli/tests/native_interrupt.rs",
        "crates/pentect-cli/tests/native_unix_supervisor.rs",
        "crates/pentect-cli/tests/native_windows_supervisor.rs",
        "crates/pentect-cli/tests/*claude*.rs",
    ):
        assert f"- '{boundary}'" in supervisor_filter.group("body"), (
            f"Claude supervisor tests do not watch {boundary}"
        )
    supervisor_guard = "needs.changes.outputs.claude_supervisor == 'true'"
    app_setup_guard = (
        "needs.changes.outputs.codex_app == 'true' || "
        "needs.changes.outputs.claude_app == 'true' || "
        "needs.changes.outputs.openai_proxy == 'true' || "
        f"needs.changes.outputs.command_shims == 'true' || {supervisor_guard}"
    )
    # Checkout, toolchain, and cache must run for supervisor changes on both
    # app-platform operating systems. The linker remains Windows-specific.
    assert ci.count(f"\n        if: {app_setup_guard}\n") == 3
    assert (
        "cargo test -p pentect-cli --no-default-features --bin pentect "
        "claude_windows_supervisor::tests --locked"
    ) in ci
    assert (
        "cargo test -p pentect-cli --no-default-features "
        "--test native_windows_supervisor --locked"
    ) in ci
    macos_step = re.search(
        r"      - name: Test macOS Claude supervisor boundaries\n"
        r"        if: .*claude_supervisor.*runner\.os == 'macOS'\n"
        r"        timeout-minutes: 5\n"
        r"        run: (?P<command>.+)\n",
        ci,
    )
    assert macos_step is not None
    assert macos_step.group("command") == (
        "cargo test -p pentect-cli --no-default-features --locked "
        "--test claude_guardian_boundary --test claude_unix_supervisor "
        "--test native_interrupt --test native_unix_supervisor"
    )
    assert (
        "needs.changes.outputs.command_shims != 'true' && "
        "needs.changes.outputs.claude_supervisor != 'true'"
    ) in ci


if __name__ == "__main__":
    main()
