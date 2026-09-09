#!/usr/bin/env python3
"""Verify installed-agent fixtures cannot inherit client state or credentials."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "installed_agent_e2e", ROOT / "tools" / "installed_agent_e2e.py"
)
assert SPEC is not None and SPEC.loader is not None
E2E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E2E)


def main() -> None:
    sentinel_names = (
        "CODEX_HOME",
        "CLAUDE_CONFIG_DIR",
        "OPENCODE_CONFIG_DIR",
        "OPENCODE_CONFIG_CONTENT",
        "PI_CODING_AGENT_DIR",
        "PENTECT_MEMORY_STORE_TOKEN",
        "PENTECT_GATEWAY_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "SERVICE_TOKEN",
        "AWS_SHARED_CREDENTIALS_FILE",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "OPENAI_BASE_URL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "NODE_OPTIONS",
    )
    previous = {name: os.environ.get(name) for name in sentinel_names}
    previous_preserved = {name: os.environ.get(name) for name in ("PATH", "SystemRoot", "COMSPEC", "PATHEXT")}
    try:
        os.environ.update({name: "fixture-sentinel" for name in sentinel_names})
        # Exercise Windows' case-insensitive environment spelling on every
        # runner; the helper must preserve the actual key/value.
        os.environ.update({
            "PATH": "fixture-path",
            "SystemRoot": "fixture-system-root",
            "COMSPEC": "fixture-comspec",
            "PATHEXT": "fixture-pathext",
        })
        with tempfile.TemporaryDirectory() as raw:
            environment = E2E.isolated_environment(Path(raw) / "home", Path(raw) / "logs")
        missing = [name for name in sentinel_names if name in environment]
        assert not missing, f"ambient variables survived isolation: {missing}"
        expected_preserved = {
            "PATH": "fixture-path",
            "SystemRoot": "fixture-system-root",
            "COMSPEC": "fixture-comspec",
            "PATHEXT": "fixture-pathext",
        }
        missing_preserved = [
            name for name, value in expected_preserved.items()
            if environment.get(name) != value
        ]
        assert not missing_preserved, f"required OS variables were dropped: {missing_preserved}"
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        for name, value in previous_preserved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    print("installed-agent environment isolation: ok")


if __name__ == "__main__":
    main()
