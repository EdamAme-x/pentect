#!/usr/bin/env python3
"""Start every supported public client through a real Pentect binary."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


PORTABLE_CLIENTS = (
    ("codex", None),
    ("claude", None),
    ("opencode", None),
    ("pi", None),
)

NATIVE_CLIENTS = ()

APP_SURFACES = ("codex-app", "claude-app")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--pentect",
        type=Path,
        default=os.environ.get("PENTECT_SMOKE_BINARY"),
    )
    parser.add_argument(
        "--group", choices=("portable", "native", "all"), default="portable"
    )
    parser.add_argument("--client-root", type=Path)
    return parser.parse_args()


def native_command(root: Path, executable: str) -> Path:
    if executable == "code":
        command = shutil.which("code")
        if not command:
            raise RuntimeError("VS Code CLI is required for the Roo smoke test")
        return Path(command)
    if executable in {"junie", "zed"}:
        return root / "home" / ".local" / "bin" / executable
    return root / "bin" / executable


def run_client(pentect: Path, name: str, command: Path | None) -> None:
    invocation = [str(pentect), name]
    if command is not None:
        if not command.is_file():
            raise RuntimeError(f"{name} executable is missing: {command}")
        invocation.extend(["--tool", str(command)])
    invocation.extend(["--", "--version"])
    if os.name == "nt" and pentect.suffix.lower() in {".cmd", ".bat"}:
        invocation = [
            os.environ.get("COMSPEC", "cmd.exe"),
            "/d",
            "/s",
            "/c",
            subprocess.list2cmdline(invocation),
        ]
    print(f"::group::{name}", flush=True)
    try:
        subprocess.run(invocation, check=True)
    finally:
        print("::endgroup::", flush=True)


def main() -> int:
    args = parse_args()
    if args.pentect is None:
        raise RuntimeError("--pentect or PENTECT_SMOKE_BINARY is required")
    pentect = args.pentect.resolve()
    if not pentect.is_file():
        raise RuntimeError(f"Pentect executable is missing: {pentect}")

    if args.group in {"portable", "all"}:
        for name, _ in PORTABLE_CLIENTS:
            run_client(pentect, name, None)

    if args.group in {"native", "all"}:
        if args.client_root is None:
            raise RuntimeError("--client-root is required for native clients")
        root = args.client_root.resolve()
        os.environ["HOME"] = str(root / "home")
        for name, executable in NATIVE_CLIENTS:
            run_client(pentect, name, native_command(root, executable))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"client smoke failed: {error}", file=sys.stderr)
        raise SystemExit(1)
