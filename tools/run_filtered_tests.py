#!/usr/bin/env python3
"""Run a Rust test filter and fail if it selects no unit tests."""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].endswith("::tests"):
        print("usage: run_filtered_tests.py MODULE::tests", file=sys.stderr)
        return 2

    test_filter = sys.argv[1]
    command = [
        "cargo",
        "test",
        "-p",
        "pentect-cli",
        "--no-default-features",
        test_filter,
        "--locked",
    ]
    listed = subprocess.run(
        [*command, "--", "--list"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    print(listed.stdout, end="")
    prefix = f"{test_filter}::"
    if not any(line.startswith(prefix) and ": test" in line for line in listed.stdout.splitlines()):
        print(f"no tests selected by {test_filter!r}", file=sys.stderr)
        return 1
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
