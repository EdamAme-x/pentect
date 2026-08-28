#!/usr/bin/env python3
"""Fail unless every applicable CI dependency succeeded."""

from __future__ import annotations

import json
import os
import sys


EXPECTED_JOBS = {
    "changes",
    "npm-package",
    "native-ocr",
    "plugin-platform",
    "app-platform",
    "windows-powershell-installer",
    "test",
}


def failed_jobs(needs: object) -> list[str]:
    if not isinstance(needs, dict):
        return ["CI dependency payload is not an object"]
    missing = sorted(EXPECTED_JOBS - needs.keys())
    failures = [f"{name}: missing" for name in missing]
    for name in sorted(EXPECTED_JOBS & needs.keys()):
        dependency = needs[name]
        result = dependency.get("result") if isinstance(dependency, dict) else None
        allowed = {"success"} if name == "changes" else {"success", "skipped"}
        if result not in allowed:
            failures.append(f"{name}: {result or 'missing result'}")
    return failures


def main() -> int:
    try:
        needs = json.loads(os.environ["PENTECT_CI_NEEDS"])
    except KeyError:
        print("PENTECT_CI_NEEDS is missing", file=sys.stderr)
        return 2
    except json.JSONDecodeError as error:
        print(f"PENTECT_CI_NEEDS is invalid JSON: {error}", file=sys.stderr)
        return 2
    failures = failed_jobs(needs)
    if failures:
        print("CI Gate blocked:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("CI Gate passed: every applicable job succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
