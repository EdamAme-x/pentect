#!/usr/bin/env python3
"""Reject drift and unproven claims in the native CredSweeper port."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, default=Path("tools/credsweeper-reference-inventory.json"))
    parser.add_argument("--status", type=Path, default=Path("tools/credsweeper-rust-port-status.json"))
    parser.add_argument("--require-exact", action="store_true")
    args = parser.parse_args()

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    status = json.loads(args.status.read_text(encoding="utf-8"))
    expected = set(inventory["filter_classes"])
    declared = set(status["filters"])
    missing = sorted(expected - declared)
    stale = sorted(declared - expected)
    if status["credsweeper_version"] != inventory["credsweeper_version"]:
        raise SystemExit("CredSweeper version differs between reference inventory and Rust status")
    if missing or stale:
        raise SystemExit(f"Rust filter inventory drift: missing={missing}, stale={stale}")
    invalid = {name: value for name, value in status["filters"].items() if value not in {"unverified", "exact"}}
    if invalid:
        raise SystemExit(f"invalid Rust port statuses: {invalid}")
    unverified = sorted(name for name, value in status["filters"].items() if value != "exact")
    print(f"CredSweeper {inventory['credsweeper_version']}: {len(expected)} filters, {len(unverified)} unverified")
    if args.require_exact and unverified:
        raise SystemExit("Rust CredSweeper port is not exact: " + ", ".join(unverified))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
