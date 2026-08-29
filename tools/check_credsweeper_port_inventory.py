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
    if inventory.get("schema") != 2:
        raise SystemExit("CredSweeper reference inventory schema must be 2")
    rules = inventory["rules"]
    if inventory["rule_count"] != len(rules):
        raise SystemExit("CredSweeper rule_count does not match the rule inventory")
    rule_names = [rule["name"] for rule in rules]
    if len(rule_names) != len(set(rule_names)):
        raise SystemExit("CredSweeper rule inventory contains duplicate names")
    typed_rules = {
        name for names in inventory["rule_types"].values() for name in names
    }
    if typed_rules != set(rule_names):
        raise SystemExit("CredSweeper rule-type inventory does not cover every rule")
    ml_rules = {rule["name"] for rule in rules if rule["runtime"]["use_ml"]}
    if ml_rules != set(inventory["ml"]["rules"]):
        raise SystemExit("CredSweeper ML rule inventory differs from runtime rule state")
    if not inventory["output_fields"]["candidate"] or not inventory["output_fields"]["line_data"]:
        raise SystemExit("CredSweeper output-field inventory is empty")
    expected = set(inventory["filter_classes"])
    definitions = set(inventory["filter_definitions"])
    referenced = {identifier for rule in rules for identifier in rule["filters"]}
    grouped = {
        identifier for identifiers in inventory["filter_groups"].values() for identifier in identifiers
    }
    if referenced != definitions:
        raise SystemExit("CredSweeper rule filter references differ from filter definitions")
    if not grouped.issubset(definitions):
        raise SystemExit("CredSweeper filter group references an unknown definition")
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
