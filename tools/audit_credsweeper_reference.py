#!/usr/bin/env python3
"""Emit the authoritative, fully-expanded CredSweeper rule/filter inventory.

Run with the vendored CredSweeper package on PYTHONPATH.  The output is derived
from real ``Rule`` instances, rather than duplicating group definitions here,
so an upstream group or constructor change is visible to the Rust-port audit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any

from credsweeper.common.constants import Severity
from credsweeper.config.config import Config
from credsweeper.rules.rule import Rule
from credsweeper.utils.util import Util

import credsweeper

APP_PATH = Path(credsweeper.__file__).resolve().parent


def reference_config() -> Config:
    raw = Util.json_load(APP_PATH / "secret" / "config.json")
    raw.update(
        use_filters=True,
        find_by_ext=False,
        size_limit=None,
        pedantic=False,
        depth=0,
        doc=False,
        severity=Severity.INFO.value,
    )
    return Config(raw)


def stable_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (list, tuple)):
        return [stable_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(stable_value(item) for item in value)
    if isinstance(value, dict):
        return {str(key): stable_value(item) for key, item in sorted(value.items())}
    if hasattr(value, "pattern") and isinstance(value.pattern, str):
        return {"regex": value.pattern, "flags": value.flags}
    if isinstance(value, Config) or hasattr(value, "__dict__"):
        return {
            "class": type(value).__name__,
            "state": {
                key: stable_value(item)
                for key, item in sorted(vars(value).items())
            },
        }
    return repr(value)


def filter_record(instance: Any) -> dict[str, Any]:
    state = {
        key: stable_value(value)
        for key, value in sorted(vars(instance).items())
        if not key.startswith("__")
    }
    return {"class": type(instance).__name__, "state": state}


def inventory() -> dict[str, Any]:
    config = reference_config()
    raw_rules = Util.yaml_load(APP_PATH / "rules" / "config.yaml")
    rules = [Rule(config, raw) for raw in raw_rules]
    definitions: dict[str, dict[str, Any]] = {}
    rule_records = []
    for rule in rules:
        filter_ids = []
        for item in rule.filters:
            record = filter_record(item)
            canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            identifier = hashlib.sha256(canonical.encode()).hexdigest()
            definitions[identifier] = record
            filter_ids.append(identifier)
        rule_records.append(
            {
                "name": rule.rule_name,
                "type": rule.rule_type.value,
                "filters": filter_ids,
            }
        )
    filter_classes = sorted({record["class"] for record in definitions.values()})
    return {
        "credsweeper_version": __import__("credsweeper").__version__,
        "rule_count": len(rules),
        "filter_classes": filter_classes,
        "filter_definitions": dict(sorted(definitions.items())),
        "rules": rule_records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(inventory(), indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
