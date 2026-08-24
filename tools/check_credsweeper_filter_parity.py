#!/usr/bin/env python3
"""Compare every official filter invocation in CredSweeper's tests with Rust."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def filter_spec(instance: Any) -> str:
    name = type(instance).__name__
    if name == "ValueLengthCheck":
        return f"{name}({instance.min_len},{instance.max_len})"
    if name == "ValuePatternCheck" and instance.pattern_len >= 0:
        return f"{name}({instance.pattern_len})"
    if name == "ValueMorphemesCheck" and len(set(instance.thresholds)) == 1:
        return f"{name}({instance.thresholds[0]})"
    return name


def byte_offset(text: str, character_offset: int) -> int:
    if character_offset < 0:
        return 0
    return len(text[:character_offset].encode("utf-8"))


def capture_probe(instance: Any, line_data: Any, target: Any) -> dict[str, Any]:
    lines = list(target.lines)
    line_pos = line_data.line_pos
    target_text = "\n".join(lines)
    return {
        "filter": filter_spec(instance),
        "value": line_data.value,
        "line": line_data.line,
        "value_start": byte_offset(line_data.line, line_data.value_start),
        "value_end": byte_offset(line_data.line, line_data.value_end),
        "variable": line_data.variable,
        "separator": line_data.separator,
        "wrap": line_data.wrap,
        "value_leftquote": line_data.value_leftquote,
        "value_rightquote": line_data.value_rightquote,
        "previous": lines[line_pos - 1] if 0 < line_pos <= len(lines) else None,
        "next": lines[line_pos + 1] if 0 <= line_pos + 1 < len(lines) else None,
        "file_type": line_data.file_type or "",
        "target": target_text,
        "line_index": max(0, line_pos),
    }


class Recorder:
    def __init__(self, filter_names: set[str]) -> None:
        self.filter_names = filter_names
        self.records: list[tuple[dict[str, Any], bool]] = []
        self.originals: list[tuple[type[Any], Any]] = []

    def install(self) -> None:
        import credsweeper.filters as filters

        for name in sorted(self.filter_names):
            cls = getattr(filters, name)
            original = cls.run
            self.originals.append((cls, original))

            def wrapped(instance: Any, line_data: Any, target: Any, _run=original) -> bool:
                probe = capture_probe(instance, line_data, target)
                result = bool(_run(instance, line_data, target))
                self.records.append((probe, result))
                return result

            cls.run = wrapped

    def restore(self) -> None:
        for cls, original in self.originals:
            cls.run = original


def exercise_filters_missing_upstream_tests() -> None:
    """Exercise official classes that CredSweeper 1.17.4 does not test."""
    import base64

    import bech32
    from credsweeper.filters import (
        ValueBase64EncodedPem,
        ValueBech32Check,
        ValueDiscordBotCheck,
        ValueJfrogTokenCheck,
    )
    from tests.filters.conftest import DUMMY_ANALYSIS_TARGET
    from tests.test_utils.dummy_line_data import get_line_data

    def run(instance: Any, value: str) -> None:
        instance.run(get_line_data(line=value), DUMMY_ANALYSIS_TARGET)

    der = bytes([0x30, 0x81, 0x80]) + bytes([0x42]) * 128
    body = base64.b64encode(der).decode("ascii")
    pem = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
    run(ValueBase64EncodedPem(), base64.b64encode(pem.encode("ascii")).decode("ascii"))
    run(ValueBase64EncodedPem(), base64.b64encode(b"not a pem key").decode("ascii"))

    run(ValueBech32Check(), bech32.bech32_encode("bc", [0, 1, 2, 3]))
    run(ValueBech32Check(), "bc1invalid")

    discord_id = base64.b64encode(b"1234567890").decode("ascii").rstrip("=")
    run(ValueDiscordBotCheck(), f"{discord_id}.abcdefghijklmnopqrstuvwxyz012345")
    run(ValueDiscordBotCheck(), "OTk5.aaaaaaaaaaaa")

    identity = "".join(
        ["cmVmdGtuOjAxOjAxMjM0NTY3ODk6", "QWJjZGVmR2hpamtsbW5vUHFyc3R1dnd4eXow"]
    )
    api_key = "".join(
        ["AKCp2UNCd8uK7hQoxZnFE4PGtRHnAcBHr43", "HgLcj7nJmWb4JhVUqBwa2iwXszftnogpo2EVFa"]
    )
    run(ValueJfrogTokenCheck(), identity)
    run(ValueJfrogTokenCheck(), api_key)
    run(ValueJfrogTokenCheck(), f"{api_key[:-1]}0")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, default=Path("tools/credsweeper-reference-inventory.json"))
    parser.add_argument(
        "--tests", type=Path, default=Path("crates/pentect-core/vendors/CredSweeper/tests/filters")
    )
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--allow-missing", action="store_true")
    args = parser.parse_args()

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    expected_filters = set(inventory["filter_classes"])
    recorder = Recorder(expected_filters)
    recorder.install()
    try:
        import pytest

        status = pytest.main([str(args.tests), "-q", "--disable-warnings"])
        if status == 0:
            exercise_filters_missing_upstream_tests()
    finally:
        recorder.restore()
    if status != 0:
        raise SystemExit(f"official CredSweeper filter tests failed with status {status}")

    deduplicated: dict[str, tuple[dict[str, Any], bool]] = {}
    for probe, expected in recorder.records:
        key = json.dumps([probe, expected], ensure_ascii=False, sort_keys=True)
        deduplicated[key] = (probe, expected)
    records = list(deduplicated.values())
    covered = {probe["filter"].split("(", 1)[0] for probe, _ in records}
    missing = sorted(expected_filters - covered)
    if missing and not args.allow_missing:
        raise SystemExit("official tests did not exercise filters: " + ", ".join(missing))

    args.work.mkdir(parents=True, exist_ok=True)
    probes_path = args.work / "filter-probes.json"
    probes_path.write_text(
        json.dumps([probe for probe, _ in records], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [str(args.rust), "credsweeper-filter-probe", str(probes_path)],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"Rust filter probe failed with status {completed.returncode}: {completed.stderr.strip()}"
        )
    actual = json.loads(completed.stdout)
    if len(actual) != len(records):
        raise SystemExit(f"Rust returned {len(actual)} results for {len(records)} probes")
    mismatches = [
        {"probe": probe, "official": expected, "rust": got}
        for (probe, expected), got in zip(records, actual)
        if expected != got
    ]
    print(
        f"CredSweeper filter parity: {len(records)} probes, "
        f"{len(covered)}/{len(expected_filters)} classes, {len(mismatches)} mismatches"
    )
    if mismatches:
        print(json.dumps(mismatches[:50], ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
