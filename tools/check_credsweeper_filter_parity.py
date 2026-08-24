#!/usr/bin/env python3
"""Compare every official filter invocation in CredSweeper's tests with Rust."""

from __future__ import annotations

import argparse
import base64
import json
import logging
import random
import string
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


def exercise_generated_inputs(filter_names: set[str], case_count: int) -> int:
    """Run deterministic shape/boundary probes through every official class."""
    import credsweeper.filters as filters
    from credsweeper.file_handler.analysis_target import AnalysisTarget
    from credsweeper.file_handler.descriptor import Descriptor
    from tests.test_utils.dummy_line_data import get_line_data

    rng = random.Random(0xC0ED5EE9)
    alphabet = string.ascii_letters + string.digits + "+/=_-. :\\[]{}()$%*"
    values = [
        "a",
        "abc",
        "abcd",
        "A1b2C3d4",
        "秘密鍵",
        "pässwörd",
        "../secret/key",
        "C:\\secret\\key",
        "https://example.invalid/token",
        "${SECRET_NAME}",
        "ENC(secret)",
        "A" * 64,
        "A1" * 128,
    ]
    boundary_lengths = [1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 15, 16, 17, 18, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256]
    for length in boundary_lengths:
        values.append("".join(rng.choice(alphabet) for _ in range(length)))
    while len(values) < case_count:
        length = rng.randrange(1, 321)
        raw = bytes(rng.randrange(256) for _ in range(max(1, length * 3 // 4)))
        if len(values) % 4 == 0:
            values.append(base64.b64encode(raw).decode("ascii")[:length])
        elif len(values) % 4 == 1:
            values.append(base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")[:length])
        elif len(values) % 4 == 2:
            values.append("".join(rng.choice(alphabet) for _ in range(length)))
        else:
            values.append("秘密" + "".join(rng.choice(string.ascii_letters) for _ in range(length)))

    instances: list[Any] = []
    for name in sorted(filter_names):
        cls = getattr(filters, name)
        instances.append(cls())
        if name == "ValueLengthCheck":
            instances.extend([cls(None, 4, 64), cls(None, 4, 80)])
        elif name == "ValuePatternCheck":
            instances.append(cls(None, 5))
        elif name == "ValueMorphemesCheck":
            instances.extend([cls(None, 0), cls(None, 1), cls(None, 9)])

    exceptions = 0
    previous_logging_level = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        for instance_index, instance in enumerate(instances):
            for value_index, value in enumerate(values):
                mode = (instance_index + value_index) % 3
                if mode == 0:
                    line = value
                    start = 0
                    variable = separator = wrap = left = right = None
                elif mode == 1:
                    line = f'secret = "{value}"'
                    start = len('secret = "')
                    variable, separator, wrap, left, right = "secret", "=", None, '"', '"'
                else:
                    line = f"prefix({value})"
                    start = len("prefix(")
                    variable, separator, wrap, left, right = None, None, "prefix(", None, None
                line_data = get_line_data(line=line)
                line_data.value = value
                line_data.value_start = start
                line_data.value_end = start + len(value)
                line_data.variable = variable
                line_data.separator = separator
                line_data.wrap = wrap
                line_data.value_leftquote = left
                line_data.value_rightquote = right
                line_data.line_pos = 1
                line_data.line_num = 2
                extension = [".py", ".php", ".json", ".txt"][value_index % 4]
                line_data.file_type = extension
                lines = ["A1b2" * 16, line, "C3d4" * 4]
                target = AnalysisTarget(1, lines, [1, 2, 3], Descriptor("", extension, ""))
                try:
                    instance.run(line_data, target)
                except Exception:
                    exceptions += 1
    finally:
        logging.disable(previous_logging_level)
    return exceptions


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, default=Path("tools/credsweeper-reference-inventory.json"))
    parser.add_argument(
        "--tests", type=Path, default=Path("crates/pentect-core/vendors/CredSweeper/tests/filters")
    )
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--allow-missing", action="store_true")
    parser.add_argument("--generated-cases", type=int, default=256)
    parser.add_argument("--batch-size", type=int, default=16_384)
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
            generated_exceptions = exercise_generated_inputs(expected_filters, args.generated_cases)
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
    if args.batch_size <= 0:
        raise SystemExit("--batch-size must be positive")
    actual: list[bool] = []
    try:
        for start in range(0, len(records), args.batch_size):
            batch = records[start : start + args.batch_size]
            probes_path.write_text(
                json.dumps(
                    [probe for probe, _ in batch],
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [str(args.rust), "credsweeper-filter-probe", str(probes_path)],
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                raise SystemExit(
                    f"Rust filter probe failed with status {completed.returncode}: "
                    f"{completed.stderr.strip()}"
                )
            actual.extend(json.loads(completed.stdout))
    finally:
        probes_path.unlink(missing_ok=True)
    if len(actual) != len(records):
        raise SystemExit(f"Rust returned {len(actual)} results for {len(records)} probes")
    mismatches = [
        {"probe": probe, "official": expected, "rust": got}
        for (probe, expected), got in zip(records, actual)
        if expected != got
    ]
    print(
        f"CredSweeper filter parity: {len(records)} probes, "
        f"{len(covered)}/{len(expected_filters)} classes, {len(mismatches)} mismatches, "
        f"{generated_exceptions} generated inputs outside official filter contracts"
    )
    if mismatches:
        print(json.dumps(mismatches[:50], ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
