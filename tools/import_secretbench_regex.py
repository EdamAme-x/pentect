#!/usr/bin/env python3
"""Generate Pentect rule packs from SecretBench's public regex workbook.

This uses only the public regular-expression workbook from the SecretBench
repository. It does not fetch or embed the gated SecretBench dataset rows.

The output is split into several TOML packs because a single RegexSet containing
the full public list can exceed the regex crate's default compiled-size limit.
Pass every generated pack to the CLI with repeated `--pack` arguments.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import tempfile
import urllib.request
import warnings
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipFile


DEFAULT_WORKBOOK_URL = (
    "https://raw.githubusercontent.com/setu1421/SecretBench/main/"
    "Regular%20Expressions/Secret%20Regular%20Expression.xlsx"
)

NS = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


@dataclass(frozen=True)
class SecretBenchRule:
    pattern_id: str
    secret_type: str
    pattern: str
    source: str


@dataclass(frozen=True)
class SkippedRule:
    pattern_id: str
    secret_type: str
    reason: str
    pattern: str


def main() -> int:
    args = parse_args()
    workbook = args.workbook or download_workbook()
    rules, skipped = convert_rules(read_workbook(workbook))

    if args.dry_run:
        print_summary(rules, skipped)
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for old in args.out_dir.glob(f"{args.prefix}-*.toml"):
        old.unlink()

    chunks = list(chunked(rules, args.chunk_size))
    for index, chunk in enumerate(chunks, start=1):
        write_pack(
            args.out_dir / f"{args.prefix}-{index:03d}.toml",
            chunk,
            confidence=args.confidence,
        )
    write_skipped(args.out_dir / f"{args.prefix}-skipped.tsv", skipped)

    print_summary(rules, skipped)
    print(f"wrote {len(chunks)} pack(s) to {args.out_dir}")
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "workbook",
        nargs="?",
        type=Path,
        help="SecretBench `Secret Regular Expression.xlsx`; downloads the public workbook if omitted",
    )
    p.add_argument(
        "--out-dir",
        type=Path,
        default=Path("target/secretbench-public-regex"),
        help="directory for generated TOML packs",
    )
    p.add_argument("--prefix", default="secretbench-public-regex")
    p.add_argument("--chunk-size", type=int, default=50)
    p.add_argument("--confidence", default="medium", choices=["low", "medium", "high"])
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()


def download_workbook() -> Path:
    path = Path(tempfile.gettempdir()) / "secretbench-secret-regular-expression.xlsx"
    urllib.request.urlretrieve(DEFAULT_WORKBOOK_URL, path)
    return path


def read_workbook(path: Path) -> list[SecretBenchRule]:
    rows = list(xlsx_rows(path))
    if not rows:
        raise SystemExit(f"no rows in workbook: {path}")
    header = [str(c).strip() for c in rows[0]]
    try:
        id_col = header.index("Pattern_ID")
        type_col = header.index("Secret Type")
        pattern_col = header.index("Regular Expression")
        source_col = header.index("Source")
    except ValueError as e:
        raise SystemExit(f"unexpected workbook header: {header}") from e

    out = []
    for row in rows[1:]:
        if len(row) <= pattern_col:
            continue
        pattern = cell(row, pattern_col)
        if not pattern:
            continue
        out.append(
            SecretBenchRule(
                pattern_id=cell(row, id_col),
                secret_type=cell(row, type_col),
                pattern=pattern,
                source=cell(row, source_col) if len(row) > source_col else "",
            )
        )
    return out


def xlsx_rows(path: Path) -> list[list[str]]:
    with ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall("a:si", NS):
                shared.append("".join((t.text or "") for t in si.findall(".//a:t", NS)))

        root = ET.fromstring(z.read("xl/worksheets/sheet1.xml"))
        rows = []
        for row in root.findall(".//a:sheetData/a:row", NS):
            cells = []
            for c in row.findall("a:c", NS):
                v = c.find("a:v", NS)
                value = "" if v is None else v.text or ""
                if c.attrib.get("t") == "s" and value:
                    value = shared[int(value)]
                cells.append(value)
            rows.append(cells)
        return rows


def convert_rules(rules: list[SecretBenchRule]) -> tuple[list[SecretBenchRule], list[SkippedRule]]:
    kept = []
    skipped = []
    for rule in rules:
        reason = skip_reason(rule.pattern)
        if reason:
            skipped.append(
                SkippedRule(
                    pattern_id=rule.pattern_id,
                    secret_type=rule.secret_type,
                    reason=reason,
                    pattern=rule.pattern,
                )
            )
        else:
            kept.append(rule)
    return kept, skipped


def skip_reason(pattern: str) -> str | None:
    if "%s" in pattern:
        return "template_placeholder"
    if any(token in pattern for token in ("(?=", "(?!", "(?<=", "(?<!")):
        return "lookaround"
    if re.search(r"\\[1-9]", pattern):
        return "backreference"
    if is_slash_delimited_with_flags(pattern):
        return "slash_delimited_flags"
    if "[[" in pattern:
        return "nested_character_class"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        try:
            re.compile(pattern)
        except re.error as e:
            return f"python_regex_error:{e.msg}"
    return None


def is_slash_delimited_with_flags(pattern: str) -> bool:
    text = pattern.strip()
    return text.startswith("/") and re.search(r"/[a-zA-Z]*$", text) is not None


def write_pack(path: Path, rules: list[SecretBenchRule], confidence: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        f.write("# Generated from SecretBench's public regular-expression workbook.\n")
        f.write("# Source: https://github.com/setu1421/SecretBench\n")
        f.write("# This pack contains no gated SecretBench dataset rows.\n\n")
        for rule in rules:
            f.write("[[detector]]\n")
            f.write(f"label = {toml_string('SB_' + safe_label(rule.secret_type))}\n")
            f.write('category = "Secret"\n')
            f.write(f"confidence = {toml_string(confidence)}\n")
            f.write(f"# pattern_id = {rule.pattern_id}; source = {rule.source}\n")
            f.write(f"pattern = {toml_string(rule.pattern)}\n\n")


def write_skipped(path: Path, skipped: list[SkippedRule]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["pattern_id", "secret_type", "reason", "pattern"])
        for rule in skipped:
            w.writerow([rule.pattern_id, rule.secret_type, rule.reason, rule.pattern])


def print_summary(rules: list[SecretBenchRule], skipped: list[SkippedRule]) -> None:
    print(f"kept={len(rules)} skipped={len(skipped)}")
    reasons: dict[str, int] = {}
    for rule in skipped:
        reasons[rule.reason] = reasons.get(rule.reason, 0) + 1
    for reason, count in sorted(reasons.items(), key=lambda item: (-item[1], item[0])):
        print(f"skipped.{reason}={count}")


def chunked(items: list[SecretBenchRule], size: int) -> list[list[SecretBenchRule]]:
    if size <= 0:
        raise SystemExit("--chunk-size must be positive")
    return [items[i : i + size] for i in range(0, len(items), size)]


def safe_label(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "_", value.upper()).strip("_")
    if not text or not text[0].isalpha():
        return "SECRETBENCH"
    return text[:80]


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def cell(row: list[str], index: int) -> str:
    return str(row[index]).strip() if index < len(row) else ""


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
