#!/usr/bin/env python3
"""Build Pentect rule packs from an external regex source.

The source can be a generic CSV/TSV/XLSX/JSON/JSONL file with column mappings,
or the public SecretBench regular-expression workbook via a preset. This tool
does not embed any dataset rows; it only converts detector rules into Pentect's
existing TOML pack format.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import tempfile
import urllib.request
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET
from zipfile import ZipFile


SECRETBENCH_PUBLIC_WORKBOOK_URL = (
    "https://raw.githubusercontent.com/setu1421/SecretBench/main/"
    "Regular%20Expressions/Secret%20Regular%20Expression.xlsx"
)

NS = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


@dataclass(frozen=True)
class RegexRule:
    rule_id: str
    label_source: str
    pattern: str
    origin: str


@dataclass(frozen=True)
class SkippedRule:
    rule_id: str
    label_source: str
    reason: str
    pattern: str


def main() -> int:
    args = parse_args()
    configure_preset(args)
    source_path = resolve_source(args)
    rules, skipped = convert_rules(read_rules(source_path, args))

    if args.dry_run:
        print_summary(rules, skipped)
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for old in args.out_dir.glob(f"{args.prefix}-*.toml"):
        old.unlink()

    chunks = list(chunked(rules, args.chunk_size))
    for index, chunk in enumerate(chunks, start=1):
        write_pack(args.out_dir / f"{args.prefix}-{index:03d}.toml", chunk, args)
    write_skipped(args.out_dir / f"{args.prefix}-skipped.tsv", skipped)

    print_summary(rules, skipped)
    print(f"wrote {len(chunks)} pack(s) to {args.out_dir}")
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", nargs="?", type=Path, help="CSV/TSV/XLSX/JSON/JSONL regex source")
    p.add_argument(
        "--source",
        default="file",
        choices=["file", "secretbench-public"],
        help="input preset; `file` uses the explicit column mappings",
    )
    p.add_argument("--pattern-col", default="pattern")
    p.add_argument("--label-col", default="label")
    p.add_argument("--id-col", default="")
    p.add_argument("--origin-col", default="")
    p.add_argument("--label-prefix", default="REGEX")
    p.add_argument("--out-dir", type=Path, default=Path("target/regex-packs"))
    p.add_argument("--prefix", default="regex-pack")
    p.add_argument("--chunk-size", type=int, default=50)
    p.add_argument("--category", default="secret", choices=["secret", "identifier", "endpoint", "pii", "other"])
    p.add_argument("--confidence", default="medium", choices=["low", "medium", "high"])
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()


def configure_preset(args: argparse.Namespace) -> None:
    if args.source != "secretbench-public":
        return
    args.pattern_col = "Regular Expression"
    args.label_col = "Secret Type"
    args.id_col = "Pattern_ID"
    args.origin_col = "Source"
    args.label_prefix = "SB"
    args.prefix = "secretbench-public-regex"
    if args.out_dir == Path("target/regex-packs"):
        args.out_dir = Path("target/secretbench-public-regex")


def resolve_source(args: argparse.Namespace) -> Path:
    if args.input:
        return args.input
    if args.source == "secretbench-public":
        path = Path(tempfile.gettempdir()) / "secretbench-secret-regular-expression.xlsx"
        urllib.request.urlretrieve(SECRETBENCH_PUBLIC_WORKBOOK_URL, path)
        return path
    raise SystemExit("input file is required unless --source secretbench-public is used")


def read_rules(path: Path, args: argparse.Namespace) -> list[RegexRule]:
    records = read_records(path)
    out = []
    for index, row in enumerate(records, start=1):
        pattern = text(row.get(args.pattern_col, ""))
        if not pattern:
            continue
        out.append(
            RegexRule(
                rule_id=text(row.get(args.id_col, "")) if args.id_col else str(index),
                label_source=text(row.get(args.label_col, "")) if args.label_col else "CUSTOM",
                pattern=pattern,
                origin=text(row.get(args.origin_col, "")) if args.origin_col else "",
            )
        )
    return out


def read_records(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".xlsx":
        return xlsx_records(path)
    if suffix == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))
    if suffix == ".tsv":
        with path.open(newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f, delimiter="\t"))
    if suffix == ".jsonl":
        with path.open(encoding="utf-8-sig") as f:
            return [json.loads(line) for line in f if line.strip()]
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("rows"), list):
            return data["rows"]
        raise SystemExit("JSON input must be a list or an object with a `rows` list")
    raise SystemExit(f"unsupported regex source extension: {path.suffix}")


def xlsx_records(path: Path) -> list[dict[str, str]]:
    rows = xlsx_rows(path)
    if not rows:
        return []
    header = [str(c).strip() for c in rows[0]]
    return [dict(zip(header, row)) for row in rows[1:]]


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
            values: dict[int, str] = {}
            for c in row.findall("a:c", NS):
                v = c.find("a:v", NS)
                value = "" if v is None else v.text or ""
                if c.attrib.get("t") == "s" and value:
                    value = shared[int(value)]
                values[cell_index(c.attrib.get("r", ""))] = value
            if values:
                rows.append([values.get(i, "") for i in range(max(values) + 1)])
        return rows


def cell_index(cell_ref: str) -> int:
    letters = "".join(c for c in cell_ref if c.isalpha()).upper()
    if not letters:
        return 0
    n = 0
    for c in letters:
        n = n * 26 + (ord(c) - ord("A") + 1)
    return n - 1


def convert_rules(rules: list[RegexRule]) -> tuple[list[RegexRule], list[SkippedRule]]:
    kept = []
    skipped = []
    for rule in rules:
        reason = skip_reason(rule.pattern)
        if reason:
            skipped.append(
                SkippedRule(
                    rule_id=rule.rule_id,
                    label_source=rule.label_source,
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
    value = pattern.strip()
    return value.startswith("/") and re.search(r"/[a-zA-Z]*$", value) is not None


def write_pack(path: Path, rules: list[RegexRule], args: argparse.Namespace) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        f.write("# Generated from an external regex source.\n")
        f.write(f"# source = {args.source}\n")
        f.write("# This pack contains detector rules only, not dataset rows.\n\n")
        for rule in rules:
            label = safe_label(f"{args.label_prefix}_{rule.label_source}")
            f.write("[[detector]]\n")
            f.write(f"label = {toml_string(label)}\n")
            f.write(f"category = {toml_string(args.category)}\n")
            f.write(f"confidence = {toml_string(args.confidence)}\n")
            f.write(f"# rule_id = {rule.rule_id}; origin = {rule.origin}\n")
            f.write(f"pattern = {toml_string(rule.pattern)}\n\n")


def write_skipped(path: Path, skipped: list[SkippedRule]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["rule_id", "label_source", "reason", "pattern"])
        for rule in skipped:
            w.writerow([rule.rule_id, rule.label_source, rule.reason, rule.pattern])


def print_summary(rules: list[RegexRule], skipped: list[SkippedRule]) -> None:
    print(f"kept={len(rules)} skipped={len(skipped)}")
    reasons: dict[str, int] = {}
    for rule in skipped:
        reasons[rule.reason] = reasons.get(rule.reason, 0) + 1
    for reason, count in sorted(reasons.items(), key=lambda item: (-item[1], item[0])):
        print(f"skipped.{reason}={count}")


def chunked(items: list[RegexRule], size: int) -> list[list[RegexRule]]:
    if size <= 0:
        raise SystemExit("--chunk-size must be positive")
    return [items[i : i + size] for i in range(0, len(items), size)]


def safe_label(value: str) -> str:
    label = re.sub(r"[^A-Za-z0-9]+", "_", value.upper()).strip("_")
    if not label or not label[0].isalpha():
        return "CUSTOM_REGEX"
    return label[:96]


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def text(value: Any) -> str:
    return "" if value is None else str(value).strip()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
