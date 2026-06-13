#!/usr/bin/env python3
"""Evaluate Pentect on ai4privacy-style PII masking exports.

This runner consumes external JSON, JSONL, or CSV rows. It does not contain a
local fixture corpus. It expects ai4privacy-style fields:

  - source_text: original text
  - privacy_mask: list of {value,start,end,label}, often encoded as a string
  - span_labels: fallback list of [start,end,label]

The metric is detection-only recall: a labeled value is counted as concealed if
the raw value is absent from Pentect's masked output. Pentect does not emit
ai4privacy label names, so this runner intentionally does not score type
accuracy.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


CORE_STRUCTURED_LABELS = {
    "ACCOUNTNUMBER",
    "ACCOUNT_NUMBER",
    "BIC",
    "CREDITCARD",
    "CREDIT_CARD",
    "CREDIT_CARD_NUMBER",
    "DRIVERLICENSE",
    "DRIVER_LICENSE",
    "EMAIL",
    "IBAN",
    "IBAN_CODE",
    "IP",
    "IPV4",
    "IPV6",
    "MAC",
    "PASSPORT",
    "PHONENUMBER",
    "PHONE_NUMBER",
    "SOCIALNUMBER",
    "SOCIAL_SECURITY_NUMBER",
    "SSN",
    "SWIFT",
    "TAXNUMBER",
    "TAX_ID",
    "TEL",
    "URL",
    "USERNAME",
    "VAT",
    "VAT_NUMBER",
}

SEMANTIC_LABELS = {
    "ADDRESS",
    "CITY",
    "COUNTRY",
    "DATE",
    "FIRSTNAME",
    "GENDER",
    "JOBTITLE",
    "LASTNAME",
    "LOCATION",
    "NAME",
    "ORGANIZATION",
    "PERSON",
    "STATE",
    "TIME",
    "TITLE",
}


@dataclass(frozen=True)
class Annotation:
    row_id: str
    label: str
    value: str
    start: int | None
    end: int | None


def main() -> int:
    args = parse_args()
    rows = list(read_rows(args.data))
    if args.limit:
        rows = rows[: args.limit]
    if not rows:
        print("no rows", file=sys.stderr)
        return 2

    if args.list_labels:
        print_label_counts(args, rows)
        return 0

    results = evaluate(args, rows)
    report = summarize(results)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_report(report)
    if args.fail_under_recall is not None and report["overall"]["recall"] is not None:
        return 1 if report["overall"]["recall"] < args.fail_under_recall else 0
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("data", type=Path, help="ai4privacy export: .jsonl, .json, or .csv")
    p.add_argument(
        "--bin",
        default="target/release/pentect.exe" if sys.platform == "win32" else "target/release/pentect",
        help="pentect binary path",
    )
    p.add_argument("--kind", default="text", choices=["text", "json", "env", "har"])
    p.add_argument("--profile", default="balanced")
    p.add_argument("--text-field", default="source_text")
    p.add_argument("--mask-field", default="privacy_mask")
    p.add_argument("--span-field", default="span_labels")
    p.add_argument("--id-field", default="id")
    p.add_argument(
        "--preset",
        default="all",
        choices=["all", "core-structured", "semantic"],
        help="label filter preset",
    )
    p.add_argument("--include-label", action="append", default=[], help="label to include")
    p.add_argument("--exclude-label", action="append", default=[], help="label to exclude")
    p.add_argument("--min-value-len", type=int, default=1)
    p.add_argument("--limit", type=int)
    p.add_argument("--json", action="store_true")
    p.add_argument("--list-labels", action="store_true")
    p.add_argument("--fail-under-recall", type=float)
    p.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        help="extra argument passed after `pentect mask` (repeatable)",
    )
    return p.parse_args()


def read_rows(path: Path) -> Iterable[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as f:
            yield from csv.DictReader(f)
        return
    if suffix == ".jsonl":
        with path.open(encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)
        return
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(data, list):
            yield from data
        elif isinstance(data, dict) and isinstance(data.get("rows"), list):
            yield from data["rows"]
        else:
            raise SystemExit("JSON must be a list or an object with a `rows` list")
        return
    raise SystemExit(f"unsupported file extension: {path.suffix}")


def print_label_counts(args: argparse.Namespace, rows: list[dict[str, Any]]) -> None:
    counts = Counter()
    for index, row in enumerate(rows):
        for ann in row_annotations(args, row, index):
            counts[ann.label] += 1
    for label, count in counts.most_common():
        print(f"{label}\t{count}")


def evaluate(args: argparse.Namespace, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []
    for index, row in enumerate(rows):
        text = as_text(row.get(args.text_field, ""))
        annotations = [a for a in row_annotations(args, row, index) if include_annotation(args, a)]
        if not text or not annotations:
            continue
        masked = run_pentect(args, text)
        for ann in annotations:
            concealed = ann.value not in masked
            results.append(
                {
                    "row_id": ann.row_id,
                    "label": ann.label,
                    "concealed": concealed,
                    "value_preview": preview(ann.value),
                    "span": span_preview(ann),
                }
            )
    return results


def row_annotations(args: argparse.Namespace, row: dict[str, Any], index: int) -> list[Annotation]:
    row_id = as_text(row.get(args.id_field, "")) or str(index)
    text = as_text(row.get(args.text_field, ""))
    mask_items = parse_blob(row.get(args.mask_field))
    if mask_items:
        return annotations_from_mask(row_id, text, mask_items)
    span_items = parse_blob(row.get(args.span_field))
    return annotations_from_spans(row_id, text, span_items)


def annotations_from_mask(row_id: str, text: str, items: list[Any]) -> list[Annotation]:
    out = []
    for item in items:
        if isinstance(item, dict):
            label = normalize_label(item.get("label", ""))
            start = parse_int(item.get("start"))
            end = parse_int(item.get("end"))
            value = as_text(item.get("value", ""))
            if not value and start is not None and end is not None:
                value = text[start:end]
            ann = annotation(row_id, label, value, start, end)
            if ann:
                out.append(ann)
        elif isinstance(item, (list, tuple)) and len(item) >= 3:
            start = parse_int(item[0])
            end = parse_int(item[1])
            label = normalize_label(item[2])
            value = text[start:end] if start is not None and end is not None else ""
            ann = annotation(row_id, label, value, start, end)
            if ann:
                out.append(ann)
    return out


def annotations_from_spans(row_id: str, text: str, items: list[Any]) -> list[Annotation]:
    out = []
    for item in items:
        if not isinstance(item, (list, tuple)) or len(item) < 3:
            continue
        start = parse_int(item[0])
        end = parse_int(item[1])
        label = normalize_label(item[2])
        value = text[start:end] if start is not None and end is not None else ""
        ann = annotation(row_id, label, value, start, end)
        if ann:
            out.append(ann)
    return out


def annotation(
    row_id: str,
    label: str,
    value: str,
    start: int | None,
    end: int | None,
) -> Annotation | None:
    value = value.strip()
    if not label or not value:
        return None
    return Annotation(row_id=row_id, label=label, value=value, start=start, end=end)


def parse_blob(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    parsed = value
    for _ in range(2):
        if isinstance(parsed, str):
            parsed = parsed.strip()
            if not parsed:
                return []
            try:
                parsed = json.loads(parsed)
            except json.JSONDecodeError:
                parsed = ast.literal_eval(parsed)
            continue
        break
    return parsed if isinstance(parsed, list) else []


def include_annotation(args: argparse.Namespace, ann: Annotation) -> bool:
    if len(ann.value) < args.min_value_len:
        return False
    include = label_set(args.include_label)
    exclude = label_set(args.exclude_label)
    if ann.label in exclude:
        return False
    if include:
        return ann.label in include
    if args.preset == "core-structured":
        return ann.label in CORE_STRUCTURED_LABELS
    if args.preset == "semantic":
        return ann.label in SEMANTIC_LABELS
    return True


def run_pentect(args: argparse.Namespace, text: str) -> str:
    cmd = [
        args.bin,
        "mask",
        "--kind",
        args.kind,
        "--profile",
        args.profile,
        *args.extra_arg,
    ]
    proc = subprocess.run(
        cmd,
        input=text,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"pentect failed with exit {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc.stdout


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    concealed = sum(1 for r in results if r["concealed"])
    by_label = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in results:
        grouped[r["label"]].append(r)
    for label, rows in sorted(grouped.items(), key=lambda item: len(item[1]), reverse=True):
        label_total = len(rows)
        label_concealed = sum(1 for r in rows if r["concealed"])
        by_label[label] = {
            "total": label_total,
            "concealed": label_concealed,
            "missed": label_total - label_concealed,
            "recall": ratio(label_concealed, label_total),
        }
    return {
        "overall": {
            "annotations": total,
            "concealed": concealed,
            "missed": total - concealed,
            "recall": ratio(concealed, total),
        },
        "by_label": by_label,
        "miss_examples": [r for r in results if not r["concealed"]][:20],
    }


def print_report(report: dict[str, Any]) -> None:
    o = report["overall"]
    print(
        "ai4privacy export: "
        f"annotations={o['annotations']} recall={fmt(o['recall'])} "
        f"concealed={o['concealed']} missed={o['missed']}"
    )
    print()
    print(f"{'label':<28} {'total':>8} {'recall':>8} {'concealed/missed':>18}")
    for label, row in report["by_label"].items():
        print(
            f"{label[:28]:<28} {row['total']:>8} {fmt(row['recall']):>8} "
            f"{row['concealed']}/{row['missed']:>8}"
        )
    if report["miss_examples"]:
        print("\nmiss examples:")
        for ex in report["miss_examples"][:10]:
            print(
                f"  row={ex['row_id']} label={ex['label']} "
                f"value={ex['value_preview']} span={ex['span']}"
            )


def label_set(values: list[str]) -> set[str]:
    labels: set[str] = set()
    for value in values:
        for part in value.split(","):
            label = normalize_label(part)
            if label:
                labels.add(label)
    return labels


def normalize_label(value: Any) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", as_text(value).upper()).strip("_")


def parse_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_text(value: Any) -> str:
    return "" if value is None else str(value)


def ratio(num: int, den: int) -> float | None:
    return None if den == 0 else num / den


def fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


def preview(value: str) -> str:
    if len(value) <= 16:
        return value
    return f"{value[:6]}...{value[-4:]}({len(value)})"


def span_preview(ann: Annotation) -> str:
    if ann.start is None or ann.end is None:
        return "n/a"
    return f"{ann.start}:{ann.end}"


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
