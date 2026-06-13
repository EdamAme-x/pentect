#!/usr/bin/env python3
"""Evaluate Pentect against a SecretBench BigQuery export.

SecretBench itself is gated: researchers must request access, then export rows
from `dev-range-332204.secretbench.secrets`. This runner consumes that export in
CSV, JSON, or JSONL form and computes candidate-level precision/recall:

  - label=True and Pentect masks the candidate secret  => true positive
  - label=True and the candidate remains visible      => false negative
  - label=False and Pentect masks the candidate       => false positive
  - label=False and the candidate remains visible     => true negative

Expected fields follow the SecretBench README:
`secret`, `label`, and optionally `category`, `comment`, `file_path`, plus a
context field if you exported one. If no context field is present, the script
evaluates the candidate string by itself.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


DEFAULT_CONTEXT_FIELDS = (
    "context",
    "source",
    "source_text",
    "content",
    "file_content",
    "line",
    "snippet",
)


def main() -> int:
    args = parse_args()
    rows = list(read_rows(args.data))
    if args.limit:
        rows = rows[: args.limit]
    if not rows:
        print("no rows", file=sys.stderr)
        return 2

    results = [evaluate_row(args, row) for row in rows]
    report = summarize(results)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_report(report)
    return 1 if should_fail(args, report) else 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("data", type=Path, help="SecretBench export: .csv, .jsonl, or .json")
    p.add_argument(
        "--bin",
        default="target/release/pentect.exe" if sys.platform == "win32" else "target/release/pentect",
        help="pentect binary path",
    )
    p.add_argument("--kind", default="text", choices=["text", "json", "env", "har"])
    p.add_argument("--profile", default="balanced")
    p.add_argument("--context-field", action="append", default=[])
    p.add_argument("--secret-field", default="secret")
    p.add_argument("--label-field", default="label")
    p.add_argument("--category-field", default="category")
    p.add_argument("--limit", type=int)
    p.add_argument("--json", action="store_true")
    p.add_argument("--fail-on-false-negative", action="store_true")
    p.add_argument("--fail-on-false-positive", action="store_true")
    p.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        help="extra argument passed after `pentect mask` (repeatable)",
    )
    return p.parse_args()


def should_fail(args: argparse.Namespace, report: dict[str, Any]) -> bool:
    o = report["overall"]
    return (args.fail_on_false_negative and o["false_negative"] > 0) or (
        args.fail_on_false_positive and o["false_positive"] > 0
    )


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


def evaluate_row(args: argparse.Namespace, row: dict[str, Any]) -> dict[str, Any]:
    raw_secret = as_text(row.get(args.secret_field, ""))
    secret = normalize_secret(raw_secret)
    label = parse_label(row.get(args.label_field))
    text = choose_context(args, row, secret)
    masked = run_pentect(args, text)
    masked_candidate = bool(secret) and secret not in masked

    if label and masked_candidate:
        outcome = "true_positive"
    elif label and not masked_candidate:
        outcome = "false_negative"
    elif not label and masked_candidate:
        outcome = "false_positive"
    else:
        outcome = "true_negative"

    return {
        "outcome": outcome,
        "label": label,
        "masked_candidate": masked_candidate,
        "category": as_text(row.get(args.category_field, "")) or "unknown",
        "comment": as_text(row.get("comment", "")),
        "file_path": as_text(row.get("file_path", "")),
        "secret_preview": preview(secret),
        "used_context": text != secret,
    }


def choose_context(args: argparse.Namespace, row: dict[str, Any], secret: str) -> str:
    for field in [*args.context_field, *DEFAULT_CONTEXT_FIELDS]:
        value = as_text(row.get(field, ""))
        if value:
            return value
    return secret


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
    counts = Counter(r["outcome"] for r in results)
    tp = counts["true_positive"]
    fp = counts["false_positive"]
    fn = counts["false_negative"]
    tn = counts["true_negative"]
    overall = {
        "rows": len(results),
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "context_rows": sum(1 for r in results if r["used_context"]),
    }
    by_category = group_by(results, "category")
    by_comment = group_by(results, "comment")
    return {
        "overall": overall,
        "by_category": by_category,
        "by_comment_top20": dict(list(by_comment.items())[:20]),
        "false_negative_examples": examples(results, "false_negative"),
        "false_positive_examples": examples(results, "false_positive"),
    }


def group_by(results: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in results:
        groups[r.get(key) or "unknown"].append(r)
    out = {}
    for name, rows in sorted(groups.items(), key=lambda item: len(item[1]), reverse=True):
        counts = Counter(r["outcome"] for r in rows)
        tp = counts["true_positive"]
        fp = counts["false_positive"]
        fn = counts["false_negative"]
        tn = counts["true_negative"]
        out[name] = {
            "rows": len(rows),
            "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn),
            "false_positive_rate": ratio(fp, fp + tn),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
        }
    return out


def examples(results: list[dict[str, Any]], outcome: str, limit: int = 20) -> list[dict[str, Any]]:
    keys = ("category", "comment", "file_path", "secret_preview", "used_context")
    return [{k: r[k] for k in keys} for r in results if r["outcome"] == outcome][:limit]


def print_report(report: dict[str, Any]) -> None:
    o = report["overall"]
    print(
        "SecretBench export: "
        f"rows={o['rows']} precision={fmt(o['precision'])} "
        f"recall={fmt(o['recall'])} f1={fmt(o['f1'])} "
        f"fpr={fmt(o['false_positive_rate'])}"
    )
    print(
        f"tp={o['true_positive']} fp={o['false_positive']} "
        f"fn={o['false_negative']} tn={o['true_negative']} "
        f"context_rows={o['context_rows']}"
    )
    print()
    print(f"{'category':<34} {'rows':>7} {'prec':>8} {'recall':>8} {'fpr':>8} {'tp/fp/fn/tn':>18}")
    for name, row in report["by_category"].items():
        print(
            f"{name[:34]:<34} {row['rows']:>7} {fmt(row['precision']):>8} "
            f"{fmt(row['recall']):>8} {fmt(row['false_positive_rate']):>8} "
            f"{row['tp']}/{row['fp']}/{row['fn']}/{row['tn']:>7}"
        )
    if report["false_negative_examples"]:
        print("\nfalse negative examples:")
        for ex in report["false_negative_examples"][:10]:
            print(f"  {ex}")
    if report["false_positive_examples"]:
        print("\nfalse positive examples:")
        for ex in report["false_positive_examples"][:10]:
            print(f"  {ex}")


def normalize_secret(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == "[" and value[-1] == "]":
        return value[1:-1]
    return value


def parse_label(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in {"true", "t", "1", "yes", "y", "actual", "positive"}:
        return True
    if text in {"false", "f", "0", "no", "n", "dummy", "negative"}:
        return False
    raise ValueError(f"cannot parse label: {value!r}")


def as_text(value: Any) -> str:
    return "" if value is None else str(value)


def ratio(num: int, den: int) -> float | None:
    return None if den == 0 else num / den


def fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


def preview(value: str) -> str:
    if len(value) <= 12:
        return value
    return f"{value[:4]}...{value[-4:]}({len(value)})"


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
