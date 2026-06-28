#!/usr/bin/env python3
"""Compare Pentect masking recall with Gitleaks detection recall.

This is a local benchmark, not a GitHub Actions secret scan. It reuses the
hostile real-world corpus so Pentect and Gitleaks face the same expected values.

The score is target-level recall:
- Pentect catches a target when that exact value no longer appears after masking.
- Gitleaks catches a target when a JSON finding's Secret or Match overlaps it.

Install Gitleaks separately and pass --gitleaks-bin if it is not on PATH.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from eval_hostile_realworld import (
    DEFAULT_BIN,
    Case,
    build_cases,
    render_corpus,
    split_case_outputs,
)


@dataclass(frozen=True)
class TargetRef:
    case_name: str
    index: int
    value: str
    category: str
    note: str


@dataclass(frozen=True)
class ToolResult:
    name: str
    caught: set[tuple[str, int]]
    seconds: float
    status: str
    stderr: str = ""


def main() -> int:
    args = parse_args()
    cases = build_cases(args.scale)
    if args.case_limit is not None:
        cases = cases[: args.case_limit]
    if not cases:
        print("no cases", file=sys.stderr)
        return 2

    targets = list(enumerate_targets(cases))
    with tempfile.TemporaryDirectory(prefix="pentect-gitleaks-") as tmp:
        corpus_dir = Path(tmp) / "corpus"
        file_to_case = write_gitleaks_corpus(cases, corpus_dir)
        pentect = run_pentect(args, cases)
        gitleaks = (
            ToolResult("gitleaks", set(), 0.0, "skipped")
            if args.skip_gitleaks
            else run_gitleaks(args, corpus_dir, file_to_case, targets)
        )

    report = build_report(args, cases, targets, [pentect, gitleaks])
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_report(report)
    return 0 if pentect.status == "ok" and gitleaks.status in {"ok", "skipped"} else 2


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pentect-bin", default=DEFAULT_BIN, help="pentect binary path")
    p.add_argument("--gitleaks-bin", default="gitleaks", help="gitleaks binary path")
    p.add_argument("--profile", default="balanced")
    p.add_argument("--kind", default="text", choices=["text", "json", "env", "har"])
    p.add_argument("--scale", type=int, default=1, help="repeat hostile corpus N times")
    p.add_argument("--case-limit", type=int, help="evaluate only the first N cases")
    p.add_argument("--sample-limit", type=int, default=20)
    p.add_argument("--skip-gitleaks", action="store_true", help="run only the Pentect side")
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--pentect-arg",
        action="append",
        default=[],
        help="extra argument passed after `pentect mask` (repeatable)",
    )
    return p.parse_args()


def enumerate_targets(cases: Iterable[Case]) -> Iterable[TargetRef]:
    for case in cases:
        for index, target in enumerate(case.sensitive):
            yield TargetRef(
                case_name=case.name,
                index=index,
                value=target.value,
                category=target.category,
                note=target.note,
            )


def write_gitleaks_corpus(cases: list[Case], corpus_dir: Path) -> dict[str, str]:
    corpus_dir.mkdir(parents=True, exist_ok=True)
    file_to_case: dict[str, str] = {}
    for i, case in enumerate(cases):
        filename = f"{i:05d}_{safe_name(case.name)}.txt"
        (corpus_dir / filename).write_text(case.text, encoding="utf-8")
        file_to_case[filename] = case.name
    return file_to_case


def safe_name(value: str) -> str:
    out = []
    for ch in value:
        out.append(ch if ch.isalnum() or ch in "-_" else "_")
    return "".join(out)[:80] or "case"


def run_pentect(args: argparse.Namespace, cases: list[Case]) -> ToolResult:
    text = render_corpus(cases)
    cmd = [
        args.pentect_bin,
        "mask",
        "--kind",
        args.kind,
        "--profile",
        args.profile,
        *args.pentect_arg,
    ]
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        input=text,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    seconds = time.perf_counter() - start
    if proc.returncode != 0:
        return ToolResult("pentect", set(), seconds, f"exit {proc.returncode}", proc.stderr)

    masked_cases = split_case_outputs(proc.stdout, cases)
    caught: set[tuple[str, int]] = set()
    for case in cases:
        case_out = masked_cases.get(case.name, proc.stdout)
        for index, target in enumerate(case.sensitive):
            if target.value not in case_out:
                caught.add((case.name, index))
    return ToolResult("pentect", caught, seconds, "ok", proc.stderr)


def run_gitleaks(
    args: argparse.Namespace,
    corpus_dir: Path,
    file_to_case: dict[str, str],
    targets: list[TargetRef],
) -> ToolResult:
    if shutil.which(args.gitleaks_bin) is None and not Path(args.gitleaks_bin).exists():
        return ToolResult(
            "gitleaks",
            set(),
            0.0,
            "missing",
            f"gitleaks binary not found: {args.gitleaks_bin}",
        )

    report_path = corpus_dir.parent / "gitleaks.json"
    cmd = [
        args.gitleaks_bin,
        "detect",
        "--no-git",
        "--source",
        str(corpus_dir),
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--no-banner",
    ]
    start = time.perf_counter()
    proc = subprocess.run(cmd, text=True, encoding="utf-8", capture_output=True, check=False)
    seconds = time.perf_counter() - start
    if proc.returncode not in {0, 1}:
        return ToolResult("gitleaks", set(), seconds, f"exit {proc.returncode}", proc.stderr)

    findings = read_gitleaks_report(report_path)
    by_case = group_gitleaks_findings(findings, file_to_case)
    caught: set[tuple[str, int]] = set()
    for target in targets:
        if gitleaks_caught(target.value, by_case.get(target.case_name, [])):
            caught.add((target.case_name, target.index))
    return ToolResult("gitleaks", caught, seconds, "ok", proc.stderr)


def read_gitleaks_report(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return []
    data = json.loads(text)
    if not isinstance(data, list):
        raise SystemExit("gitleaks report must be a JSON list")
    return [item for item in data if isinstance(item, dict)]


def group_gitleaks_findings(
    findings: list[dict[str, Any]], file_to_case: dict[str, str]
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        file_name = Path(str(finding.get("File", ""))).name
        case_name = file_to_case.get(file_name)
        if case_name is None:
            continue
        grouped.setdefault(case_name, []).append(finding)
    return grouped


def gitleaks_caught(value: str, findings: list[dict[str, Any]]) -> bool:
    for finding in findings:
        for key in ("Secret", "Match"):
            found = str(finding.get(key, "") or "")
            if overlaps_secret(value, found):
                return True
    return False


def overlaps_secret(expected: str, found: str) -> bool:
    expected = expected.strip()
    found = found.strip()
    if not expected or not found:
        return False
    if expected in found or found in expected:
        return True
    return normalize_token(expected) in normalize_token(found)


def normalize_token(value: str) -> str:
    return (
        value.replace("%2D", "-")
        .replace("%2d", "-")
        .replace("\\u002d", "-")
        .replace("\\u002D", "-")
        .replace("\u200b", "")
        .replace(" ", "")
    )


def build_report(
    args: argparse.Namespace,
    cases: list[Case],
    targets: list[TargetRef],
    results: list[ToolResult],
) -> dict[str, Any]:
    total = len(targets)
    by_category: dict[str, dict[str, Any]] = {}
    for target in targets:
        row = by_category.setdefault(target.category, {"category": target.category, "total": 0})
        row["total"] += 1
    for result in results:
        for row in by_category.values():
            row[result.name] = 0
        for target in targets:
            if (target.case_name, target.index) in result.caught:
                by_category[target.category][result.name] += 1

    tool_rows = []
    for result in results:
        caught = len(result.caught)
        tool_rows.append(
            {
                "tool": result.name,
                "status": result.status,
                "caught": caught,
                "total": total,
                "recall": ratio(caught, total),
                "seconds": result.seconds,
                "stderr": result.stderr.strip(),
            }
        )

    pentect = results[0]
    gitleaks = results[1]
    if gitleaks.status == "ok":
        pentect_only = pentect.caught - gitleaks.caught
        gitleaks_only = gitleaks.caught - pentect.caught
        missed_by_both = {
            (target.case_name, target.index)
            for target in targets
            if (target.case_name, target.index) not in pentect.caught
            and (target.case_name, target.index) not in gitleaks.caught
        }
    else:
        pentect_only = set()
        gitleaks_only = set()
        missed_by_both = set()

    return {
        "profile": args.profile,
        "kind": args.kind,
        "cases": len(cases),
        "targets": total,
        "tools": tool_rows,
        "by_category": sorted(by_category.values(), key=lambda r: r["category"]),
        "pentect_only": samples(targets, pentect_only, args.sample_limit),
        "gitleaks_only": samples(targets, gitleaks_only, args.sample_limit),
        "missed_by_both": samples(targets, missed_by_both, args.sample_limit),
    }


def samples(
    targets: list[TargetRef], selected: set[tuple[str, int]], limit: int
) -> list[dict[str, str]]:
    out = []
    for target in targets:
        if (target.case_name, target.index) not in selected:
            continue
        out.append(
            {
                "case": target.case_name,
                "category": target.category,
                "note": target.note,
                "value": safe_preview(target.value),
            }
        )
        if len(out) >= limit:
            break
    return out


def safe_preview(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"length={len(value)} sha256={digest}"


def print_report(report: dict[str, Any]) -> None:
    print(
        "gitleaks showdown "
        f"profile={report['profile']} kind={report['kind']} "
        f"cases={report['cases']} targets={report['targets']}"
    )
    print(f"{'tool':<10} {'status':<12} {'caught':>8} {'total':>8} {'recall':>8} {'sec':>8}")
    for row in report["tools"]:
        print(
            f"{row['tool']:<10} {row['status']:<12} {row['caught']:>8} "
            f"{row['total']:>8} {row['recall']:>8.3f} {row['seconds']:>8.3f}"
        )
    print("\nby category:")
    print(f"{'category':<24} {'total':>8} {'pentect':>8} {'gitleaks':>8}")
    for row in report["by_category"]:
        print(
            f"{row['category']:<24} {row['total']:>8} "
            f"{row.get('pentect', 0):>8} {row.get('gitleaks', 0):>8}"
        )
    print_sample_block("pentect-only samples", report["pentect_only"])
    print_sample_block("gitleaks-only samples", report["gitleaks_only"])
    print_sample_block("missed-by-both samples", report["missed_by_both"])
    for row in report["tools"]:
        if row["status"] != "ok" and row["stderr"]:
            print(f"\n{row['tool']}: {row['stderr']}")


def print_sample_block(title: str, rows: list[dict[str, str]]) -> None:
    if not rows:
        return
    print(f"\n{title}:")
    for row in rows:
        print(f"  - {row['category']:<20} {row['case']}: {row['note']} => {row['value']}")


def ratio(num: int, den: int) -> float:
    return num / den if den else 0.0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
