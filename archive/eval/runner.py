"""Test case runner.

Usage:
    python -m eval.runner testcases/har
    python -m eval.runner testcases/har --compare
"""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from eval.context_check import keyword_match
from eval.metrics import compute_detection
from testcases.schema import TestCase, load_testcases_from_dir


MaskFn = Callable[[str], str]


@dataclass
class CaseReport:
    case_id: str
    engine: str
    recall: float
    missed: list[str]
    context_pass_rate: float
    context_detail: list[dict]


def run_case(case: TestCase, base_dir: Path, masker: MaskFn, engine_name: str) -> CaseReport:
    input_text = case.resolve_input(base_dir)
    masked = masker(input_text)

    det = compute_detection(masked, case)

    context_detail: list[dict] = []
    passes = 0
    for cp in case.context_preservation:
        r = keyword_match(masked, cp)
        context_detail.append(
            {"prompt": r.prompt, "matched": r.matched, "passed": r.passed}
        )
        if r.passed:
            passes += 1
    context_pass_rate = passes / len(case.context_preservation) if case.context_preservation else 1.0

    return CaseReport(
        case_id=case.id,
        engine=engine_name,
        recall=det.recall,
        missed=det.missed,
        context_pass_rate=context_pass_rate,
        context_detail=context_detail,
    )


def _default_masker() -> MaskFn:
    from engine.core import PentectEngine

    engine = PentectEngine()

    def fn(text: str) -> str:
        return engine.mask_text(text).masked_text

    return fn


def _ft_masker() -> MaskFn:
    from engine.core import PentectEngine

    os.environ.setdefault("PENTECT_LLM_ADAPTER", "training/runs/gemma3_4b_lora")
    os.environ.setdefault("PENTECT_LLM_4BIT", "1")
    engine = PentectEngine(use_llm=True)

    def fn(text: str) -> str:
        return engine.mask_text(text).masked_text

    return fn


def _baseline_presidio_masker() -> MaskFn:
    from eval.baselines.presidio_only import mask_with_presidio

    return mask_with_presidio


def _baseline_vanilla_gemma_masker() -> MaskFn:
    from eval.baselines.vanilla_gemma import mask_with_vanilla_gemma

    return mask_with_vanilla_gemma


def aggregate(reports: list[CaseReport]) -> dict:
    if not reports:
        return {}
    recall_avg = sum(r.recall for r in reports) / len(reports)
    ctx_avg = sum(r.context_pass_rate for r in reports) / len(reports)
    return {
        "engine": reports[0].engine,
        "cases": len(reports),
        "recall_avg": recall_avg,
        "context_pass_rate_avg": ctx_avg,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path, help="Directory containing test case YAMLs")
    ap.add_argument("--compare", action="store_true", help="Run Presidio and vanilla Gemma baselines too")
    ap.add_argument("--ft", action="store_true", help="Include rule + FT-LLM (Pentect) engine")
    ap.add_argument("--json", action="store_true", help="Output JSON only")
    args = ap.parse_args()

    cases = load_testcases_from_dir(args.path)

    engines: list[tuple[str, Callable[[], MaskFn]]] = [("pentect_rule", _default_masker)]
    if args.ft:
        engines.append(("pentect_rule_ft", _ft_masker))
    if args.compare:
        engines.append(("presidio_only", _baseline_presidio_masker))
        engines.append(("vanilla_gemma", _baseline_vanilla_gemma_masker))

    summary: list[dict] = []
    per_case: list[dict] = []

    for name, factory in engines:
        try:
            masker = factory()
        except Exception as e:  # noqa: BLE001
            print(f"[warn] engine {name} unavailable: {e}")
            continue
        reports: list[CaseReport] = []
        for path, case in cases:
            try:
                r = run_case(case, base_dir=path.parent, masker=masker, engine_name=name)
            except Exception as e:  # noqa: BLE001
                print(f"[warn] {name}: case {case.id} failed: {e}")
                continue
            reports.append(r)
            per_case.append(
                {
                    "engine": name,
                    "case": case.id,
                    "recall": r.recall,
                    "missed": r.missed,
                    "context_pass_rate": r.context_pass_rate,
                }
            )
        agg = aggregate(reports)
        if agg:
            summary.append(agg)

    if args.json:
        print(json.dumps({"summary": summary, "per_case": per_case}, ensure_ascii=False, indent=2))
        return

    print("\n=== Summary ===")
    for s in summary:
        print(
            f"{s['engine']:16}  cases={s['cases']:3}  recall={s['recall_avg']:.3f}  context={s['context_pass_rate_avg']:.3f}"
        )

    print("\n=== Per case ===")
    for p in per_case:
        print(
            f"{p['engine']:16}  {p['case']:30}  recall={p['recall']:.2f}  ctx={p['context_pass_rate']:.2f}  missed={p['missed']}"
        )


if __name__ == "__main__":
    main()
