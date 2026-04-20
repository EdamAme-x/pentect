"""Measure span recall on the held-out validation set across engines.

Engines available:
    --rule-only        Rule-based regex only
    --ft               Rule + FT LoRA Gemma 3 4B
    --vanilla-gemma    Rule + base Gemma 3 4B (prompt-only)
    --presidio         Rule + Presidio

Usage:
    python -m eval.ft_compare --rule-only
    python -m eval.ft_compare --ft --batch 8
    python -m eval.ft_compare --vanilla-gemma --batch 4
    python -m eval.ft_compare --presidio
"""
from __future__ import annotations

import json
import os
import re
import time
import argparse
from pathlib import Path

from engine.detectors.rule import RuleDetector


def _rule_hits(text: str, detector: RuleDetector) -> set[str]:
    out: set[str] = set()
    for s in detector.detect(text):
        out.add(text[s.start:s.end])
    return out


def _score(records: list[dict], hits_per_record: list[set[str]]) -> dict:
    """A span is considered recalled only if some detected hit FULLY COVERS it.

    In other words: val must be a substring of at least one hit string. The
    reverse direction (hit ⊂ val) is NOT accepted, because that would reward
    a detector for partial fragments like matching "Lucas" against the span
    "Lucas Martinez" — after masking, "Martinez" would still leak.
    """
    per_cat: dict[str, dict[str, int]] = {}
    grand = {"hit": 0, "total": 0}
    for rec, hits in zip(records, hits_per_record):
        for span in rec["spans"]:
            cat = span["category"]
            val = span["value"]
            per_cat.setdefault(cat, {"hit": 0, "total": 0})
            per_cat[cat]["total"] += 1
            grand["total"] += 1
            if any(val in h for h in hits):
                per_cat[cat]["hit"] += 1
                grand["hit"] += 1
    return {"per_category": per_cat, "overall": grand}


_MASK_TOKEN_RE = re.compile(r"<MASKED>|<PRESIDIO_MASKED>")


def _infer_vanilla_hits(original: str, masked: str) -> set[str]:
    """Vanilla Gemma outputs free-form masked text. Infer what got masked by
    diffing original tokens vs tokens in the masked output."""
    orig_tokens = set(re.findall(r"[A-Za-z0-9._\-/:@+]+", original))
    masked_tokens = set(re.findall(r"[A-Za-z0-9._\-/:@+]+", masked))
    return orig_tokens - masked_tokens


def _run(
    val_path: Path,
    *,
    engine: str,
    batch: int,
) -> dict:
    rule = RuleDetector()
    records: list[dict] = []
    with val_path.open("r", encoding="utf-8") as f:
        for line in f:
            records.append(json.loads(line))

    hits_per_record: list[set[str]] = [set() for _ in records]

    if engine != "vanilla-gemma":
        for i, rec in enumerate(records):
            hits_per_record[i] |= _rule_hits(rec["input"], rule)

    if engine == "ft":
        from engine.detectors.llm import LLMDetector

        llm = LLMDetector()
        t0 = time.time()
        for i in range(0, len(records), batch):
            chunk = records[i:i + batch]
            texts = [r["input"] for r in chunk]
            batch_spans = llm.detect_batch(texts)
            for j, spans in enumerate(batch_spans):
                for s in spans:
                    hits_per_record[i + j].add(chunk[j]["input"][s.start:s.end])
            elapsed = time.time() - t0
            done = min(i + batch, len(records))
            rate = done / elapsed if elapsed > 0 else 0
            print(f"  {done}/{len(records)} samples, {elapsed:.1f}s, {rate:.2f} samples/s")

    elif engine == "vanilla-gemma":
        from eval.baselines.vanilla_gemma import mask_with_vanilla_gemma

        t0 = time.time()
        for i, rec in enumerate(records):
            masked = mask_with_vanilla_gemma(rec["input"])
            hits_per_record[i] = _infer_vanilla_hits(rec["input"], masked)
            elapsed = time.time() - t0
            done = i + 1
            rate = done / elapsed if elapsed > 0 else 0
            if done % 4 == 0 or done == len(records):
                print(f"  {done}/{len(records)} samples, {elapsed:.1f}s, {rate:.2f} samples/s")

    elif engine == "presidio":
        from presidio_analyzer import AnalyzerEngine

        threshold = float(os.environ.get("PENTECT_PRESIDIO_THRESHOLD", "0.5"))
        analyzer = AnalyzerEngine()
        t0 = time.time()
        for i, rec in enumerate(records):
            results = analyzer.analyze(text=rec["input"], language="en")
            for r in results:
                if r.score < threshold:
                    continue
                hits_per_record[i].add(rec["input"][r.start:r.end])
            if (i + 1) % 20 == 0 or i + 1 == len(records):
                elapsed = time.time() - t0
                print(f"  {i + 1}/{len(records)} samples, {elapsed:.1f}s (threshold={threshold})")

    return _score(records, hits_per_record)


def _print_report(label: str, result: dict) -> None:
    overall = result["overall"]
    recall = overall["hit"] / overall["total"] if overall["total"] else 0.0
    print(f"\n=== {label} ===")
    print(f"Overall recall: {overall['hit']}/{overall['total']} = {recall:.3f}")
    print("Per category:")
    for cat, d in sorted(result["per_category"].items()):
        r = d["hit"] / d["total"] if d["total"] else 0.0
        print(f"  {cat:15} {d['hit']:3}/{d['total']:3} = {r:.3f}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--val", type=Path, default=Path("training/data/train.val.jsonl"))
    ap.add_argument("--rule-only", action="store_true")
    ap.add_argument("--ft", action="store_true", help="Rule + FT LLM (expects $PENTECT_LLM_ADAPTER)")
    ap.add_argument("--vanilla-gemma", action="store_true", help="Rule + base Gemma 3 4B prompt-only")
    ap.add_argument("--presidio", action="store_true", help="Rule + Presidio")
    ap.add_argument("--all", action="store_true", help="Run all engines in sequence")
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--json-out", type=Path, help="Write aggregated results to this JSON file")
    args = ap.parse_args()

    if args.ft or args.all:
        os.environ.setdefault("PENTECT_LLM_ADAPTER", "training/runs/gemma3_4b_lora")
        os.environ.setdefault("PENTECT_LLM_4BIT", "1")

    engines: list[tuple[str, str]] = []
    if args.rule_only or args.all:
        engines.append(("rule-only", "rule-only"))
    if args.presidio or args.all:
        engines.append(("rule + Presidio", "presidio"))
    if args.vanilla_gemma or args.all:
        engines.append(("rule + vanilla Gemma 3 4B", "vanilla-gemma"))
    if args.ft or args.all:
        engines.append(("rule + FT Gemma 3 4B", "ft"))

    if not engines:
        ap.error("pick at least one of --rule-only, --ft, --vanilla-gemma, --presidio, --all")

    all_results: list[tuple[str, dict]] = []
    for label, name in engines:
        print(f"\n>>> Running {label} ...")
        result = _run(args.val, engine=name, batch=args.batch)
        all_results.append((label, result))
        _print_report(label, result)

    if len(all_results) > 1:
        print("\n=== Summary ===")
        for label, result in all_results:
            overall = result["overall"]
            recall = overall["hit"] / overall["total"] if overall["total"] else 0.0
            print(f"  {label:32}  recall={recall:.3f}  ({overall['hit']}/{overall['total']})")

    if args.json_out:
        payload = {
            "val_path": str(args.val),
            "engines": [
                {
                    "label": label,
                    "overall": result["overall"],
                    "overall_recall": (
                        result["overall"]["hit"] / result["overall"]["total"]
                        if result["overall"]["total"] else 0.0
                    ),
                    "per_category": result["per_category"],
                }
                for label, result in all_results
            ],
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nWrote {args.json_out}")


if __name__ == "__main__":
    main()
