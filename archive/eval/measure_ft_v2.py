"""Standalone measurement of FT LoRA v2 on hard_val.

Runs only the FT (rule + LLMDetector) pipeline on hard_val.jsonl with the
current `training/runs/gemma3_4b_lora` adapter, so it picks up whatever the
latest training produced without being wired into eval/runner.py or
eval/ft_compare.py.

Writes eval/results/hard_val_recall_v2.json for later inspection.

Usage:
    python -m eval.measure_ft_v2                   # default paths
    python -m eval.measure_ft_v2 --batch 8 --limit 0
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path


def _one_directional_hit(gold_value: str, hits: set[str]) -> bool:
    # strict: gold span must be a substring of at least one detected hit
    return any(gold_value in h for h in hits)


def _main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--val", type=Path, default=Path("training/data/hard_val.jsonl"))
    ap.add_argument("--adapter", type=Path, default=Path("training/runs/gemma3_4b_lora"))
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", type=Path, default=Path("eval/results/hard_val_recall_v2.json"))
    args = ap.parse_args()

    os.environ["PENTECT_LLM_ADAPTER"] = str(args.adapter)
    os.environ.setdefault("PENTECT_LLM_4BIT", "1")

    records: list[dict] = []
    with args.val.open("r", encoding="utf-8") as f:
        for line in f:
            records.append(json.loads(line))
    if args.limit > 0:
        records = records[: args.limit]

    from engine.detectors.rule import RuleDetector
    from engine.detectors.llm import LLMDetector

    print(f">>> adapter: {args.adapter}")
    print(f">>> loading rule + FT LLM detectors ...")
    rule = RuleDetector()
    llm = LLMDetector()

    print(f">>> detecting on {len(records)} samples (batch={args.batch}) ...")
    t0 = time.time()
    inputs = [r["input"] for r in records]
    hits_per_record: list[set[str]] = [set() for _ in records]

    for i in range(0, len(inputs), args.batch):
        chunk_idx = list(range(i, min(i + args.batch, len(inputs))))
        chunk_texts = [inputs[j] for j in chunk_idx]
        # rule on each
        for j, text in zip(chunk_idx, chunk_texts):
            for sp in rule.detect(text):
                hits_per_record[j].add(text[sp.start:sp.end])
        # llm in batch
        llm_batch = llm.detect_batch(chunk_texts)
        for j, spans in zip(chunk_idx, llm_batch):
            text = inputs[j]
            for sp in spans:
                hits_per_record[j].add(text[sp.start:sp.end])
        done = chunk_idx[-1] + 1
        print(f"  {done}/{len(inputs)}  ({time.time() - t0:.1f}s)")

    # scoring
    total = 0
    hit = 0
    by_cat: dict[str, dict[str, int]] = {}
    misses: list[dict] = []
    for i, rec in enumerate(records):
        for span in rec["spans"]:
            total += 1
            cat = span["category"]
            by_cat.setdefault(cat, {"hit": 0, "total": 0})
            by_cat[cat]["total"] += 1
            if _one_directional_hit(span["value"], hits_per_record[i]):
                hit += 1
                by_cat[cat]["hit"] += 1
            else:
                misses.append({
                    "idx": i,
                    "category": cat,
                    "value": span["value"],
                    "input_preview": rec["input"][:120],
                })

    per_cat = {
        k: {"hit": v["hit"], "total": v["total"],
            "recall": round(v["hit"] / v["total"], 3) if v["total"] else 0.0}
        for k, v in sorted(by_cat.items())
    }
    overall = round(hit / total, 4) if total else 0.0

    print("\n=== FT v2 on hard_val ===")
    print(f"Adapter:  {args.adapter}")
    print(f"Samples:  {len(records)}")
    print(f"Overall:  {hit}/{total} = {overall:.1%}")
    print("\nPer category:")
    for k, v in per_cat.items():
        print(f"  {k:15s} {v['hit']:3d}/{v['total']:3d}  ({v['recall']:.1%})")

    # write JSON
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "val_path": str(args.val),
        "adapter": str(args.adapter),
        "num_samples": len(records),
        "num_spans": total,
        "scoring": "strict one-directional: gold span must be substring of a detected hit",
        "overall": {"hit": hit, "total": total, "recall": overall},
        "per_category": per_cat,
        "misses": misses,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    _main()
