"""OpenAI Privacy Filter (vanilla) baseline on hard_val.

OpenAI 公式 `opf` パッケージで一発推論。category 一致は見ず
「gold 値が検出 span の substring で見つかるか」で hit 判定。
既存 measure_ft_v2 と同じ strict one-directional スコアリング。

Usage:
    python -m eval.measure_openai_privacy
    python -m eval.measure_openai_privacy --limit 20 --device cpu
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def _one_directional_hit(gold_value: str, hits: set[str]) -> bool:
    return any(gold_value in h for h in hits)


def _main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--val", type=Path, default=Path("training/data/hard_val.jsonl"))
    ap.add_argument("--device", type=str, default="cuda", choices=["cuda", "cpu"])
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--checkpoint", type=str, default=None,
                    help="Path to a finetuned opf checkpoint dir. If omitted, loads the vanilla privacy-filter.")
    ap.add_argument("--out", type=Path, default=Path("eval/results/hard_val_recall_openai_pf.json"))
    args = ap.parse_args()

    from opf._api import OPF

    records: list[dict] = []
    with args.val.open("r", encoding="utf-8") as f:
        for line in f:
            records.append(json.loads(line))
    if args.limit > 0:
        records = records[: args.limit]

    tag = args.checkpoint or "openai/privacy-filter"
    print(f">>> loading {tag} on {args.device} ...")
    opf = OPF(model=args.checkpoint, device=args.device, output_mode="typed")

    print(f">>> detecting on {len(records)} samples ...")
    t0 = time.time()
    hits_per_record: list[set[str]] = [set() for _ in records]
    labels_per_record: list[list[str]] = [[] for _ in records]

    for j, rec in enumerate(records):
        text = rec["input"]
        result = opf.redact(text)
        for sp in result.detected_spans:
            if sp.text:
                hits_per_record[j].add(sp.text)
                labels_per_record[j].append(sp.label)
        if (j + 1) % 20 == 0 or j + 1 == len(records):
            print(f"  {j+1}/{len(records)}  ({time.time() - t0:.1f}s)")

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
                    "detected_labels": labels_per_record[i],
                })

    per_cat = {
        k: {"hit": v["hit"], "total": v["total"],
            "recall": round(v["hit"] / v["total"], 3) if v["total"] else 0.0}
        for k, v in sorted(by_cat.items())
    }
    overall = round(hit / total, 4) if total else 0.0

    print("\n=== OpenAI Privacy Filter (vanilla) on hard_val ===")
    print(f"Samples:  {len(records)}")
    print(f"Overall:  {hit}/{total} = {overall:.1%}")
    print("\nPer Pentect category:")
    for k, v in per_cat.items():
        print(f"  {k:15s} {v['hit']:3d}/{v['total']:3d}  ({v['recall']:.1%})")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "val_path": str(args.val),
        "model": tag,
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
