"""Measure whether the Qwen Verifier catches leaks that the FT Gemma missed.

Pipeline:
    hard_val.jsonl -> PentectEngine(ft) -> masked_text
                                          -> QwenVerifier.verify(masked_text)

For each sample we know the gold leak set (from hard_val.jsonl spans).
We compute:
    - FT-only recall: gold spans no longer appearing verbatim in masked_text
    - (FT + Verifier) recall: same, but additionally flagging leaks the
      verifier explicitly reports

Usage:
    python -m eval.verify_check --val training/data/hard_val.jsonl --batch 4
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path


def _gold_still_present(masked: str, gold_values: list[str]) -> list[str]:
    return [v for v in gold_values if v in masked]


def _main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--val", type=Path, default=Path("training/data/hard_val.jsonl"))
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0, help="Limit number of samples (0 = all)")
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    os.environ.setdefault("PENTECT_LLM_ADAPTER", "training/runs/gemma3_4b_lora")
    os.environ.setdefault("PENTECT_LLM_4BIT", "1")

    records: list[dict] = []
    with args.val.open("r", encoding="utf-8") as f:
        for line in f:
            records.append(json.loads(line))
    if args.limit > 0:
        records = records[: args.limit]

    from engine.core import PentectEngine
    from engine.detectors.rule import RuleDetector
    from engine.detectors.llm import LLMDetector
    from engine.granularity import apply_granularity, apply_replacements
    from engine.merger import merge
    from engine.verifier import QwenVerifier

    print(f">>> Loading FT engine (rule + FT Gemma) ...")
    rule = RuleDetector()
    llm = LLMDetector()

    print(f">>> Loading Qwen verifier ...")
    verifier = QwenVerifier()

    total_spans = sum(len(r["spans"]) for r in records)
    ft_leaked = 0          # gold values that FT failed to mask (still in masked text)
    verifier_caught = 0    # of the above, how many the verifier reported as leaks
    verifier_false_pos = 0  # verifier reported values that weren't gold (may include placeholders)
    samples_flagged = 0

    details: list[dict] = []
    t0 = time.time()

    masked_texts: list[str] = []
    gold_per_record: list[list[str]] = []
    inputs = [rec["input"] for rec in records]
    print(f">>> Detecting with FT (batch={args.batch}) ...")
    t_ft = time.time()
    for i in range(0, len(inputs), args.batch):
        chunk = inputs[i:i + args.batch]
        llm_spans_batch = llm.detect_batch(chunk)
        for text, llm_spans in zip(chunk, llm_spans_batch):
            spans = merge(list(rule.detect(text)) + list(llm_spans))
            repl = apply_granularity(text, spans)
            masked_texts.append(apply_replacements(text, repl))
        print(f"  FT {min(i + args.batch, len(inputs))}/{len(inputs)}  ({time.time() - t_ft:.1f}s)")
    for rec in records:
        gold_per_record.append([s["value"] for s in rec["spans"]])

    # verifier in batches
    for i in range(0, len(records), args.batch):
        chunk_mt = masked_texts[i:i + args.batch]
        reports = verifier.verify_batch(chunk_mt)
        for j, rep in enumerate(reports):
            idx = i + j
            masked = masked_texts[idx]
            gold = gold_per_record[idx]
            still = _gold_still_present(masked, gold)
            ft_leaked += len(still)
            caught = [v for v in still if any(v in L or L in v for L in rep.leaks)]
            verifier_caught += len(caught)
            extras = [L for L in rep.leaks if L not in gold and L not in still]
            verifier_false_pos += len(extras)
            if not rep.ok:
                samples_flagged += 1
            details.append({
                "input": records[idx]["input"][:200],
                "masked": masked[:200],
                "ft_leaked": still,
                "verifier_ok": rep.ok,
                "verifier_leaks": rep.leaks,
                "verifier_caught_of_ft_leak": caught,
            })
        elapsed = time.time() - t0
        done = min(i + args.batch, len(records))
        print(f"  {done}/{len(records)} samples, {elapsed:.1f}s")

    rescue = verifier_caught / ft_leaked if ft_leaked else 0.0
    print("\n=== Verifier evaluation ===")
    print(f"Total gold spans:               {total_spans}")
    print(f"FT-leaked (still in masked):    {ft_leaked}")
    print(f"Verifier rescued of those:      {verifier_caught} ({rescue:.1%})")
    print(f"Samples where verifier said NOT ok: {samples_flagged}/{len(records)}")
    print(f"Verifier-reported extras (potential false positives): {verifier_false_pos}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps({
            "val_path": str(args.val),
            "totals": {
                "total_spans": total_spans,
                "ft_leaked": ft_leaked,
                "verifier_rescued": verifier_caught,
                "verifier_rescue_rate": rescue,
                "samples_flagged": samples_flagged,
                "samples": len(records),
                "verifier_false_positives": verifier_false_pos,
            },
            "details": details,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nWrote {args.json_out}")


if __name__ == "__main__":
    _main()
