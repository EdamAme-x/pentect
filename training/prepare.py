"""Convert (input + spans) JSONL into instruction-tuning format."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


INSTRUCTION = (
    "Detect sensitive spans in the following text and output a JSON array of objects with "
    "fields 'span' (the exact substring) and 'category' (one of CREDENTIAL, INTERNAL_URL, "
    "INTERNAL_IP, PII_EMAIL, PII_NAME, USER_ID)."
)


def convert(line: dict) -> dict:
    out = [
        {"span": s["value"], "category": s["category"]}
        for s in line.get("spans", [])
    ]
    return {
        "instruction": INSTRUCTION,
        "input": line["input"],
        "output": json.dumps(out, ensure_ascii=False),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with args.inp.open("r", encoding="utf-8") as f, args.out.open("w", encoding="utf-8") as g:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = convert(json.loads(line))
            g.write(json.dumps(rec, ensure_ascii=False) + "\n")
            count += 1
    print(f"converted {count} samples -> {args.out}")


if __name__ == "__main__":
    main()
