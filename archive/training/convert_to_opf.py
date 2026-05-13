"""Pentect の span jsonl を OpenAI Privacy Filter の学習/評価形式に変換。

入力形式 (Pentect):
    {"input": "...", "spans": [{"start": 0, "end": 5, "value": "...", "category": "PII_NAME"}]}

出力形式 (opf):
    {"text": "...", "spans": {"label: text": [[start, end]]}, "info": {...}}

ラベル方針: 既存 opf の 8 ラベルに寄せて、ペンテスト特化の 2 つだけ新規追加。
vanilla で既に 90%+ 取れてる既存カテゴリを活かしつつ、弱い INTERNAL_URL/IP を強化。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


CATEGORY_TO_OPF = {
    "CREDENTIAL": "secret",
    "PII_EMAIL": "private_email",
    "PII_NAME": "private_person",
    "USER_ID": "account_number",  # 数値 ID、opf の既存 account_number に寄せる
    "INTERNAL_URL": "internal_url",  # 新規
    "INTERNAL_IP": "internal_ip",    # 新規
}


def convert(in_path: Path, out_path: Path) -> tuple[int, dict[str, int]]:
    n = 0
    by_label: dict[str, int] = {}
    with in_path.open("r", encoding="utf-8") as fin, out_path.open("w", encoding="utf-8") as fout:
        for line in fin:
            rec = json.loads(line)
            text = rec["input"]
            spans_dict: dict[str, list[list[int]]] = {}
            for sp in rec.get("spans", []):
                cat = sp["category"]
                label = CATEGORY_TO_OPF.get(cat)
                if label is None:
                    continue
                key = f"{label}: {sp['value']}"
                spans_dict.setdefault(key, []).append([sp["start"], sp["end"]])
                by_label[label] = by_label.get(label, 0) + 1
            out = {
                "text": text,
                "spans": spans_dict,
                "info": {"id": f"pentect_{n}", "source": "pentect"},
            }
            fout.write(json.dumps(out, ensure_ascii=False) + "\n")
            n += 1
    return n, by_label


def write_label_space(out_path: Path) -> None:
    # 既存 8 + 独自 2。"O" は先頭必須。
    span_classes = [
        "O",
        "account_number",
        "private_address",
        "private_date",
        "private_email",
        "private_person",
        "private_phone",
        "private_url",
        "secret",
        "internal_url",
        "internal_ip",
    ]
    out_path.write_text(json.dumps({
        "category_version": "pentect_v1",
        "span_class_names": span_classes,
    }, indent=2) + "\n", encoding="utf-8")


def _main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", type=Path, default=Path("training/data/opf"))
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    pairs = [
        (Path("training/data/train.jsonl"), args.out_dir / "train.jsonl"),
        (Path("training/data/hard_val.jsonl"), args.out_dir / "hard_val.jsonl"),
    ]
    for src, dst in pairs:
        n, by = convert(src, dst)
        print(f"{src} -> {dst}: {n} records")
        for k, v in sorted(by.items()):
            print(f"  {k:20s} {v}")

    ls = args.out_dir / "label_space.json"
    write_label_space(ls)
    print(f"\nwrote label space: {ls}")


if __name__ == "__main__":
    _main()
