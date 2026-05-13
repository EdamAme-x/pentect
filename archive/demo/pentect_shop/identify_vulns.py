"""Pentect Shop end-to-end demo (mirror of demo/juice/identify_vulns.py).

Same flow:
  1. Load demo/pentect_shop/captured.har
  2. Extract a compact per-request summary
  3. Mask it with PentectEngine (rule + opf_pf by default)
  4. Build raw + masked Claude prompts
  5. Optionally call Claude (--api), otherwise dump prompts to disk
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.core import PentectEngine


HAR = Path(__file__).parent / "captured.har"
OUT_RAW = Path(__file__).parent / "raw_summary.txt"
OUT_PROMPT_RAW = Path(__file__).parent / "prompt_raw.txt"


def _masked_paths(backend: str) -> tuple[Path, Path, Path]:
    base = Path(__file__).parent
    s = f"_{backend}"
    return (
        base / f"masked_summary{s}.txt",
        base / f"prompt_masked{s}.txt",
        base / f"compare{s}.md",
    )


SYSTEM_PROMPT = """You are a security reviewer. You will be given a compact HAR summary
(a list of HTTP requests a pentester captured against a single target). List the
specific vulnerabilities you can identify from this trace.

For each finding, output:
- title (short, e.g. "SQL injection in search")
- evidence (the exact line or request that shows it)
- severity (info/low/medium/high/critical)
- brief explanation

Use a numbered list. Only include findings you can actually point to in the
trace. Do not speculate about things that are not in the trace."""


# Lines we care about (mirror Juice settings, but adjusted for pentect_shop paths).
INTERESTING = (
    "api/", "backup",
)


def _is_interesting(url: str) -> bool:
    return any(k in url for k in INTERESTING)


def _extract_summary(har_path: Path) -> str:
    har = json.loads(har_path.read_text(encoding="utf-8"))
    lines: list[str] = []
    for e in har["log"]["entries"]:
        req = e["request"]
        url = req["url"]
        if not _is_interesting(url):
            continue
        lines.append(f"{req['method']} {url}")
        body = (req.get("postData") or {}).get("text")
        if body:
            lines.append(f"  body: {body[:400]}")
        for h in req.get("headers", []):
            n = h["name"].lower()
            if n in ("authorization", "cookie"):
                lines.append(f"  {h['name']}: {h['value'][:300]}")
        resp = e.get("response") or {}
        status = resp.get("status")
        st_txt = resp.get("statusText", "")
        if status:
            lines.append(f"  -> {status} {st_txt}".rstrip())
        body_text = (resp.get("content") or {}).get("text") or ""
        if body_text and len(body_text) < 600 and any(
            k in body_text.lower() for k in ("error", "trace", "email", "admin", "token", "password", "role")
        ):
            lines.append(f"  resp: {body_text[:400]}")
    seen: set[str] = set()
    out: list[str] = []
    for ln in lines:
        if ln in seen:
            continue
        seen.add(ln)
        out.append(ln)
    return "\n".join(out)


def _split_summary_blocks(summary: str) -> list[str]:
    method_re = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s")
    blocks: list[str] = []
    cur: list[str] = []
    for line in summary.splitlines():
        if method_re.match(line):
            if cur:
                blocks.append("\n".join(cur))
            cur = [line]
        else:
            if cur:
                cur.append(line)
    if cur:
        blocks.append("\n".join(cur))
    return blocks


def _mask_blocks(engine, blocks: list[str]) -> str:
    from engine.detectors.base import Span
    from engine.detectors.rule import RuleDetector
    from engine.granularity import apply_granularity, apply_replacements
    from engine.merger import merge

    joined = "\n".join(blocks)
    rule = next((d for d in engine.detectors if isinstance(d, RuleDetector)), None)
    anchors: dict[str, object] = {}
    if rule is not None:
        for sp in rule.detect(joined):
            anchors.setdefault(joined[sp.start:sp.end], sp.category)

    per_block_spans = engine._detect_all_batch(blocks)

    masked_blocks: list[str] = []
    for block, spans in zip(blocks, per_block_spans):
        for val, cat in anchors.items():
            if not val:
                continue
            start = 0
            while True:
                idx = block.find(val, start)
                if idx < 0:
                    break
                spans.append(Span(
                    start=idx, end=idx + len(val),
                    category=cat, source="anchor",
                ))
                start = idx + len(val)
        spans = merge(spans)
        replacements = apply_granularity(block, spans)
        masked_blocks.append(apply_replacements(block, replacements))
    return "\n".join(masked_blocks)


def _build_prompt(summary: str, label: str) -> str:
    return f"""{SYSTEM_PROMPT}

HAR summary ({label}):
---
{summary}
---
"""


def _build_engine(backend: str) -> PentectEngine:
    if backend == "rule":
        return PentectEngine(backend="rule")
    if backend == "opf_pf":
        os.environ.setdefault(
            "PENTECT_PF_CHECKPOINT", "training/runs/opf_pentect_v4_e3"
        )
        return PentectEngine(backend="opf_pf")
    if backend == "gemma":
        os.environ.setdefault("PENTECT_LLM_ADAPTER", "training/runs/gemma3_4b_lora")
        os.environ.setdefault("PENTECT_LLM_4BIT", "1")
        return PentectEngine(backend="gemma")
    raise ValueError(backend)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="opf_pf",
                    choices=["rule", "gemma", "opf_pf"])
    args = ap.parse_args()

    out_masked, out_prompt_masked, _ = _masked_paths(args.backend)

    raw_summary = _extract_summary(HAR)
    OUT_RAW.write_text(raw_summary, encoding="utf-8")
    print(f"raw -> {OUT_RAW} ({len(raw_summary)} chars)")

    engine = _build_engine(args.backend)
    blocks = _split_summary_blocks(raw_summary)
    masked_text = _mask_blocks(engine, blocks)
    out_masked.write_text(masked_text, encoding="utf-8")
    placeholders = len(set(re.findall(r"<<[A-Z_]+_[a-f0-9]{8}>>", masked_text)))
    print(f"masked -> {out_masked} ({len(masked_text)} chars, {placeholders} placeholders)")

    OUT_PROMPT_RAW.write_text(_build_prompt(raw_summary, "raw, unmasked"), encoding="utf-8")
    out_prompt_masked.write_text(_build_prompt(masked_text, f"pentect-masked ({args.backend})"), encoding="utf-8")
    print(f"prompts -> {OUT_PROMPT_RAW}, {out_prompt_masked}")


if __name__ == "__main__":
    main()
