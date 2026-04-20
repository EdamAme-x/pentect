"""Pentect end-to-end demo: real HAR -> mask -> vulnerability identification.

Flow:
  1. Load demo/juice/captured.har (Juice Shop pentest trace, Host=juice-shop.local)
  2. Extract a compact per-request summary (method, url, body, auth, response status)
  3. Produce two views of the summary:
       A. raw           -- nothing redacted, contains JWTs, admin email, host
       B. pentect-mask  -- same summary but piped through PentectEngine.mask_text
  4. Build an identical prompt for each view asking "what vulnerabilities are
     in this HAR summary?"
  5. If ANTHROPIC_API_KEY is set AND --api is passed, send both prompts to
     Claude and print the two lists side-by-side. Otherwise (default) just
     dump the two prompts to stdout + files so the user can paste them
     anywhere (web UI, another model, etc) and compare manually.

The point of the demo is: if the Pentect-masked version still lets the LLM
identify the same vulnerabilities, then Pentect succeeded -- sensitive values
are removed but the analytic signal survives.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

# Allow running as a script without -m
import sys
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.core import PentectEngine


HAR = Path(__file__).parent / "captured.har"
OUT_RAW = Path(__file__).parent / "raw_summary.txt"
OUT_MASKED = Path(__file__).parent / "masked_summary.txt"
OUT_PROMPT_RAW = Path(__file__).parent / "prompt_raw.txt"
OUT_PROMPT_MASKED = Path(__file__).parent / "prompt_masked.txt"
OUT_COMPARE = Path(__file__).parent / "compare.md"


SYSTEM_PROMPT = """You are a security reviewer. You will be given a compact HAR summary
(a list of HTTP requests a pentester captured against a single target). List the
specific vulnerabilities you can identify from this trace.

For each finding, output:
- title (short, e.g. "SQL injection in login")
- evidence (the exact line or request that shows it)
- severity (info/low/medium/high/critical)
- brief explanation

Use a numbered list. Only include findings you can actually point to in the
trace. Do not speculate about things that are not in the trace."""


INTERESTING = (
    "api/", "rest/", "ftp/", "login", "whoami",
    "search", "Users", "Feedbacks", "Baskets", "Basket",
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
        if body_text and len(body_text) < 500 and any(
            k in body_text.lower() for k in ("error", "sqlite", "email", "admin", "token")
        ):
            lines.append(f"  resp: {body_text[:400]}")
    # Dedup noisy identical rows
    seen: set[str] = set()
    out: list[str] = []
    for ln in lines:
        if ln in seen:
            continue
        seen.add(ln)
        out.append(ln)
    return "\n".join(out)


def _split_summary_blocks(summary: str) -> list[str]:
    """Split a filtered summary back into per-request blocks.

    A block starts at an HTTP method line and includes any indented
    continuation rows (body/header/response) until the next method line.
    """
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
    """Mask each block independently, keeping cross-block consistency.

    Strategy:
      1. Run rule detector across the full joined text to fix anchors
         (internal hosts, JWTs, IPs) that every block agrees on.
      2. Run detect_batch on the individual blocks so the FT model sees
         inputs that match its training distribution (one request each).
      3. Merge anchors into each block's spans before applying granularity.
    """
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


def _call_claude(prompt: str) -> str:
    import anthropic  # type: ignore

    client = anthropic.Anthropic()
    resp = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", action="store_true",
                    help="Actually call Claude (requires ANTHROPIC_API_KEY). "
                         "Default: write prompts to disk and stop.")
    ap.add_argument("--no-ft", action="store_true",
                    help="Skip the FT Gemma LLM detector (use rule-only). "
                         "Useful when the adapter is currently being retrained.")
    args = ap.parse_args()

    print(f">>> extracting summary from {HAR.name}")
    raw_summary = _extract_summary(HAR)
    OUT_RAW.write_text(raw_summary, encoding="utf-8")
    print(f"    wrote {OUT_RAW}  ({len(raw_summary)} chars)")

    if args.no_ft:
        print(">>> masking summary with Pentect (RULE ONLY, --no-ft)")
        engine = PentectEngine(use_llm=False)
    else:
        print(">>> masking summary with Pentect (rule + FT Gemma, per-entry)")
        os.environ.setdefault("PENTECT_LLM_ADAPTER", "training/runs/gemma3_4b_lora")
        os.environ.setdefault("PENTECT_LLM_4BIT", "1")
        engine = PentectEngine(use_llm=True)
    # Per-entry path: split the filtered summary into its individual request
    # blocks and mask each independently. Each block is short (in-distribution
    # for the FT model) and cross-block consistency is preserved via
    # SHA-derived placeholders plus a global rule-anchor pass.
    blocks = _split_summary_blocks(raw_summary)
    print(f">>> masking {len(blocks)} entry blocks in one batch")
    masked_text = _mask_blocks(engine, blocks)
    OUT_MASKED.write_text(masked_text, encoding="utf-8")
    placeholder_count = len(set(re.findall(r"<<[A-Z_]+_[a-f0-9]{8}>>", masked_text)))
    print(f"    wrote {OUT_MASKED}  ({len(masked_text)} chars, "
          f"{placeholder_count} unique placeholders)")

    prompt_raw = _build_prompt(raw_summary, "raw, unmasked")
    prompt_masked = _build_prompt(masked_text, "pentect-masked")
    OUT_PROMPT_RAW.write_text(prompt_raw, encoding="utf-8")
    OUT_PROMPT_MASKED.write_text(prompt_masked, encoding="utf-8")
    print(f"    wrote {OUT_PROMPT_RAW}")
    print(f"    wrote {OUT_PROMPT_MASKED}")

    if not args.api:
        print("\n--- dry-run complete ---")
        print("To run both against Claude and compare:")
        print("  pip install anthropic")
        print("  export ANTHROPIC_API_KEY=...")
        print("  python demo/juice/identify_vulns.py --api")
        return

    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("ANTHROPIC_API_KEY is not set")

    print("\n>>> calling Claude on RAW prompt ...")
    ans_raw = _call_claude(prompt_raw)
    print("\n>>> calling Claude on MASKED prompt ...")
    ans_masked = _call_claude(prompt_masked)

    report = (
        "# Pentect end-to-end demo: vulnerability identification\n\n"
        f"Source HAR: `{HAR.name}`  ({placeholder_count} unique placeholders inserted)\n\n"
        "## Vulns found from RAW (unmasked) trace\n\n"
        f"{ans_raw}\n\n"
        "## Vulns found from PENTECT-MASKED trace\n\n"
        f"{ans_masked}\n"
    )
    OUT_COMPARE.write_text(report, encoding="utf-8")
    print(f"\nwrote {OUT_COMPARE}")


if __name__ == "__main__":
    main()
