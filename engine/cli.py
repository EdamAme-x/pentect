"""Command-line entrypoint: mask a HAR or text from stdin/file."""
from __future__ import annotations

import argparse
import json
import sys

from engine.core import PentectEngine


def main() -> None:
    ap = argparse.ArgumentParser(prog="pentect", description="Mask sensitive values in HAR or text.")
    ap.add_argument("input", nargs="?", help="Input file path. Reads stdin if omitted.")
    ap.add_argument("--text", action="store_true", help="Treat input as plain text (default: HAR).")
    ap.add_argument("--llm", action="store_true", help="Enable LLM detector.")
    args = ap.parse_args()

    raw = open(args.input, "r", encoding="utf-8").read() if args.input else sys.stdin.read()

    engine = PentectEngine(use_llm=args.llm)
    result = engine.mask_text(raw) if args.text else engine.mask_har(raw)

    json.dump(
        {"masked_text": result.masked_text, "map": result.map, "summary": result.summary},
        sys.stdout,
        ensure_ascii=False,
        indent=2,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
