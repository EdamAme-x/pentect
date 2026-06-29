#!/usr/bin/env python3
"""Minimal Pentect model-adapter example.

This is not a production NER model. Replace `detect()` with a local model call
that returns UTF-8 byte spans, then keep the same stdin/stdout protocol.
"""

import json
import re
import sys


PERSON_LIKE = re.compile(r"\b[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\b")


def byte_span(text: str, start: int, end: int) -> tuple[int, int]:
    return len(text[:start].encode("utf-8")), len(text[:end].encode("utf-8"))


def detect(text: str) -> list[dict[str, object]]:
    spans: list[dict[str, object]] = []
    for match in PERSON_LIKE.finditer(text):
        start, end = byte_span(text, match.start(), match.end())
        spans.append(
            {
                "start": start,
                "end": end,
                "label": "PERSON_NAME",
                "category": "pii",
                "confidence": "medium",
            }
        )
    return spans


def main() -> int:
    request = json.load(sys.stdin)
    text = request.get("text")
    if not isinstance(text, str):
        print(json.dumps({"spans": []}, separators=(",", ":")))
        return 0
    print(json.dumps({"spans": detect(text)}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
