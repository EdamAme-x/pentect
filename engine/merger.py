"""Merge detector outputs with conflict resolution.

Priority rules:
- Pentest categories win over PII: CREDENTIAL/INTERNAL_URL/INTERNAL_IP/USER_ID > PII_EMAIL/PII_NAME
- Same range, same category: rule > llm
"""
from __future__ import annotations

from engine.categories import Category
from engine.detectors.base import Span


_PENTEST_CATEGORIES = {
    Category.CREDENTIAL,
    Category.INTERNAL_URL,
    Category.INTERNAL_IP,
    Category.USER_ID,
}

_SOURCE_PRIORITY = {"rule": 3, "llm": 2}


def _overlaps(a: Span, b: Span) -> bool:
    return a.start < b.end and b.start < a.end


def _score(span: Span) -> tuple[int, int, int]:
    """Higher score wins. Returns (is_pentest_category, source_priority, length)."""
    pent = 1 if span.category in _PENTEST_CATEGORIES else 0
    src = _SOURCE_PRIORITY.get(span.source, 0)
    length = span.end - span.start
    return (pent, src, length)


def merge(spans: list[Span]) -> list[Span]:
    # sort by length desc, then score desc
    spans = sorted(spans, key=lambda s: (-(s.end - s.start), -_score(s)[0], -_score(s)[1]))

    accepted: list[Span] = []
    for s in spans:
        conflict = False
        for a in accepted:
            if _overlaps(a, s):
                if _score(s) > _score(a):
                    accepted.remove(a)
                    accepted.append(s)
                conflict = True
                break
        if not conflict:
            accepted.append(s)

    return sorted(accepted, key=lambda s: s.start)
