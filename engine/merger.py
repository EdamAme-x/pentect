"""Merge detector outputs with conflict resolution.

Priority rules (highest first):
- Source priority: rule > opf_pf / hybrid > llm
  Rules use exact regex patterns, so when a rule matches a span we trust its
  category over a learned classifier's. This stops e.g. opf_pf labelling
  `alice@corp.example` as INTERNAL_IP from beating the rule's PII_EMAIL.
- Pentest categories win over PII when sources tie:
  CREDENTIAL / INTERNAL_URL / INTERNAL_IP / USER_ID > PII_EMAIL / PII_NAME
- Longer span wins as a final tie-breaker.
"""
from __future__ import annotations

from engine.categories import Category
from engine.detectors.base import Span


_PENTEST_CATEGORIES = {
    Category.CREDENTIAL,
    Category.INTERNAL_URL,
    Category.INTERNAL_IP,
    Category.EXTERNAL_IP,
    Category.USER_ID,
    Category.RESOURCE_ID,
}

# Higher number = wins on conflict.
_SOURCE_PRIORITY = {
    "rule": 3,
    "anchor": 3,    # rule-derived global anchors (engine.core)
    "har": 3,       # rule-derived HAR-field anchors (engine.core)
    "detect_secrets": 3,  # vendor regexes from the detect-secrets project
    "hybrid": 2,
    "opf_pf": 2,
    "llm": 2,
    "llm_audit": 1,
}


def _overlaps(a: Span, b: Span) -> bool:
    return a.start < b.end and b.start < a.end


def _score(span: Span) -> tuple[int, int, int]:
    """Higher score wins. Returns (source_priority, is_pentest_category, length)."""
    src = _SOURCE_PRIORITY.get(span.source, 0)
    pent = 1 if span.category in _PENTEST_CATEGORIES else 0
    length = span.end - span.start
    return (src, pent, length)


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
