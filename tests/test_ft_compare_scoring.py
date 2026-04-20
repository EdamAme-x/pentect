"""Regression tests for eval.ft_compare._score.

These pin down the strict substring semantics:
  - A gold span is recalled only if the full span value is a substring of some hit.
  - The reverse direction (hit being a substring of the span) must NOT count.

Without these tests, it's easy to silently regress back to two-directional match,
which inflated Presidio USER_ID from 4.8% to 95.2% during development.
"""
from __future__ import annotations

from eval.ft_compare import _score


def _record(input_text: str, spans: list[tuple[str, str]]) -> dict:
    return {
        "input": input_text,
        "spans": [
            {"start": input_text.find(v), "end": input_text.find(v) + len(v), "value": v, "category": c}
            for v, c in spans
        ],
    }


def test_full_match_counts_as_hit():
    records = [_record("Lucas Martinez opened a ticket", [("Lucas Martinez", "PII_NAME")])]
    hits = [{"Lucas Martinez"}]
    out = _score(records, hits)
    assert out["overall"] == {"hit": 1, "total": 1}


def test_hit_contains_span_counts_as_hit():
    # detector returned a larger span that fully contains the gold — still OK
    records = [_record("Lucas Martinez opened a ticket", [("Lucas Martinez", "PII_NAME")])]
    hits = [{"Lucas Martinez opened"}]
    out = _score(records, hits)
    assert out["overall"] == {"hit": 1, "total": 1}


def test_span_contains_hit_does_NOT_count():
    # detector only caught the first name. Strict scoring rejects this.
    records = [_record("Lucas Martinez opened a ticket", [("Lucas Martinez", "PII_NAME")])]
    hits = [{"Lucas"}]
    out = _score(records, hits)
    assert out["overall"] == {"hit": 0, "total": 1}, (
        "partial match must not count — otherwise a detector that finds 'Lucas' "
        "but leaves 'Martinez' in the masked text would appear to succeed"
    )


def test_no_overlap_misses():
    records = [_record("Lucas Martinez opened a ticket", [("Lucas Martinez", "PII_NAME")])]
    hits = [{"ticket"}]
    out = _score(records, hits)
    assert out["overall"] == {"hit": 0, "total": 1}


def test_per_category_buckets():
    text = "Liam leaked TK-ABCD and visited billing-svc"
    records = [_record(text, [
        ("Liam", "PII_NAME"),
        ("TK-ABCD", "CREDENTIAL"),
        ("billing-svc", "INTERNAL_URL"),
    ])]
    hits = [{"TK-ABCD", "billing-svc"}]  # PII_NAME missed
    out = _score(records, hits)
    assert out["overall"] == {"hit": 2, "total": 3}
    assert out["per_category"]["CREDENTIAL"] == {"hit": 1, "total": 1}
    assert out["per_category"]["INTERNAL_URL"] == {"hit": 1, "total": 1}
    assert out["per_category"]["PII_NAME"] == {"hit": 0, "total": 1}
