from engine.detectors.base import Span
from engine.categories import Category
from engine.merger import merge


def test_overlap_rule_wins_over_llm():
    spans = [
        Span(0, 10, Category.CREDENTIAL, "rule", 1.0),
        Span(0, 10, Category.PII_NAME, "llm", 0.8),
    ]
    out = merge(spans)
    assert len(out) == 1
    assert out[0].source == "rule"


def test_non_overlap_both_kept():
    spans = [
        Span(0, 5, Category.CREDENTIAL, "rule", 1.0),
        Span(10, 20, Category.PII_EMAIL, "llm", 0.8),
    ]
    out = merge(spans)
    assert len(out) == 2
