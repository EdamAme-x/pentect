"""Hybrid detector: Privacy Filter (primary) + Gemma auditor (second opinion).

Design goal: keep the cost profile of Privacy Filter (1.5B, fast) for the bulk
of the work, and only ask the heavier Gemma 4B FT a short audit question per
entry: "did the primary miss anything?"

Cost shape vs. running Gemma standalone:
- Standalone Gemma generates a full JSON span array per entry (~200-400 tokens)
- Auditor generates "[]" or a tiny missed-list (~2-32 tokens) per entry

This is the implementation of the "second opinion" plan that the slides
describe -- not a half-baked OR-merge of two detectors.
"""
from __future__ import annotations

from engine.detectors.base import Span
from engine.detectors.opf_pf import PrivacyFilterDetector


class HybridDetector:
    name = "hybrid"

    def __init__(self) -> None:
        self._primary = PrivacyFilterDetector()
        # Auditor is heavy (loads Gemma 4B). Lazy-load on first detect call so
        # importing the module is cheap.
        self._auditor = None

    def _get_auditor(self):
        if self._auditor is None:
            from engine.detectors.llm_audit import LLMAuditor

            self._auditor = LLMAuditor()
        return self._auditor

    @staticmethod
    def _merge(primary: list[Span], audit: list[Span]) -> list[Span]:
        # Drop any audit spans that exactly overlap a primary span. The primary
        # detector "won" that span; audit is only for missed regions.
        prim_ranges = {(sp.start, sp.end) for sp in primary}
        out = list(primary)
        for sp in audit:
            if (sp.start, sp.end) in prim_ranges:
                continue
            out.append(sp)
        return out

    def detect(self, text: str) -> list[Span]:
        primary = self._primary.detect(text)
        audit = self._get_auditor().audit_batch([text], [primary])[0]
        return self._merge(primary, audit)

    def detect_batch(self, texts: list[str]) -> list[list[Span]]:
        primary_per = self._primary.detect_batch(texts)
        audit_per = self._get_auditor().audit_batch(texts, primary_per)
        return [self._merge(p, a) for p, a in zip(primary_per, audit_per)]
