"""Simple context-preservation check.

Keyword substring matching (PoC). Interface allows future replacement with LLM-as-judge.
"""
from __future__ import annotations

from dataclasses import dataclass

from testcases.schema import ContextPreservation


@dataclass
class ContextCheckResult:
    prompt: str
    matched: list[str]
    min_match: int

    @property
    def passed(self) -> bool:
        return len(self.matched) >= self.min_match


def keyword_match(masked_text: str, expect: ContextPreservation) -> ContextCheckResult:
    matched = [kw for kw in expect.expected_keywords if kw in masked_text]
    return ContextCheckResult(prompt=expect.prompt, matched=matched, min_match=expect.min_match)
