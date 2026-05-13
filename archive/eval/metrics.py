"""Evaluation metrics.

- Recall: secret value absent from masked_text => detected
- Category agreement rate: detected category matches expected
"""
from __future__ import annotations

from dataclasses import dataclass

from testcases.schema import TestCase


@dataclass
class DetectionResult:
    total: int
    masked: int
    missed: list[str]

    @property
    def recall(self) -> float:
        return self.masked / self.total if self.total else 1.0


def compute_detection(masked_text: str, case: TestCase) -> DetectionResult:
    total = len(case.secrets)
    missed: list[str] = []
    masked = 0
    for s in case.secrets:
        if s.value and s.value in masked_text:
            missed.append(s.value)
        else:
            masked += 1
    return DetectionResult(total=total, masked=masked, missed=missed)


@dataclass
class CategoryAgreement:
    total: int
    agreed: int

    @property
    def rate(self) -> float:
        return self.agreed / self.total if self.total else 1.0


def compute_category_agreement(
    category_map: dict[str, str],  # original value -> detected category
    case: TestCase,
) -> CategoryAgreement:
    agreed = 0
    total = 0
    for s in case.secrets:
        total += 1
        got = category_map.get(s.value)
        if got == s.expected_category:
            agreed += 1
    return CategoryAgreement(total=total, agreed=agreed)
