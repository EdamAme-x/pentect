"""Orchestration layer for the Pentect masking engine.

Accepts HAR or plain text and runs: parse → detect → merge → granularity → output.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from engine.categories import Category, get_spec
from engine.detectors.base import Detector, Span
from engine.detectors.rule import RuleDetector
from engine.granularity import apply_granularity, apply_replacements
from engine.merger import merge
from engine.parsers.har import parse_har


@dataclass
class MaskResult:
    masked_text: str
    map: dict[str, dict[str, str]] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(
            {"masked_text": self.masked_text, "map": self.map, "summary": self.summary},
            ensure_ascii=False,
            indent=2,
        )


_PLACEHOLDER_RE = re.compile(r"<<([A-Z_]+)_([a-f0-9]{8})>>")


class PentectEngine:
    def __init__(
        self,
        detectors: list[Detector] | None = None,
        *,
        use_llm: bool = False,
    ) -> None:
        if detectors is not None:
            self.detectors: list[Detector] = detectors
        else:
            self.detectors = [RuleDetector()]
            if use_llm:
                from engine.detectors.llm import LLMDetector

                self.detectors.append(LLMDetector())

    def _detect_all(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for d in self.detectors:
            spans.extend(d.detect(text))
        return merge(spans)

    def mask_text(self, text: str) -> MaskResult:
        spans = self._detect_all(text)
        replacements = apply_granularity(text, spans)
        masked = apply_replacements(text, replacements)
        return _build_result(masked, replacements)

    def mask_har(self, har_raw: str | dict) -> MaskResult:
        """Accept a HAR JSON string or dict and mask it.

        PoC: stringifies and scans the whole HAR as text.
        """
        if isinstance(har_raw, dict):
            text = json.dumps(har_raw, ensure_ascii=False)
        else:
            # validate by parsing, then use raw string
            parse_har(har_raw)
            text = har_raw
        return self.mask_text(text)


def _build_result(masked_text: str, replacements) -> MaskResult:
    mapping: dict[str, dict[str, str]] = {}
    by_category: dict[str, int] = {}

    for m in _PLACEHOLDER_RE.finditer(masked_text):
        placeholder = m.group(0)
        label = m.group(1)
        if placeholder in mapping:
            continue
        category = _guess_category(label)
        if category is None:
            mapping[placeholder] = {"category": label, "description": label}
            by_category[label] = by_category.get(label, 0) + 1
        else:
            mapping[placeholder] = {
                "category": category.value,
                "description": get_spec(category).description,
            }
            by_category[category.value] = by_category.get(category.value, 0) + 1

    return MaskResult(
        masked_text=masked_text,
        map=mapping,
        summary={
            "total_masked": len(mapping),
            "by_category": by_category,
        },
    )


def _guess_category(label: str) -> Category | None:
    # try matching progressively shorter prefixes (e.g. INTERNAL_URL_HOST)
    parts = label.split("_")
    for n in range(len(parts), 0, -1):
        head = "_".join(parts[:n])
        if head in Category.__members__:
            return Category[head]
    return None
