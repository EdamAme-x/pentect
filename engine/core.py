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
from engine.parsers.har import HarEntryText, iter_entry_texts, parse_har


@dataclass
class MaskResult:
    masked_text: str
    map: dict[str, dict[str, str]] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    verifier: dict[str, Any] | None = None  # set when a Verifier ran

    def to_json(self) -> str:
        payload: dict[str, Any] = {
            "masked_text": self.masked_text,
            "map": self.map,
            "summary": self.summary,
        }
        if self.verifier is not None:
            payload["verifier"] = self.verifier
        return json.dumps(payload, ensure_ascii=False, indent=2)


@dataclass
class HarEntryMaskResult:
    masked_text: str  # all entries joined (for convenience / compare diffs)
    map: dict[str, dict[str, str]] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    entries: list[dict[str, Any]] = field(default_factory=list)  # per-entry masked


_PLACEHOLDER_RE = re.compile(r"<<([A-Z_]+)_([a-f0-9]{8})>>")


class PentectEngine:
    def __init__(
        self,
        detectors: list[Detector] | None = None,
        *,
        use_llm: bool = False,
        use_verifier: bool = False,
    ) -> None:
        if detectors is not None:
            self.detectors: list[Detector] = detectors
        else:
            self.detectors = [RuleDetector()]
            if use_llm:
                from engine.detectors.llm import LLMDetector

                self.detectors.append(LLMDetector())

        self._verifier = None
        if use_verifier:
            from engine.verifier import QwenVerifier

            self._verifier = QwenVerifier()

    def _detect_all(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for d in self.detectors:
            spans.extend(d.detect(text))
        return merge(spans)

    def _detect_all_batch(self, texts: list[str]) -> list[list[Span]]:
        """Run all detectors over a batch, returning one span list per input.

        Uses detect_batch where supported (LLMDetector) so the FT model runs
        a single padded batch instead of N sequential forward passes.
        """
        per_text: list[list[Span]] = [[] for _ in texts]
        for d in self.detectors:
            batch_fn = getattr(d, "detect_batch", None)
            if callable(batch_fn):
                batched = batch_fn(texts)
                for i, spans in enumerate(batched):
                    per_text[i].extend(spans)
            else:
                for i, t in enumerate(texts):
                    per_text[i].extend(d.detect(t))
        return [merge(s) for s in per_text]

    def mask_text(self, text: str) -> MaskResult:
        spans = self._detect_all(text)
        replacements = apply_granularity(text, spans)
        masked = apply_replacements(text, replacements)
        result = _build_result(masked, replacements)
        if self._verifier is not None:
            report = self._verifier.verify(masked)
            result.verifier = {
                "ok": report.ok,
                "leaks": report.leaks,
                "model": self._verifier.name,
            }
        return result

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

    def mask_har_entries(self, har_raw: str | dict) -> "HarEntryMaskResult":
        """Per-entry masking path.

        For each HAR entry, render it as a compact text block (method+url+auth+
        response) and mask it independently. Cross-entry consistency is
        preserved automatically because placeholders are SHA-derived from the
        underlying value: the same JWT or internal host collapses to the same
        placeholder in every entry. A global rule pass across the full HAR is
        also taken to anchor values that per-entry inputs might miss.
        """
        entries = iter_entry_texts(har_raw)
        full_text = "\n".join(e.text for e in entries)

        # Global anchors: rule detector across the entire HAR. This fixes
        # high-confidence values (internal hosts, JWTs, IPs) so they are
        # masked consistently even if the per-entry LLM pass misses one.
        rule = next((d for d in self.detectors if isinstance(d, RuleDetector)), None)
        anchors: dict[str, Category] = {}
        if rule is not None:
            for sp in rule.detect(full_text):
                value = full_text[sp.start:sp.end]
                anchors.setdefault(value, sp.category)

        entry_texts = [e.text for e in entries]
        batched_spans = self._detect_all_batch(entry_texts)

        per_entry: list[dict[str, Any]] = []
        all_masked_chunks: list[str] = []
        for e, spans in zip(entries, batched_spans):
            for val, cat in anchors.items():
                if not val:
                    continue
                start = 0
                while True:
                    idx = e.text.find(val, start)
                    if idx < 0:
                        break
                    spans.append(Span(
                        start=idx, end=idx + len(val),
                        category=cat, source="anchor",
                    ))
                    start = idx + len(val)
            spans = merge(spans)
            replacements = apply_granularity(e.text, spans)
            masked = apply_replacements(e.text, replacements)
            per_entry.append({"index": e.index, "masked": masked})
            all_masked_chunks.append(masked)

        combined = "\n".join(all_masked_chunks)
        result = _build_result(combined, [])
        return HarEntryMaskResult(
            masked_text=combined,
            map=result.map,
            summary=result.summary,
            entries=per_entry,
        )


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
