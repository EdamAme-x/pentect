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


def _load_lenient_har(raw: str) -> dict:
    """Tolerant HAR loader.

    Real-world HAR files land malformed often enough that a hard json.loads
    fails the whole pipeline. This loader tries, in order:
      1. strict json.loads
      2. BOM strip + // and /* */ comments removed + trailing-comma fix
      3. truncate at the last syntactically recoverable entries entry (close
         any open arrays/objects) so a mid-export cutoff still yields data
    """
    try:
        return json.loads(raw)
    except Exception:
        pass

    text = raw.lstrip("\ufeff").strip()
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    try:
        return json.loads(text)
    except Exception:
        pass

    # Salvage: walk balanced braces/brackets and cut at the last complete one.
    depth = 0
    last_ok = -1
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                last_ok = i
    if last_ok > 0:
        try:
            return json.loads(text[: last_ok + 1])
        except Exception:
            pass

    # Last resort: return an empty HAR shell so the caller can keep going.
    return {"log": {"entries": []}}


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
        """Mask a HAR file while preserving its JSON structure.

        Uses the same per-entry routing as mask_har_entries: each HAR entry
        becomes one compact text block that the FT LLM sees as a single
        in-distribution input. The detected sensitive values are then written
        back into every JSON field (url, headers, body, response) that
        contains them, so the returned masked_text is a valid masked HAR JSON.
        """
        if isinstance(har_raw, str):
            data = _load_lenient_har(har_raw)
        else:
            data = json.loads(json.dumps(har_raw))

        raw_entries = (data.get("log", {}) or {}).get("entries", []) or []
        entry_texts = iter_entry_texts(data)

        # Rule anchors come from the full serialized HAR so values that live in
        # response bodies / query strings / anywhere JSON are still caught even
        # when the compact entry text (used only as the LLM's in-distribution
        # input) wouldn't include them.
        rule = next((d for d in self.detectors if isinstance(d, RuleDetector)), None)
        anchors: dict[str, Category] = {}
        if rule is not None:
            rule_source = json.dumps(data, ensure_ascii=False)
            for sp in rule.detect(rule_source):
                anchors.setdefault(rule_source[sp.start:sp.end], sp.category)

        batched_spans = self._detect_all_batch([e.text for e in entry_texts]) if entry_texts else []

        # Collapse per-entry detections + global anchors into one set of
        # (value, category) pairs per entry. Each field inside that entry
        # will be masked by substring replacement against this set, which
        # guarantees cross-field consistency inside the JSON.
        def _fields_of(entry: dict) -> list[tuple[dict, str]]:
            out: list[tuple[dict, str]] = []
            req = entry.get("request", {}) or {}
            res = entry.get("response", {}) or {}
            if isinstance(req.get("url"), str):
                out.append((req, "url"))
            for h in req.get("headers", []) or []:
                if isinstance(h.get("value"), str):
                    out.append((h, "value"))
            for h in res.get("headers", []) or []:
                if isinstance(h.get("value"), str):
                    out.append((h, "value"))
            for q in req.get("queryString", []) or []:
                if isinstance(q.get("value"), str):
                    out.append((q, "value"))
            for c in (req.get("cookies", []) or []) + (res.get("cookies", []) or []):
                if isinstance(c.get("value"), str):
                    out.append((c, "value"))
            post = req.get("postData") or {}
            if isinstance(post.get("text"), str):
                out.append((post, "text"))
            content = res.get("content") or {}
            if isinstance(content.get("text"), str):
                out.append((content, "text"))
            return out

        combined_map: dict[str, dict[str, str]] = {}
        by_category: dict[str, int] = {}

        for idx, entry in enumerate(raw_entries):
            spans = batched_spans[idx] if idx < len(batched_spans) else []
            entry_values: dict[str, Category] = {}
            for sp in spans:
                val = entry_texts[idx].text[sp.start:sp.end]
                entry_values.setdefault(val, sp.category)
            for val, cat in anchors.items():
                entry_values.setdefault(val, cat)

            for target, key in _fields_of(entry):
                text = target[key]
                field_spans: list[Span] = []
                for val, cat in entry_values.items():
                    if not val:
                        continue
                    start = 0
                    while True:
                        hit = text.find(val, start)
                        if hit < 0:
                            break
                        field_spans.append(Span(
                            start=hit, end=hit + len(val),
                            category=cat, source="har",
                        ))
                        start = hit + len(val)
                field_spans = merge(field_spans)
                if not field_spans:
                    continue
                replacements = apply_granularity(text, field_spans)
                target[key] = apply_replacements(text, replacements)

        masked_json = json.dumps(data, ensure_ascii=False, indent=2)
        for m in _PLACEHOLDER_RE.finditer(masked_json):
            ph = m.group(0)
            if ph in combined_map:
                continue
            cat = _guess_category(m.group(1))
            if cat is None:
                combined_map[ph] = {"category": m.group(1), "description": m.group(1)}
                by_category[m.group(1)] = by_category.get(m.group(1), 0) + 1
            else:
                combined_map[ph] = {
                    "category": cat.value,
                    "description": get_spec(cat).description,
                }
                by_category[cat.value] = by_category.get(cat.value, 0) + 1

        return MaskResult(
            masked_text=masked_json,
            map=combined_map,
            summary={"total_masked": len(combined_map), "by_category": by_category},
        )

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
