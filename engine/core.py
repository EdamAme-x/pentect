"""Orchestration layer for the Pentect masking engine.

Accepts HAR or plain text and runs: parse → detect → merge → granularity → output.
"""
from __future__ import annotations

import json
import os
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
    # placeholder -> original value. Lives in process memory only; never
    # serialized, never logged through repr. Used by .recover() so a local
    # caller can pull the real value back when (and only when) it needs to
    # show it to a human or hand it to a downstream tool that stays local.
    _recovery_map: dict[str, str] = field(default_factory=dict, repr=False, compare=False)

    def to_json(self) -> str:
        payload: dict[str, Any] = {
            "masked_text": self.masked_text,
            "map": self.map,
            "summary": self.summary,
        }
        if self.verifier is not None:
            payload["verifier"] = self.verifier
        return json.dumps(payload, ensure_ascii=False, indent=2)

    def recover(self, placeholder: str) -> str | None:
        """Return the original value behind a single placeholder, or None.

        Intended for local-only use: callers should not forward the result
        to a remote service. The recovery map is kept out of to_json() and
        out of repr() to make accidental leakage harder.
        """
        return self._recovery_map.get(placeholder)

    def recover_all(self, text: str) -> str:
        """Replace every known placeholder in `text` with its original value.

        Same caveat as .recover(): never feed the output back to a remote
        service. This is for ground-truth viewing on the local machine
        (e.g., a final report displayed to the analyst).
        """
        if not self._recovery_map:
            return text
        # Replace longer placeholders first to avoid prefix collisions.
        out = text
        for ph in sorted(self._recovery_map, key=len, reverse=True):
            out = out.replace(ph, self._recovery_map[ph])
        return out


@dataclass
class HarEntryMaskResult:
    masked_text: str  # all entries joined (for convenience / compare diffs)
    map: dict[str, dict[str, str]] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    entries: list[dict[str, Any]] = field(default_factory=list)  # per-entry masked
    _recovery_map: dict[str, str] = field(default_factory=dict, repr=False, compare=False)

    def recover(self, placeholder: str) -> str | None:
        return self._recovery_map.get(placeholder)

    def recover_all(self, text: str) -> str:
        if not self._recovery_map:
            return text
        out = text
        for ph in sorted(self._recovery_map, key=len, reverse=True):
            out = out.replace(ph, self._recovery_map[ph])
        return out


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
    """Pentect masking engine.

    Backends (controlled by `backend=` or env `PENTECT_DETECTOR_BACKEND`):
      - "rule"   : RuleDetector only (lightweight, no model loaded)
      - "gemma"  : RuleDetector + Gemma 3 4B FT (the original LLMDetector)
      - "opf_pf" : RuleDetector + Privacy Filter FT (fast, 1.5B MoE)
      - "hybrid" : RuleDetector + Privacy Filter + Gemma "second opinion"

    `use_llm=True` is a legacy alias for backend="gemma".
    """

    def __init__(
        self,
        detectors: list[Detector] | None = None,
        *,
        use_llm: bool = False,
        use_verifier: bool = False,
        backend: str | None = None,
    ) -> None:
        if detectors is not None:
            self.detectors: list[Detector] = detectors
            self.backend = "custom"
        else:
            chosen = backend or os.environ.get("PENTECT_DETECTOR_BACKEND")
            if chosen is None:
                chosen = "gemma" if use_llm else "rule"
            self.backend = chosen
            self.detectors = [RuleDetector()]
            # Always run detect-secrets plugin regexes alongside our own
            # rules. They add coverage for vendor token formats Pentect
            # otherwise wouldn't know (Stripe / Twilio / SendGrid / Discord
            # / private keys / Basic auth / Azure / npm / pypi / square /
            # telegram). We skip it silently if the package isn't available
            # so existing minimum installs still work.
            try:
                from engine.detectors.detect_secrets_plugins import (
                    DetectSecretsPluginDetector,
                )
                self.detectors.append(DetectSecretsPluginDetector())
            except RuntimeError:
                pass
            if chosen == "rule":
                pass
            elif chosen == "gemma":
                from engine.detectors.llm import LLMDetector

                self.detectors.append(LLMDetector())
            elif chosen == "opf_pf":
                from engine.detectors.opf_pf import PrivacyFilterDetector

                self.detectors.append(PrivacyFilterDetector())
            elif chosen == "hybrid":
                from engine.detectors.hybrid import HybridDetector

                self.detectors.append(HybridDetector())
            else:
                raise ValueError(
                    f"unknown backend {chosen!r} (expected: rule|gemma|opf_pf|hybrid)"
                )

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
        combined_recovery: dict[str, str] = {}

        for idx, entry in enumerate(raw_entries):
            spans = batched_spans[idx] if idx < len(batched_spans) else []
            entry_values: dict[str, Category] = {}
            for sp in spans:
                val = entry_texts[idx].text[sp.start:sp.end]
                entry_values.setdefault(val, sp.category)
            for val, cat in anchors.items():
                entry_values.setdefault(val, cat)

            all_replacements = []
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
                all_replacements.extend(replacements)

            # Build a per-entry recovery map by reusing the same logic the
            # plain-text path uses. This stays inside the loop so we don't
            # accumulate a giant combined map; cross-entry recoveries land
            # in `combined_recovery` below.
            entry_recovery: dict[str, str] = {}
            for r in all_replacements:
                # straight 1:1 replacement (entire span -> single placeholder)
                if r.replacement.startswith("<<") and r.replacement.endswith(">>"):
                    entry_recovery.setdefault(r.replacement, r.original)
            _recover_split_url(all_replacements, entry_recovery)
            _recover_split_email(all_replacements, entry_recovery)
            _recover_credential_prefix(all_replacements, entry_recovery)
            for ph, original in entry_recovery.items():
                combined_recovery.setdefault(ph, original)

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
            _recovery_map=combined_recovery,
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
        all_replacements = []
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
            all_replacements.extend(replacements)

        combined = "\n".join(all_masked_chunks)
        result = _build_result(combined, all_replacements)
        return HarEntryMaskResult(
            masked_text=combined,
            map=result.map,
            summary=result.summary,
            entries=per_entry,
            _recovery_map=result._recovery_map,
        )


def _build_result(masked_text: str, replacements) -> MaskResult:
    mapping: dict[str, dict[str, str]] = {}
    by_category: dict[str, int] = {}

    # Collect placeholder -> original value pairs from the replacements that
    # actually fired in this pass. Two replacements may produce the same
    # placeholder (same value, same category) -- they collapse to one entry,
    # which is what we want.
    recovery_map: dict[str, str] = {}
    for r in replacements or ():
        for m in _PLACEHOLDER_RE.finditer(r.replacement):
            ph = m.group(0)
            # The granularity layer may emit a multi-part replacement like
            # "<<HOST>>/api/users/<<USER_ID>>" -- in that case we can't pin
            # a single original to a single placeholder, so fall through and
            # let the per-mode helpers below set up the map for split cases.
            if r.replacement == ph:
                recovery_map.setdefault(ph, r.original)

    # Plus, walk the (host, id) split URL replacements: their .replacement
    # is a rebuilt URL string that contains multiple placeholders, but the
    # granularity helper packs each placeholder's original into the parent
    # span. We recover them by re-parsing the rebuilt URL.
    _recover_split_url(replacements or (), recovery_map)
    _recover_split_email(replacements or (), recovery_map)
    _recover_credential_prefix(replacements or (), recovery_map)

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
        _recovery_map=recovery_map,
    )


def _recover_split_url(replacements, recovery_map: dict[str, str]) -> None:
    """Re-derive recovery entries for URL_STRUCTURED replacements.

    The granularity helper rebuilds URLs as
    "<scheme>://<<INTERNAL_URL_HOST_xxxx>>/<path>/<<USER_ID_yyyy>>?<query>"
    so a single Replacement covers several placeholders. To recover them we
    split both the masked URL and the original URL on the same path
    structure.
    """
    from urllib.parse import urlparse

    for r in replacements:
        if r.replacement == r.original or "<<" not in r.replacement:
            continue
        # Only URLs are interesting here; emails are handled separately.
        if "@" in r.replacement and "://" not in r.replacement:
            continue
        try:
            masked_p = urlparse(r.replacement)
            orig_p = urlparse(r.original)
        except Exception:  # noqa: BLE001
            continue
        if not masked_p.netloc or not orig_p.netloc:
            continue
        # netloc placeholder
        if masked_p.netloc.startswith("<<") and masked_p.netloc.endswith(">>"):
            recovery_map.setdefault(masked_p.netloc, orig_p.netloc)
        # trailing path id placeholder
        masked_segments = (masked_p.path or "").split("/")
        orig_segments = (orig_p.path or "").split("/")
        if masked_segments and orig_segments and len(masked_segments) == len(orig_segments):
            last_m, last_o = masked_segments[-1], orig_segments[-1]
            if last_m.startswith("<<") and last_m.endswith(">>"):
                recovery_map.setdefault(last_m, last_o)


def _recover_split_email(replacements, recovery_map: dict[str, str]) -> None:
    """Re-derive recovery entries for EMAIL_SPLIT_HASH replacements."""
    for r in replacements:
        if r.replacement == r.original or "@" not in r.replacement:
            continue
        if "://" in r.replacement:
            continue  # URLs handled by _recover_split_url
        masked_local, _, masked_domain = r.replacement.partition("@")
        orig_local, _, orig_domain = r.original.partition("@")
        if masked_local.startswith("<<") and masked_local.endswith(">>"):
            recovery_map.setdefault(masked_local, orig_local)
        if masked_domain.startswith("<<") and masked_domain.endswith(">>"):
            recovery_map.setdefault(masked_domain, orig_domain)


def _recover_credential_prefix(replacements, recovery_map: dict[str, str]) -> None:
    """Re-derive recovery entries for CREDENTIAL_PREFIX replacements.

    The granularity helper produces "<prefix><<CREDENTIAL_xxxx>>" -- we
    pull the placeholder out and pair it with the secret tail of the
    original (everything after the prefix).
    """
    for r in replacements:
        if r.replacement == r.original:
            continue
        # Find the embedded placeholder. There must be exactly one for this
        # to be a credential-prefix shape; multi-placeholder shapes are
        # already handled by the URL/email helpers above.
        matches = list(_PLACEHOLDER_RE.finditer(r.replacement))
        if len(matches) != 1:
            continue
        m = matches[0]
        ph = m.group(0)
        prefix = r.replacement[: m.start()]
        if prefix and r.original.startswith(prefix):
            recovery_map.setdefault(ph, r.original[len(prefix):])


def _guess_category(label: str) -> Category | None:
    # try matching progressively shorter prefixes (e.g. INTERNAL_URL_HOST)
    parts = label.split("_")
    for n in range(len(parts), 0, -1):
        head = "_".join(parts[:n])
        if head in Category.__members__:
            return Category[head]
    return None
