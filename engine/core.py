"""Orchestration layer for the Pentect masking engine.

Accepts HAR or plain text and runs: parse → detect → merge → granularity → output.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from engine.categories import Category, get_spec
from engine.detectors.base import Detector, Span
from engine.detectors.rule import RuleDetector
from engine.granularity import Replacement, apply_granularity, apply_replacements
from engine.merger import merge
from engine.parsers.har import HarEntryText, iter_entry_texts, parse_har
from engine.placeholder import make_placeholder


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


# Static-asset shortcut. minified JS / CSS / images / fonts coming
# from a public CDN are by far the bulk of a real HAR (often >90% of
# bytes) and contain effectively no secrets — but walking them
# through every detector is 70+ s of pure work. We pre-mask their
# body with a single STATIC_ASSET placeholder and skip detection on
# them entirely. The original bytes go into the recovery map so a
# local caller can still get them back via MaskResult.recover().
#
# Detection is by URL suffix and by MIME type. We deliberately don't
# look at body content sniffing: build artifacts can be large enough
# that a heuristic scan dominates the cost we're trying to avoid.
_STATIC_URL_SUFFIXES = (
    ".js", ".mjs", ".cjs", ".js.map", ".css", ".css.map",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".svg",
    ".mp4", ".mp3", ".webm", ".ogg", ".wav",
    ".wasm", ".pdf",
)
_STATIC_MIME_PREFIXES = (
    "image/",
    "font/",
    "audio/",
    "video/",
    "application/javascript",
    "application/x-javascript",
    "text/javascript",
    "text/css",
    "application/wasm",
    "application/font-",
    "application/x-font",
)


def _looks_like_static_asset(url: str, mime: str) -> bool:
    """True iff this entry's response body should be treated as a
    public-CDN asset and not walked by the detectors."""
    if mime:
        m = mime.lower().split(";", 1)[0].strip()
        if m.startswith(_STATIC_MIME_PREFIXES):
            return True
    if url:
        # strip query string before suffix match
        u = url.split("?", 1)[0].split("#", 1)[0].lower()
        if u.endswith(_STATIC_URL_SUFFIXES):
            return True
    return False

# Minimum leaf length we'll pay spaCy NER inference cost on. Below
# this we either won't have a multi-word entity to find, or the
# string is a URL / token / short identifier that NER will hallucinate
# on. 64 chars is roughly the smallest length where a real-world body
# might contain a name (e.g. "© 2024 Acme Corp" is 18 chars but ones
# we actually need to catch like "Bjoern Kimminich" appear inside
# multi-line copyright headers or descriptions).
_MIN_NER_LEAF_LEN = 64


# Categories whose values are short handles / common words and must only
# match on word boundaries when re-applied as anchors. Without this, an
# anchor like `bootstrap` (from github.com/twbs/bootstrap) would also match
# `getbootstrap.com` and replace just the middle of an unrelated host.
_WORD_BOUNDED_ANCHOR_CATEGORIES = {Category.PII_HANDLE}


def _anchor_iter_hits(text: str, value: str, category: Category):
    """Yield (start, end) for every place `value` appears in `text` that we
    should treat as an anchor hit.

    For most categories that means every substring occurrence. For handle-
    like categories we additionally require that the surrounding characters
    are not part of an identifier, so `bootstrap` (handle) does not match
    inside `getbootstrap.com`.
    """
    if not value:
        return
    word_bounded = category in _WORD_BOUNDED_ANCHOR_CATEGORIES
    n = len(value)
    start = 0
    while True:
        hit = text.find(value, start)
        if hit < 0:
            return
        if word_bounded:
            before = text[hit - 1] if hit > 0 else ""
            after = text[hit + n] if hit + n < len(text) else ""
            if (before and (before.isalnum() or before == "_")) or (
                after and (after.isalnum() or after == "_")
            ):
                start = hit + 1
                continue
        yield hit, hit + n
        start = hit + n


def _build_anchor_matcher(anchor_items: list[tuple[str, Category]]):
    """Compile the anchor set into a single regex that scans a target
    string in one pass. Returns a callable
    ``match(text) -> Iterable[tuple[int, int, Category]]``.

    The naive implementation iterates each anchor against each target
    field and calls ``str.find`` in a loop — that's O(F * A * T). With
    a combined alternation, the regex engine walks the input once
    while NFA-matching all alternatives, dropping the cost to
    O((F + A) * T) which is what keeps the pipeline at k <= 1.2.

    Two technical caveats:
      - longer anchors are listed first so a substring anchor doesn't
        win over a longer overlapping one (regex alternation is
        leftmost-first, so order matters);
      - PII_HANDLE-category anchors require word boundaries — we wrap
        them with a lookbehind/lookahead via a per-anchor named
        group so the same regex covers both regular and word-bounded
        anchors.
    """
    if not anchor_items:
        return None

    # Sort anchors longest-first so alternation prefers the longer
    # match. Empty anchors are skipped.
    items = [(v, c) for v, c in anchor_items if v]
    items.sort(key=lambda vc: -len(vc[0]))

    parts: list[str] = []
    cats: list[Category] = []
    for value, category in items:
        word_bounded = category in _WORD_BOUNDED_ANCHOR_CATEGORIES
        body = re.escape(value)
        if word_bounded:
            body = rf"(?<![A-Za-z0-9_]){body}(?![A-Za-z0-9_])"
        parts.append(f"(?:{body})")
        cats.append(category)

    # We use a single non-capturing alternation and look at the match
    # text to decide which anchor fired. Using one named group per
    # anchor would blow past Python's 100-group regex limit on
    # realistic HARs. For very large anchor sets we fall back to the
    # per-anchor loop.
    if sum(len(p) for p in parts) > 800_000:
        return None

    pattern = re.compile("|".join(parts))
    # Map original anchor value (already normalized to longest-first
    # order) to its category for fast post-match lookup.
    cat_by_value: dict[str, Category] = {v: c for v, c in items}

    def matcher(text: str):
        for m in pattern.finditer(text):
            val = m.group(0)
            cat = cat_by_value.get(val)
            if cat is None:
                continue
            yield m.start(), m.end(), cat

    return matcher


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
            # spaCy NER catches person / organization names that the
            # FT model misses (long-form descriptions, copyright lines,
            # etc.). On real HARs (3-4 MB, mostly minified bundles +
            # JSON) NER costs 5-6x the rest of the pipeline combined
            # while contributing roughly zero new leak-relevant masks
            # — every name that mattered (Bjoern Kimminich, OWASP,
            # davegandy, daneden, Dittmeyer) is already caught by the
            # banner / @handle / detect-secrets rules. So NER is
            # off-by-default and opted into via PENTECT_ENABLE_SPACY=1.
            if os.environ.get("PENTECT_ENABLE_SPACY") in ("1", "true", "yes"):
                try:
                    from engine.detectors.spacy_ner import SpacyNERDetector
                    self.detectors.append(SpacyNERDetector())
                except RuntimeError:
                    pass
            # Entropy-based fallback for query / cookie / JSON-credential
            # values whose shape isn't covered by any explicit pattern
            # (Socket.IO sids, opaque session tokens, etc.).
            from engine.detectors.entropy import EntropyDetector
            self.detectors.append(EntropyDetector())
            # Base64-wrapped credentials: decode candidate chunks, check
            # whether the plaintext contains a credential-shaped payload,
            # mask the encoded blob if so.
            from engine.detectors.base64_unwrap import Base64UnwrapDetector
            self.detectors.append(Base64UnwrapDetector())
            # BIP39 mnemonic phrases and PEM private key blocks. Neither
            # shows up in the entropy path (lowercase prose is too low
            # entropy; PEM b64 decodes to binary DER) so they get their
            # own dictionary / regex pass.
            from engine.detectors.seed_phrase import SeedPhraseDetector
            self.detectors.append(SeedPhraseDetector())
            # Cryptocurrency wallet addresses (BTC, ETH, Solana, ...).
            # These are stable identifiers that link a person to their
            # transaction history — same threat model as a username.
            from engine.detectors.crypto_address import CryptoAddressDetector
            self.detectors.append(CryptoAddressDetector())
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

        # Pre-pass: collapse public CDN bodies (minified JS / CSS,
        # images, fonts, ...) to a single STATIC_ASSET placeholder
        # before the detectors ever see them. On real-world HARs this
        # is by far the biggest wall-clock win: a Juice Shop /
        # Angular bundle is ~1.4 MB of minified JS that would
        # otherwise eat 70+ s of detector time for no leak gain.
        static_recovery: dict[str, str] = {}
        _collapse_static_assets(data, static_recovery)

        raw_entries = (data.get("log", {}) or {}).get("entries", []) or []
        entry_texts = iter_entry_texts(data)

        # Anchors come from the full serialized HAR so values that live in
        # response bodies / query strings / anywhere JSON are still caught even
        # when the compact entry text (used only as the LLM's in-distribution
        # input) wouldn't include them. We run *every* lightweight detector
        # (rule, detect-secrets, spaCy NER) on the full JSON so e.g. a person
        # name buried inside a "description" field still becomes an anchor.
        rule_source = json.dumps(data, ensure_ascii=False)
        anchors: dict[str, Category] = {}
        # Plain-text values walked from the HAR: feeding spaCy raw rule_source
        # mixes JSON escapes / minified JS / huge bundles together and the
        # parser collapses to single-token false positives. Walking the leaf
        # strings instead gives the NER a clean human-language context.
        leaf_strings = list(_iter_leaf_strings(data))
        for d in self.detectors:
            # Skip the heavy LLM detectors here -- they are designed to run
            # on a single per-entry text block, not on a multi-MB HAR.
            cls = d.__class__.__name__
            if cls in ("LLMDetector", "PrivacyFilterDetector", "HybridDetector"):
                continue
            # spaCy NER and the entropy detector both blow up if you feed
            # them a 4 MB blob mixing escaped JSON / minified JS / CSS:
            # NER collapses to single-token false positives, and entropy
            # mistakes minified-JS expressions like `?b:c)` for query
            # parameters. Walking the HAR leaf-string by leaf-string keeps
            # each detector inside a clean per-field context.
            if cls in ("SpacyNERDetector", "EntropyDetector"):
                # spaCy NER and entropy use different size budgets:
                # - NER chunks internally and benefits from seeing full
                #   HTML pages (where copyright comments live), so we
                #   give it up to 200 KB per leaf.
                # - Entropy is line-noise sensitive; very large minified
                #   strings produce massive false positives, so cap it
                #   tighter.
                cap = 200_000 if cls == "SpacyNERDetector" else 20_000
                if cls == "SpacyNERDetector":
                    # Names live in human-language fields: HTML pages,
                    # long copyright comments, JSON descriptions. URL
                    # paths, header values, and short tokens almost
                    # never carry a PERSON/ORG entity, but feeding them
                    # to spaCy is by far the biggest wall-clock cost
                    # in the pipeline. Filter by minimum length AND
                    # by a quick "looks like prose" heuristic: must
                    # contain at least one space character (entities
                    # require multi-word tokens) and must include some
                    # uppercase letters (proper nouns).
                    # Also enforce a per-leaf upper bound smaller than
                    # the chunk cap above: a multi-MB body is almost
                    # always minified JS or base64, and even when it's
                    # not the bulk of the runtime is spent on those
                    # bytes for negligible recall gain. Keep this
                    # tunable via env var so a user with very long
                    # human-language documents can opt in to scanning
                    # them.
                    ner_cap = int(
                        os.environ.get("PENTECT_NER_LEAF_CAP", "32000")
                    )
                    cand: list[str] = [
                        s for s in leaf_strings
                        if _MIN_NER_LEAF_LEN <= len(s) <= ner_cap
                        and " " in s
                        and any(c.isupper() for c in s)
                    ]
                else:
                    cand = [s for s in leaf_strings if 0 < len(s) <= cap]
                # Prefer batched inference where the detector exposes
                # one — for spaCy NER this collapses hundreds of small
                # forwards into one piped call (huge speedup).
                batch_fn = getattr(d, "detect_batch", None)
                try:
                    if callable(batch_fn):
                        per = batch_fn(cand)
                        for s, spans in zip(cand, per):
                            for sp in spans:
                                val = s[sp.start:sp.end]
                                if val:
                                    anchors.setdefault(val, sp.category)
                    else:
                        for s in cand:
                            for sp in d.detect(s):
                                val = s[sp.start:sp.end]
                                if val:
                                    anchors.setdefault(val, sp.category)
                except Exception:  # noqa: BLE001
                    continue
                continue
            try:
                for sp in d.detect(rule_source):
                    val = rule_source[sp.start:sp.end]
                    if val:
                        anchors.setdefault(val, sp.category)
            except Exception:  # noqa: BLE001
                continue

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
        # Carry over static-asset recovery entries built during the
        # pre-pass so callers can recover() the original CDN bodies.
        for ph, body in static_recovery.items():
            combined_recovery.setdefault(ph, body)

        for idx, entry in enumerate(raw_entries):
            spans = batched_spans[idx] if idx < len(batched_spans) else []
            entry_values: dict[str, Category] = {}
            for sp in spans:
                val = entry_texts[idx].text[sp.start:sp.end]
                entry_values.setdefault(val, sp.category)
            for val, cat in anchors.items():
                entry_values.setdefault(val, cat)

            # Compile the per-entry anchor set once; reuse across
            # every field of this entry so we walk each field text a
            # single time instead of len(anchors) times.
            entry_matcher = _build_anchor_matcher(list(entry_values.items()))

            all_replacements = []
            for target, key in _fields_of(entry):
                text = target[key]
                field_spans: list[Span] = []
                if entry_matcher is not None:
                    for s_, e_, cat in entry_matcher(text):
                        field_spans.append(Span(
                            start=s_, end=e_,
                            category=cat, source="har",
                        ))
                else:
                    for val, cat in entry_values.items():
                        for s_, e_ in _anchor_iter_hits(text, val, cat):
                            field_spans.append(Span(
                                start=s_, end=e_,
                                category=cat, source="har",
                            ))
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

        # Final sweep: anchors that landed on HAR fields outside entries
        # (e.g. log.pages[i].title) are not reached by the per-entry loop
        # above. Walk every string in `data` and apply substring replacement
        # for each anchor we have. This is O(N * anchors) where N is total
        # string content; in practice anchors stays in the dozens.
        if anchors:
            tail_replacements = _apply_anchors_in_place(data, anchors)
            for r in tail_replacements:
                if r.replacement.startswith("<<") and r.replacement.endswith(">>"):
                    combined_recovery.setdefault(r.replacement, r.original)

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
                for s_, e_ in _anchor_iter_hits(e.text, val, cat):
                    spans.append(Span(
                        start=s_, end=e_,
                        category=cat, source="anchor",
                    ))
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


def _collapse_static_assets(data: Any, recovery: dict[str, str]) -> None:
    """Replace static-asset response bodies in-place with a single
    STATIC_ASSET placeholder. ``recovery`` is appended with the
    placeholder -> original-body mapping so MaskResult.recover() can
    return the bytes when a local caller asks.

    We touch only ``log.entries[*].response.content.text``. URL is
    read from ``log.entries[*].request.url`` and MIME from
    ``response.content.mimeType``; either positive signal is enough
    to mark the body as static.
    """
    log = data.get("log") if isinstance(data, dict) else None
    if not isinstance(log, dict):
        return
    entries = log.get("entries") or []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") or {}
        res = entry.get("response") or {}
        if not isinstance(req, dict) or not isinstance(res, dict):
            continue
        content = res.get("content") or {}
        if not isinstance(content, dict):
            continue
        body = content.get("text")
        if not isinstance(body, str) or not body:
            continue
        url = req.get("url") if isinstance(req.get("url"), str) else ""
        mime = content.get("mimeType") if isinstance(content.get("mimeType"), str) else ""
        if not _looks_like_static_asset(url, mime):
            continue
        ph = make_placeholder(Category.STATIC_ASSET, body)
        recovery.setdefault(ph, body)
        content["text"] = ph


def _apply_anchors_in_place(obj: Any, anchors: dict[str, Category]):
    """Walk a HAR-like structure and apply `anchors` to every string leaf.

    Used after the per-entry pass to pick up strings that live outside
    `log.entries[*]` (e.g. `log.pages[i].title`). Modifies the structure
    in place where it can (for dict / list of strings) and returns the
    list of Replacement objects produced so the caller can build a
    recovery map.
    """
    out: list[Replacement] = []
    matcher = _build_anchor_matcher(list(anchors.items()))

    def _walk(node: Any, parent: Any, key: Any) -> None:
        if isinstance(node, str):
            field_spans: list[Span] = []
            if matcher is not None:
                for s_, e_, cat in matcher(node):
                    field_spans.append(Span(
                        start=s_, end=e_,
                        category=cat, source="har",
                    ))
            else:
                for val, cat in anchors.items():
                    for s_, e_ in _anchor_iter_hits(node, val, cat):
                        field_spans.append(Span(
                            start=s_, end=e_,
                            category=cat, source="har",
                        ))
            if not field_spans:
                return
            field_spans = merge(field_spans)
            replacements = apply_granularity(node, field_spans)
            new_text = apply_replacements(node, replacements)
            if new_text != node and parent is not None and key is not None:
                parent[key] = new_text
                out.extend(replacements)
        elif isinstance(node, dict):
            for k in list(node.keys()):
                _walk(node[k], node, k)
        elif isinstance(node, list):
            for i in range(len(node)):
                _walk(node[i], node, i)

    _walk(obj, None, None)
    return out


def _iter_leaf_strings(obj: Any) -> "Iterable[str]":
    """Yield every string value from a nested HAR-like data structure.

    Used to feed spaCy NER one human-language field at a time instead of
    the whole serialized HAR, since the parser otherwise drowns in JSON
    escapes / minified JS and produces single-token noise.
    """
    if isinstance(obj, str):
        # Only feed strings that have a chance of containing a name.
        # Skip pure base64 / dataURIs / very short tokens.
        # Upper bound: spaCy chunks internally to 80k, so 200k strings
        # (full HTML responses w/ scripts) are fine; over that the entire
        # body is almost certainly minified bundles or base64 binary --
        # not human-language content NER would help with.
        if len(obj) < 6 or len(obj) > 200_000:
            return
        if obj.startswith("data:") or obj.startswith("blob:"):
            return
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_leaf_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_leaf_strings(v)


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
