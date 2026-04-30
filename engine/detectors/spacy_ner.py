"""spaCy-based NER detector for person and organization names.

Why this exists
===============
The Privacy Filter FT model is good on the names that look like English
or Japanese personal names in our training distribution, but it misses
unusual ones embedded in JSON product descriptions, HTML comments,
copyright lines etc. (e.g. "Uncle Dittmeyer", "Bjoern Kimminich"). spaCy
ships a battle-tested NER pipeline that catches a wider range of these
without any additional fine-tuning.

We deliberately use only PERSON and ORG labels and route both to the
Pentect PII_NAME category. Other entity types (DATE, MONEY, etc.) are
not what Pentect masks.
"""
from __future__ import annotations

import os
import re
from typing import Iterable

from engine.categories import Category
from engine.detectors.base import Span


# Strip Pentect placeholders (`<<CATEGORY_xxxxxxxx>>`) before feeding text
# to spaCy: in real HARs, copyright comments and product descriptions get
# previous detector passes mixed into them, and spaCy's NER collapses on
# adjacent placeholder noise. We blank them out with same-length spaces so
# downstream offsets still line up with the original text.
_PLACEHOLDER_RE = re.compile(r"<<[A-Z_]+_[a-f0-9]{8}>>")


def _clean_for_ner(s: str) -> str:
    return _PLACEHOLDER_RE.sub(lambda m: " " * len(m.group()), s)


# Default to the small English model so the first install is light.
# Set PENTECT_SPACY_MODEL to a different model (e.g. en_core_web_lg, ja_ginza)
# to override.
_DEFAULT_MODEL = os.environ.get("PENTECT_SPACY_MODEL", "en_core_web_sm")


class SpacyNERDetector:
    name = "spacy_ner"

    def __init__(self, model: str | None = None) -> None:
        try:
            import spacy
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "spaCy is not installed. Install with: pip install spacy "
                "&& python -m spacy download en_core_web_sm"
            ) from e

        try:
            self._nlp = spacy.load(model or _DEFAULT_MODEL)
        except OSError as e:  # pragma: no cover
            raise RuntimeError(
                f"spaCy model {model or _DEFAULT_MODEL!r} not found. "
                f"Run: python -m spacy download {model or _DEFAULT_MODEL}"
            ) from e

    # spaCy's parser is O(n) but memory-bound, and the default model
    # silently truncates documents past ~1MB. We chunk large inputs so a
    # multi-MB HAR still gets full coverage. Overlap stitches across the
    # boundary so a name straddling two chunks is still caught.
    _CHUNK_SIZE = 80_000
    _CHUNK_OVERLAP = 200

    def detect(self, text: str) -> list[Span]:
        if len(text) <= self._CHUNK_SIZE:
            return self._detect_chunk(text, 0)
        out: list[Span] = []
        seen: set[tuple[int, int]] = set()
        offset = 0
        while offset < len(text):
            end = min(offset + self._CHUNK_SIZE, len(text))
            for sp in self._detect_chunk(text[offset:end], offset):
                key = (sp.start, sp.end)
                if key in seen:
                    continue
                seen.add(key)
                out.append(sp)
            if end == len(text):
                break
            offset = end - self._CHUNK_OVERLAP
        return out

    def _detect_chunk(self, chunk: str, base_offset: int) -> list[Span]:
        out: list[Span] = []
        cleaned = _clean_for_ner(chunk)
        try:
            doc = self._nlp(cleaned)
        except Exception:  # noqa: BLE001
            return out
        for ent in doc.ents:
            if ent.label_ not in ("PERSON", "ORG"):
                continue
            text_slice = chunk[ent.start_char:ent.end_char].rstrip(" &.,;:")
            if not _looks_like_real_name(text_slice):
                continue
            end = ent.start_char + len(text_slice)
            out.append(
                Span(
                    start=base_offset + ent.start_char,
                    end=base_offset + end,
                    category=Category.PII_NAME,
                    source=self.name,
                )
            )
        return out


def _looks_like_real_name(s: str) -> bool:
    """Discard spaCy entities that are clearly not human / organization names.

    spaCy is happy to label minified JS identifiers (`__webpack`, `t`, `e`),
    HTML attribute fragments, and stray product strings as PERSON. None of
    those are PII, and tagging them blows up false-positive count, so we
    keep only entities that look like multi-word proper-noun phrases.
    """
    if not s or len(s) < 4:
        return False
    # Must contain at least one space (single-word "Uncle" / "Logan" can be
    # too noisy; require the model picked up a multi-word name).
    if " " not in s:
        return False
    # Reject identifier-ish strings (snake_case, camelCase, dotted, with digits).
    if any(c in s for c in "_.<>{}[]()=;:#|/\\@"):
        return False
    if any(c.isdigit() for c in s):
        return False
    # Each token should start with an uppercase letter -- proper-noun shape.
    parts = s.split()
    if len(parts) < 2 or len(parts) > 4:
        return False
    if not all(p and p[0].isupper() for p in parts):
        return False
    return True

    def detect_batch(self, texts: Iterable[str]) -> list[list[Span]]:
        return [self.detect(t) for t in texts]
