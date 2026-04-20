"""Apply per-category granularity rules to produce placeholder replacements."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from engine.categories import Category, GranularityMode, get_spec
from engine.detectors.base import Span
from engine.placeholder import make_placeholder


@dataclass
class Replacement:
    start: int
    end: int
    replacement: str
    category: Category
    original: str


def _mask_internal_url(text: str, span: Span) -> list[Replacement]:
    """Mask host + trailing path ID; preserve path structure."""
    original = text[span.start:span.end]
    parsed = urlparse(original)

    if not parsed.scheme or not parsed.netloc:
        # not a parseable URL: mask the whole thing
        ph = make_placeholder(Category.INTERNAL_URL, original)
        return [Replacement(span.start, span.end, ph, Category.INTERNAL_URL, original)]

    host_ph = make_placeholder(Category.INTERNAL_URL, parsed.netloc, suffix="HOST")

    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""

    # mask trailing segment if it looks like a numeric or long alphanumeric ID
    segments = path.split("/")
    if segments and segments[-1]:
        last = segments[-1]
        if re.fullmatch(r"\d+", last) or re.fullmatch(r"[A-Za-z0-9_\-]{16,}", last):
            segments[-1] = make_placeholder(Category.USER_ID, last)
    new_path = "/".join(segments)

    rebuilt = f"{parsed.scheme}://{host_ph}{new_path}{query}"
    return [Replacement(span.start, span.end, rebuilt, Category.INTERNAL_URL, original)]


def _mask_email_local(text: str, span: Span) -> list[Replacement]:
    original = text[span.start:span.end]
    if "@" not in original:
        ph = make_placeholder(Category.PII_EMAIL, original)
        return [Replacement(span.start, span.end, ph, Category.PII_EMAIL, original)]
    local, domain = original.rsplit("@", 1)
    local_ph = make_placeholder(Category.PII_EMAIL, local, suffix="LOCAL")
    return [
        Replacement(span.start, span.end, f"{local_ph}@{domain}", Category.PII_EMAIL, original)
    ]


def _mask_full(text: str, span: Span) -> list[Replacement]:
    original = text[span.start:span.end]
    ph = make_placeholder(span.category, original)
    return [Replacement(span.start, span.end, ph, span.category, original)]


def _mask_hash_only(text: str, span: Span) -> list[Replacement]:
    original = text[span.start:span.end]
    ph = make_placeholder(span.category, original)
    return [Replacement(span.start, span.end, ph, span.category, original)]


def apply_granularity(text: str, spans: list[Span]) -> list[Replacement]:
    """Convert spans to replacements according to per-category granularity rules."""
    out: list[Replacement] = []
    for span in spans:
        spec = get_spec(span.category)
        mode = spec.mode
        if mode is GranularityMode.URL_STRUCTURED:
            out.extend(_mask_internal_url(text, span))
        elif mode is GranularityMode.EMAIL_LOCAL:
            out.extend(_mask_email_local(text, span))
        elif mode is GranularityMode.HASH_ONLY:
            out.extend(_mask_hash_only(text, span))
        else:
            out.extend(_mask_full(text, span))
    return out


def apply_replacements(text: str, replacements: list[Replacement]) -> str:
    """Apply replacements right-to-left to keep indices stable."""
    ordered = sorted(replacements, key=lambda r: r.start, reverse=True)
    buf = text
    for r in ordered:
        buf = buf[: r.start] + r.replacement + buf[r.end :]
    return buf
