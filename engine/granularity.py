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

    # Mask trailing segment if it looks like a numeric or long alphanumeric
    # ID. Pick USER_ID vs RESOURCE_ID based on the *previous* segment so
    # `/api/users/42` stays semantically a user identifier while
    # `/api/issues/1001` or `/api/baskets/3` end up as resource ids.
    segments = path.split("/")
    if segments and segments[-1]:
        last = segments[-1]
        if re.fullmatch(r"\d+", last) or re.fullmatch(r"[A-Za-z0-9_\-]{16,}", last):
            prev = segments[-2].lower() if len(segments) >= 2 else ""
            user_collections = {"users", "user", "customers", "customer",
                                "accounts", "account", "members", "owners"}
            id_cat = (Category.USER_ID if prev in user_collections
                      else Category.RESOURCE_ID)
            segments[-1] = make_placeholder(id_cat, last)
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


def _mask_email_split_hash(text: str, span: Span) -> list[Replacement]:
    """Hash local part and domain independently.

    Output shape:  <<PII_EMAIL_LOCAL_xxxx>>@<<PII_EMAIL_DOMAIN_yyyy>>

    Same local string yields the same LOCAL placeholder, same domain yields
    the same DOMAIN placeholder. This preserves cross-record relationships
    (e.g., two users on the same internal domain, or one identity reused
    across services) without leaking the actual values.
    """
    original = text[span.start:span.end]
    if "@" not in original:
        ph = make_placeholder(Category.PII_EMAIL, original)
        return [Replacement(span.start, span.end, ph, Category.PII_EMAIL, original)]
    local, domain = original.rsplit("@", 1)
    local_ph = make_placeholder(Category.PII_EMAIL, local, suffix="LOCAL")
    domain_ph = make_placeholder(Category.PII_EMAIL, domain, suffix="DOMAIN")
    return [
        Replacement(
            span.start, span.end,
            f"{local_ph}@{domain_ph}",
            Category.PII_EMAIL, original,
        )
    ]


# Known credential prefixes. When a CREDENTIAL span starts with one of these,
# we keep the prefix readable so the analyst can tell which provider/scheme
# the secret belongs to (Google vs OpenAI vs GitHub vs ...). Order matters:
# longer prefixes first so "sk-proj-" wins over "sk-".
_CRED_PREFIXES: tuple[str, ...] = (
    "Bearer ",
    "Basic ",
    "github_pat_",
    "sk-proj-",
    "xoxb-", "xoxa-", "xoxp-",
    "ghp_", "gho_", "ghs_",
    "AKIA", "ASIA",
    "AIza",
    "sk_live_", "sk_test_", "pk_live_", "pk_test_",
    "sk-",
    "eyJ",  # JWT (header is base64-encoded {"alg":...} which always starts eyJ)
)


def _mask_credential_prefix(text: str, span: Span) -> list[Replacement]:
    """Keep a well-known token prefix and mask the rest.

    Input:  "AIza7h1515dummy..."  -> "AIza<<CREDENTIAL_xxxx>>"
            "Bearer eyJ..."       -> "Bearer <<CREDENTIAL_xxxx>>"
            "<unknown>"           -> "<<CREDENTIAL_xxxx>>" (full mask, fallback)
    """
    original = text[span.start:span.end]
    for prefix in _CRED_PREFIXES:
        if original.startswith(prefix):
            secret = original[len(prefix):]
            secret_ph = make_placeholder(Category.CREDENTIAL, secret)
            return [Replacement(
                span.start, span.end,
                f"{prefix}{secret_ph}",
                Category.CREDENTIAL, original,
            )]
    ph = make_placeholder(Category.CREDENTIAL, original)
    return [Replacement(span.start, span.end, ph, Category.CREDENTIAL, original)]


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
        elif mode is GranularityMode.EMAIL_SPLIT_HASH:
            out.extend(_mask_email_split_hash(text, span))
        elif mode is GranularityMode.CREDENTIAL_PREFIX:
            out.extend(_mask_credential_prefix(text, span))
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
