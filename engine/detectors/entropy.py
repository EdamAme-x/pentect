"""High-entropy string detector, scoped to known-leakage spots.

Why scoped, not global
======================
A pure "find every high-entropy string" pass is what detect-secrets'
``high_entropy_strings`` plugin does, and it's a noise factory on real
HARs: it hits placeholder hashes (``<<CREDENTIAL_a3f1b2c8>>``), data
URIs, minified JS identifiers, base64-encoded images, etc. Pentect needs
to mask things, not paint the whole HAR red.

Instead we look at three contexts where a random-looking string is
overwhelmingly likely to be a secret:

  1. URL query parameter values (``?sid=Yp_crOiZaE3qykxGAAAE``)
  2. Cookie / Set-Cookie value parts
  3. JSON string values whose key name suggests a credential
     (``token``, ``sid``, ``session``, ``signature``, ``key``,
     ``access_token``, ``refresh_token``, ``nonce``)

Each candidate is gated on length + Shannon entropy and explicit
exclusions (no placeholders, no obvious human prose).
"""
from __future__ import annotations

import math
import re
from typing import Iterable

from engine.categories import Category
from engine.detectors.base import Span


# A value must be at least this many chars before we even look at entropy.
_MIN_LEN = 16
# Shannon entropy threshold (bits/symbol). Empirically:
# - random base64 ~= 5.5
# - hex hash ~= 3.9
# - English words ~= 3.0
_MIN_ENTROPY = 3.5

# Allowed character set inside a candidate value: token-shaped only.
_TOKEN_CHARSET = re.compile(r"^[A-Za-z0-9._\-/+=]+$")


# Query-string parameter values: `?key=value` or `&key=value`.
_QUERY_VALUE_RE = re.compile(
    r"[?&](?P<key>[A-Za-z0-9_.\-]{1,64})=(?P<val>[A-Za-z0-9._\-/+=]{16,256})"
)

# Cookie pairs in raw HTTP headers.
_COOKIE_VALUE_RE = re.compile(
    r"(?:^|;|\s|>|^Cookie:|Set-Cookie:)\s*(?P<key>[A-Za-z0-9_.\-]{1,64})="
    r"(?P<val>[A-Za-z0-9._\-/+=]{16,256})",
    re.MULTILINE,
)

# JSON-style "key":"value" where the key looks credential-shaped.
_CRED_KEY_NAMES = {
    "token", "access_token", "accesstoken", "refresh_token", "refreshtoken",
    "id_token", "idtoken", "session", "sessionid", "session_id",
    "sid", "signature", "sig", "nonce", "csrf", "csrf_token", "csrftoken",
    "key", "secret", "auth", "authtoken", "auth_token", "bearer",
    "api_key", "apikey", "client_secret", "clientsecret",
}
_JSON_CRED_VALUE_RE = re.compile(
    r'\\?"(?P<key>[A-Za-z_][A-Za-z0-9_]*)\\?"\s*:\s*\\?"(?P<val>[A-Za-z0-9._\-/+=]{16,512})\\?"'
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    total = len(s)
    entropy = 0.0
    for n in counts.values():
        p = n / total
        entropy -= p * math.log2(p)
    return entropy


# Hex shape: only 0-9 a-f, length sane for SHA / MD5 / commit hash.
_HEX_SHAPE_RE = re.compile(r"^[0-9a-f]{16,}$")
# UUID 8-4-4-4-12 form, hex digits only.
_UUID_SHAPE_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# Vowels we use to score "human prose"-ness. Only lowercase ASCII; tokens
# with mixed case rarely have vowel alternation.
_VOWELS = frozenset("aeiou")


def _human_prose_score(s: str) -> float:
    """Return the vowel/consonant alternation rate for the lowercase
    letters in `s`, in [0, 1]. English prose averages ≈ 0.55; random
    hex / base64 averages well below 0.30 because the hex alphabet has
    only 2 of 6 vowel-class letters.

    The score ignores non-letters so `configuration-management`
    (separator stripped) keeps its high alternation rate, while hashes
    (mostly consonants) score low.
    """
    letters = [c for c in s.lower() if c.isalpha()]
    if len(letters) < 4:
        return 0.0
    transitions = 0
    for a, b in zip(letters, letters[1:]):
        if (a in _VOWELS) != (b in _VOWELS):
            transitions += 1
    return transitions / (len(letters) - 1)


def _effective_alphabet_size(s: str) -> int:
    """Number of distinct symbols in `s`. Used as the practical upper
    bound on Shannon entropy (theoretical max = log2(alphabet))."""
    return len(set(s))


def _entropy_ratio(s: str) -> float:
    """Shannon H normalized by the upper bound for the observed
    alphabet. 1.0 means a perfectly uniform distribution over the
    symbols actually present; ~0.95 is what genuinely random tokens
    achieve in practice; English prose drops below ~0.85 because of
    skewed letter frequencies."""
    alphabet = _effective_alphabet_size(s)
    if alphabet < 2:
        return 0.0
    return _shannon_entropy(s) / math.log2(alphabet)


def _classify_high_entropy(val: str) -> Category | None:
    """Decide whether `val` looks random enough to mask, and if so
    return the most informative category for it.

    Returns:
      - Category.LIKELY_HASH  for hex / UUID shape that passes the
        digest-style entropy threshold (md5 / sha1 / sha256 / uuid).
      - Category.LIKELY_TOKEN for general high-entropy strings that
        clear the ratio + prose checks.
      - None                  if the value looks like prose, an ID,
        a placeholder, a bundle artifact, etc.

    The shape-aware split is necessary because a single Shannon
    threshold can't separate hex hashes (alphabet=16, max H=4.0) from
    base64 tokens (alphabet=64, max H=6) from human prose with
    separators (alphabet ≈ 13, H ≈ 3.5).
    """
    if len(val) < _MIN_LEN:
        return None
    if "<<" in val or ">>" in val:
        return None
    if not _TOKEN_CHARSET.match(val):
        return None
    if _FILE_EXT_RE.search(val):
        return None
    lower = val.lower()
    # Pure-digit values are IDs, not credentials.
    if val.isdigit():
        return None
    if _UUID_SHAPE_RE.match(val):
        return Category.LIKELY_HASH
    if _HEX_SHAPE_RE.match(lower):
        if _effective_alphabet_size(val) < 6:
            return None
        if _entropy_ratio(val) < 0.80:
            return None
        return Category.LIKELY_HASH
    # General token path.
    if _entropy_ratio(val) < 0.85:
        return None
    if _shannon_entropy(val) < _MIN_ENTROPY:
        return None
    if _human_prose_score(val) >= 0.60:
        return None
    return Category.LIKELY_TOKEN


def _is_high_entropy_secret(val: str) -> bool:
    """Backward-compatible boolean predicate. Prefer
    :func:`_classify_high_entropy` when the caller needs to know
    whether the value looked like a hash vs an opaque token."""
    return _classify_high_entropy(val) is not None


# Common bundle / asset extensions. If a candidate value ends in one of
# these, treat it as a build artifact and skip.
_FILE_EXT_RE = re.compile(
    r"\.(?:woff2?|ttf|otf|eot|js|mjs|cjs|css|map|png|jpe?g|gif|svg|webp|"
    r"avif|ico|json|html?|xml|yaml|yml|md|txt|csv|tsv|pdf|zip|gz|tar|"
    r"wasm|exe|so|dll|class|jar|war)$",
    re.IGNORECASE,
)


class EntropyDetector:
    """Mask high-entropy secrets that hide in query strings, cookies, and
    credential-shaped JSON values."""

    name = "entropy"

    def detect(self, text: str) -> list[Span]:
        out: list[Span] = []

        for m in _QUERY_VALUE_RE.finditer(text):
            val = m.group("val")
            if _is_high_entropy_secret(val):
                out.append(
                    Span(
                        start=m.start("val"),
                        end=m.end("val"),
                        category=Category.CREDENTIAL,
                        source=self.name,
                    )
                )

        for m in _COOKIE_VALUE_RE.finditer(text):
            val = m.group("val")
            if _is_high_entropy_secret(val):
                out.append(
                    Span(
                        start=m.start("val"),
                        end=m.end("val"),
                        category=Category.CREDENTIAL,
                        source=self.name,
                    )
                )

        for m in _JSON_CRED_VALUE_RE.finditer(text):
            key = m.group("key").lower()
            if key not in _CRED_KEY_NAMES:
                continue
            val = m.group("val")
            if _is_high_entropy_secret(val):
                out.append(
                    Span(
                        start=m.start("val"),
                        end=m.end("val"),
                        category=Category.CREDENTIAL,
                        source=self.name,
                    )
                )

        return out

    def detect_batch(self, texts: Iterable[str]) -> list[list[Span]]:
        return [self.detect(t) for t in texts]
