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


def _is_high_entropy_secret(val: str) -> bool:
    if len(val) < _MIN_LEN:
        return False
    # Skip Pentect placeholders and anything that contains them.
    if "<<" in val or ">>" in val:
        return False
    # Strict char set; avoids JSON / HTML fragments leaking in.
    if not _TOKEN_CHARSET.match(val):
        return False
    # File-extension shaped values (e.g. `Material-Icons-7Hx9bN.woff2`) are
    # high-entropy bundle artifacts, not credentials. Real secrets very
    # rarely show up as a query value with a known file extension.
    if _FILE_EXT_RE.search(val):
        return False
    # Drop strings that look like human text (mostly lowercase + spaces, or
    # a long readable word with vowels alternating with consonants). Our
    # charset already excludes spaces, so we mostly care about run-of-letters
    # checks.
    if val.lower() == val and "-" not in val and "_" not in val and "." not in val:
        # all-lowercase, no separators -> looks like a slug/word; skip unless
        # entropy is unusually high.
        if _shannon_entropy(val) < _MIN_ENTROPY + 0.5:
            return False
    return _shannon_entropy(val) >= _MIN_ENTROPY


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
