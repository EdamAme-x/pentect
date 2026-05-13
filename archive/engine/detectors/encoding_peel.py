"""Encoding-peel detectors.

Same shape as Base64UnwrapDetector: don't classify anything ourselves,
just decode and ask peer detectors. The encoded blob is masked if any
peer flags the decoded form.

Why this file exists separately from base64_unwrap.py:
base64 has its own resource-budget / fixed-point loop because nested
base64 is a real attack pattern. URL / HTML / hex encoding rarely
nest (they're just transport encodings, not concealment), so the
implementation here stays simple: decode once, ask peers, done.

Add more peelers under the EncodingPeeler base class when needed —
HTML entities, hex literals, punycode, MIME quoted-printable, etc.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Iterable

from engine.categories import Category
from engine.detectors.base import Detector, Span


def _default_peers() -> list[Detector]:
    """Light-weight peer chain used to judge the decoded plaintext.
    Mirrors Base64UnwrapDetector's choice — rule + entropy + the
    detect-secrets plugin bundle. We deliberately don't include the
    FT model here because it's heavy and these peelers run on every
    URL-shaped value in a HAR."""
    from engine.detectors.entropy import EntropyDetector
    from engine.detectors.rule import RuleDetector

    peers: list[Detector] = [RuleDetector(), EntropyDetector()]
    try:
        from engine.detectors.detect_secrets_plugins import (
            DetectSecretsPluginDetector,
        )
        peers.append(DetectSecretsPluginDetector())
    except RuntimeError:  # pragma: no cover -- optional dep
        pass
    return peers


# A single `%XX` triple. We then expand to the surrounding non-space
# token. False positives like `50% off` get filtered by requiring the
# *expanded token* to contain 2 or more percent-runs (so a stray
# single `%` in prose doesn't fire).
_PERCENT_TRIPLE_RE = re.compile(r"%[0-9A-Fa-f]{2}")


class UrlEncodingPeeler:
    """Find percent-encoded runs, decode them, hand to peer detectors.

    Catches things like ``Authorization%3A%20Bearer%20eyJ...`` where
    a credential is hidden behind URL encoding. The encoded run as a
    whole is masked if peers flag the decoded form.
    """

    name = "url_encoding_peel"

    def __init__(self, peers: Iterable[Detector] | None = None) -> None:
        self._peers: list[Detector] | None = (
            list(peers) if peers is not None else None
        )

    def _get_peers(self) -> list[Detector]:
        if self._peers is None:
            self._peers = _default_peers()
        return self._peers

    def _peers_flag(self, plaintext: str) -> bool:
        for peer in self._get_peers():
            try:
                if peer.detect(plaintext):
                    return True
            except Exception:  # noqa: BLE001 -- never let a peer break us
                continue
        return False

    def detect(self, text: str) -> list[Span]:
        out: list[Span] = []
        seen: set[tuple[int, int]] = set()
        for m in _PERCENT_TRIPLE_RE.finditer(text):
            # Expand the match to include immediately adjacent
            # non-whitespace characters so we judge the *full token*
            # the percent-run is embedded in (e.g. `Bearer%20eyJ...`
            # has a non-encoded `Bearer` prefix we want to feed to
            # peers along with the decoded suffix).
            left = m.start()
            right = m.end()
            while left > 0 and not text[left - 1].isspace() and text[left - 1] not in '"\'<>':
                left -= 1
            while right < len(text) and not text[right].isspace() and text[right] not in '"\'<>':
                right += 1
            token = text[left:right]
            if not token:
                continue
            # Stray single `%XX` in prose (`50% off`) is noise. Only
            # fire when the surrounding token has at least 2 triples.
            if len(_PERCENT_TRIPLE_RE.findall(token)) < 2:
                continue
            try:
                decoded = urllib.parse.unquote(token, errors="strict")
            except (UnicodeDecodeError, ValueError):
                continue
            if decoded == token:
                continue  # nothing was actually encoded
            if not self._peers_flag(decoded):
                continue
            key = (left, right)
            if key in seen:
                continue
            seen.add(key)
            out.append(Span(
                start=left, end=right,
                category=Category.CREDENTIAL, source=self.name,
            ))
        return out
