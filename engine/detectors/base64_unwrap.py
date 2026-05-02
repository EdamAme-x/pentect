"""Base64-aware unwrapper detector.

Opens a window through base64 encoding so peer detectors can see the
plaintext. Holds no opinion on what counts as a secret — if any peer
flags the decoded payload, the encoded chunk is tagged as CREDENTIAL.

Peers default to the engine's lightweight chain (rule, entropy,
detect-secrets). They're built lazily and may be overridden via the
constructor for tests.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Iterable

from engine.categories import Category
from engine.detectors.base import Detector, Span


_B64_CHUNK_RE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")
_BASIC_AUTH_RE = re.compile(
    r"(?im)Authorization\s*[:=]\s*Basic\s+(?P<val>[A-Za-z0-9+/=_-]{8,})"
)


def _maybe_decode(chunk: str) -> bytes | None:
    rem = len(chunk) % 4
    padded = chunk + ("=" * (4 - rem) if rem else "")
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(padded)
        except (binascii.Error, ValueError):
            continue
    return None


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) >= 0.80


def _decode_to_text(chunk: str) -> str | None:
    decoded = _maybe_decode(chunk)
    if decoded is None or not _looks_like_text(decoded):
        return None
    return decoded.decode("ascii", errors="ignore")


def _default_peers() -> list[Detector]:
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


class Base64UnwrapDetector:
    name = "base64_unwrap"

    def __init__(
        self,
        peers: Iterable[Detector] | None = None,
        max_depth: int = 3,
    ) -> None:
        self._peers: list[Detector] | None = (
            list(peers) if peers is not None else None
        )
        self._max_depth = max_depth

    def _get_peers(self) -> list[Detector]:
        if self._peers is None:
            self._peers = _default_peers()
        return self._peers

    def _peers_flag(self, plaintext: str, depth: int) -> bool:
        for peer in self._get_peers():
            try:
                if peer.detect(plaintext):
                    return True
            except Exception:  # noqa: BLE001 -- never let a peer break us
                continue
        if depth >= self._max_depth:
            return False
        stripped = plaintext.strip()
        if not _B64_CHUNK_RE.fullmatch(stripped):
            return False
        inner = _decode_to_text(stripped)
        return inner is not None and self._peers_flag(inner, depth + 1)

    def _emit(self, start: int, end: int) -> Span:
        return Span(
            start=start, end=end,
            category=Category.CREDENTIAL, source=self.name,
        )

    def detect(self, text: str) -> list[Span]:
        out: list[Span] = []
        seen: set[tuple[int, int]] = set()

        # Pass 1: Authorization: Basic <b64> is always a credential.
        for m in _BASIC_AUTH_RE.finditer(text):
            key = (m.start("val"), m.end("val"))
            if key not in seen:
                seen.add(key)
                out.append(self._emit(*key))

        # Pass 2: any base64-shaped chunk whose plaintext peers flag.
        for m in _B64_CHUNK_RE.finditer(text):
            key = (m.start(), m.end())
            if key in seen:
                continue
            if (key[1] - key[0]) > 4096:
                continue
            plaintext = _decode_to_text(m.group(0))
            if plaintext is None:
                continue
            if not self._peers_flag(plaintext, depth=0):
                continue
            seen.add(key)
            out.append(self._emit(*key))

        return out
