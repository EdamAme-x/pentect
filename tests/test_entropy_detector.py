"""Tests for the high-entropy detector.

The detector is deliberately scoped to query strings, cookie values, and
JSON values whose key looks credential-shaped, because a global "find
high-entropy strings" pass is too noisy on real HARs (it hits placeholder
hashes, base64 image data, minified JS identifiers, etc.).
"""
from __future__ import annotations

from engine.categories import Category
from engine.detectors.entropy import EntropyDetector


_DETECTOR = EntropyDetector()


def _matches(text: str) -> list[str]:
    return [text[s.start:s.end] for s in _DETECTOR.detect(text)
            if s.category is Category.CREDENTIAL]


def test_query_socket_io_sid_caught():
    text = "GET wss://example.com/socket.io/?EIO=4&transport=websocket&sid=Yp_crOiZaE3qykxGAAAE"
    matched = _matches(text)
    assert any("Yp_crOiZaE3qykxGAAAE" in m for m in matched), matched


def test_query_random_token_caught():
    # 22 chars random, mid-entropy; should fire.
    text = "GET https://api.example.com/v1?token=Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh"
    matched = _matches(text)
    assert any("Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh" in m for m in matched), matched


def test_query_short_value_skipped():
    text = "GET https://api.example.com/v1?id=42"
    assert _matches(text) == []


def test_query_value_with_file_extension_skipped():
    # Bundle filename in a query value -- not a credential.
    text = "GET https://cdn.example.com/static?file=MaterialIcons-Regular-6R3D3MIQ.woff2"
    assert _matches(text) == []


def test_cookie_value_caught():
    text = "Set-Cookie: session=abcXYZ123_987654321ZZ; Path=/"
    matched = _matches(text)
    assert any("abcXYZ123_987654321ZZ" in m for m in matched), matched


def test_json_credential_key_value_caught():
    text = '{"access_token":"Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii","scope":"read"}'
    matched = _matches(text)
    assert any("Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii" in m for m in matched), matched


def test_json_non_credential_key_skipped():
    # Same value under a non-credential key -- should not fire.
    text = '{"product_name":"Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii","price":1480}'
    assert _matches(text) == []


def test_pentect_placeholder_not_treated_as_secret():
    # The placeholder hash itself is high-entropy looking but must never
    # be flagged.
    text = "GET https://api.example.com/?token=<<CREDENTIAL_8b6cf4fd>>"
    assert _matches(text) == []


def test_lowercase_word_skipped():
    # "configuration" / "implementation" etc. look fine but aren't secrets.
    text = "GET https://api.example.com/?topic=configurationmanagement"
    assert _matches(text) == []
