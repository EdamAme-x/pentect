"""Tests for the encoding-peel detectors (URL encoding, ...) and the
HAR-body base64 pre-pass."""
from __future__ import annotations

import base64
import json
import urllib.parse

import pytest

from engine.categories import Category
from engine.core import PentectEngine, _decode_har_body_base64
from engine.detectors.encoding_peel import UrlEncodingPeeler


# ---------------------------------------------------------------------------
# UrlEncodingPeeler
# ---------------------------------------------------------------------------


def _matches(text: str) -> list[str]:
    return [text[s.start:s.end] for s in UrlEncodingPeeler().detect(text)
            if s.category is Category.CREDENTIAL]


def test_authorization_header_url_encoded():
    """A JWT hidden behind percent-encoding must be caught."""
    plain = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MTAwMSJ9.s5fak3sIg"
    encoded = urllib.parse.quote(plain)
    hits = _matches(encoded)
    assert hits, "URL-encoded JWT not caught"


def test_random_percent_run_does_not_fire():
    """A few %20 in a sentence isn't a credential — peers must say so."""
    text = "lorem%20ipsum%20dolor%20sit%20amet"
    assert _matches(text) == []


def test_short_percent_run_with_creds_caught():
    """%20-only separator before a Bearer token + JWT."""
    text = "X-Custom:%20Bearer%20eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1IjogIjEifQ.s5fak3sIg"
    assert _matches(text)


def test_single_percent_does_not_match():
    """We require at least 2 consecutive %XX runs (one stray % is noise)."""
    text = "use 50% off coupon"
    assert _matches(text) == []


# ---------------------------------------------------------------------------
# End-to-end via the engine
# ---------------------------------------------------------------------------


class TestEngineWithUrlEncoding:
    def test_engine_masks_url_encoded_jwt(self):
        plain = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MTAwMSJ9.s5fak3sIg"
        encoded = urllib.parse.quote(plain)
        res = PentectEngine(backend="rule").mask_text(encoded)
        assert "CREDENTIAL" in res.summary["by_category"]
        # Encoded blob should be fully replaced, not just the JWT part.
        assert "%20" not in res.masked_text or "<<CREDENTIAL_" in res.masked_text


# ---------------------------------------------------------------------------
# HAR base64 pre-pass
# ---------------------------------------------------------------------------


class TestHarBase64PrePass:
    def test_body_decoded_in_place(self):
        body = '{"token":"Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj"}'
        encoded = base64.b64encode(body.encode()).decode()
        data = {
            "log": {"entries": [{
                "response": {"content": {
                    "encoding": "base64",
                    "text": encoded,
                }},
            }]}
        }
        _decode_har_body_base64(data)
        out = data["log"]["entries"][0]["response"]["content"]
        assert out["text"] == body
        assert out["encoding"] == ""

    def test_non_base64_body_left_alone(self):
        data = {
            "log": {"entries": [{
                "response": {"content": {
                    "encoding": "",
                    "text": '{"k":"v"}',
                }},
            }]}
        }
        _decode_har_body_base64(data)
        assert data["log"]["entries"][0]["response"]["content"]["text"] == '{"k":"v"}'

    def test_malformed_base64_does_not_crash(self):
        data = {
            "log": {"entries": [{
                "response": {"content": {
                    "encoding": "base64",
                    "text": "!!!not_base64!!!",
                }},
            }]}
        }
        # Must not raise. Whether the body is decoded or left alone is
        # implementation detail; we only require it doesn't crash.
        _decode_har_body_base64(data)

    def test_engine_masks_credentials_inside_base64_body(self):
        """End-to-end: a HAR with a base64-encoded response body that
        contains a credential should produce a masked output where
        the credential is gone."""
        body_text = (
            '{"access_token":"Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj"}'
        )
        encoded = base64.b64encode(body_text.encode()).decode()
        har = json.dumps({
            "log": {
                "version": "1.2",
                "creator": {"name": "t", "version": "0"},
                "entries": [{
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/me",
                        "headers": [], "queryString": [], "cookies": [],
                    },
                    "response": {
                        "status": 200, "headers": [], "cookies": [],
                        "content": {
                            "mimeType": "application/json",
                            "encoding": "base64",
                            "text": encoded,
                        },
                    },
                }],
            }
        })
        res = PentectEngine(backend="rule").mask_har(har)
        out = json.loads(res.masked_text)
        body_out = out["log"]["entries"][0]["response"]["content"]["text"]
        # The credential token must not survive verbatim.
        assert "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj" not in body_out
        # And the encoded blob shouldn't still be base64 — pre-pass
        # has converted it to readable text + placeholder.
        assert "<<" in body_out
