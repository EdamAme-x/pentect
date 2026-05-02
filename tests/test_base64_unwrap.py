"""Tests for the base64-unwrap detector.

The adversarial case here is "wrap a real secret in base64 so the rule
detector and the FT model both miss it". The detector must:

- catch Authorization: Basic <b64>
- catch a stand-alone base64 chunk that decodes to credential-shaped text
- catch nested base64 wrapping
- NOT fire on base64 of plain non-credential prose
"""
from __future__ import annotations

import base64
import json

from engine.categories import Category
from engine.detectors.base64_unwrap import Base64UnwrapDetector


def _detect(text: str) -> list[tuple[str, str]]:
    spans = Base64UnwrapDetector().detect(text)
    return [(text[s.start:s.end], s.category.name) for s in spans]


def test_basic_auth_b64_is_masked():
    text = "Authorization: Basic " + base64.b64encode(b"admin:Hunter2pass!").decode()
    hits = _detect(text)
    assert hits, "Authorization: Basic <b64> should always be flagged"
    assert all(cat == Category.CREDENTIAL.value for _, cat in hits)


def test_b64_wrapped_api_key_caught():
    # Real-shape Google API key: AIza + 35 chars = 39 chars total.
    key = "AIza" + "SyD1234567890abcdefghij_klmnopQRSTUVx"[:35]
    assert len(key) == 39
    payload = base64.b64encode(key.encode()).decode()
    hits = _detect(payload)
    assert hits, "base64 of an AIza-prefixed key must be caught"


def test_b64_wrapped_db_url_caught():
    payload = base64.b64encode(b"postgres://admin:Hunter2pass!@db.corp.internal:5432/prod").decode()
    hits = _detect(payload)
    assert hits, "base64 of a postgres:// URL must be caught"


def test_b64_wrapped_json_creds_caught():
    payload = base64.b64encode(json.dumps({
        "user": "alice",
        "password": "Hunter2pass!",
    }).encode()).decode()
    hits = _detect(payload)
    assert hits, "base64 of JSON credentials must be caught"


def test_double_b64_caught():
    inner = base64.b64encode(b"sk-" + b"X" * 40)
    payload = base64.b64encode(inner).decode()
    hits = _detect(payload)
    assert hits, "base64 nested twice should still surface the credential"


def test_random_text_is_not_credential():
    # Prose that contains no credential hint should not fire.
    payload = base64.b64encode(b"lorem ipsum dolor sit amet consectetur").decode()
    hits = _detect(payload)
    assert not hits, f"plain prose should not be flagged, got {hits}"


def test_url_safe_b64_caught():
    payload = base64.urlsafe_b64encode(b"Bearer eyJabc.def.ghi" + b"X" * 30).decode()
    hits = _detect(payload)
    assert hits, "url-safe base64 of a Bearer token should be caught"
