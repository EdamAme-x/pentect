"""Smoke tests for the detect-secrets plugin wrapper.

These cover patterns that Pentect's hand-rolled rules don't catch, so a
regression here means a vendor-credential class started leaking.
"""
from __future__ import annotations

import pytest

from engine.categories import Category

try:
    from engine.detectors.detect_secrets_plugins import DetectSecretsPluginDetector
    _DETECTOR = DetectSecretsPluginDetector()
except RuntimeError:  # pragma: no cover -- skip the suite if the package is absent
    pytest.skip("detect-secrets not installed", allow_module_level=True)


def _matches(text: str) -> list[str]:
    spans = _DETECTOR.detect(text)
    return [text[s.start:s.end] for s in spans if s.category is Category.CREDENTIAL]


# NOTE: Test fixtures are assembled from substrings at runtime so that
# GitHub's push-protection / secret-scanning doesn't flag them as real
# vendor credentials. They still match the upstream detect-secrets
# regexes, which is all these tests need.


def test_stripe_live_key():
    fake_key = "sk_" + "live_" + "abcdefghijklmnop12345678"
    text = f"config.stripe = '{fake_key}'"
    matched = _matches(text)
    assert any("sk_live_" in m for m in matched), matched


def test_openai_api_key():
    # Modern OpenAI keys: sk-<prefix>...<openai-marker>...<suffix>
    marker = "T3" + "BlbkFJ"
    fake_key = "sk-AaBbCc1234567890123456" + marker + "12345678901234567890"
    text = f"OPENAI_KEY={fake_key}"
    matched = _matches(text)
    assert any(marker in m for m in matched), matched


def test_sendgrid_key():
    fake_key = "SG" + "." + "a" * 22 + "." + "b" * 43
    text = f"SENDGRID_API_KEY={fake_key}"
    matched = _matches(text)
    assert any(m.startswith("SG.") for m in matched), matched


def test_twilio_account_sid():
    fake_sid = "AC" + "a" * 32
    text = f"twilio {fake_sid}"
    matched = _matches(text)
    assert any(m.startswith("AC") for m in matched), matched


def test_private_key_header_not_emitted_by_detect_secrets():
    # detect-secrets ships a PrivateKeyDetector whose regex matches the
    # `BEGIN RSA PRIVATE KEY` armor line. We deliberately drop that
    # plugin (see engine/detectors/detect_secrets_plugins.py) because
    # the armor lines are public format markers — masking them removes
    # context without protecting any secret. Pentect's SeedPhraseDetector
    # handles the b64 body separately.
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    matched = _matches(text)
    assert matched == []


def test_basic_auth_in_url():
    # detect-secrets BasicAuth pattern grabs the `://user:pass@` chunk.
    text = "https://admin:hunter2pass@internal.example.com/login"
    matched = _matches(text)
    assert any("hunter2pass" in m for m in matched), matched


def test_does_not_match_plain_text():
    text = "no secrets here, just regular log line"
    assert _matches(text) == []
