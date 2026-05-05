"""Regressions pinned as tests so that bugs we already fixed can't
silently come back.

Each test names the symptom it's pinning and the commit / context in
which it was first observed. When one of these breaks, the bisect
tells you exactly which behavioural contract regressed.
"""
from __future__ import annotations

import json
import os

import pytest

from engine.categories import Category
from engine.core import PentectEngine, _looks_like_static_asset
from engine.detectors.rule import RuleDetector
from engine.detectors.spacy_ner import SpacyNERDetector  # noqa: F401  (import-only)


# ---------------------------------------------------------------------------
# WebGoat boundary bug: opf_pf labelled `8089/WebGo` (a slice of a URL
# host:port + path prefix) as a CREDENTIAL, leaving `at/plugins` exposed.
# Fix: the opf_pf wrapper drops CREDENTIAL spans whose value contains
# `/`, since real credentials never carry slashes.
# ---------------------------------------------------------------------------


def test_credential_span_with_slash_dropped_in_opf_pf_wrapper():
    """The opf_pf post-filter must reject CREDENTIAL spans containing
    `/`. We reach into the helper directly to avoid loading the FT
    checkpoint."""
    from types import SimpleNamespace
    from engine.detectors.opf_pf import PrivacyFilterDetector

    text = "http://10.0.0.1:8089/WebGoat/plugins"
    fake_result = SimpleNamespace(
        detected_spans=[
            SimpleNamespace(label="secret", start=15, end=25),  # "8089/WebGo"
        ]
    )
    # Bypass __init__ so we don't need the FT checkpoint loaded here.
    instance = PrivacyFilterDetector.__new__(PrivacyFilterDetector)
    spans = instance._spans_from_result(text, fake_result)
    assert spans == [], (
        "CREDENTIAL span containing `/` should be dropped — "
        "see WebGoat boundary bug in CHANGELOG / commit 6b2979a"
    )


# ---------------------------------------------------------------------------
# github.com/twbs/bootstrap: previously emitted as a single CREDENTIAL
# span, which both over-masked the host and produced anchors that ate
# into unrelated strings. Fix: PII_HANDLE category, owner+repo split,
# host stays readable.
# ---------------------------------------------------------------------------


def test_github_owner_repo_split_into_pii_handle():
    text = "see https://github.com/twbs/bootstrap/blob/master/LICENSE"
    spans = RuleDetector().detect(text)
    handles = [text[s.start:s.end] for s in spans
               if s.category is Category.PII_HANDLE]
    assert "twbs" in handles
    assert "bootstrap" in handles
    # Host must NOT be tagged as a handle; it stays readable in the
    # masked output.
    assert "github.com" not in handles


# ---------------------------------------------------------------------------
# Allowlist removal: the OSS host allowlist (github.com, getbootstrap.com,
# fontawesome.io, etc.) was deleted because maintaining it was a tax
# we never won back. Inside a /*! ... */ banner, every host is masked
# uniformly. Confirms the allowlist is GONE — if someone reintroduces
# one, this fails.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host", [
    "github.com", "opensource.org", "getbootstrap.com",
    "fontawesome.io", "fonts.gstatic.com",
])
def test_banner_host_uniformly_masked_no_allowlist(host: str):
    text = f"/*! See license at https://{host}/license */"
    spans = RuleDetector().detect(text)
    handle_values = [text[s.start:s.end] for s in spans
                     if s.category is Category.PII_HANDLE]
    assert host in handle_values, (
        f"banner host {host!r} should be masked indiscriminately "
        "(no allowlist)"
    )


# ---------------------------------------------------------------------------
# base64-wrapped credentials: an adversarial-but-trivial pattern where
# the secret is base64-encoded before being placed in the body. The
# unwrap detector hands the plaintext to peers; if any peer flags it,
# the encoded blob becomes a CREDENTIAL. Pinned so the unwrap path
# stays in place even if peers' rules change.
# ---------------------------------------------------------------------------


def test_base64_basic_auth_caught():
    import base64
    payload = "Authorization: Basic " + base64.b64encode(
        b"admin:Hunter2pass!"
    ).decode()
    eng = PentectEngine(backend="rule")
    res = eng.mask_text(payload)
    assert "CREDENTIAL" in res.summary["by_category"]


def test_base64_db_url_caught():
    import base64
    inner = b"postgres://admin:Hunter2pass!@db.corp.internal:5432/prod"
    payload = base64.b64encode(inner).decode()
    eng = PentectEngine(backend="rule")
    res = eng.mask_text(payload)
    assert res.summary["total_masked"] > 0


# ---------------------------------------------------------------------------
# spaCy NER opt-in: the detector must NOT be present in the chain by
# default. PENTECT_ENABLE_SPACY=1 is the only way it appears. This
# pins the deprecation/perf decision (spaCy adds 5-6x runtime, ~zero
# unique catches on real HARs).
# ---------------------------------------------------------------------------


def test_spacy_off_by_default(monkeypatch):
    monkeypatch.delenv("PENTECT_ENABLE_SPACY", raising=False)
    eng = PentectEngine(backend="rule")
    names = [d.__class__.__name__ for d in eng.detectors]
    assert "SpacyNERDetector" not in names


@pytest.mark.parametrize("flag", ["1", "true", "yes"])
def test_spacy_on_with_env(monkeypatch, flag):
    monkeypatch.setenv("PENTECT_ENABLE_SPACY", flag)
    eng = PentectEngine(backend="rule")
    names = [d.__class__.__name__ for d in eng.detectors]
    assert "SpacyNERDetector" in names


# ---------------------------------------------------------------------------
# STATIC_ASSET pre-pass: response bodies that look like a CDN asset
# (mimeType + URL suffix) get replaced with one placeholder before
# detectors run. The detectors never see those bytes; the recovery
# map carries the original content for local use.
# ---------------------------------------------------------------------------


def test_looks_like_static_asset_by_url_suffix():
    assert _looks_like_static_asset("https://cdn.example.com/app.js", "")
    assert _looks_like_static_asset("https://cdn.example.com/style.css", "")
    assert _looks_like_static_asset("https://cdn.example.com/font.woff2", "")
    assert _looks_like_static_asset("/assets/logo.png?v=2", "")
    # API endpoint — not an asset.
    assert not _looks_like_static_asset("/api/items/42", "application/json")


def test_looks_like_static_asset_by_mime():
    assert _looks_like_static_asset("/anything", "image/png")
    assert _looks_like_static_asset("/anything", "text/css; charset=utf-8")
    assert _looks_like_static_asset("/anything", "application/javascript")
    assert not _looks_like_static_asset("/anything", "application/json")


def test_static_asset_body_collapsed_in_har():
    # Build a minimal HAR with a JS body. The body is replaced with one
    # STATIC_ASSET placeholder; the original content is recoverable.
    js_body = (
        "var Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh = 'should-not-be-scanned';\n"
        + ("function f(){return 1;}\n" * 50)
    )
    har = json.dumps({
        "log": {
            "version": "1.2",
            "creator": {"name": "t", "version": "0"},
            "entries": [{
                "request": {
                    "method": "GET",
                    "url": "https://cdn.example.com/app.js",
                    "headers": [],
                    "queryString": [],
                    "cookies": [],
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "cookies": [],
                    "content": {"mimeType": "application/javascript",
                                "text": js_body},
                },
            }],
        }
    })
    eng = PentectEngine(backend="rule")
    res = eng.mask_har(har)
    masked = json.loads(res.masked_text)
    body_out = masked["log"]["entries"][0]["response"]["content"]["text"]
    assert body_out.startswith("<<STATIC_ASSET_") and body_out.endswith(">>")
    # The original credential-shaped substring must NOT survive
    # verbatim — the whole body went into the recovery map under one
    # opaque placeholder.
    assert "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh" not in res.masked_text
    # And recover() returns the original bytes.
    recovered = res.recover(body_out)
    assert recovered == js_body


def test_static_asset_pre_pass_does_not_touch_json_responses():
    """A JSON response body should still be walked by the detectors —
    only public-CDN-looking responses skip detection."""
    har = json.dumps({
        "log": {
            "version": "1.2",
            "creator": {"name": "t", "version": "0"},
            "entries": [{
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/me",
                    "headers": [],
                    "queryString": [],
                    "cookies": [],
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "cookies": [],
                    "content": {"mimeType": "application/json",
                                "text": '{"token":"Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh"}'},
                },
            }],
        }
    })
    eng = PentectEngine(backend="rule")
    res = eng.mask_har(har)
    # The inner credential-shaped value must have been masked, not
    # collapsed — i.e. the body still contains a placeholder for the
    # token, not for the whole body.
    masked = json.loads(res.masked_text)
    body = masked["log"]["entries"][0]["response"]["content"]["text"]
    assert body.startswith('{"token":"<<')
    assert body.endswith('"}')
    assert "STATIC_ASSET" not in body
