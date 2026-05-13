"""Tests for the recovery API on MaskResult.

The recovery map lets a local caller turn a placeholder back into its
original value. It must:
  - cover every placeholder kind we emit (FULL, URL_STRUCTURED with
    host+id split, EMAIL_SPLIT_HASH, HASH_ONLY)
  - stay out of to_json() so it never gets serialized accidentally
  - work the same way for plain text masking and HAR masking
"""
from __future__ import annotations

import json

from engine.core import PentectEngine


def _engine():
    # Rule-only backend keeps these tests free of any model loading.
    return PentectEngine(backend="rule")


def test_recover_full_credential():
    # AWS access key id matches AWS_AKID_RE in rule.py.
    text = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
    eng = _engine()
    r = eng.mask_text(text)
    creds = [ph for ph, m in r.map.items() if m["category"] == "CREDENTIAL"]
    assert creds, r.masked_text
    for ph in creds:
        original = r.recover(ph)
        assert original is not None and original in text


def test_recover_split_email():
    text = "Contact: alice@corp.example for details"
    eng = _engine()
    r = eng.mask_text(text)
    locals_ = [ph for ph in r.map if "PII_EMAIL_LOCAL" in ph]
    domains = [ph for ph in r.map if "PII_EMAIL_DOMAIN" in ph]
    assert locals_ and domains
    assert r.recover(locals_[0]) == "alice"
    assert r.recover(domains[0]) == "corp.example"


def test_recover_internal_url_host_and_trailing_id():
    text = "GET http://jira.corp.internal/api/issues/1001"
    eng = _engine()
    r = eng.mask_text(text)
    host = next((ph for ph in r.map if "INTERNAL_URL_HOST" in ph), None)
    rid = next((ph for ph in r.map if ph.startswith("<<USER_ID")
                or ph.startswith("<<RESOURCE_ID")), None)
    assert host is not None and rid is not None, r.masked_text
    assert r.recover(host) == "jira.corp.internal"
    assert r.recover(rid) == "1001"


def test_recover_all_round_trips_to_original():
    text = (
        "Reporter: alice@corp.example\n"
        "Endpoint: http://jira.corp.internal/api/issues/1001\n"
        "IP: 10.0.5.42\n"
    )
    eng = _engine()
    r = eng.mask_text(text)
    restored = r.recover_all(r.masked_text)
    assert restored == text, restored


def test_recovery_map_is_not_serialized():
    text = "alice@corp.example with token AKIAIOSFODNN7EXAMPLE"
    r = _engine().mask_text(text)
    payload = json.loads(r.to_json())
    # The recovery information must never end up in to_json output.
    assert "_recovery_map" not in payload
    assert "alice" not in r.to_json()


def test_recover_returns_none_for_unknown_placeholder():
    r = _engine().mask_text("nothing sensitive here")
    assert r.recover("<<CREDENTIAL_deadbeef>>") is None


def test_har_recovery_map_includes_response_body_ids():
    har = {
        "log": {
            "entries": [{
                "request": {
                    "method": "GET",
                    "url": "http://jira.corp.internal/api/issues/1001",
                    "headers": [],
                },
                "response": {
                    "content": {
                        "text": '{"id": 1001, "reporter": "alice@corp.example"}',
                    },
                },
            }]
        }
    }
    r = _engine().mask_har(json.dumps(har))
    # host + numeric id + email split should all be recoverable.
    host = next((ph for ph in r.map if "INTERNAL_URL_HOST" in ph), None)
    email_local = next((ph for ph in r.map if "PII_EMAIL_LOCAL" in ph), None)
    assert host is not None
    assert email_local is not None
    assert r.recover(host) == "jira.corp.internal"
    assert r.recover(email_local) == "alice"
