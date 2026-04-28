from engine.detectors.rule import RuleDetector
from engine.categories import Category


def test_detects_jwt():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.sig_part"
    spans = RuleDetector().detect(text)
    cats = {s.category for s in spans}
    assert Category.CREDENTIAL in cats


def test_detects_internal_host():
    text = "GET http://jira.corp.internal/api/issues/1001"
    spans = RuleDetector().detect(text)
    cats = {s.category for s in spans}
    assert Category.INTERNAL_URL in cats


def test_detects_private_ip():
    text = '"ip": "10.0.5.42"'
    spans = RuleDetector().detect(text)
    cats = {s.category for s in spans}
    assert Category.INTERNAL_IP in cats


def test_detects_email():
    text = '"reporter": "alice@corp.example"'
    spans = RuleDetector().detect(text)
    cats = {s.category for s in spans}
    assert Category.PII_EMAIL in cats


def test_detects_google_oauth_client_id():
    # Regression: this exact pattern leaked through the Juice Shop demo HAR
    # because rule.py only knew Google API keys (AIza...) and not OAuth
    # Client IDs (digits-alnum.apps.googleusercontent.com).
    text = 'oauth_client_id="1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.com"'
    spans = RuleDetector().detect(text)
    cats = {s.category for s in spans}
    assert Category.CREDENTIAL in cats
    matched = [text[s.start:s.end] for s in spans if s.category is Category.CREDENTIAL]
    assert any("apps.googleusercontent.com" in m for m in matched)
