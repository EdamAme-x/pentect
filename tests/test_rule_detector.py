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
