"""Rule-based detector using high-confidence regex patterns.

Targets secrets common in pentest context: JWT, API keys, internal IPs, internal hostnames, etc.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from engine.categories import Category
from engine.detectors.base import Span


@dataclass(frozen=True)
class Rule:
    category: Category
    pattern: re.Pattern[str]
    name: str


def _compile(p: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(p, flags)


# known token / key formats
JWT_RE = _compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
AWS_AKID_RE = _compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_PAT_RE = _compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
SLACK_TOKEN_RE = _compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b")
GOOGLE_API_RE = _compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
# AWS Secret Access Key: 40 chars base64-ish, context-anchored to avoid false positives.
AWS_SECRET_RE = _compile(
    r"(?i)(?:aws[_-]?secret(?:[_-]?access)?[_-]?key)\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"
)
GENERIC_BEARER_RE = _compile(r"(?i)Bearer\s+([A-Za-z0-9._\-]{20,})")
GENERIC_API_KEY_RE = _compile(
    r"(?i)(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.\/+=]{12,})[\"']?"
)
# Credentials embedded in connection URLs: scheme://user:password@host
URL_CRED_RE = _compile(
    r"(?i)[a-z][a-z0-9+\-.]*://[^\s:/@]+:([^@\s/]{4,})@"
)
# session / auth cookie values inside HAR JSON
HAR_COOKIE_VALUE_RE = _compile(
    r"\"name\"\s*:\s*\"(?:session|sess|sid|auth|token|access[_-]?token|refresh[_-]?token|jsessionid|phpsessid|csrftoken)\"\s*,\s*\"value\"\s*:\s*\"([^\"]{8,})\"",
    re.IGNORECASE,
)
# raw HTTP headers: Cookie: / Set-Cookie: sensitive-name=value
RAW_COOKIE_RE = _compile(
    r"(?im)(?:^|[>\s])(?:Set-)?Cookie:\s*[^\r\n]*?\b(?:session|sess|sid|auth|token|access[_-]?token|refresh[_-]?token|jsessionid|phpsessid|csrftoken)=([^;\s]{8,})",
)

# URL / host
URL_RE = _compile(r"https?://([A-Za-z0-9\-._]+)(:[0-9]+)?(/[^\s\"'<>]*)?")
# heuristic: internal-looking hostnames (including RFC1918)
INTERNAL_HOST_HINT = re.compile(
    r"(?:\.corp\b|\.internal\b|\.local\b|\.lan\b|\.intra(?:net)?\b|\.test\b)",
    re.IGNORECASE,
)

# IP / email
IPV4_RE = _compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
EMAIL_RE = _compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


_CREDENTIAL_RULES: list[Rule] = [
    Rule(Category.CREDENTIAL, JWT_RE, "jwt"),
    Rule(Category.CREDENTIAL, AWS_AKID_RE, "aws_akid"),
    Rule(Category.CREDENTIAL, GITHUB_PAT_RE, "github_pat"),
    Rule(Category.CREDENTIAL, SLACK_TOKEN_RE, "slack_token"),
    Rule(Category.CREDENTIAL, GOOGLE_API_RE, "google_api_key"),
]

_CAPTURING_CREDENTIAL_RULES: list[Rule] = [
    Rule(Category.CREDENTIAL, AWS_SECRET_RE, "aws_secret"),
    Rule(Category.CREDENTIAL, URL_CRED_RE, "url_embedded_cred"),
]


def _is_private_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _is_internal_host(host: str) -> bool:
    if INTERNAL_HOST_HINT.search(host):
        return True
    # single-label hostname (e.g. "intranet") treated as internal
    if "." not in host:
        return True
    return False


class RuleDetector:
    name = "rule"

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []

        for rule in _CREDENTIAL_RULES:
            for m in rule.pattern.finditer(text):
                spans.append(
                    Span(start=m.start(), end=m.end(), category=rule.category, source=self.name)
                )

        for rule in _CAPTURING_CREDENTIAL_RULES:
            for m in rule.pattern.finditer(text):
                spans.append(
                    Span(
                        start=m.start(1),
                        end=m.end(1),
                        category=rule.category,
                        source=self.name,
                    )
                )

        for m in GENERIC_BEARER_RE.finditer(text):
            # mask only the token value (group 1), not the "Bearer" keyword
            spans.append(
                Span(
                    start=m.start(1),
                    end=m.end(1),
                    category=Category.CREDENTIAL,
                    source=self.name,
                )
            )

        for m in GENERIC_API_KEY_RE.finditer(text):
            spans.append(
                Span(
                    start=m.start(1),
                    end=m.end(1),
                    category=Category.CREDENTIAL,
                    source=self.name,
                )
            )

        for m in HAR_COOKIE_VALUE_RE.finditer(text):
            spans.append(
                Span(
                    start=m.start(1),
                    end=m.end(1),
                    category=Category.CREDENTIAL,
                    source=self.name,
                )
            )

        for m in RAW_COOKIE_RE.finditer(text):
            spans.append(
                Span(
                    start=m.start(1),
                    end=m.end(1),
                    category=Category.CREDENTIAL,
                    source=self.name,
                )
            )

        for m in IPV4_RE.finditer(text):
            try:
                ipaddress.ip_address(m.group(0))
            except ValueError:
                continue
            cat = (
                Category.INTERNAL_IP
                if _is_private_ip(m.group(0))
                else Category.EXTERNAL_IP
            )
            spans.append(
                Span(
                    start=m.start(),
                    end=m.end(),
                    category=cat,
                    source=self.name,
                )
            )

        url_spans_ranges: list[tuple[int, int]] = []
        for m in URL_RE.finditer(text):
            host = m.group(1) or ""
            if _is_internal_host(host):
                # emit full URL span; granularity controller will decompose it
                spans.append(
                    Span(
                        start=m.start(),
                        end=m.end(),
                        category=Category.INTERNAL_URL,
                        source=self.name,
                    )
                )
                url_spans_ranges.append((m.start(), m.end()))

        # bare hostnames not already inside a URL span (e.g. foo.corp.internal)
        BARE_HOST_RE = re.compile(
            r"\b[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*"
            r"\.(?:corp|internal|local|lan|intranet|intra|test)\b",
            re.IGNORECASE,
        )
        for m in BARE_HOST_RE.finditer(text):
            start, end = m.start(), m.end()
            if any(us <= start and end <= ue for us, ue in url_spans_ranges):
                continue
            spans.append(
                Span(start=start, end=end, category=Category.INTERNAL_URL, source=self.name)
            )

        for m in EMAIL_RE.finditer(text):
            spans.append(
                Span(
                    start=m.start(),
                    end=m.end(),
                    category=Category.PII_EMAIL,
                    source=self.name,
                )
            )

        return spans
