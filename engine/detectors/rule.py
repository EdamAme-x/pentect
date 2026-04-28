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
# Google OAuth Client ID format: <digits>-<32 lower-alnum>.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_ID_RE = _compile(
    r"\b[0-9]{6,}-[a-z0-9]{20,}\.apps\.googleusercontent\.com\b"
)
# Keybase user URL: keybase.io/<username> -- identifies a person.
KEYBASE_USER_RE = _compile(r"\bkeybase\.io/[A-Za-z0-9_]{2,32}\b")
# GitHub owner / org / repo path: github.com/<owner>(/<repo>)? -- identifies
# a project or a person. Mask the whole owner+repo segment, not just the host.
GITHUB_OWNER_REPO_RE = _compile(
    r"\bgithub\.com/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[A-Za-z0-9._-]{1,100})?\b"
)
# Social handles in URL form: twitter.com/<user>, x.com/<user>, linkedin.com/in/<user>.
# Skip well-known non-handle landing paths (twitter.com/intent etc).
SOCIAL_HANDLE_URL_RE = _compile(
    r"\b(?:twitter\.com|x\.com|linkedin\.com/(?:in|company))/(?!intent\b|share\b|home\b)"
    r"[A-Za-z0-9._-]{2,40}\b"
)
# Long hex blobs: SHA1 (40) / SHA256 (64) fingerprints, git commits, API key
# digests. Some sources concatenate fingerprints back-to-back (Juice Shop's
# /rest/admin/application-configuration does this in the "supportedFingerprints"
# array), so a strict lookbehind boundary misses runs of them. Instead we
# capture any 40+ char hex run and mask each 40-char window in it.
HEX_BLOB_RE = _compile(r"[A-Fa-f0-9]{40,}")
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
# TODO: replace with FT-side coverage. The opf checkpoint is fine on free-form
# text but does not yet generalise to numeric IDs sitting under id-typed JSON
# keys (e.g. {"id": 1001}). Until the synthetic dataset has enough JSON-shaped
# samples to teach the classifier this pattern, we catch it with a rule and
# whitelist a few common non-id numeric keys to avoid over-masking.
JSON_ID_KEY_RE = _compile(
    r'"(?P<key>[A-Za-z_][A-Za-z0-9_]*[Ii]d|id|userId|user_id|basket_id|order_id|account_id|customer_id|product_id)"\s*:\s*(?P<val>[0-9]+)'
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
    Rule(Category.CREDENTIAL, GOOGLE_OAUTH_CLIENT_ID_RE, "google_oauth_client_id"),
    Rule(Category.CREDENTIAL, KEYBASE_USER_RE, "keybase_user"),
    Rule(Category.CREDENTIAL, GITHUB_OWNER_REPO_RE, "github_owner_repo"),
    Rule(Category.CREDENTIAL, SOCIAL_HANDLE_URL_RE, "social_handle_url"),
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

        # Hex blobs (concatenated SHA1/SHA256 fingerprints, git commits etc).
        # Slice each run into 40-char windows so a "supportedFingerprints"
        # array of back-to-back SHA1s gets every entry masked.
        for m in HEX_BLOB_RE.finditer(text):
            blob_start, blob_end = m.start(), m.end()
            blob_len = blob_end - blob_start
            window = 64 if blob_len >= 64 and blob_len % 64 == 0 else 40
            for off in range(0, blob_len, window):
                end = min(off + window, blob_len)
                if end - off < 40:
                    break
                spans.append(
                    Span(
                        start=blob_start + off,
                        end=blob_start + end,
                        category=Category.CREDENTIAL,
                        source=self.name,
                    )
                )

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

        # TODO: drop this rule once the FT data covers JSON-shaped numeric IDs.
        # See JSON_ID_KEY_RE definition above for context.
        _NON_ID_KEYS = {"page", "per_page", "perpage", "total", "count",
                        "qty", "quantity", "size", "limit", "offset",
                        "price", "amount", "score", "rating"}
        for m in JSON_ID_KEY_RE.finditer(text):
            if m.group("key").lower() in _NON_ID_KEYS:
                continue
            spans.append(
                Span(
                    start=m.start("val"),
                    end=m.end("val"),
                    category=Category.USER_ID,
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
