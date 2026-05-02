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
# OpenAI API keys: sk-... (legacy) and sk-proj-... / sk-svcacct-... (newer).
# Length varies by key type but always >= 30 chars after the `sk-` prefix.
OPENAI_KEY_RE = _compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{30,}\b")
# Google OAuth Client ID format: <digits>-<32 lower-alnum>.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_ID_RE = _compile(
    r"\b[0-9]{6,}-[a-z0-9]{20,}\.apps\.googleusercontent\.com\b"
)
# Keybase user URL: keybase.io/<username> -- identifies a person.
# We mask only the username segment so the keybase.io domain stays readable
# (keybase.io itself is public, the leak is which person owns the account).
KEYBASE_USER_RE = _compile(
    r"\bkeybase\.io/(?P<handle>[A-Za-z0-9_]{2,32})\b"
)
# GitHub owner / org / repo path: github.com/<owner>(/<repo>)? -- identifies
# a project or a person. Mask owner and repo as separate handles; the
# github.com host stays readable so the masked output still tells the reader
# this is a GitHub link.
GITHUB_OWNER_REPO_RE = _compile(
    r"\bgithub\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))"
    r"(?:/(?P<repo>[A-Za-z0-9._-]{1,100}))?\b"
)
# Social handles in URL form: twitter.com/<user>, x.com/<user>, linkedin.com/in/<user>.
# Skip well-known non-handle landing paths (twitter.com/intent etc).
SOCIAL_HANDLE_URL_RE = _compile(
    r"\b(?:twitter\.com|x\.com|linkedin\.com/(?:in|company))/(?!intent\b|share\b|home\b)"
    r"(?P<handle>[A-Za-z0-9._-]{2,40})\b"
)
# Bare "@handle" form -- common in OSS license headers / changelogs / social
# attribution ("by @davegandy", "thanks @torvalds").
# We require a leading whitespace or "by " so we don't fire on:
#   - email local parts ("user@example.com" — char before @ is not space)
#   - decorators ("@property" — leading char is `\n` but `property` is a
#     reserved Python keyword which we exclude via length+stoplist below)
#   - JSON keys ('"@type"' — preceded by a quote)
SOCIAL_HANDLE_AT_RE = _compile(
    r"(?:^|(?<=\s)|(?<=by\s))@(?P<handle>[A-Za-z][A-Za-z0-9_]{2,29})\b"
)
# OSS license / banner block: /*! ... */ — a CSS/JS convention that wraps
# attribution headers. Hosts, project names, and emails in here can identify
# the author or the project; we mask all of them indiscriminately. The
# upstream caller can always undo a mask with MaskResult.recover(...) when
# context is needed, so the policy is "if in doubt, mask" rather than
# maintain an OSS allowlist.
_LICENSE_BANNER_RE = _compile(r"/\*!.*?\*/", re.DOTALL)
_BANNER_URL_HOST_RE = _compile(
    r"https?://(?P<host>[A-Za-z0-9._-]+)(?:[/:][^\s]*)?",
    re.IGNORECASE,
)
# Banner copyright holder: `(c) 2018 Twitter, Inc.`, `Copyright 2014 Foo Bar`.
# Captures the entity name that follows a copyright marker + year. Stops at
# end-of-line, period, comma, pipe, or another copyright clause.
_BANNER_COPYRIGHT_RE = _compile(
    r"(?:\(c\)|©|Copyright(?:\s+\(c\))?)\s*\d{4}(?:\s*[-–]\s*\d{4})?\s+"
    r"(?P<holder>[A-Z][A-Za-z0-9.&]*(?:\s+[A-Z][A-Za-z0-9.&]*){0,5}?)"
    r"(?=\s*(?:[,.|\n;:*]|$|Inc\b|LLC\b|Ltd\b|Foundation\b|Project\b))",
    re.IGNORECASE,
)
# Banner project / product name: `Bootstrap`, `Animate.css`, `Font Awesome`,
# `jQuery`. Captured at the start of a banner line (after the leading `/*!`,
# `*`, or whitespace). Stops at version markers (`v3.1.1`), parentheses,
# pipes, dashes, and version-y characters so we don't swallow the whole
# header line.
_BANNER_PROJECT_RE = _compile(
    r"(?:^|\n)\s*(?:/\*!|\*)?\s*"
    r"(?P<name>[A-Z][A-Za-z0-9]+(?:[. ][A-Za-z0-9]+){0,3})"
    r"(?=\s+(?:v?\d|\(|\||-|by\b|version\b))",
    re.IGNORECASE,
)

# Names that look like @handle but are language keywords / well-known
# decorators / well-known npm-scope-like words. Filtered post-match so the
# regex stays simple.
_AT_HANDLE_STOPLIST: frozenset[str] = frozenset({
    "property", "staticmethod", "classmethod", "abstractmethod",
    "override", "deprecated", "param", "return", "returns", "throws",
    "see", "since", "version", "author", "license", "private", "public",
    "protected", "internal", "deprecated", "todo", "todos", "fixme",
    "type", "typedef", "interface", "namespace", "module", "package",
    "import", "export", "default", "this", "super", "self",
    "media", "import", "supports", "keyframes", "font", "charset",
    "Component", "Injectable", "NgModule", "Input", "Output",
})
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
    # Two alternations:
    #   - api_key / apikey / secret / token  (>= 12 chars from charset)
    #   - password / passwd / pwd            (>= 6 chars, broader symbol set)
    # The optional [\"']? blocks bracketing the value let the same pattern
    # cover plain `key=value`, JSON `"key":"value"`, and YAML `key: "value"`.
    r"[\"']?(?:api[_-]?key|apikey|secret|token)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.\/+=]{12,})[\"']?"
    r"|[\"']?(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.\/+=!@#$%^&*()]{6,})[\"']?",
    re.IGNORECASE,
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
    # Allow zero/one backslash before the quotes so this still fires when the
    # input is a HAR body (where the inner JSON is escaped: \"id\": 1001).
    r'\\?"(?P<key>[A-Za-z_][A-Za-z0-9_]*[Ii]d|id|userId|user_id|basket_id|order_id|account_id|customer_id|product_id)\\?"\s*:\s*(?P<val>[0-9]+)'
)
# Domain/host appears as a string value under host-shaped JSON keys.
# Catches `"domain":"juice-sh.op"` / `"host":"corp.local"` and the HAR-escaped
# variants (\"domain\":\"...\").
JSON_HOST_KEY_RE = _compile(
    r'\\?"(?P<key>domain|host|hostname|server|origin)\\?"\s*:\s*\\?"(?P<val>[A-Za-z0-9][A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,32})\\?"'
)

# HTML form attributes that carry user input back into rendered HTML
# (e.g. login form re-rendered with the typed password as `value="..."`).
# Allow optional backslashes around the quotes so this still fires inside
# HAR-escaped JSON content bodies. The "name" attribute tells us what kind
# of credential it is.
HTML_FORM_VALUE_RE = _compile(
    r'name=\\?["\'](?P<key>username|user|email|password|passwd|pwd|matchingPassword|new_password|confirm_password|token|api_key|secret|csrf|csrf_token)\\?["\']\s*'
    r'value=\\?["\'](?P<val>[^"\'\\<>]{3,256})\\?["\']',
    re.IGNORECASE,
)
# Same shape but with attributes in the opposite order (value before name).
HTML_FORM_VALUE_REV_RE = _compile(
    r'value=\\?["\'](?P<val>[^"\'\\<>]{3,256})\\?["\']\s*'
    r'name=\\?["\'](?P<key>username|user|email|password|passwd|pwd|matchingPassword|new_password|confirm_password|token|api_key|secret|csrf|csrf_token)\\?["\']',
    re.IGNORECASE,
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
    Rule(Category.CREDENTIAL, OPENAI_KEY_RE, "openai_key"),
    Rule(Category.CREDENTIAL, GOOGLE_OAUTH_CLIENT_ID_RE, "google_oauth_client_id"),
]

# Public-handle rules. Each pattern names one or more capture groups and we
# emit one span per named group. The host portion stays unmasked (e.g.
# "github.com/<<PII_HANDLE_xxx>>/<<PII_HANDLE_yyy>>") so the reader can still
# tell the link goes to a known platform.
_HANDLE_RULES: list[Rule] = [
    Rule(Category.PII_HANDLE, KEYBASE_USER_RE, "keybase_user"),
    Rule(Category.PII_HANDLE, GITHUB_OWNER_REPO_RE, "github_owner_repo"),
    Rule(Category.PII_HANDLE, SOCIAL_HANDLE_URL_RE, "social_handle_url"),
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

        # Public handles: emit one span per named group so a github.com/owner/repo
        # path becomes "github.com/<<PII_HANDLE_xxx>>/<<PII_HANDLE_yyy>>".
        for rule in _HANDLE_RULES:
            for m in rule.pattern.finditer(text):
                for name in m.groupdict():
                    if m.group(name) is None:
                        continue
                    spans.append(
                        Span(
                            start=m.start(name),
                            end=m.end(name),
                            category=rule.category,
                            source=self.name,
                        )
                    )

        # OSS license banner: every URL host inside a /*! ... */ block is
        # masked unconditionally; the project name on the header line is
        # masked too. Pure-IP hosts are skipped here because the IPv4 rule
        # above already handles them.
        for banner in _LICENSE_BANNER_RE.finditer(text):
            block = banner.group(0)
            block_start = banner.start()
            for um in _BANNER_URL_HOST_RE.finditer(block):
                host = (um.group("host") or "").rstrip(".")
                if not host:
                    continue
                if all(c.isdigit() or c == "." for c in host):
                    continue
                spans.append(
                    Span(
                        start=block_start + um.start("host"),
                        end=block_start + um.end("host"),
                        category=Category.PII_HANDLE,
                        source=self.name,
                    )
                )
            for pm in _BANNER_PROJECT_RE.finditer(block):
                spans.append(
                    Span(
                        start=block_start + pm.start("name"),
                        end=block_start + pm.end("name"),
                        category=Category.PII_HANDLE,
                        source=self.name,
                    )
                )
            for cm in _BANNER_COPYRIGHT_RE.finditer(block):
                spans.append(
                    Span(
                        start=block_start + cm.start("holder"),
                        end=block_start + cm.end("holder"),
                        category=Category.PII_HANDLE,
                        source=self.name,
                    )
                )

        # Bare "@handle" attribution form (CSS / JS / changelog headers).
        for m in SOCIAL_HANDLE_AT_RE.finditer(text):
            handle = m.group("handle")
            if handle.lower() in _AT_HANDLE_STOPLIST:
                continue
            if handle in _AT_HANDLE_STOPLIST:
                continue
            spans.append(
                Span(
                    start=m.start("handle"),
                    end=m.end("handle"),
                    category=Category.PII_HANDLE,
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
        # Keys whose value identifies a *person/account* go to USER_ID, the
        # rest (issue id, order id, basket id, generic "id", ...) go to
        # RESOURCE_ID. Both end up hashed identically; the separation is for
        # readability of the masked output.
        _USER_ID_KEYS = {"user_id", "userid", "customer_id", "customerid",
                         "account_id", "accountid", "owner_id", "ownerid"}
        for m in JSON_ID_KEY_RE.finditer(text):
            key_lower = m.group("key").lower()
            if key_lower in _NON_ID_KEYS:
                continue
            cat = Category.USER_ID if key_lower in _USER_ID_KEYS else Category.RESOURCE_ID
            spans.append(
                Span(
                    start=m.start("val"),
                    end=m.end("val"),
                    category=cat,
                    source=self.name,
                )
            )

        # Hostname / domain captured directly from JSON. This is what catches
        # the `"application":{"domain":"juice-sh.op"}` shape that the FT
        # classifier doesn't generalise to (only specific INTERNAL_HOST_HINT
        # TLDs like .corp / .local trigger the URL-side path).
        for m in JSON_HOST_KEY_RE.finditer(text):
            spans.append(
                Span(
                    start=m.start("val"),
                    end=m.end("val"),
                    category=Category.INTERNAL_URL,
                    source=self.name,
                )
            )

        # HTML form values that re-render the user's typed credentials.
        # WebGoat (Spring Boot) shows this on the login / registration page
        # after a failed submission: `<input name="password" value="...">`.
        _USER_KEYS = {"username", "user", "email"}
        for re_obj in (HTML_FORM_VALUE_RE, HTML_FORM_VALUE_REV_RE):
            for m in re_obj.finditer(text):
                key = m.group("key").lower()
                cat = Category.USER_ID if key in _USER_KEYS else Category.CREDENTIAL
                spans.append(
                    Span(
                        start=m.start("val"),
                        end=m.end("val"),
                        category=cat,
                        source=self.name,
                    )
                )

        for m in GENERIC_API_KEY_RE.finditer(text):
            # The pattern has two alternations (api_key/token vs
            # password/passwd/pwd) with separate capture groups.
            grp = 1 if m.group(1) is not None else 2
            spans.append(
                Span(
                    start=m.start(grp),
                    end=m.end(grp),
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
