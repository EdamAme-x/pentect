"""Granularity mode contracts.

For each Category we pin which GranularityMode it uses and what the
masked output looks like. These tests are the single source of truth
for "given this kind of value, what shape will the placeholder take".

Existing detector tests exercise rules in passing; here we go the
other way around — for a given category build a synthetic Span and
check apply_granularity produces exactly the expected shape.
"""
from __future__ import annotations

import re

import pytest

from engine.categories import Category, GranularityMode, get_spec
from engine.detectors.base import Span
from engine.granularity import (
    Replacement,
    apply_granularity,
    apply_replacements,
)


_PLACEHOLDER_RE = re.compile(r"<<([A-Z_]+)_([a-f0-9]{8})>>")


def _make_span(start: int, end: int, category: Category) -> Span:
    return Span(start=start, end=end, category=category, source="test")


def _apply(text: str, category: Category, *, start: int = 0, end: int | None = None) -> str:
    if end is None:
        end = len(text)
    span = _make_span(start, end, category)
    reps = apply_granularity(text, [span])
    return apply_replacements(text, reps)


# ---------------------------------------------------------------------------
# Category -> GranularityMode mapping. The mode chosen for each category
# is a behavioural decision; if someone changes one of these, downstream
# placeholders change shape and we should know.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("category,expected_mode", [
    (Category.CREDENTIAL, GranularityMode.CREDENTIAL_PREFIX),
    (Category.INTERNAL_URL, GranularityMode.URL_STRUCTURED),
    (Category.INTERNAL_IP, GranularityMode.FULL),
    (Category.EXTERNAL_IP, GranularityMode.FULL),
    (Category.PII_EMAIL, GranularityMode.EMAIL_SPLIT_HASH),
    (Category.PII_NAME, GranularityMode.FULL),
    (Category.USER_ID, GranularityMode.HASH_ONLY),
    (Category.RESOURCE_ID, GranularityMode.HASH_ONLY),
    (Category.PII_HANDLE, GranularityMode.HASH_ONLY),
    (Category.LIKELY_CRYPTO_ADDRESS, GranularityMode.HASH_ONLY),
    (Category.LIKELY_HASH, GranularityMode.HASH_ONLY),
    (Category.LIKELY_TOKEN, GranularityMode.HASH_ONLY),
    (Category.STATIC_ASSET, GranularityMode.HASH_ONLY),
])
def test_category_uses_expected_mode(category, expected_mode):
    assert get_spec(category).mode is expected_mode


# ---------------------------------------------------------------------------
# Output shape per category.
# ---------------------------------------------------------------------------


class TestHashOnlyCategories:
    """HASH_ONLY -> single placeholder, deterministic by SHA(value)."""

    @pytest.mark.parametrize("category", [
        Category.USER_ID,
        Category.RESOURCE_ID,
        Category.PII_HANDLE,
        Category.LIKELY_CRYPTO_ADDRESS,
        Category.LIKELY_HASH,
        Category.LIKELY_TOKEN,
        Category.STATIC_ASSET,
    ])
    def test_single_placeholder_with_category_label(self, category):
        out = _apply("alice", category)
        m = _PLACEHOLDER_RE.fullmatch(out)
        assert m is not None
        assert m.group(1) == category.value

    @pytest.mark.parametrize("category", [
        Category.USER_ID, Category.PII_HANDLE,
        Category.LIKELY_CRYPTO_ADDRESS, Category.STATIC_ASSET,
    ])
    def test_same_value_same_hash(self, category):
        # SHA-derived placeholders must collide for identical values.
        a = _apply("bob", category)
        b = _apply("bob", category)
        assert a == b

    @pytest.mark.parametrize("category", [
        Category.USER_ID, Category.PII_HANDLE,
        Category.LIKELY_CRYPTO_ADDRESS, Category.STATIC_ASSET,
    ])
    def test_different_value_different_hash(self, category):
        a = _apply("bob", category)
        b = _apply("eve", category)
        assert a != b


class TestFullCategories:
    """FULL -> single placeholder for the whole span; same hash semantics
    as HASH_ONLY, separated category for clarity."""

    @pytest.mark.parametrize("category", [
        Category.INTERNAL_IP,
        Category.EXTERNAL_IP,
        Category.PII_NAME,
    ])
    def test_full_replacement(self, category):
        out = _apply("10.1.2.3", category)
        m = _PLACEHOLDER_RE.fullmatch(out)
        assert m is not None
        assert m.group(1) == category.value


class TestEmailSplitHash:
    """PII_EMAIL -> '<<PII_EMAIL_LOCAL_x>>@<<PII_EMAIL_DOMAIN_y>>'."""

    def test_email_split_into_local_and_domain(self):
        out = _apply("alice@example.com", Category.PII_EMAIL)
        # Expect exactly two placeholders separated by `@`.
        assert "@" in out
        local, _, domain = out.partition("@")
        ml = _PLACEHOLDER_RE.fullmatch(local)
        md = _PLACEHOLDER_RE.fullmatch(domain)
        assert ml is not None and md is not None
        assert ml.group(1) == "PII_EMAIL_LOCAL"
        assert md.group(1) == "PII_EMAIL_DOMAIN"

    def test_same_local_same_placeholder(self):
        a = _apply("alice@example.com", Category.PII_EMAIL)
        b = _apply("alice@other.example.org", Category.PII_EMAIL)
        # Local part is "alice" in both -> identical PII_EMAIL_LOCAL.
        local_a = a.split("@", 1)[0]
        local_b = b.split("@", 1)[0]
        assert local_a == local_b

    def test_same_domain_same_placeholder(self):
        a = _apply("alice@example.com", Category.PII_EMAIL)
        b = _apply("bob@example.com", Category.PII_EMAIL)
        # Domain "example.com" -> identical PII_EMAIL_DOMAIN.
        dom_a = a.split("@", 1)[1]
        dom_b = b.split("@", 1)[1]
        assert dom_a == dom_b

    def test_email_without_at_falls_back_to_full(self):
        # No `@`: the helper masks the whole span as a regular email
        # placeholder rather than crashing.
        out = _apply("alice", Category.PII_EMAIL)
        m = _PLACEHOLDER_RE.fullmatch(out)
        assert m is not None


class TestCredentialPrefix:
    """CREDENTIAL_PREFIX -> well-known prefix kept, secret tail masked.

    Falls back to a full mask if the prefix isn't recognized.
    """

    @pytest.mark.parametrize("prefix,tail", [
        ("AIza", "SyD" + "1234567890abcdefghij_klmnopQRSTU0"),
        ("ghp_", "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk0000"),
        ("Bearer ", "eyJabc.def.ghi-but-much-longer"),
    ])
    def test_known_prefix_kept(self, prefix, tail):
        out = _apply(prefix + tail, Category.CREDENTIAL)
        assert out.startswith(prefix)
        rest = out[len(prefix):]
        m = _PLACEHOLDER_RE.fullmatch(rest)
        assert m is not None
        assert m.group(1) == "CREDENTIAL"

    def test_unknown_prefix_falls_back_to_full_mask(self):
        out = _apply("anonymous-secret-zzzz-1234", Category.CREDENTIAL)
        # Whole span replaced with one CREDENTIAL placeholder.
        m = _PLACEHOLDER_RE.fullmatch(out)
        assert m is not None
        assert m.group(1) == "CREDENTIAL"


class TestUrlStructured:
    """URL_STRUCTURED -> host masked, path structure preserved, trailing
    numeric / opaque ID masked under USER_ID or RESOURCE_ID."""

    def test_host_masked_path_preserved(self):
        url = "http://jira.corp.internal/api/issues"
        out = _apply(url, Category.INTERNAL_URL)
        # Scheme and path structure intact.
        assert out.startswith("http://")
        assert "/api/issues" in out
        assert "jira.corp.internal" not in out
        # Host now a placeholder.
        assert "<<INTERNAL_URL_HOST_" in out

    def test_trailing_numeric_id_masked_as_resource_id(self):
        url = "http://jira.corp.internal/api/issues/1001"
        out = _apply(url, Category.INTERNAL_URL)
        assert "<<RESOURCE_ID_" in out
        assert "/1001" not in out

    def test_trailing_id_under_users_collection_is_user_id(self):
        url = "http://app.corp.internal/api/users/42"
        out = _apply(url, Category.INTERNAL_URL)
        assert "<<USER_ID_" in out

    def test_query_string_credential_value_masked(self):
        url = "http://jira.corp.internal/socket.io/?sid=Yp_crOiZaE3qykxGAAAE"
        out = _apply(url, Category.INTERNAL_URL)
        # The high-entropy sid value must be masked even though it lives
        # in the URL's query string.
        assert "Yp_crOiZaE3qykxGAAAE" not in out

    def test_non_url_falls_back_to_full_mask(self):
        # Bizarre input: not parseable as a URL. Helper should still
        # return one placeholder and not crash.
        out = _apply("not-a-url", Category.INTERNAL_URL)
        m = _PLACEHOLDER_RE.fullmatch(out)
        assert m is not None


# ---------------------------------------------------------------------------
# Replacement bookkeeping invariants
# ---------------------------------------------------------------------------


class TestReplacementInvariants:
    def test_apply_replacements_right_to_left_preserves_indices(self):
        # Two non-overlapping spans applied at once shouldn't shift
        # each other's offsets.
        text = "ip1=10.0.0.1 ip2=10.0.0.2"
        spans = [
            _make_span(text.index("10.0.0.1"), text.index("10.0.0.1") + 8,
                       Category.INTERNAL_IP),
            _make_span(text.index("10.0.0.2"), text.index("10.0.0.2") + 8,
                       Category.INTERNAL_IP),
        ]
        reps = apply_granularity(text, spans)
        out = apply_replacements(text, reps)
        # Both IPs gone, two placeholders present.
        assert "10.0.0.1" not in out
        assert "10.0.0.2" not in out
        assert out.count("<<INTERNAL_IP_") == 2

    def test_replacement_carries_original_value(self):
        text = "alice"
        reps = apply_granularity(text, [_make_span(0, 5, Category.PII_NAME)])
        assert reps and isinstance(reps[0], Replacement)
        assert reps[0].original == "alice"

    def test_zero_spans_leaves_text_intact(self):
        text = "nothing here"
        out = apply_replacements(text, apply_granularity(text, []))
        assert out == text
