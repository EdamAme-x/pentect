"""End-to-end coverage for engine.core.

The detector chain has plenty of unit tests; this file pins the
*orchestration* — the parts of mask_har / mask_text / MaskResult that
make the engine usable as a whole. If you regress any of:

  - HAR JSON shape preservation
  - per-entry value consistency (same secret -> same placeholder)
  - lenient HAR loader fallbacks
  - recovery map lifecycle (built, accessible, never serialized)
  - to_json / summary / map invariants

these tests catch it before a downstream caller does.
"""
from __future__ import annotations

import json
import re

import pytest

from engine.categories import Category
from engine.core import (
    HarEntryMaskResult,
    MaskResult,
    PentectEngine,
    _anchor_iter_hits,
    _build_anchor_matcher,
    _collapse_static_assets,
    _guess_category,
    _iter_leaf_strings,
    _load_lenient_har,
)


_PLACEHOLDER_RE = re.compile(r"<<([A-Z_]+)_([a-f0-9]{8})>>")


def _make_har(entries: list[dict]) -> str:
    return json.dumps({
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "0"},
            "entries": entries,
        }
    })


def _basic_entry(*, url: str = "https://api.example.com/v1",
                 body: str = "{}", mime: str = "application/json",
                 headers: list[dict] | None = None) -> dict:
    return {
        "request": {
            "method": "GET",
            "url": url,
            "headers": headers or [],
            "queryString": [],
            "cookies": [],
        },
        "response": {
            "status": 200,
            "headers": [],
            "cookies": [],
            "content": {"mimeType": mime, "text": body},
        },
    }


# ---------------------------------------------------------------------------
# MaskResult / to_json contract
# ---------------------------------------------------------------------------


class TestMaskResultShape:
    def test_to_json_contains_masked_text_map_summary(self):
        text = "GET http://10.0.0.1/api/users/42"
        res = PentectEngine(backend="rule").mask_text(text)
        payload = json.loads(res.to_json())
        assert set(payload) >= {"masked_text", "map", "summary"}
        assert payload["masked_text"] == res.masked_text
        assert payload["summary"]["total_masked"] == len(res.map)

    def test_to_json_does_not_serialize_recovery(self):
        # Recovery map must never leave the local process via to_json:
        # it carries the original sensitive bytes.
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1IjogIjEifQ.s5fak3sIg"
        res = PentectEngine(backend="rule").mask_text(text)
        assert res._recovery_map  # built
        payload = json.loads(res.to_json())
        assert "_recovery_map" not in payload
        assert "recovery" not in payload

    def test_repr_does_not_include_recovery(self):
        # MaskResult uses repr=False on _recovery_map so a print()
        # accident in a notebook doesn't dump secrets to stdout.
        text = "secret=Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj"
        res = PentectEngine(backend="rule").mask_text(text)
        s = repr(res)
        for original in res._recovery_map.values():
            assert original not in s

    def test_summary_by_category_matches_map_categories(self):
        text = (
            "ip=10.0.0.1 token=Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj "
            "email=alice@example.com"
        )
        res = PentectEngine(backend="rule").mask_text(text)
        # by_category counts must equal the placeholders observed in
        # the masked text, grouped by category.
        seen: dict[str, int] = {}
        for ph, info in res.map.items():
            seen[info["category"]] = seen.get(info["category"], 0) + 1
        assert seen == res.summary["by_category"]


# ---------------------------------------------------------------------------
# Recovery API
# ---------------------------------------------------------------------------


class TestRecovery:
    def test_recover_returns_original_for_full_mask(self):
        text = "ip=10.0.0.1"
        res = PentectEngine(backend="rule").mask_text(text)
        ph = next(iter(res.map))
        assert res.recover(ph) == "10.0.0.1"

    def test_recover_unknown_placeholder_returns_none(self):
        res = PentectEngine(backend="rule").mask_text("nothing sensitive here")
        assert res.recover("<<INTERNAL_IP_deadbeef>>") is None

    def test_recover_all_round_trips_simple_input(self):
        text = "ip=10.0.0.1 host=10.0.0.2"
        res = PentectEngine(backend="rule").mask_text(text)
        # recover_all rewrites every placeholder back to its original.
        recovered = res.recover_all(res.masked_text)
        assert "10.0.0.1" in recovered
        assert "10.0.0.2" in recovered

    def test_recover_all_no_placeholders_in_input_is_noop(self):
        res = PentectEngine(backend="rule").mask_text("ip=10.0.0.1")
        # Plain text without any placeholder -- recover_all returns it
        # unchanged.
        assert res.recover_all("just some text") == "just some text"

    def test_har_entry_result_has_recovery(self):
        har = _make_har([_basic_entry(
            url="http://10.0.0.1:8080/api",
            body='{"token":"Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj"}',
        )])
        res: MaskResult = PentectEngine(backend="rule").mask_har(har)
        assert isinstance(res._recovery_map, dict)
        assert res._recovery_map  # at least the IP got recovered
        # to_json still doesn't carry it
        assert "_recovery_map" not in res.to_json()


# ---------------------------------------------------------------------------
# HAR JSON shape preservation
# ---------------------------------------------------------------------------


class TestMaskHarShape:
    def test_output_is_valid_json(self):
        har = _make_har([_basic_entry()])
        res = PentectEngine(backend="rule").mask_har(har)
        # masked_text must round-trip through json.loads.
        json.loads(res.masked_text)

    def test_output_preserves_entry_count(self):
        har = _make_har([_basic_entry() for _ in range(7)])
        res = PentectEngine(backend="rule").mask_har(har)
        out = json.loads(res.masked_text)
        assert len(out["log"]["entries"]) == 7

    def test_output_preserves_creator_metadata(self):
        har = _make_har([_basic_entry()])
        res = PentectEngine(backend="rule").mask_har(har)
        out = json.loads(res.masked_text)
        assert out["log"]["creator"]["name"] == "test"
        assert out["log"]["version"] == "1.2"

    def test_dict_input_is_accepted(self):
        # mask_har accepts both raw JSON strings and pre-parsed dicts.
        d = json.loads(_make_har([_basic_entry()]))
        res = PentectEngine(backend="rule").mask_har(d)
        json.loads(res.masked_text)

    def test_empty_har_does_not_crash(self):
        res = PentectEngine(backend="rule").mask_har(_make_har([]))
        out = json.loads(res.masked_text)
        assert out["log"]["entries"] == []
        assert res.summary["total_masked"] == 0


# ---------------------------------------------------------------------------
# Per-entry consistency: the same value should map to the same
# placeholder everywhere it appears (placeholder is SHA-derived).
# ---------------------------------------------------------------------------


class TestCrossEntryConsistency:
    def test_same_internal_ip_same_placeholder(self):
        har = _make_har([
            _basic_entry(url="http://10.0.0.1:8080/a"),
            _basic_entry(url="http://10.0.0.1:8080/b"),
            _basic_entry(url="http://10.0.0.2:8080/c"),
        ])
        res = PentectEngine(backend="rule").mask_har(har)
        out = json.loads(res.masked_text)
        urls = [e["request"]["url"] for e in out["log"]["entries"]]
        # The first two entries share the same IP and must therefore
        # share the same placeholder. The third has a different IP
        # and must get a different one.
        ph0 = re.search(r"<<INTERNAL_IP_[a-f0-9]{8}>>", urls[0]).group(0)
        ph1 = re.search(r"<<INTERNAL_IP_[a-f0-9]{8}>>", urls[1]).group(0)
        ph2 = re.search(r"<<INTERNAL_IP_[a-f0-9]{8}>>", urls[2]).group(0)
        assert ph0 == ph1
        assert ph0 != ph2

    def test_same_value_in_url_and_body_share_placeholder(self):
        har = _make_har([_basic_entry(
            url="http://10.0.0.7/login",
            body='{"server":"10.0.0.7"}',
        )])
        res = PentectEngine(backend="rule").mask_har(har)
        out = json.loads(res.masked_text)
        url = out["log"]["entries"][0]["request"]["url"]
        body = out["log"]["entries"][0]["response"]["content"]["text"]
        ph_url = re.search(r"<<INTERNAL_IP_[a-f0-9]{8}>>", url).group(0)
        ph_body = re.search(r"<<INTERNAL_IP_[a-f0-9]{8}>>", body).group(0)
        assert ph_url == ph_body


# ---------------------------------------------------------------------------
# Lenient HAR loader: the engine should not blow up on slightly
# malformed JSON because real-world HARs are routinely malformed.
# ---------------------------------------------------------------------------


class TestLenientHarLoader:
    def test_strict_json_path(self):
        d = _load_lenient_har('{"log":{"entries":[]}}')
        assert d == {"log": {"entries": []}}

    def test_bom_stripped(self):
        d = _load_lenient_har('﻿{"log":{"entries":[]}}')
        assert d == {"log": {"entries": []}}

    def test_line_comments_removed(self):
        d = _load_lenient_har('{"log":{"entries":[]}} // trailing comment')
        assert d == {"log": {"entries": []}}

    def test_block_comments_removed(self):
        d = _load_lenient_har('{"log":/* inline */{"entries":[]}}')
        assert d == {"log": {"entries": []}}

    def test_trailing_commas_tolerated(self):
        d = _load_lenient_har('{"log":{"entries":[],}}')
        assert d == {"log": {"entries": []}}

    def test_truncated_input_salvages_what_it_can(self):
        # Mid-export cutoff: dropped at a random byte. Loader should
        # close brackets and return the prefix, not crash.
        truncated = '{"log":{"entries":[{"request":{"url":"https://example.com"'
        d = _load_lenient_har(truncated)
        # We don't pin the exact recovered shape — only that it's a
        # dict and didn't raise.
        assert isinstance(d, dict)

    def test_unrecoverable_input_returns_empty_har_shell(self):
        d = _load_lenient_har("not json at all")
        assert d == {"log": {"entries": []}}


# ---------------------------------------------------------------------------
# Helper invariants
# ---------------------------------------------------------------------------


class TestHelperInvariants:
    def test_iter_leaf_strings_yields_only_strings(self):
        data = {"a": [{"b": "x"}, "y", 42, None], "c": "z"}
        leaves = list(_iter_leaf_strings(data))
        # All leaves are strings; numeric / null are skipped.
        # Default filter also drops strings shorter than 6 chars.
        for leaf in leaves:
            assert isinstance(leaf, str)
            assert len(leaf) >= 6

    def test_iter_leaf_strings_skips_data_uri(self):
        # Data URIs would otherwise pull big base64 binaries through
        # detectors that aren't built for them.
        data = {"img": "data:image/png;base64,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
        assert list(_iter_leaf_strings(data)) == []

    def test_anchor_iter_hits_returns_all_substring_matches(self):
        text = "foo bar foo baz foo"
        hits = list(_anchor_iter_hits(text, "foo", Category.CREDENTIAL))
        # 3 occurrences, each (start, end).
        assert hits == [(0, 3), (8, 11), (16, 19)]

    def test_anchor_iter_hits_word_bounded_for_pii_handle(self):
        # A PII_HANDLE anchor must match only on alnum-class boundaries
        # so a short handle (e.g., `bootstrap`) doesn't bleed into
        # `getbootstrap.com`.
        text = "getbootstrap.com vs bootstrap"
        hits = list(_anchor_iter_hits(text, "bootstrap", Category.PII_HANDLE))
        # Only the standalone occurrence, not the substring inside
        # `getbootstrap`.
        assert hits == [(20, 29)]

    def test_build_anchor_matcher_returns_none_for_empty_input(self):
        assert _build_anchor_matcher([]) is None

    def test_build_anchor_matcher_yields_category_for_each_hit(self):
        matcher = _build_anchor_matcher([
            ("hello", Category.PII_NAME),
            ("world", Category.CREDENTIAL),
        ])
        assert matcher is not None
        hits = list(matcher("say hello world"))
        cats = [c for _, _, c in hits]
        assert Category.PII_NAME in cats
        assert Category.CREDENTIAL in cats

    def test_collapse_static_assets_ignores_non_asset_response(self):
        data = {
            "log": {"entries": [{
                "request": {"url": "https://api.example.com/data"},
                "response": {"content": {
                    "mimeType": "application/json",
                    "text": '{"k":"v"}',
                }},
            }]}
        }
        recovery: dict[str, str] = {}
        _collapse_static_assets(data, recovery)
        # Body left alone, recovery untouched.
        assert data["log"]["entries"][0]["response"]["content"]["text"] == '{"k":"v"}'
        assert recovery == {}

    def test_collapse_static_assets_replaces_asset_body(self):
        body = "console.log('hello')"
        data = {
            "log": {"entries": [{
                "request": {"url": "https://cdn.example.com/app.js"},
                "response": {"content": {
                    "mimeType": "application/javascript",
                    "text": body,
                }},
            }]}
        }
        recovery: dict[str, str] = {}
        _collapse_static_assets(data, recovery)
        out = data["log"]["entries"][0]["response"]["content"]["text"]
        assert out.startswith("<<STATIC_ASSET_") and out.endswith(">>")
        assert recovery[out] == body


class TestGuessCategory:
    @pytest.mark.parametrize("label,expected", [
        ("INTERNAL_IP", Category.INTERNAL_IP),
        ("INTERNAL_URL_HOST", Category.INTERNAL_URL),     # falls back to longest-prefix
        ("PII_EMAIL_LOCAL", Category.PII_EMAIL),
        ("PII_EMAIL_DOMAIN", Category.PII_EMAIL),
        ("CREDENTIAL", Category.CREDENTIAL),
        ("STATIC_ASSET", Category.STATIC_ASSET),
        ("LIKELY_TOKEN", Category.LIKELY_TOKEN),
    ])
    def test_known_labels_resolve(self, label: str, expected: Category):
        assert _guess_category(label) is expected

    def test_unknown_label_returns_none(self):
        assert _guess_category("ZZZ_UNKNOWN_THING") is None


# ---------------------------------------------------------------------------
# mask_har_entries (per-entry path)
# ---------------------------------------------------------------------------


class TestMaskHarEntries:
    def test_returns_har_entry_mask_result(self):
        har = _make_har([_basic_entry(url="http://10.0.0.1/a")])
        res = PentectEngine(backend="rule").mask_har_entries(har)
        assert isinstance(res, HarEntryMaskResult)
        assert res.entries  # at least one entry returned
        assert res.entries[0]["index"] == 0

    def test_entries_carry_index_and_masked_text(self):
        har = _make_har([
            _basic_entry(url="http://10.0.0.1/a"),
            _basic_entry(url="http://10.0.0.2/b"),
        ])
        res = PentectEngine(backend="rule").mask_har_entries(har)
        assert [e["index"] for e in res.entries] == [0, 1]
        # Both masked strings must mention some placeholder.
        assert all("<<" in e["masked"] for e in res.entries)
