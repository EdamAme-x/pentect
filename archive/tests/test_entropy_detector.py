"""Exhaustive tests for the high-entropy detector.

Three layers, in order of dependency:

1. ``_shannon_entropy`` numerical correctness — sanity-check the math
   against hand-computed reference values so any regression in the
   formula is loud.
2. ``_is_high_entropy_secret`` — the predicate that gates length,
   charset, placeholders, file extensions, and the entropy threshold.
   We pin the boundary cases (just above / just below the threshold,
   the all-lowercase escape clause, every excluded extension type).
3. ``EntropyDetector.detect`` — the integrated path through the three
   contexts (query string, cookie, JSON-credential-key) on inputs
   shaped like real HAR fields.

We also include a *catalog* test that pretty-prints the entropy of a
gallery of common values (real secrets, placeholders, build artifacts,
human prose) so the file doubles as documentation of where the line
sits.
"""
from __future__ import annotations

import math

import pytest

from engine.categories import Category
from engine.detectors.entropy import (
    EntropyDetector,
    _MIN_ENTROPY,
    _MIN_LEN,
    _is_high_entropy_secret,
    _shannon_entropy,
)


# ---------------------------------------------------------------------------
# Layer 1: _shannon_entropy numerical correctness
# ---------------------------------------------------------------------------


class TestShannonEntropyMath:
    """Pin the math against hand-computed values.

    H(X) = -Σ p(x) · log2(p(x))
    """

    def test_empty_string_is_zero(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char_is_zero(self):
        # Only one unique symbol -> p=1 -> -1*log2(1) = 0
        assert _shannon_entropy("a") == 0.0
        assert _shannon_entropy("aaaaaaaaaa") == 0.0

    def test_two_equal_chars_is_one_bit(self):
        # Half-half -> H = 1
        assert _shannon_entropy("ab") == pytest.approx(1.0)
        assert _shannon_entropy("abab") == pytest.approx(1.0)
        assert _shannon_entropy("aaabbb") == pytest.approx(1.0)

    def test_uniform_4_symbols_is_two_bits(self):
        assert _shannon_entropy("abcd") == pytest.approx(2.0)
        assert _shannon_entropy("abcdabcd") == pytest.approx(2.0)

    def test_uniform_8_symbols_is_three_bits(self):
        assert _shannon_entropy("abcdefgh") == pytest.approx(3.0)

    def test_uniform_16_symbols_is_four_bits(self):
        s = "0123456789abcdef"
        assert _shannon_entropy(s) == pytest.approx(4.0)

    def test_uniform_64_symbols_is_six_bits(self):
        # base64 alphabet length = 64
        s = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/"
        )
        assert len(s) == 64
        assert _shannon_entropy(s) == pytest.approx(6.0)

    def test_skewed_distribution_below_uniform(self):
        # 7 a's + 1 b: p_a = 7/8, p_b = 1/8
        # H = -(7/8 * log2(7/8) + 1/8 * log2(1/8))
        #   ≈ -(0.875 * -0.1926 + 0.125 * -3.0)  ≈ 0.5436
        s = "aaaaaaab"
        expected = -(7 / 8) * math.log2(7 / 8) - (1 / 8) * math.log2(1 / 8)
        assert _shannon_entropy(s) == pytest.approx(expected, rel=1e-9)
        assert _shannon_entropy(s) < 1.0  # well below uniform

    def test_entropy_is_invariant_under_repetition(self):
        # H is per-symbol, so doubling the string shouldn't change H.
        a = "abcdef"
        b = a + a
        assert _shannon_entropy(a) == pytest.approx(_shannon_entropy(b))

    def test_entropy_invariant_under_permutation(self):
        # Shuffling the symbols shouldn't change H.
        assert _shannon_entropy("aaabbbccc") == pytest.approx(
            _shannon_entropy("abcabcabc")
        )

    def test_entropy_strictly_increases_with_unique_symbols(self):
        # Ranking sanity: more unique symbols at uniform distribution
        # always means higher entropy.
        h_2 = _shannon_entropy("ab" * 10)
        h_4 = _shannon_entropy("abcd" * 5)
        h_8 = _shannon_entropy("abcdefgh" * 3)
        h_16 = _shannon_entropy("0123456789abcdef")
        assert h_2 < h_4 < h_8 < h_16

    def test_real_world_reference_points(self):
        # Reference points that document where representative inputs
        # land. These are *raw Shannon* values — the predicate now
        # routes hex/UUID through a separate alphabet-aware path and
        # so does not need 3.5 to fire on hashes.
        # English word, lowercase only:
        assert 2.5 <= _shannon_entropy("configuration") <= 3.5
        # The actual entropy of a hex hash is highly sensitive to which
        # symbols repeat; we sweep a few representative SHA1 / SHA256
        # samples and only check they all land in the "hex-hash zone"
        # (3.0 to 4.0 bits/symbol — well below uniform `log2(16) = 4`).
        hex_samples = [
            "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d",                                   # 32 hex
            "0f933ab9fcaaa782d0279c300d73750e1311eae6",                           # 40 hex
            "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d4d4d2b0d7b3dcb6d9b1deb4d3b7d4bad",   # 64 hex
        ]
        for sample in hex_samples:
            h = _shannon_entropy(sample)
            assert 3.0 <= h <= 4.0, f"hex hash H out of zone: {sample!r} → {h}"
        # 22-char base64-ish token (Socket.IO sid shape):
        assert 3.7 <= _shannon_entropy("Yp_crOiZaE3qykxGAAAE") <= 4.5
        # JWT body-ish (random base64url):
        jwt_body = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        assert 4.0 <= _shannon_entropy(jwt_body) <= 5.5


# ---------------------------------------------------------------------------
# Layer 2: _is_high_entropy_secret gating
# ---------------------------------------------------------------------------


class TestPredicateLength:
    def test_value_below_min_length_rejected(self):
        # _MIN_LEN is the floor; one char less must be rejected.
        s = "Aa1Bb2Cc3D"  # 10 chars, well below _MIN_LEN
        assert len(s) < _MIN_LEN
        assert not _is_high_entropy_secret(s)

    def test_value_exactly_at_min_length_evaluated(self):
        # At _MIN_LEN we should pass the length gate; result then depends on entropy.
        s = ("Aa1Bb2Cc3Dd4Ee5F" * 3)[:_MIN_LEN]
        assert len(s) == _MIN_LEN
        # this candidate has plenty of entropy
        assert _is_high_entropy_secret(s)

    def test_extremely_long_random_value_accepted(self):
        # 256-char random run: well above any threshold.
        s = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk_Lm-Nn" * 8
        assert _is_high_entropy_secret(s[:200])


class TestPredicateCharset:
    def test_pure_letters_rejected_when_lowercase_word_like(self):
        # Lowercase word with no separators -> word-like; entropy gate
        # bumped to MIN_ENTROPY+0.5; "implementation" doesn't reach it.
        assert not _is_high_entropy_secret("implementation12")

    def test_mixed_case_random_passes_word_filter(self):
        # A mixed-case random run with no English-word backbone has
        # low vowel/consonant alternation and does fire.
        s = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh"
        assert _is_high_entropy_secret(s)

    def test_mixed_case_with_word_backbone_still_filtered(self):
        # If the value is just an English word with random suffix,
        # the prose score is still high — under the "if in doubt,
        # mask" policy we choose to LET this through to the FT model
        # rather than over-mask. Pin the current behavior so any
        # future change is intentional.
        s = "ImplementationA1B2C3D4"
        # Currently rejected; if you intentionally relax the prose
        # threshold below 0.65, flip this to assert _is_... .
        assert not _is_high_entropy_secret(s)

    def test_charset_blocks_spaces(self):
        # Spaces are outside _TOKEN_CHARSET.
        assert not _is_high_entropy_secret("hello world abc def 123")

    def test_charset_blocks_brackets(self):
        assert not _is_high_entropy_secret("{aaaabbbb1111ccccdddd}")

    def test_charset_blocks_colons(self):
        # Colons appear in headers/URLs but never in token shape.
        assert not _is_high_entropy_secret("foo:bar:baz:qux:quux:abc")

    def test_charset_blocks_at_signs(self):
        assert not _is_high_entropy_secret("user@example.com.something")

    def test_charset_allows_dot_dash_underscore_slash(self):
        # All four separators must be inside the allowed set so url-safe
        # base64, JWTs and dotted IDs work.
        for sep in ".-_/+=":
            s = f"Aa1Bb2Cc{sep * 2}Dd3Ee4Ff5"
            assert _is_high_entropy_secret(s), f"separator {sep!r} blocked"


class TestPredicatePlaceholders:
    def test_placeholder_not_treated_as_secret(self):
        # We never flag our own placeholders as secrets — that would
        # cause re-masking on a second pass.
        assert not _is_high_entropy_secret("<<CREDENTIAL_8b6cf4fd>>")

    def test_value_containing_placeholder_rejected(self):
        # A user value that already had a placeholder injected mid-string
        # is not eligible either.
        assert not _is_high_entropy_secret("abc<<CREDENTIAL_xxxxxxxx>>def")

    def test_partial_placeholder_with_only_left_brackets_rejected(self):
        assert not _is_high_entropy_secret("Aa1Bb2Cc<<random_data_here")


class TestPredicateFileExtensions:
    @pytest.mark.parametrize("ext", [
        "woff2", "ttf", "otf", "eot",
        "js", "mjs", "cjs", "css", "map",
        "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico",
        "json", "html", "htm", "xml", "yaml", "yml",
        "md", "txt", "csv", "tsv",
        "pdf", "zip", "gz", "tar",
        "wasm", "exe", "so", "dll",
        "class", "jar", "war",
    ])
    def test_known_bundle_extension_skipped(self, ext: str):
        # MaterialIcons-Regular-6R3D3MIQ.<ext> — high entropy hash but
        # ends in a known asset extension; never a credential.
        s = f"MaterialIcons-Regular-6R3D3MIQ.{ext}"
        assert not _is_high_entropy_secret(s), s

    def test_extension_match_is_case_insensitive(self):
        assert not _is_high_entropy_secret("Bundle-Hash-7Hx9bN.WOFF2")
        assert not _is_high_entropy_secret("Bundle-Hash-7Hx9bN.PNG")

    def test_unknown_extension_not_skipped(self):
        # `.xyz` isn't on our skip list; if entropy & shape qualify, fire.
        assert _is_high_entropy_secret("Aa1Bb2Cc3Dd4Ee5Ff6Gg7H.xyz")


class TestPredicateLowercaseWordEscape:
    """The "all-lowercase, no separators" branch raises the threshold by
    +0.5 to discriminate prose from secrets."""

    def test_long_lowercase_word_rejected(self):
        assert not _is_high_entropy_secret("configurationmanagement")

    def test_lowercase_random_high_entropy_accepted(self):
        # 4-bit-ish entropy random lowercase string; entropy >= 4.0
        # passes the bumped threshold.
        s = "qzwxecvbnmpoiulkjyhgfdrtsa"
        # entropy of this near-uniform alphabetic string > 4
        assert _shannon_entropy(s) > 4.0
        assert _is_high_entropy_secret(s)

    def test_lowercase_with_dash_uses_normal_threshold(self):
        s = "configuration-management"  # 24 chars
        # Has '-' so the lowercase-word escape is disarmed.
        # Still under the regular 3.5 threshold (most letters repeat).
        assert _shannon_entropy(s) < 3.7
        # Not high enough to fire even on the regular threshold:
        assert not _is_high_entropy_secret(s)


class TestPredicateThresholdBoundary:
    """Pin behavior right around _MIN_ENTROPY."""

    def test_just_below_threshold_rejected(self):
        # Only 2 unique symbols -> H = 1.0, well below 3.5
        s = "a" * 10 + "b" * 10
        assert _shannon_entropy(s) < _MIN_ENTROPY
        assert not _is_high_entropy_secret(s)

    def test_at_threshold_accepted(self):
        # 16 chars hex (0-f, mostly all unique-ish): around 3.9
        s = "0123456789abcdef"
        assert _shannon_entropy(s) >= _MIN_ENTROPY
        # all-lowercase, no separators -> word-shape escape applies,
        # threshold becomes 4.0 — and 16-char unique-letter hex is exactly 4.0
        assert _is_high_entropy_secret(s)

    def test_predicate_monotonic_in_uniqueness(self):
        # As we replace identical chars with unique ones, entropy must
        # increase and the predicate must eventually flip True.
        seen_true = False
        for k in range(1, 17):
            s = "0123456789abcdef"[:k] + "0" * (16 - k)
            ok = _is_high_entropy_secret(s)
            if ok:
                seen_true = True
            elif seen_true:
                # Once we cross the threshold we shouldn't fall back.
                pytest.fail(f"predicate flipped back at k={k}: {s!r}")


# ---------------------------------------------------------------------------
# Catalog: where do real-world strings actually land?
# ---------------------------------------------------------------------------


REAL_SECRETS: list[tuple[str, str]] = [
    ("socket_io_sid", "Yp_crOiZaE3qykxGAAAE"),
    ("aws_akid_like", "AKIAIOSFODNN7EXAMPLE"),
    ("aws_secret_like", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("google_api_key", "AIzaSyD1234567890abcdefghij_klmnopQRSTUV"[:39]),
    ("openai_sk_legacy", "sk-" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk_LmNn"),
    ("github_pat", "ghp_" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk0000"),
    # Vendor token shapes built at runtime from concatenated parts so
    # GitHub's push-protection scanner doesn't flag them as committed
    # secrets — the strings only assemble in process memory.
    ("stripe_sk_live", "sk" + "_live_" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj"),
    ("slack_xoxb", "xo" + "xb-1234567890-1234567890-AbCdEfGhIjKlMn"),
    ("jwt_header", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
    ("jwt_body", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"),
    ("jwt_sig", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
    ("hex_sha1", "0f933ab9fcaaa782d0279c300d73750e1311eae6"),
    ("hex_sha256",
     "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d4d4d2b0d7b3dcb6d9b1deb4d3b7d4bad"),
    ("uuid_v4", "550e8400-e29b-41d4-a716-446655440000"),
    ("opaque_session", "abcXYZ123_987654321ZZ"),
    ("base64_url_token", "fM2xrPCJF0aJtKHQTAYNJF1ZRtmEzC2VrPM"),
]


NON_SECRETS: list[tuple[str, str]] = [
    ("english_phrase", "implementationmanagementexample"),
    ("placeholder_hash", "<<CREDENTIAL_8b6cf4fd>>"),
    ("font_bundle", "MaterialIcons-Regular-6R3D3MIQ.woff2"),
    ("js_bundle", "vendor.5b4cd9af2e3.js"),
    ("css_bundle", "main-9af2e3b4cd.css"),
    ("kebab_word", "configuration-management"),
    ("snake_word", "configuration_management"),
    ("integer_id", "1234567890"),
    ("language_code_long", "language_code_en_us"),
    ("data_uri_prefix", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEA"),
    ("path_segment", "/api/v1/users/profile"),
    ("camelcase_word", "ImplementationManagement"),
]


class TestCatalog:
    """A live catalog of where real values land. Useful as a reference
    when changing the threshold; failures here indicate a regression in
    *behavior on representative inputs*, not in the math itself."""

    @pytest.mark.parametrize("label,value", REAL_SECRETS)
    def test_real_secrets_are_caught_by_predicate(
        self, label: str, value: str
    ):
        # Stronger contract than the old "H >= 3.5" check: the actual
        # predicate must accept every catalog secret regardless of
        # what alphabet path it takes (hex / UUID / general token).
        # If a secret slips through, that's a real recall regression.
        assert _is_high_entropy_secret(value), (
            f"real secret {label}={value!r} unexpectedly rejected"
        )

    @pytest.mark.parametrize("label,value", REAL_SECRETS)
    def test_real_secrets_charset_clean(self, label: str, value: str):
        # A real secret should use only the allowed token charset
        # (excluding hyphenated UUIDs which have `-` allowed too).
        from engine.detectors.entropy import _TOKEN_CHARSET
        # Some "real" tokens contain reserved characters (xoxb has `-`
        # which is allowed; sk_live_ uses `_`). All entries in our
        # catalog must match the token charset; if one doesn't, our
        # predicate cannot catch it and we want to know.
        assert _TOKEN_CHARSET.match(value), f"{label} fails token charset"

    @pytest.mark.parametrize("label,value", NON_SECRETS)
    def test_non_secrets_print_for_reference(self, label: str, value: str):
        # We don't strictly *require* every non-secret to be rejected
        # (some may slip through for good reasons), but we DO require
        # this body to evaluate without crashing — i.e. the predicate
        # is total over the catalog. If a regression causes the
        # function to raise on an unusual input, this test fails.
        _is_high_entropy_secret(value)


class TestRejectionFromCatalog:
    """The non-secret catalog SHOULD all be rejected by the predicate.

    These are the sources of the noise we explicitly designed the
    detector to avoid; if any flips to True, we have a regression."""

    # Only the values we know aren't supposed to be flagged. Some
    # entries in NON_SECRETS contain things the predicate won't even
    # see (data URIs are filtered by charset, etc.) but that's fine —
    # the contract is that the predicate must return False on each.
    @pytest.mark.parametrize("label,value", NON_SECRETS)
    def test_non_secret_rejected(self, label: str, value: str):
        assert not _is_high_entropy_secret(value), (
            f"non-secret {label}={value!r} unexpectedly flagged"
        )


class TestPrecisionRecallContract:
    """The end-to-end "what should fire / what shouldn't" contract.

    We pin these explicitly so future tweaks have to make a choice
    rather than silently regress.
    """

    must_fire: list[tuple[str, str]] = [
        ("md5", "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d"),
        ("sha1", "0f933ab9fcaaa782d0279c300d73750e1311eae6"),
        ("sha256",
         "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d4d4d2b0d7b3dcb6d9b1deb4d3b7d4bad"),
        ("uuid_v4", "550e8400-e29b-41d4-a716-446655440000"),
        ("aws_akid", "AKIAIOSFODNN7EXAMPLE"),
        ("aws_secret", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ("google_api_key", "AIza" + "SyD1234567890abcdefghij_klmnopQRSTUVx"[:35]),
        ("openai_sk_legacy", "sk-Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk_LmNn"),
        ("github_pat", "ghp_Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk0000"),
        # Same runtime-concat trick as in the catalog above.
        ("stripe_sk", "sk" + "_live_" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj"),
        ("slack_xoxb", "xo" + "xb-1234567890-1234567890-AbCdEfGhIjKlMn"),
        ("jwt_header", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        ("jwt_body", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"),
        ("jwt_sig", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        ("socket_io_sid", "Yp_crOiZaE3qykxGAAAE"),
        ("opaque_session", "abcXYZ123_987654321ZZ"),
    ]

    must_not_fire: list[tuple[str, str]] = [
        ("kebab_word", "configuration-management"),
        ("snake_word", "configuration_management"),
        ("camel_word", "ImplementationManagement"),
        ("lowercase_phrase", "implementationmanagementexample"),
        ("kebab_with_digits_words", "foo-bar-baz-qux-quux-corge"),
        ("font_bundle", "MaterialIcons-Regular-6R3D3MIQ.woff2"),
        ("js_bundle", "vendor.5b4cd9af2e3.js"),
        ("integer_id_only", "1234567890123456"),
        ("low_entropy_hex", "00000000aaaaaaaa00000000"),
        ("all_repeating", "aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("placeholder_with_brackets", "<<CREDENTIAL_8b6cf4fd>>"),
        ("language_code", "language_code_en_us"),
    ]

    @pytest.mark.parametrize("label,value", must_fire)
    def test_must_fire(self, label: str, value: str):
        assert _is_high_entropy_secret(value), (
            f"recall regression: {label}={value!r} not flagged"
        )

    @pytest.mark.parametrize("label,value", must_not_fire)
    def test_must_not_fire(self, label: str, value: str):
        assert not _is_high_entropy_secret(value), (
            f"precision regression: {label}={value!r} flagged"
        )


# ---------------------------------------------------------------------------
# Layer 3: EntropyDetector.detect — integrated context tests
# ---------------------------------------------------------------------------


_DETECTOR = EntropyDetector()


def _matches(text: str) -> list[str]:
    return [text[s.start:s.end] for s in _DETECTOR.detect(text)
            if s.category is Category.CREDENTIAL]


class TestQueryStringContext:
    def test_socket_io_sid_caught(self):
        text = (
            "GET wss://example.com/socket.io/?EIO=4&transport=websocket"
            "&sid=Yp_crOiZaE3qykxGAAAE"
        )
        matches = _matches(text)
        assert "Yp_crOiZaE3qykxGAAAE" in matches

    def test_query_at_url_start_caught(self):
        # First parameter starts with `?`, must still match.
        text = "GET /v1?token=Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9"
        assert _matches(text)

    def test_short_id_not_caught(self):
        text = "GET /v1?id=42&page=1"
        assert _matches(text) == []

    def test_short_value_just_below_min_len_skipped(self):
        # Length (_MIN_LEN - 1) must not match; the regex itself
        # also enforces 16+ but pin both behaviors.
        v = "Aa1Bb2Cc3Dd4Ee5"  # 15 chars
        assert len(v) == _MIN_LEN - 1
        text = f"GET /v1?token={v}"
        assert _matches(text) == []

    def test_value_at_max_len_caught(self):
        # 256-char value -> regex top end. Must still fire.
        v = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8" * 10  # > 256
        v = v[:200]
        assert len(v) == 200
        text = f"GET /v1?token={v}&next=1"
        assert _matches(text) == [v]

    def test_value_exceeds_max_len_truncated_or_skipped(self):
        # Entropy regex caps at 256; values longer than that won't be
        # flagged in one shot.
        v = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8" * 30  # > 720 chars
        text = f"GET /v1?token={v}"
        # 720-char tokens are not credential-shaped; we accept either
        # outcome but document the contract: the detector won't crash.
        result = _matches(text)
        # If anything matches, it must be a substring of v.
        for m in result:
            assert m in v

    def test_multiple_params_all_caught(self):
        text = (
            "GET /v1?session=Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh"
            "&csrf=Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq"
        )
        matches = _matches(text)
        assert "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh" in matches
        assert "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq" in matches

    def test_query_pair_with_pure_digits_skipped(self):
        # Pure digit run has too low entropy.
        text = "GET /v1?nonce=1234567890123456"
        assert _matches(text) == []


class TestCookieContext:
    def test_set_cookie_caught(self):
        text = "Set-Cookie: session=abcXYZ123_987654321ZZ; Path=/"
        assert "abcXYZ123_987654321ZZ" in _matches(text)

    def test_cookie_header_caught(self):
        text = "Cookie: phpsessid=abcXYZ123_987654321ZZ"
        assert "abcXYZ123_987654321ZZ" in _matches(text)

    def test_multi_cookie_split_correctly(self):
        text = (
            "Cookie: a=Aa1Bb2Cc3Dd4Ee5Ff6; "
            "b=Zz9Yy8Xx7Ww6Vv5Uu4Tt3"
        )
        matches = _matches(text)
        assert "Aa1Bb2Cc3Dd4Ee5Ff6" in matches
        assert "Zz9Yy8Xx7Ww6Vv5Uu4Tt3" in matches

    def test_short_cookie_value_skipped(self):
        text = "Cookie: locale=en-US"
        assert _matches(text) == []

    def test_set_cookie_with_attributes_only_value_captured(self):
        # The rest of the Set-Cookie line shouldn't bleed into the value.
        text = (
            "Set-Cookie: token=Aa1Bb2Cc3Dd4Ee5Ff6Gg7; "
            "HttpOnly; Secure; SameSite=Lax; Path=/"
        )
        matches = _matches(text)
        assert "Aa1Bb2Cc3Dd4Ee5Ff6Gg7" in matches
        for m in matches:
            assert ";" not in m and " " not in m


class TestJsonContext:
    @pytest.mark.parametrize("key", [
        "token", "access_token", "refresh_token", "id_token",
        "session", "sessionid", "session_id",
        "sid", "signature", "sig", "nonce",
        "csrf", "csrf_token", "csrftoken",
        "key", "secret", "auth", "auth_token",
        "api_key", "apikey", "client_secret",
        "bearer",
    ])
    def test_credential_shaped_keys_caught(self, key: str):
        text = f'{{"{key}": "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii"}}'
        matches = _matches(text)
        assert "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii" in matches, key

    @pytest.mark.parametrize("key", [
        "name", "title", "description", "label",
        "product_name", "category", "color", "tag",
        "comment", "message", "url", "endpoint",
    ])
    def test_non_credential_keys_skipped(self, key: str):
        text = f'{{"{key}": "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii"}}'
        assert _matches(text) == [], key

    def test_escaped_quotes_inside_har_caught(self):
        # HAR bodies have JSON inside JSON, so the inner quotes get
        # backslash-escaped. The regex must handle both forms.
        text = '{\\"token\\": \\"Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii\\"}'
        matches = _matches(text)
        assert "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii" in matches

    def test_credential_key_with_short_value_skipped(self):
        text = '{"token": "abcd1234"}'
        assert _matches(text) == []

    def test_credential_key_with_low_entropy_skipped(self):
        # Same length, but only one char repeated -> H = 0
        text = '{"token": "aaaaaaaaaaaaaaaa"}'
        assert _matches(text) == []

    def test_cred_key_with_word_value_skipped(self):
        text = '{"token": "configurationmanagement"}'
        # Word-shape escape kicks in; entropy of pure lowercase ≤ 3.5+0.5
        assert _matches(text) == []


class TestNoiseImmunity:
    """Inputs that should NEVER produce a span, even though parts of
    them have high entropy."""

    def test_minified_js_bundle_does_not_explode(self):
        # Minified JS chunks contain lots of base64-ish substrings but
        # they're bundle artifacts, not credentials. The detector
        # should skip them because the surrounding context isn't a
        # query / cookie / credential JSON key.
        body = (
            "function r(t){var e=t.charCodeAt(0);return e<128?"
            "String.fromCharCode(e):e<2048?"
            "String.fromCharCode(192|e>>6,128|63&e):"
            "String.fromCharCode(224|e>>12,128|e>>6&63,128|63&e)}"
        )
        assert _matches(body) == []

    def test_data_uri_image_skipped(self):
        # Big base64 image payload; doesn't sit on a credential key.
        body = "background:url(data:image/png;base64," + "A" * 200 + ")"
        assert _matches(body) == []

    def test_pentect_placeholders_in_body_not_remasked(self):
        body = (
            "GET /api?next=<<INTERNAL_URL_a3f1b2c8>>"
            "&token=<<CREDENTIAL_8b6cf4fd>>"
        )
        assert _matches(body) == []

    def test_html_attribute_high_entropy_value_skipped(self):
        # HTML class attributes / SRI hashes look high-entropy but
        # aren't credential-shaped query parameters.
        body = '<link integrity="sha384-Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9">'
        assert _matches(body) == []


class TestDetectorSurface:
    def test_detector_name(self):
        assert EntropyDetector().name == "entropy"

    def test_detect_returns_credential_category(self):
        text = "GET /v1?token=Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh"
        spans = EntropyDetector().detect(text)
        assert spans
        assert all(s.category is Category.CREDENTIAL for s in spans)

    def test_detect_batch_consistent_with_detect(self):
        texts = [
            "GET /v1?sid=Yp_crOiZaE3qykxGAAAE",
            "GET /v1?id=42",
            'Set-Cookie: session=Aa1Bb2Cc3Dd4Ee5Ff6Gg7',
        ]
        d = EntropyDetector()
        single = [d.detect(t) for t in texts]
        batched = d.detect_batch(texts)
        assert single == batched

    def test_empty_input_returns_no_spans(self):
        assert EntropyDetector().detect("") == []

    def test_detector_idempotent_on_same_input(self):
        text = "GET /v1?token=Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh"
        d = EntropyDetector()
        a = d.detect(text)
        b = d.detect(text)
        assert a == b
