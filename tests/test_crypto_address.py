"""Tests for the cryptocurrency wallet address detector.

The detector splits matches into two confidence tiers:

  - **CREDENTIAL** for protocol-specific patterns whose prefix
    uniquely identifies the chain (`0x` ETH, `bc1` Bech32, `cosmos1`,
    `T` Tron, `r` XRP, JSON key paired with shape).
  - **LIKELY_CRYPTO_ADDRESS** for shape-only matches (`1...` / `3...`
    Base58, generic key-anchored Base58 32-64 chars) where the prefix
    is ambiguous between several chains and other token systems.
"""
from __future__ import annotations

import pytest

from engine.categories import Category
from engine.detectors.crypto_address import CryptoAddressDetector


def _detect(text: str) -> list[tuple[str, str]]:
    spans = CryptoAddressDetector().detect(text)
    return [(text[s.start:s.end], s.category.value) for s in spans]


# ---------------------------------------------------------------------------
# Strong (CREDENTIAL) tier
# ---------------------------------------------------------------------------


class TestStrongPatterns:
    @pytest.mark.parametrize("addr", [
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "0x" + "0" * 40,
    ])
    def test_eth_address(self, addr: str):
        text = f"to: {addr}"
        hits = _detect(text)
        assert (addr, Category.CREDENTIAL.value) in hits

    @pytest.mark.parametrize("addr", [
        "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        "bc1pmzfrwwndsqmk5yh69yjr5lfgfg4ev8c0tsc06e",
        "tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    ])
    def test_btc_bech32_address(self, addr: str):
        hits = _detect(f"addr={addr}")
        assert (addr, Category.CREDENTIAL.value) in hits

    def test_cosmos_bech32(self):
        addr = "cosmos1lhgcwmpv9zsm95g8gug2v3xwqlz4j8j8tj9rrm"
        hits = _detect(f"validator: {addr}")
        assert (addr, Category.CREDENTIAL.value) in hits

    def test_tron_address(self):
        addr = "TRX9JtLQR8mGm9pa4q5wGMYn5LP9Aw6dTm"
        hits = _detect(f"sent {addr}")
        assert (addr, Category.CREDENTIAL.value) in hits

    def test_xrp_address(self):
        addr = "r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59"
        hits = _detect(f"destination={addr}")
        assert (addr, Category.CREDENTIAL.value) in hits

    def test_solana_keyword_anchored(self):
        addr = "7vYoXtq1c8GpfFc5amPzZSLfh1nW1QSpw3xTqEgT5z6r"
        hits = _detect(f'{{"sol_address": "{addr}"}}')
        assert (addr, Category.CREDENTIAL.value) in hits

    def test_evm_under_json_key(self):
        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        hits = _detect(f'{{"to": "{addr}"}}')
        assert (addr, Category.CREDENTIAL.value) in hits


# ---------------------------------------------------------------------------
# Weak (LIKELY_CRYPTO_ADDRESS) tier
# ---------------------------------------------------------------------------


class TestLikelyTier:
    @pytest.mark.parametrize("addr", [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",        # P2PKH (1...)
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",        # P2SH (3...)
        "LcHK4dJq1mFZh3pCwYM7r3jLyB2KJtP7eD",        # Litecoin (L...)
    ])
    def test_legacy_base58_addresses_are_likely(self, addr: str):
        hits = _detect(f"send {addr}")
        # Must fire, but as LIKELY (not CREDENTIAL).
        labels = [c for s, c in hits if s == addr]
        assert labels == [Category.LIKELY_CRYPTO_ADDRESS.value]

    def test_generic_wallet_key_value_is_likely(self):
        # No chain-specific prefix; the JSON key is the only hint.
        addr = "7vYoXtq1c8GpfFc5amPzZSLfh1nW1QSpw3xTqEgT5z6r"
        text = f'{{"deposit_address":"{addr}"}}'
        hits = _detect(text)
        labels = [c for s, c in hits if s == addr]
        assert Category.LIKELY_CRYPTO_ADDRESS.value in labels


# ---------------------------------------------------------------------------
# Negative cases — must not fire
# ---------------------------------------------------------------------------


class TestNoiseImmunity:
    def test_random_lowercase_word_not_addr(self):
        assert _detect("just a regular sentence about bitcoin") == []

    def test_zero_x_short_hex_not_addr(self):
        # 38-hex, one char short of the ETH length — must not match.
        assert _detect("0x" + "a" * 38) == []

    def test_zero_x_too_long_not_addr(self):
        # 42-hex, one char too long.
        text = "0x" + "a" * 42
        # The first 40 hex after `0x` would match if not anchored;
        # we anchor with `\b` so the 42-hex run produces no match.
        hits = _detect(text)
        assert all(s != "0x" + "a" * 40 for s, _ in hits)

    def test_short_base58_not_addr(self):
        # 20 chars Base58 with `1` prefix — under our minimum 26.
        assert _detect("send 1abcdEFGhJKLmnpQRSTUv") == []

    def test_pure_word_no_match(self):
        assert _detect("transaction confirmed yesterday") == []


class TestDetectorSurface:
    def test_name(self):
        assert CryptoAddressDetector().name == "crypto_address"

    def test_empty_input_returns_no_spans(self):
        assert CryptoAddressDetector().detect("") == []

    def test_idempotent(self):
        text = "tx: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        d = CryptoAddressDetector()
        assert d.detect(text) == d.detect(text)
