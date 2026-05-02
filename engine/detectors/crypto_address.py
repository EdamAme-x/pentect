"""Cryptocurrency wallet address detector.

Why this exists
===============
Wallet addresses are stable, public-but-doxxing identifiers: a single
address ties together a person's transaction history, balances, and
counterparties. In a HAR they show up in:

  - request bodies of exchange / wallet APIs
  - response payloads of block explorer queries
  - log lines / error pages that echo a transaction parameter back
  - JSON config that hard-codes the user's deposit address

Confidence tiers
================
We split detections into two categories so the masked output tells
the reader how sure we are:

  - **CREDENTIAL** — the value matches a strong, protocol-specific
    pattern (`0x` + 40 hex, `bc1` Bech32, `cosmos1` Bech32, `T` + 33
    Base58 for Tron, `r` + 24-34 Base58 for XRP). Effectively zero
    false positives outside crafted adversarial inputs.

  - **LIKELY_CRYPTO_ADDRESS** — Base58 / hex shape that *might* be a
    wallet on a chain we didn't write a strong rule for (Solana
    without a keyword anchor, Polkadot, Cardano, NEAR, ...). We mask
    anyway — over-masking is recoverable; under-masking isn't —
    but tag it as LIKELY so a downstream reader can tell.

We DON'T do checksum validation here — it's expensive (Base58Check
double-SHA256 for BTC, ECRecover for ETH EIP-55 case-mix) and the
predicate is already conservative enough.
"""
from __future__ import annotations

import re

from engine.categories import Category
from engine.detectors.base import Span


# Ethereum / EVM-compatible: `0x` + 40 hex chars. Word-boundary-anchored
# so a 40-hex SHA1 sitting inside a longer hex blob doesn't accidentally
# match. EIP-55 mixed-case is allowed.
_ETH_ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")


# Bitcoin Bech32 / Bech32m (segwit, taproot). Mainnet hrp = "bc",
# testnet hrp = "tb". Body uses the bech32 alphabet (no 1, b, i, o).
# Total length 14-74 per BIP-173/350.
_BTC_BECH32_RE = re.compile(
    r"\b(?:bc|tb)1[acdefghjklmnpqrstuvwxyz023456789]{6,87}\b",
    re.IGNORECASE,
)


# Bitcoin / Litecoin / Dogecoin legacy Base58Check. Starts with 1 (P2PKH
# mainnet), 3 (P2SH mainnet), L/M (Litecoin), or D (Dogecoin) and
# carries 25-34 chars total in the Base58 alphabet (no 0, O, I, l).
# We anchor on a non-alphanumeric boundary so addresses pasted into
# JSON / URL contexts don't bleed into surrounding tokens.
_BTC_LEGACY_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"[13LMD][1-9A-HJ-NP-Za-km-z]{25,33}"
    r"(?![A-Za-z0-9])"
)


# Tron mainnet: 34-char Base58 starting with capital T.
_TRON_RE = re.compile(
    r"(?<![A-Za-z0-9])T[1-9A-HJ-NP-Za-km-z]{33}(?![A-Za-z0-9])"
)


# XRP / Ripple classic address: 25-35 Base58 starting with `r`.
_XRP_RE = re.compile(
    r"(?<![A-Za-z0-9])r[1-9A-HJ-NP-Za-km-z]{24,34}(?![A-Za-z0-9])"
)


# Cosmos ecosystem Bech32: prefix `cosmos1`, `osmo1`, `juno1`, `terra1`,
# `kava1` etc. Body is 38 chars in the bech32 alphabet for the standard
# acc address, longer for validator and other prefixes.
_COSMOS_BECH32_RE = re.compile(
    r"\b(?:cosmos|osmo|juno|terra|kava|akash|axelar|stride|injective|celestia)"
    r"(?:valoper|valcons|pub)?"
    r"1[acdefghjklmnpqrstuvwxyz023456789]{38,71}\b",
    re.IGNORECASE,
)


# Solana: 32-44 char Base58. No fixed prefix — to avoid eating random
# JWTs / opaque tokens we anchor on a `solana`/`sol` keyword nearby
# OR on key names commonly seen in Solana JSON. The body alone is too
# generic to match safely without context.
_SOLANA_KEYWORD_RE = re.compile(
    r"(?i)(?:solana|sol_address|wallet[_-]?address)"
    r"[\"' :=]+"
    r"(?P<addr>[1-9A-HJ-NP-Za-km-z]{32,44})\b"
)


# JSON cred-key pattern for crypto-shaped values: addresses often sit
# under keys like `address`, `wallet`, `to`, `from` in an EVM tx body.
# We pair these keys with an ETH-shape value so a 40-hex random run
# without that anchor still escapes.
_JSON_EVM_KEY_RE = re.compile(
    r'\\?"(?P<key>address|wallet|to|from|recipient|sender|owner|account)\\?"'
    r'\s*:\s*\\?"(?P<addr>0x[a-fA-F0-9]{40})\\?"',
    re.IGNORECASE,
)


# Generic Base58 wallet body anchored on a "wallet"-ish JSON / form key.
# Catches Solana / Cardano / Polkadot / NEAR / Aptos / Sui addresses
# that don't have a fixed prefix but appear under an obvious key name.
# Tagged LIKELY because the same shape can be an opaque session token.
_GENERIC_WALLET_KEY_RE = re.compile(
    r"(?i)\\?[\"'](?P<key>address|wallet|wallet_address|deposit_address|"
    r"recipient|payee|payout_address|destination)\\?[\"']"
    r"\s*[:=]\s*\\?[\"'](?P<addr>[1-9A-HJ-NP-Za-km-z]{32,64})\\?[\"']"
)


class CryptoAddressDetector:
    name = "crypto_address"

    def detect(self, text: str) -> list[Span]:
        out: list[Span] = []
        seen: set[tuple[int, int]] = set()

        def _emit(start: int, end: int, category: Category) -> None:
            key = (start, end)
            if key in seen:
                return
            seen.add(key)
            out.append(Span(
                start=start, end=end,
                category=category, source=self.name,
            ))

        # Strong, protocol-specific patterns -> CREDENTIAL.
        for m in _ETH_ADDRESS_RE.finditer(text):
            _emit(m.start(), m.end(), Category.CREDENTIAL)
        for m in _BTC_BECH32_RE.finditer(text):
            _emit(m.start(), m.end(), Category.CREDENTIAL)
        for m in _TRON_RE.finditer(text):
            _emit(m.start(), m.end(), Category.CREDENTIAL)
        for m in _XRP_RE.finditer(text):
            _emit(m.start(), m.end(), Category.CREDENTIAL)
        for m in _COSMOS_BECH32_RE.finditer(text):
            _emit(m.start(), m.end(), Category.CREDENTIAL)
        for m in _SOLANA_KEYWORD_RE.finditer(text):
            _emit(m.start("addr"), m.end("addr"), Category.CREDENTIAL)
        for m in _JSON_EVM_KEY_RE.finditer(text):
            _emit(m.start("addr"), m.end("addr"), Category.CREDENTIAL)

        # Shape-only patterns: looks like a wallet but the prefix is
        # ambiguous (`1...` / `3...` Base58, generic key-anchored
        # Base58 32-64 chars). Tag LIKELY_CRYPTO_ADDRESS so downstream
        # readers know the confidence is lower.
        for m in _BTC_LEGACY_RE.finditer(text):
            _emit(m.start(), m.end(), Category.LIKELY_CRYPTO_ADDRESS)
        for m in _GENERIC_WALLET_KEY_RE.finditer(text):
            _emit(
                m.start("addr"), m.end("addr"),
                Category.LIKELY_CRYPTO_ADDRESS,
            )

        return out
