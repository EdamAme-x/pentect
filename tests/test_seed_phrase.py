"""Tests for the seed phrase / PEM private key detector.

Two adversarial shapes the regex / entropy paths miss:

  - **BIP39 mnemonic**: 12 / 15 / 18 / 21 / 24 lowercase words from
    the official 2048-word English wordlist. Wallet recovery phrases.
  - **PEM private key**: `-----BEGIN ... PRIVATE KEY-----` block. The
    base64 body is the secret; the armor lines are public format
    markers and must remain readable so the masked output still tells
    the reader "this was a private key".
"""
from __future__ import annotations

import pytest

from engine.categories import Category
from engine.detectors.seed_phrase import (
    _BIP39_WORDS,
    SeedPhraseDetector,
)


# Real BIP39 words (verified against the official 2048-word list at
# detector init). We assemble fake mnemonics from these so the tests
# don't depend on a live wallet.
_VALID_12 = (
    "legal winner thank year wave sausage worth useful legal winner thank yellow"
)
_VALID_24 = (
    "legal winner thank year wave sausage worth useful legal winner thank yellow "
    "legal winner thank year wave sausage worth useful legal winner thank yellow"
)


def _detect(text: str) -> list[tuple[str, str]]:
    spans = SeedPhraseDetector().detect(text)
    return [(text[s.start:s.end], s.category.name) for s in spans]


class TestBip39:
    def test_wordlist_loaded(self):
        # 10 BIP39 languages, 2048 words each, with overlap between
        # Latin-script lists. After de-duplication we expect roughly
        # 17,000-20,000 unique entries.
        assert 15_000 < len(_BIP39_WORDS) < 25_000
        # Words are normalized to NFKD on load (BIP39 spec form).
        # Lookups in production normalize the candidate the same way,
        # so users typing in NFC still get a hit.
        import unicodedata as ud
        for w in ("abandon", "zoo", "あいこくしん", "가격", "ábaco"):
            assert ud.normalize("NFKD", w) in _BIP39_WORDS, w

    def test_12_word_phrase_caught(self):
        hits = _detect(_VALID_12)
        assert hits == [(_VALID_12, Category.CREDENTIAL.value)]

    def test_24_word_phrase_caught(self):
        hits = _detect(_VALID_24)
        assert len(hits) == 1
        assert hits[0][0] == _VALID_24

    def test_phrase_inside_json(self):
        text = f'{{"mnemonic":"{_VALID_12}"}}'
        hits = _detect(text)
        assert any(_VALID_12 == m for m, _ in hits)

    def test_phrase_inside_header(self):
        text = f"X-Recovery-Phrase: {_VALID_12}"
        hits = _detect(text)
        assert any(_VALID_12 == m for m, _ in hits)

    def test_eleven_words_not_caught(self):
        # 11 words: not a valid BIP39 length; must not fire.
        words = _VALID_12.split()[:-1]
        text = " ".join(words)
        assert _detect(text) == []

    def test_thirteen_words_not_caught_as_mnemonic(self):
        # 13 words: not a valid BIP39 length; the detector will still
        # see a 12-word match inside the run if one fits, so we craft
        # the phrase so no 12-word window is fully BIP39.
        # Use an extra non-BIP39 lowercase word ("xenon" — not in list)
        # at start so a 12-word slide misses every starting index.
        text = "xenon " + _VALID_12.replace(" yellow", "")
        # The first 12-word window starting at index 0 includes "xenon"
        # which isn't in the wordlist; index 1+ has only 11 words. So
        # no run should be flagged.
        assert "xenon" not in _BIP39_WORDS
        assert _detect(text) == []

    def test_random_lowercase_prose_not_caught(self):
        # Lorem ipsum-ish prose with > 12 lowercase words but none in
        # the BIP39 list.
        text = (
            "lorem ipsum dolor sit amet consectetur adipiscing elit sed "
            "do eiusmod tempor incididunt ut labore"
        )
        assert _detect(text) == []

    def test_all_uppercase_phrase_not_caught(self):
        # BIP39 mnemonics are conventionally lowercase. Uppercase
        # variants exist but are extremely rare in real leaks; we
        # tolerate a miss here in favor of fewer false positives
        # on prose like "HEADER FOOTER ...".
        upper = _VALID_12.upper()
        assert _detect(upper) == []

    def test_mixed_case_phrase_not_caught(self):
        # Same reasoning — the wordlist matching is lowercase-only.
        mixed = " ".join(w.capitalize() for w in _VALID_12.split())
        assert _detect(mixed) == []

    def test_18_word_phrase_caught(self):
        # 18 words is a valid BIP39 length too.
        words18 = (_VALID_12 + " " + _VALID_12).split()[:18]
        text = " ".join(words18)
        assert any(text == m for m, _ in _detect(text))

    def test_two_phrases_in_document_both_caught(self):
        text = f"alice: {_VALID_12}\nbob: {_VALID_12}"
        hits = _detect(text)
        assert len([h for h in hits if h[0] == _VALID_12]) == 2


def _first_n_words(lang: str, n: int = 12) -> str:
    from pathlib import Path

    p = (
        Path(__file__).parent.parent
        / "engine" / "detectors" / "data" / f"bip39_{lang}.txt"
    )
    words = [w.strip() for w in p.read_text(encoding="utf-8").splitlines() if w.strip()]
    return " ".join(words[:n])


class TestBip39MultiLanguage:
    """Each BIP39 language ships its own wordlist; the detector must
    accept all of them."""

    @pytest.mark.parametrize("lang", [
        "english",
        "japanese",
        "korean",
        "spanish",
        "chinese_simplified",
        "chinese_traditional",
        "french",
        "italian",
        "portuguese",
        "czech",
    ])
    def test_first_12_words_caught(self, lang: str):
        phrase = _first_n_words(lang, 12)
        hits = _detect(phrase)
        assert hits, f"{lang}: phrase {phrase!r} not flagged"
        # The matched span should be the entire phrase (or at minimum
        # cover the last word).
        matched, _ = hits[0]
        assert matched.endswith(phrase.split()[-1]), matched

    def test_japanese_full_width_separator(self):
        # Japanese mnemonics are sometimes written with the full-width
        # space `　` (U+3000) instead of half-width.
        phrase_hw = _first_n_words("japanese", 12)
        phrase_fw = "　".join(phrase_hw.split())
        hits = _detect(phrase_fw)
        assert hits, f"FW phrase not flagged: {phrase_fw!r}"

    def test_japanese_random_prose_not_flagged(self):
        # Hiragana prose that is not a BIP39 phrase. None of the
        # tokens are in the BIP39 list, so the detector should ignore
        # it even though the shape (12+ Hiragana words) matches.
        text = (
            "これは ふつう の にっき で あって しーど ふれーず では "
            "ありません ぜったい"
        )
        assert _detect(text) == []

    def test_spanish_with_accent_caught(self):
        # The first Spanish word `ábaco` has a leading accented vowel.
        # The wordlist file is NFKD; user input is typically NFC.
        # Membership must succeed across both normalization forms.
        phrase = _first_n_words("spanish", 12)
        hits = _detect(phrase)
        assert hits
        matched, _ = hits[0]
        # Span should start at offset 0 (the `á`) and cover the whole
        # phrase.
        assert matched == phrase, (matched, phrase)


class TestPemPrivateKeyBody:
    """Armor lines stay readable; only the body is masked."""

    def _block(self, label: str) -> str:
        return (
            f"-----BEGIN {label}-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8c\n"
            "KjMzEfYyjiWA4R\n"
            f"-----END {label}-----"
        )

    @pytest.mark.parametrize("label", [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
    ])
    def test_private_key_body_caught(self, label: str):
        text = self._block(label)
        hits = _detect(text)
        assert hits, f"label {label!r} produced no spans"
        # Span must NOT include the BEGIN/END armor lines.
        for matched, _ in hits:
            assert "BEGIN" not in matched, matched
            assert "END" not in matched, matched
            assert "-----" not in matched, matched

    def test_public_key_block_not_touched(self):
        text = (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBI\n"
            "-----END PUBLIC KEY-----"
        )
        assert _detect(text) == []

    def test_certificate_block_not_touched(self):
        text = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDazCCAlOgAwIBAgIUH8x\n"
            "-----END CERTIFICATE-----"
        )
        assert _detect(text) == []

    def test_multiple_private_key_blocks_both_caught(self):
        text = self._block("PRIVATE KEY") + "\n\n" + self._block("RSA PRIVATE KEY")
        hits = _detect(text)
        assert len(hits) == 2

    def test_armor_lines_preserved_in_engine_output(self):
        # Integration check via the full engine: the armor markers
        # must survive in masked_text so the reader can tell it was a
        # private key.
        from engine.core import PentectEngine
        text = self._block("PRIVATE KEY")
        out = PentectEngine(backend="rule").mask_text(text)
        assert "-----BEGIN PRIVATE KEY-----" in out.masked_text
        assert "-----END PRIVATE KEY-----" in out.masked_text
        # Body bytes must NOT survive verbatim.
        assert "MIIEvQIB" not in out.masked_text


class TestDetectorSurface:
    def test_name(self):
        assert SeedPhraseDetector().name == "seed_phrase"

    def test_detect_returns_credential_category(self):
        spans = SeedPhraseDetector().detect(_VALID_12)
        assert spans
        assert all(s.category is Category.CREDENTIAL for s in spans)

    def test_empty_input_returns_no_spans(self):
        assert SeedPhraseDetector().detect("") == []

    def test_idempotent(self):
        d = SeedPhraseDetector()
        text = f"{_VALID_12}\n\n-----BEGIN PRIVATE KEY-----\nABCD\n-----END PRIVATE KEY-----"
        a = d.detect(text)
        b = d.detect(text)
        assert a == b
