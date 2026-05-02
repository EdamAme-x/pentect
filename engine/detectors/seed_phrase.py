"""Seed phrase / private key detector.

Catches two adversarial shapes the regex / entropy paths miss because
the values look like ordinary lowercase prose or PEM headers:

  1. **BIP39 mnemonic** — 12 / 15 / 18 / 21 / 24 lowercase words from
     the official 2048-word English wordlist, separated by single
     spaces. Wallet recovery phrases. Cannot be recovered if leaked.
  2. **PEM-armored private keys** — `-----BEGIN ... PRIVATE KEY-----`
     ... `-----END ... PRIVATE KEY-----` blocks. The body is base64
     and high entropy, but our base64-unwrap detector won't fire on
     it because the decoded bytes are binary DER, not credential-
     shaped text.

Both shapes are masked as a single CREDENTIAL span covering the entire
phrase / block.
"""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from engine.categories import Category
from engine.detectors.base import Span


_BIP39_DATA_DIR = Path(__file__).parent / "data"
# Languages BIP39 ships a wordlist for. Each file is the canonical 2048
# words; we union them all into a single membership set so a phrase in
# any supported language is recognized.
_BIP39_LANGUAGES = (
    "english",
    "japanese",
    "korean",
    "spanish",
    "chinese_simplified",
    "chinese_traditional",
    "french",
    "italian",
    "czech",
    "portuguese",
)


def _normalize(w: str) -> str:
    """Normalize a candidate word to BIP39 spec form (NFKD).

    The official BIP39 wordlists are stored in NFKD; user input may be
    in NFC (most editors / OS clipboards default to NFC for Latin
    accented characters). Without normalization, "ábaco" typed by hand
    would not match the same word loaded from the file.
    """
    return unicodedata.normalize("NFKD", w)


def _load_bip39_words() -> frozenset[str]:
    """Load every BIP39 wordlist and store both the NFKD form (the
    file's canonical encoding) AND the NFC form so runtime lookups
    don't have to normalize each candidate. NFC and NFKD agree on
    English/Japanese/Korean/Chinese, so this only doubles the set
    size in practice for Latin-with-diacritics languages."""
    words: set[str] = set()
    for lang in _BIP39_LANGUAGES:
        path = _BIP39_DATA_DIR / f"bip39_{lang}.txt"
        try:
            with path.open(encoding="utf-8") as f:
                for line in f:
                    w = line.strip()
                    if not w:
                        continue
                    nfkd = unicodedata.normalize("NFKD", w)
                    nfc = unicodedata.normalize("NFC", w)
                    words.add(nfkd)
                    if nfc != nfkd:
                        words.add(nfc)
        except FileNotFoundError:  # pragma: no cover -- dataset always shipped
            continue
    return frozenset(words)


_BIP39_WORDS = _load_bip39_words()

# BIP39 mnemonic lengths defined by the spec.
_BIP39_VALID_LENGTHS = (12, 15, 18, 21, 24)
# Smallest n-word run we even consider, to keep the scan cheap.
_MIN_LEN = min(_BIP39_VALID_LENGTHS)
_MAX_LEN = max(_BIP39_VALID_LENGTHS)

# A run of mnemonic-shaped words separated by whitespace. We look at
# runs of any length and afterwards check whether some valid-length
# subrun of all-BIP39 words exists. The whitespace class includes the
# half-width space (` `), tab (`\t`), and the full-width Japanese space
# (`　`) so JP / ZH phrases written with `あいこくしん あいさつ ...`
# or with full-width separators all match.
#
# Word character class: every BIP39 wordlist uses one of
#   - ASCII lowercase a-z (English)
#   - Lowercase Latin with diacritics (Spanish, French, Italian,
#     Portuguese, Czech) — covered by `\w` in Unicode mode
#   - Hiragana (Japanese) U+3040–U+309F
#   - Hangul syllables (Korean) U+AC00–U+D7AF
#   - CJK ideographs (Chinese S/T) U+4E00–U+9FFF
# We use `\w` with `re.UNICODE` so any of those scripts qualify, plus
# `̀-ͯ` (combining marks) so that NFKD-decomposed Latin
# accented vowels (`á` → `a` + `◌́`) and NFKD-decomposed Hangul
# syllables stay inside one word token. The wordlist membership check
# at the end is what really decides.
_WORD = r"[\ẁ-ͯ぀-ゟ゠-ヿ가-힯ᄀ-ᇿ一-鿿]{1,32}"
_SEP = r"[ \t　]"
_LOWERCASE_RUN_RE = re.compile(
    rf"(?:{_WORD})(?:{_SEP}{_WORD}){{11,}}",
    re.UNICODE,
)


def _find_bip39_runs(text: str) -> list[tuple[int, int]]:
    """Return (start, end) for every BIP39 mnemonic run found in `text`.

    Strategy: for each candidate lowercase-word run of length >= 12,
    walk a sliding window of valid mnemonic lengths (12 / 15 / ... / 24)
    and accept the longest one whose every word is in the wordlist.
    """
    if not _BIP39_WORDS:
        return []
    out: list[tuple[int, int]] = []
    for run in _LOWERCASE_RUN_RE.finditer(text):
        run_text = run.group(0)
        # Split on any single mnemonic separator (half-width space,
        # tab, full-width space). We tokenize char-by-char so we can
        # also recover absolute character offsets while keeping the
        # mapping accurate even when separators are mixed.
        words: list[str] = []
        offsets: list[int] = []
        cur_word_chars: list[str] = []
        cur_word_start = 0
        for idx, ch in enumerate(run_text):
            if ch in (" ", "\t", "　"):
                if cur_word_chars:
                    words.append("".join(cur_word_chars))
                    offsets.append(cur_word_start)
                    cur_word_chars = []
                cur_word_start = idx + 1
            else:
                if not cur_word_chars:
                    cur_word_start = idx
                cur_word_chars.append(ch)
        if cur_word_chars:
            words.append("".join(cur_word_chars))
            offsets.append(cur_word_start)
        i = 0
        n = len(words)
        # Pre-compute "is in BIP39 dictionary" once per word; the
        # set holds both NFC and NFKD forms so we can do O(1) lookups
        # without normalizing inside the hot loop.
        is_bip = [w in _BIP39_WORDS for w in words]
        while i <= n - _MIN_LEN:
            best_k: int | None = None
            for k in (24, 21, 18, 15, 12):
                if i + k > n:
                    continue
                if all(is_bip[i : i + k]):
                    best_k = k
                    break
            if best_k is None:
                i += 1
                continue
            start_in_run = offsets[i]
            end_in_run = offsets[i + best_k - 1] + len(words[i + best_k - 1])
            out.append((run.start() + start_in_run, run.start() + end_in_run))
            i += best_k
    return out


# PEM block: `-----BEGIN <label>-----` … `-----END <label>-----`.
# Catches any block whose label contains "PRIVATE KEY" (RSA / EC / DSA
# / OPENSSH / ENCRYPTED / generic). The BEGIN/END armor lines are public
# format markers — they tell a reader "this is a private key" and contain
# no secret material. We mask only the base64 body between them so the
# masked output still says "this was a private key" without leaking the
# bytes.
_PEM_PRIVATE_KEY_BODY_RE = re.compile(
    r"(?P<begin>-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\s*\n)"
    r"(?P<body>[\s\S]+?)"
    r"(?P<end>\n-----END [A-Z0-9 ]*PRIVATE KEY-----)",
)


class SeedPhraseDetector:
    name = "seed_phrase"

    def detect(self, text: str) -> list[Span]:
        out: list[Span] = []

        for s, e in _find_bip39_runs(text):
            out.append(Span(
                start=s, end=e,
                category=Category.CREDENTIAL, source=self.name,
            ))

        for m in _PEM_PRIVATE_KEY_BODY_RE.finditer(text):
            out.append(Span(
                start=m.start("body"), end=m.end("body"),
                category=Category.CREDENTIAL, source=self.name,
            ))

        return out
