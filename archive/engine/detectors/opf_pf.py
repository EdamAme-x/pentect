"""OpenAI Privacy Filter Detector.

Wraps a finetuned `opf` checkpoint as a Pentect Detector.

Env vars:
  PENTECT_PF_CHECKPOINT  Path to a finetuned opf checkpoint dir.
                         Defaults to training/runs/opf_pentect_v4_e3.
  PENTECT_PF_DEVICE      cuda | cpu (default: cuda)
"""
from __future__ import annotations

import os
import re

from engine.categories import Category
from engine.detectors.base import Span


# Drop Privacy Filter detections that land on a JSON object key (i.e. inside
# `"key":` rather than the value side). The current FT dataset contains no
# JSON-shaped examples, so the model occasionally tags ordinary key names
# (`email`, `role`, `createdAt`) as INTERNAL_URL. Demo HAR responses are full
# of these, so we filter them out as a heuristic until the FT data is broadened.
_JSON_KEY_RE = re.compile(r'"([^"\\]+)"\s*:')


# Maps opf labels (8 default + 2 Pentect-specific) back to Pentect categories.
# Mirrors training/convert_to_opf.py CATEGORY_TO_OPF in the reverse direction.
# CJK detection helper. Currently no live caller — the post-filter
# that used it was removed (see the long comment in
# `_spans_from_result` for why). Kept around because the obvious
# "fix" for opf misclassifying CJK nouns is to reclassify rather
# than drop, and that future filter will need this same predicate.
def _contains_cjk(s: str) -> bool:
    for ch in s:
        cp = ord(ch)
        if 0x3040 <= cp <= 0x30FF:           # Hiragana + Katakana
            return True
        if 0xAC00 <= cp <= 0xD7AF:           # Hangul syllables
            return True
        if 0x4E00 <= cp <= 0x9FFF:           # CJK Unified Ideographs
            return True
        if 0x3400 <= cp <= 0x4DBF:           # CJK Extension A
            return True
        if 0xFF00 <= cp <= 0xFFEF:           # Halfwidth + Fullwidth Forms
            return True
    return False


_OPF_TO_CATEGORY: dict[str, Category] = {
    "secret": Category.CREDENTIAL,
    "private_email": Category.PII_EMAIL,
    "private_person": Category.PII_NAME,
    "account_number": Category.USER_ID,
    "internal_url": Category.INTERNAL_URL,
    "internal_ip": Category.INTERNAL_IP,
    # Default opf labels we don't currently surface — left here so the
    # detector won't crash if the model emits them; just dropped.
    # "private_address", "private_date", "private_phone", "private_url"
}


class PrivacyFilterDetector:
    name = "opf_pf"

    def __init__(self) -> None:
        try:
            from opf._api import OPF
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "opf is not installed. Install with: pip install 'git+https://github.com/openai/privacy-filter.git'"
            ) from e

        ckpt = os.environ.get(
            "PENTECT_PF_CHECKPOINT",
            "training/runs/opf_pentect_v4_e3",
        )
        device = os.environ.get("PENTECT_PF_DEVICE", "cuda")
        # Use the absolute path so the OPF loader doesn't get confused by cwd.
        if ckpt and not os.path.isabs(ckpt) and os.path.isdir(ckpt):
            ckpt = os.path.abspath(ckpt)
        self._opf = OPF(model=ckpt or None, device=device, output_mode="typed")

    @staticmethod
    def _json_key_ranges(text: str) -> list[tuple[int, int]]:
        return [(m.start(1), m.end(1)) for m in _JSON_KEY_RE.finditer(text)]

    def _spans_from_result(self, text: str, result) -> list[Span]:
        key_ranges = self._json_key_ranges(text)
        out: list[Span] = []
        for sp in result.detected_spans:
            cat = _OPF_TO_CATEGORY.get(sp.label)
            if cat is None:
                continue
            if sp.start is None or sp.end is None or sp.start >= sp.end:
                continue
            # Skip detections that land entirely inside a JSON key.
            if any(ks <= sp.start and sp.end <= ke for ks, ke in key_ranges):
                continue
            value = text[sp.start:sp.end]
            # Drop CREDENTIAL detections that are clearly URL path fragments.
            # The opf checkpoint occasionally tags `8089/WebGo` (mid-URL slice)
            # as a secret; the resulting anchor then masks the same fragment
            # everywhere, leaving the real path tail (`at/plugins`) exposed.
            # Real credentials never contain slashes (JWT segments are dot-
            # separated, base64url uses `-_`, Stripe/AWS/Slack tokens are
            # alphanumeric+`_`+`-`); any `/` inside a CREDENTIAL span means
            # we accidentally swallowed URL structure.
            if cat is Category.CREDENTIAL and "/" in value:
                continue
            # NOTE (kept disabled, do not re-enable lightly):
            # We considered dropping short (<16 chars) CREDENTIAL spans
            # whose value contains CJK — the FT model occasionally
            # tags Japanese/Chinese/Korean nouns as secrets
            # (e.g. "未踏JR" -> CREDENTIAL). The filter would have made
            # the demo prettier on those inputs.
            #
            # Why it stays off:
            #   1. Adversarial-masking policy says "if in doubt, mask".
            #      Dropping a span lets the value pass through unmasked
            #      because no other detector picks up short CJK strings
            #      (rule / entropy / seed_phrase / crypto_address all
            #      return zero spans on "未踏JR" today).
            #   2. A real CJK-prefixed credential
            #      (e.g. "Bearer 未踏JR_xxxxxxxx") right at the length
            #      boundary would be silently dropped — false negatives
            #      cost more than over-masking does.
            #   3. The "len < 16" cutoff is a magic number with no firm
            #      basis; the boundary is fragile.
            #
            # If we revisit this, the safer shape is to RECLASSIFY (e.g.
            # PII_NAME) rather than DROP, so the value is still masked.
            # if cat is Category.CREDENTIAL and len(value) < 16 and _contains_cjk(value):
            #     continue
            out.append(Span(start=sp.start, end=sp.end, category=cat, source=self.name))
        return out

    def detect(self, text: str) -> list[Span]:
        return self._spans_from_result(text, self._opf.redact(text))

    def detect_batch(self, texts: list[str]) -> list[list[Span]]:
        # opf.redact has no native batch API; call sequentially.
        # (Privacy Filter inference is fast enough that this isn't a bottleneck.)
        return [self._spans_from_result(t, self._opf.redact(t)) for t in texts]
