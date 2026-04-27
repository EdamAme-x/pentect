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
            out.append(Span(start=sp.start, end=sp.end, category=cat, source=self.name))
        return out

    def detect(self, text: str) -> list[Span]:
        return self._spans_from_result(text, self._opf.redact(text))

    def detect_batch(self, texts: list[str]) -> list[list[Span]]:
        # opf.redact has no native batch API; call sequentially.
        # (Privacy Filter inference is fast enough that this isn't a bottleneck.)
        return [self._spans_from_result(t, self._opf.redact(t)) for t in texts]
