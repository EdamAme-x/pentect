"""Measure how much precision/recall spaCy NER actually contributes.

Run two passes over each demo HAR — one with NER enabled, one with
PENTECT_DISABLE_SPACY=1 — and report:

  - wall time delta
  - new placeholders that appeared only with NER on (recall gain)
  - placeholders that appeared only with NER off (false anchors NER
    suppressed by overriding entropy / rule decisions)
  - actual leak gap: substrings that were masked by the NER-on run
    but survived in the NER-off run
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path


def _walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v)


_PLACEHOLDER_RE = re.compile(r"<<([A-Z_]+)_([a-f0-9]{8})>>")


def _mask(har_path: Path, *, disable_spacy: bool, backend: str) -> tuple[float, dict]:
    if disable_spacy:
        os.environ["PENTECT_DISABLE_SPACY"] = "1"
    else:
        os.environ.pop("PENTECT_DISABLE_SPACY", None)

    # Re-import the engine fresh so the env var is read at construction.
    for mod in list(sys.modules):
        if mod.startswith("engine"):
            del sys.modules[mod]
    from engine.core import PentectEngine  # noqa: PLC0415

    raw = har_path.read_text()
    eng = PentectEngine(backend=backend)
    t0 = time.perf_counter()
    res = eng.mask_har(raw)
    elapsed = time.perf_counter() - t0
    return elapsed, json.loads(res.masked_text)


def _summarize(masked_data: dict) -> dict[str, set[str]]:
    """Return {category_name: set(placeholder_ids)} from a masked HAR."""
    out: dict[str, set[str]] = {}
    for s in _walk_strings(masked_data):
        for m in _PLACEHOLDER_RE.finditer(s):
            out.setdefault(m.group(1), set()).add(m.group(0))
    return out


def _leak_check(har_data: dict, terms: list[str]) -> dict[str, int]:
    """Count occurrences of each `term` substring in the masked HAR."""
    counts: dict[str, int] = {t: 0 for t in terms}
    for s in _walk_strings(har_data):
        for t in terms:
            if t.lower() in s.lower():
                counts[t] += 1
    return counts


# Sensitive terms we know exist in the unmasked demo HARs and want
# to verify are masked. PII names lifted from the unmasked WebGoat /
# Juice Shop HARs (these are public OSS author / contributor names
# that NER specifically targets).
LEAK_TERMS = [
    "Bjoern Kimminich",   # Juice Shop author
    "OWASP",              # org name
    "Dittmeyer",          # JS character / NER target
    "davegandy",          # FontAwesome author handle (lowercase)
    "daneden",            # animate.css author handle
]


def main() -> None:
    backend = sys.argv[1] if len(sys.argv) > 1 else "rule"
    har_paths = [
        Path("demo/webgoat/captured.har"),
        Path("demo/juice/captured.har"),
    ]
    for path in har_paths:
        if not path.exists():
            print(f"skip {path}: not found")
            continue
        print(f"\n=== {path} (backend={backend}) ===")
        size = path.stat().st_size
        print(f"  raw size: {size:,} bytes")

        t_off, off_masked = _mask(path, disable_spacy=True, backend=backend)
        t_on,  on_masked  = _mask(path, disable_spacy=False, backend=backend)
        print(f"  time NER off: {t_off:6.2f}s")
        print(f"  time NER on : {t_on:6.2f}s   (delta +{t_on-t_off:.2f}s, x{t_on/t_off:.1f})")

        off_cats = _summarize(off_masked)
        on_cats = _summarize(on_masked)
        all_cats = sorted(set(off_cats) | set(on_cats))
        print(f"  {'category':22s} {'off':>6s}  {'on':>6s}  {'gain':>6s}")
        for c in all_cats:
            n_off = len(off_cats.get(c, set()))
            n_on = len(on_cats.get(c, set()))
            print(f"  {c:22s} {n_off:>6d}  {n_on:>6d}  {n_on-n_off:>+6d}")

        leak_off = _leak_check(off_masked, LEAK_TERMS)
        leak_on  = _leak_check(on_masked,  LEAK_TERMS)
        print(f"  {'leak term':22s} {'off':>6s}  {'on':>6s}")
        for t in LEAK_TERMS:
            n_off = leak_off[t]
            n_on = leak_on[t]
            flag = " <-- NER plugged" if n_off > n_on else ""
            print(f"  {t:22s} {n_off:>6d}  {n_on:>6d}{flag}")


if __name__ == "__main__":
    main()
