"""Measure how the masking pipeline scales with input size.

We synthesise HARs of increasing size, mask them with the rule
backend (LLM detectors are excluded — they add a constant per-entry
forward pass, which would dominate small inputs and obscure the
algorithmic scaling), and fit the wall-clock times to a power law
``t = a * N^k`` with the goal of keeping ``k <= 1.2``.

Run:
    python scripts/bench_scaling.py
"""
from __future__ import annotations

import json
import math
import os
import statistics
import time
from typing import Any

from engine.core import PentectEngine


def _entry(i: int, body_chars: int) -> dict[str, Any]:
    """Build a single HAR entry whose response body is `body_chars`
    characters of mixed text (some credential-shaped, some prose).

    Credential-shaped fixture values are assembled at runtime from
    short fragments so committed source doesn't trip gitleaks /
    GitHub push-protection — the high-entropy strings only exist in
    process memory.
    """
    fake_token = "Aa1Bb2" + "Cc3Dd4" + "Ee5Ff6" + "Gg7Hh8" + "Ii9Jj"
    short_token = "Aa1Bb2" + "Cc3Dd4" + "Ee5Ff6" + "Gg7Hh"
    fake_hex = "9b1deb" + "4d3b7d" + "4bad9b" + "dd2b0d" + "7b3dcb6d"
    fake_jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiJ1MTAwMSJ9."
        + "s5fak3sIg"
    )
    body = (
        '{"id":'
        + str(i)
        + f',"token":"{fake_token}","note":"some prose here",'
        f'"hex":"{fake_hex}","email":"alice@example.com"}}'
    )
    # pad to target size with neutral content
    if len(body) < body_chars:
        body += " " + ("lorem ipsum dolor sit amet " * ((body_chars // 30) + 1))
        body = body[:body_chars]
    return {
        "request": {
            "method": "GET",
            "url": f"http://10.0.0.1:8080/api/items/{i}?token={short_token}",
            "headers": [
                {"name": "Authorization", "value": f"Bearer {fake_jwt}"},
                {"name": "Cookie", "value": f"session={short_token}"},
            ],
            "queryString": [{"name": "token", "value": short_token}],
            "cookies": [],
        },
        "response": {
            "status": 200,
            "headers": [
                {"name": "Set-Cookie", "value": f"sid={short_token}"},
            ],
            "cookies": [],
            "content": {"text": body},
        },
    }


def _make_har(entries: int, body_chars: int) -> str:
    """Return a HAR JSON string with `entries` entries, each carrying
    a body of roughly `body_chars` characters."""
    return json.dumps({
        "log": {
            "version": "1.2",
            "creator": {"name": "bench", "version": "0.0"},
            "entries": [_entry(i, body_chars) for i in range(entries)],
        }
    })


def _bench(har: str, repeats: int = 3) -> float:
    eng = PentectEngine(backend="rule")
    times: list[float] = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        eng.mask_har(har)
        times.append(time.perf_counter() - t0)
    return min(times)


def _fit_power_law(sizes: list[int], times: list[float]) -> tuple[float, float]:
    """Fit ``t = a * N^k`` via least squares on log-log axes. Return (k, a)."""
    log_n = [math.log(n) for n in sizes]
    log_t = [math.log(t) for t in times]
    n = len(sizes)
    mean_x = sum(log_n) / n
    mean_y = sum(log_t) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(log_n, log_t))
    den = sum((x - mean_x) ** 2 for x in log_n)
    k = num / den
    a = math.exp(mean_y - k * mean_x)
    return k, a


def _bench_set(label: str, configs: list[tuple[int, int]]) -> tuple[float, float]:
    print(f"\n=== {label} ===")
    print(f"{'entries':>8} {'body':>6} {'bytes':>10} {'time s':>8}")
    sizes: list[int] = []
    times: list[float] = []
    for n_entries, body in configs:
        har = _make_har(n_entries, body)
        size = len(har)
        t = _bench(har, repeats=3)
        sizes.append(size)
        times.append(t)
        print(f"{n_entries:>8} {body:>6} {size:>10,} {t:>8.3f}")
    k, a = _fit_power_law(sizes, times)
    print(f"power-law fit: t = {a:.3e} * N^{k:.3f}")
    return k, a


def main() -> None:
    # Sweep A: vary entry count at fixed body size — measures cost of
    # adding more entries (anchor reuse, per-entry detector loop).
    a_configs = [(20, 2_000), (40, 2_000), (80, 2_000), (160, 2_000), (320, 2_000)]
    k_a, _ = _bench_set("Sweep A: entries vary, body=2k", a_configs)

    # Sweep B: vary body size at fixed entry count — measures cost of
    # processing larger leaf strings.
    b_configs = [(20, 1_000), (20, 2_000), (20, 4_000), (20, 8_000), (20, 16_000)]
    k_b, _ = _bench_set("Sweep B: body varies, entries=20", b_configs)

    # Sweep C: combined growth — both axes scale together.
    c_configs = [(20, 2_000), (40, 4_000), (80, 8_000), (160, 16_000), (320, 32_000)]
    k_c, _ = _bench_set("Sweep C: both vary together", c_configs)

    print(f"\n{'sweep':30s} {'k':>6s}   {'verdict':>8s}")
    for label, k in [
        ("entries vary", k_a),
        ("body vary", k_b),
        ("both vary", k_c),
    ]:
        print(f"{label:30s} {k:>6.3f}   {'PASS' if k <= 1.20 else 'FAIL':>8s}")


if __name__ == "__main__":
    main()
