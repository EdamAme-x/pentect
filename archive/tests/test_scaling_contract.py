"""Hard upper bound on the pipeline's growth rate.

We fit a power law ``t = a * N^k`` to a small sweep of synthetic HARs
and require k <= ~1.3. The detector chain is meant to be near-linear
on input size — if a future change pushes us toward quadratic
behavior (re.compile in a loop, str.find without an Aho–Corasick-like
matcher, repeated json.dumps inside a tight loop, etc.) this test
catches it before it reaches a real HAR.

Why 1.3 and not the bench_scaling threshold of 1.2:
the bench script uses larger inputs (up to 9.4 MB) and minimum-of-3
timing, so its log-log fit is much more stable. Inside pytest we
keep the run under ~30 seconds and use a single timing per size,
which adds noise to the small-N points and pushes the apparent k
upward by ~0.05-0.10. 1.3 leaves a safety margin while still
detecting genuine quadratic regressions.

Run pytest with ``-m slow`` to include this test; it's marked slow
so the default suite stays snappy.
"""
from __future__ import annotations

import json
import math
import time
from typing import Any

import pytest

from engine.core import PentectEngine


pytestmark = pytest.mark.slow


_K_THRESHOLD = 1.30


def _entry(i: int, body_chars: int) -> dict[str, Any]:
    """One synthetic HAR entry. Mirrors scripts/bench_scaling.py but
    with shorter fixture token strings so committed source doesn't
    trip secret scanners (the actual content is not what matters here
    — we measure scaling)."""
    fake_token = "Aa1Bb2" + "Cc3Dd4" + "Ee5Ff6" + "Gg7Hh"
    fake_hex = "9b1deb" + "4d3b7d" + "4bad9b" + "dd2b0d" + "7b3dcb6d"
    body = (
        '{"id":' + str(i)
        + f',"token":"{fake_token}","note":"some prose here",'
        f'"hex":"{fake_hex}","email":"alice@example.com"}}'
    )
    if len(body) < body_chars:
        body += " " + ("lorem ipsum dolor sit amet " * ((body_chars // 30) + 1))
        body = body[:body_chars]
    return {
        "request": {
            "method": "GET",
            "url": f"http://10.0.0.1:8080/api/items/{i}?q={fake_token}",
            "headers": [
                {"name": "Cookie", "value": f"session={fake_token}"},
            ],
            "queryString": [{"name": "q", "value": fake_token}],
            "cookies": [],
        },
        "response": {
            "status": 200,
            "headers": [],
            "cookies": [],
            "content": {"text": body},
        },
    }


def _make_har(entries: int, body_chars: int) -> str:
    return json.dumps({
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "0"},
            "entries": [_entry(i, body_chars) for i in range(entries)],
        }
    })


def _bench(har: str) -> float:
    eng = PentectEngine(backend="rule")
    # Warmup: first call pays the import + compile cost for some
    # detectors that lazy-build state (e.g., the BIP39 set). We skip
    # the warmup result.
    eng.mask_har(har)
    t0 = time.perf_counter()
    eng.mask_har(har)
    return time.perf_counter() - t0


def _fit_power_law(sizes: list[int], times: list[float]) -> float:
    """Return k from t = a * N^k, fit on log-log with least squares."""
    log_n = [math.log(n) for n in sizes]
    log_t = [math.log(t) for t in times]
    n = len(sizes)
    mx = sum(log_n) / n
    my = sum(log_t) / n
    num = sum((x - mx) * (y - my) for x, y in zip(log_n, log_t))
    den = sum((x - mx) ** 2 for x in log_n)
    return num / den


def _run_sweep(configs: list[tuple[int, int]]) -> tuple[float, list[float]]:
    sizes: list[int] = []
    times: list[float] = []
    for n_entries, body in configs:
        har = _make_har(n_entries, body)
        sizes.append(len(har))
        times.append(_bench(har))
    return _fit_power_law(sizes, times), times


def test_scaling_with_entry_count():
    """Holding body size fixed, doubling entries should at most
    slightly more than double the runtime."""
    configs = [(5, 1_000), (10, 1_000), (20, 1_000), (40, 1_000)]
    k, times = _run_sweep(configs)
    assert k <= _K_THRESHOLD, (
        f"entries-axis scaling regressed: k={k:.3f} > {_K_THRESHOLD}, "
        f"times={times}"
    )


def test_scaling_with_body_size():
    """Holding entry count fixed, growing the body should be near
    linear. Body bytes are walked by every detector, so a quadratic
    here is more likely than on the entries axis."""
    configs = [(10, 1_000), (10, 2_000), (10, 4_000), (10, 8_000)]
    k, times = _run_sweep(configs)
    assert k <= _K_THRESHOLD, (
        f"body-axis scaling regressed: k={k:.3f} > {_K_THRESHOLD}, "
        f"times={times}"
    )


def test_scaling_combined_growth():
    """Both axes grow together. Combined sweep is the closest
    analogue to a real-world HAR getting larger."""
    configs = [(5, 1_000), (10, 2_000), (20, 4_000), (40, 8_000)]
    k, times = _run_sweep(configs)
    assert k <= _K_THRESHOLD, (
        f"combined scaling regressed: k={k:.3f} > {_K_THRESHOLD}, "
        f"times={times}"
    )
