#!/usr/bin/env python3
"""Compare CredSweeper detection quality and runtime with a baseline build."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time


QUALITY_METRICS = ("precision", "recall", "f1")


def benchmark(binary: Path, args: list[str]) -> tuple[dict[str, object], float]:
    started = time.perf_counter()
    completed = subprocess.run(
        [str(binary), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError(f"{binary} produced no benchmark report")
    return json.loads(lines[-1]), elapsed_ms


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--rounds", type=int, default=7)
    parser.add_argument("--max-slowdown", type=float, default=1.20)
    parser.add_argument("--absolute-allowance-ms", type=float, default=10.0)
    return parser.parse_args()


def main() -> int:
    opts = parse_args()
    if opts.rounds < 3:
        raise ValueError("--rounds must be at least 3")
    if opts.max_slowdown < 1:
        raise ValueError("--max-slowdown must be at least 1")

    bench_args = [
        "creddata",
        str(opts.dataset),
        "--repo",
        opts.repo,
        "--ignore-x",
        "--json",
    ]

    # Warm both binaries before measuring. Alternate order during measurement so
    # runner warm-up and throttling do not consistently favor one revision.
    benchmark(opts.baseline, bench_args)
    benchmark(opts.candidate, bench_args)
    reports: dict[str, dict[str, object]] = {}
    samples: dict[str, list[float]] = {"baseline": [], "candidate": []}
    binaries = {"baseline": opts.baseline, "candidate": opts.candidate}
    for round_index in range(opts.rounds):
        order = ("baseline", "candidate") if round_index % 2 == 0 else ("candidate", "baseline")
        for name in order:
            report, elapsed_ms = benchmark(binaries[name], bench_args)
            reports[name] = report
            samples[name].append(elapsed_ms)

    baseline_report = reports["baseline"]
    candidate_report = reports["candidate"]
    regressions = []
    for metric in QUALITY_METRICS:
        baseline_value = float(baseline_report[metric])
        candidate_value = float(candidate_report[metric])
        if candidate_value + 1e-12 < baseline_value:
            regressions.append(
                f"{metric} decreased from {baseline_value:.6f} to {candidate_value:.6f}"
            )

    baseline_ms = statistics.median(samples["baseline"])
    candidate_ms = statistics.median(samples["candidate"])
    allowed_ms = baseline_ms * opts.max_slowdown + opts.absolute_allowance_ms
    slowdown = candidate_ms / baseline_ms if baseline_ms else float("inf")
    print(
        json.dumps(
            {
                "baseline": {
                    "metrics": {key: baseline_report[key] for key in QUALITY_METRICS},
                    "median_ms": round(baseline_ms, 3),
                    "samples_ms": [round(value, 3) for value in samples["baseline"]],
                },
                "candidate": {
                    "metrics": {key: candidate_report[key] for key in QUALITY_METRICS},
                    "median_ms": round(candidate_ms, 3),
                    "samples_ms": [round(value, 3) for value in samples["candidate"]],
                },
                "slowdown": round(slowdown, 4),
                "allowed_ms": round(allowed_ms, 3),
            },
            indent=2,
            sort_keys=True,
        )
    )
    if candidate_ms > allowed_ms:
        regressions.append(
            f"median runtime increased from {baseline_ms:.3f} ms to {candidate_ms:.3f} ms "
            f"(limit {allowed_ms:.3f} ms)"
        )
    if regressions:
        for regression in regressions:
            print(f"error: {regression}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
