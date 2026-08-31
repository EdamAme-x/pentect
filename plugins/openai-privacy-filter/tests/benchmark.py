#!/usr/bin/env python3
"""Benchmark the real persistent OpenAI Privacy Filter plugin process."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time


BASE_TEXT = (
    "Alice Example can be reached at alice@example.com or +1 415-555-0100. "
    "Her office is 1 Market Street, San Francisco. "
)


def sample(size: int) -> str:
    repetitions = size // len(BASE_TEXT) + 2
    return (BASE_TEXT * repetitions)[:size]


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = max(0, min(len(ordered) - 1, int(len(ordered) * fraction + 0.999) - 1))
    return ordered[position]


def linux_memory_kib(process_id: int) -> dict[str, int]:
    """Read optional Linux process memory counters without extra dependencies."""
    wanted = {"VmHWM": "peak_rss_kib", "VmRSS": "rss_kib"}
    result: dict[str, int] = {}
    try:
        lines = Path(f"/proc/{process_id}/status").read_text(
            encoding="utf-8"
        ).splitlines()
    except OSError:
        return result
    for line in lines:
        name, separator, value = line.partition(":")
        if separator and name in wanted:
            result[wanted[name]] = int(value.strip().split()[0])
    return result


def request(
    process: subprocess.Popen[str], request_id: int, text: str
) -> tuple[float, dict[str, object]]:
    assert process.stdin is not None and process.stdout is not None
    payload = {
        "schema": "pentect.plugin.v1",
        "id": request_id,
        "hook": "inspect",
        "payload": {"text": text},
    }
    started = time.perf_counter()
    process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
    process.stdin.flush()
    line = process.stdout.readline()
    elapsed = time.perf_counter() - started
    if not line:
        raise RuntimeError("OpenAI Privacy Filter exited without a response")
    response = json.loads(line)
    if response.get("error"):
        raise RuntimeError(f"OpenAI Privacy Filter failed: {response['error']!r}")
    return elapsed, response


def start_plugin(
    plugin: Path, device: str, environment: dict[str, str]
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, str(plugin), "--device", device],
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,
        env=environment,
    )


def stop_plugin(process: subprocess.Popen[str]) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--sizes", type=int, nargs="+", default=(64, 256, 1024))
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument("--batch-size", type=int)
    parser.add_argument("--compare-unchunked", action="store_true")
    args = parser.parse_args()
    if args.iterations < 1 or any(size < 1 for size in args.sizes):
        parser.error("iterations and sizes must be positive")
    if args.batch_size is not None and args.batch_size < 0:
        parser.error("--batch-size must be non-negative")
    if args.device != "cpu" and args.batch_size is not None:
        parser.error("--batch-size requires --device cpu")
    if args.compare_unchunked and args.device != "cpu":
        parser.error("--compare-unchunked requires --device cpu")

    plugin = Path(__file__).parents[1] / "server.py"
    environment = os.environ.copy()
    effective_batch_size: int | None = None
    if args.device == "cpu":
        raw_batch_size = (
            str(args.batch_size)
            if args.batch_size is not None
            else environment.get("PENTECT_OPF_CPU_MOE_BATCH_SIZE", "2")
        )
        try:
            effective_batch_size = int(raw_batch_size)
        except ValueError:
            parser.error(
                "PENTECT_OPF_CPU_MOE_BATCH_SIZE must be a non-negative integer"
            )
        if effective_batch_size < 0:
            parser.error(
                "PENTECT_OPF_CPU_MOE_BATCH_SIZE must be a non-negative integer"
            )
        environment["PENTECT_OPF_CPU_MOE_BATCH_SIZE"] = str(effective_batch_size)
    process = start_plugin(plugin, args.device, environment)
    report: dict[str, object] = {
        "schema": "pentect.opf-benchmark.v1",
        "device": args.device,
        "batch_size": effective_batch_size,
        "iterations": args.iterations,
        "measurements": [],
    }
    spans_by_size: dict[int, object] = {}
    try:
        request_id = 1
        startup_s, startup_response = request(process, request_id, sample(64))
        if not startup_response.get("spans"):
            raise RuntimeError("startup probe did not detect synthetic PII")
        report["startup_s"] = startup_s
        measurements = report["measurements"]
        assert isinstance(measurements, list)
        for size in args.sizes:
            text = sample(size)
            times: list[float] = []
            for _ in range(args.iterations):
                request_id += 1
                elapsed, response = request(process, request_id, text)
                if not response.get("spans"):
                    raise RuntimeError(f"{size}-byte probe did not detect synthetic PII")
                spans_by_size[size] = response["spans"]
                times.append(elapsed)
            measurements.append(
                {
                    "bytes": len(text.encode("utf-8")),
                    "samples_s": times,
                    "p50_s": statistics.median(times),
                    "p95_s": percentile(times, 0.95),
                    "max_s": max(times),
                }
            )
        report.update(linux_memory_kib(process.pid))
    finally:
        stop_plugin(process)

    if args.compare_unchunked:
        baseline_environment = environment.copy()
        baseline_environment["PENTECT_OPF_CPU_MOE_BATCH_SIZE"] = "0"
        baseline = start_plugin(plugin, args.device, baseline_environment)
        try:
            baseline_startup_s, response = request(baseline, 1, sample(64))
            if not response.get("spans"):
                raise RuntimeError("unchunked startup probe did not detect synthetic PII")
            for request_id, size in enumerate(args.sizes, start=2):
                _, response = request(baseline, request_id, sample(size))
                if response.get("spans") != spans_by_size[size]:
                    raise RuntimeError(
                        f"optimized and unchunked spans differ for {size} bytes"
                    )
            report["unchunked_comparison"] = {
                "equivalent": True,
                "startup_s": baseline_startup_s,
                **linux_memory_kib(baseline.pid),
            }
        finally:
            stop_plugin(baseline)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
