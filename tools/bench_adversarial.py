#!/usr/bin/env python3
"""Run adversarial local benchmarks against the Pentect CLI.

This is not a recall benchmark. It is a nasty-input harness for the failures
that make the product unusable: catastrophic runtime, obvious leaks, and
over-masking of benign technical context.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


DEFAULT_BIN = (
    "target/release/pentect.exe"
    if sys.platform == "win32"
    else "target/release/pentect"
)
MASKED_RE = re.compile(r"masked (\d+) value")


@dataclass(frozen=True)
class RunResult:
    name: str
    bytes_in: int
    seconds: float
    masked_count: int | None
    stdout: str
    stderr: str
    returncode: int


@dataclass(frozen=True)
class BenchCase:
    name: str
    kind: str
    text: str
    max_seconds: float
    check: Callable[[RunResult], list[str]]
    extra_args: tuple[str, ...] = ()


def main() -> int:
    args = parse_args()
    with tempfile.TemporaryDirectory(prefix="pentect-adversarial-") as tmp:
        cases = build_cases(args.scale, Path(tmp))
        if args.case:
            wanted = set(args.case)
            cases = [case for case in cases if case.name in wanted]
            missing = sorted(wanted - {case.name for case in cases})
            if missing:
                print(f"unknown case(s): {', '.join(missing)}", file=sys.stderr)
                return 2

        results = [run_case(args, case) for case in cases]
        failures = failures_for(args, cases, results)
        if args.json:
            print(json.dumps(report(cases, results, failures), indent=2))
        else:
            print_report(cases, results, failures)
        return 1 if failures else 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--bin",
        default=DEFAULT_BIN,
        help="pentect binary path",
    )
    p.add_argument("--profile", default="strict", choices=["strict"], help="current CLI profile")
    p.add_argument("--scale", type=float, default=1.0, help="input size multiplier")
    p.add_argument("--case", action="append", default=[], help="case name to run")
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="also fail when a case exceeds its loose runtime guardrail",
    )
    return p.parse_args()


def build_cases(scale: float, tmp: Path) -> list[BenchCase]:
    key = fake_openai_key()
    return [
        repeated_secret_text(scale, key),
        repeated_secret_env(scale, key),
        encoded_secret_storm(scale, key),
        benign_log_storm(scale),
        path_username_storm(scale),
        near_miss_secret_storm(scale),
        evil_pack_prefilter_storm(scale, tmp),
    ]


def repeated_secret_text(scale: float, key: str) -> BenchCase:
    rows = scaled(20_000, scale)
    text = ("OPENAI_API_KEY=" + key + "\n") * rows

    def check(result: RunResult) -> list[str]:
        errors = []
        if key in result.stdout:
            errors.append("raw repeated API key survived")
        if "<<OPENAI_API_KEY_" not in result.stdout:
            errors.append("OpenAI key placeholder missing")
        return errors

    return BenchCase("repeat_same_secret_text", "text", text, 8.0, check)


def repeated_secret_env(scale: float, key: str) -> BenchCase:
    rows = scaled(15_000, scale)
    text = ("OPENAI_API_KEY=" + key + "\n") * rows

    def check(result: RunResult) -> list[str]:
        errors = []
        if key in result.stdout:
            errors.append("raw repeated env API key survived")
        if "OPENAI_API_KEY=" not in result.stdout:
            errors.append("env key name was not preserved")
        return errors

    return BenchCase("repeat_same_secret_env", "env", text, 8.0, check)


def encoded_secret_storm(scale: float, key: str) -> BenchCase:
    rows = scaled(6_000, scale)
    percent = key.replace("-", "%2D")
    zero_width = key[:3] + chr(0x200B) + key[3:]
    text = (
        "debug auth percent="
        + percent
        + " zero_width="
        + zero_width
        + " status=retry\n"
    ) * rows

    def check(result: RunResult) -> list[str]:
        errors = []
        if percent in result.stdout:
            errors.append("percent-encoded key survived")
        if zero_width in result.stdout:
            errors.append("zero-width-split key survived")
        if "<<OPENAI_API_KEY_" not in result.stdout:
            errors.append("encoded key placeholder missing")
        return errors

    return BenchCase("encoded_secret_storm", "text", text, 8.0, check)


def benign_log_storm(scale: float) -> BenchCase:
    rows = scaled(18_000, scale)
    lines = []
    for i in range(rows):
        lines.append(
            "ts=2026-06-14T12:34:56Z "
            f"level=INFO request_id=550e8400-e29b-41d4-a716-{i % 10000:012d} "
            f"path=/api/items/{i % 997} status=200 build=8da1fcd version=2.10.{i % 9} "
            "sha=356a192b7913b04c54574d18c28d46e6395428ab\n"
        )
    text = "".join(lines)

    def check(result: RunResult) -> list[str]:
        if "<<" in result.stdout:
            return ["benign log storm produced placeholders"]
        return []

    return BenchCase("benign_log_storm", "text", text, 8.0, check)


def path_username_storm(scale: float) -> BenchCase:
    rows = scaled(6_000, scale)
    templates = [
        r"C:\Users\alice\project\.env",
        "C:/Users/bob/AppData/Local/Temp/log.txt",
        "/Users/carol/work/repo",
        "/home/dave/.ssh/config",
        "/var/home/erin/src/app",
        "/export/home/frank/reports/file.log",
        "~grace/.config/pentect",
        "/mnt/c/Users/heidi/project",
        "/c/Users/ivan/project",
        r"C:\Users\Public\Downloads\sample.txt",
        "/Users/Shared/cache/item",
    ]
    text = "".join(f"path={templates[i % len(templates)]}\n" for i in range(rows))
    user_names = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan"]

    def check(result: RunResult) -> list[str]:
        errors = [f"local username survived: {name}" for name in user_names if name in result.stdout]
        if "<<LOCAL_USERNAME_" not in result.stdout:
            errors.append("LOCAL_USERNAME placeholder missing")
        if r"C:\Users\Public" not in result.stdout:
            errors.append("Windows public user path was overmasked")
        if "/Users/Shared" not in result.stdout:
            errors.append("macOS shared path was overmasked")
        return errors

    return BenchCase("path_username_storm", "text", text, 8.0, check)


def near_miss_secret_storm(scale: float) -> BenchCase:
    rows = scaled(16_000, scale)
    lines = []
    for i in range(rows):
        lines.append(
            f"row={i} "
            "aws_like=AKIA12345SHORT "
            "openai_like=sk-short "
            "card_like=4242424242424243 "
            "jwt_like=aaa.bbb.ccc "
            "uuid=550e8400-e29b-41d4-a716-446655440000 "
            "sha=da39a3ee5e6b4b0d3255bfef95601890afd80709 "
            "hex_color=#aabbcc asset=app.8da1fcd.js\n"
        )
    text = "".join(lines)

    def check(result: RunResult) -> list[str]:
        if "<<" in result.stdout:
            return ["near-miss non-secrets produced placeholders"]
        return []

    return BenchCase("near_miss_secret_storm", "text", text, 8.0, check)


def evil_pack_prefilter_storm(scale: float, tmp: Path) -> BenchCase:
    pack_dir = tmp / "evil-pack"
    pack_dir.mkdir()
    rule_count = 240
    pack = []
    for i in range(rule_count):
        vendor = f"vendor{i:03d}"
        pattern = rf"(?i){vendor}[^\r\n]{{0,80}}\b([A-Z0-9]{{32}})\b"
        pack.append(
            "\n".join(
                [
                    "[[detector]]",
                    f'label = "ADVERSARIAL_VENDOR_{i:03d}"',
                    'category = "secret"',
                    'confidence = "high"',
                    f"pattern = {json.dumps(pattern)}",
                    "capture = 1",
                    f"prefilter = [{json.dumps(vendor)}]",
                    "",
                ]
            )
        )
    (pack_dir / "rules.toml").write_text("\n".join(pack), encoding="utf-8")

    rows = scaled(18_000, scale)
    hits = [3, 42, 137, 239]
    values = {i: pack_value(i) for i in hits}
    lines = []
    for i in range(rows):
        lines.append(
            f"noise={i} vendor999 status=ok ref=550e8400-e29b-41d4-a716-{i % 10000:012d}\n"
        )
    for i in hits:
        lines.append(f"hit vendor{i:03d} token {values[i]} should_mask\n")
    text = "".join(lines)

    def check(result: RunResult) -> list[str]:
        errors = [f"pack value survived: vendor{i:03d}" for i, value in values.items() if value in result.stdout]
        if "vendor999 status=ok" not in result.stdout:
            errors.append("prefilter noise context disappeared")
        if "<<ADVERSARIAL_VENDOR_" not in result.stdout:
            errors.append("pack placeholder missing")
        return errors

    return BenchCase(
        "evil_pack_prefilter_storm",
        "text",
        text,
        12.0,
        check,
        ("--pack-dir", str(pack_dir)),
    )


def run_case(args: argparse.Namespace, case: BenchCase) -> RunResult:
    cmd = [
        args.bin,
        "mask",
        "--kind",
        case.kind,
        *case.extra_args,
    ]
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        input=case.text,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    elapsed = time.perf_counter() - start
    masked = parse_masked_count(proc.stderr)
    return RunResult(
        name=case.name,
        bytes_in=len(case.text.encode("utf-8")),
        seconds=elapsed,
        masked_count=masked,
        stdout=proc.stdout,
        stderr=proc.stderr,
        returncode=proc.returncode,
    )


def failures_for(
    args: argparse.Namespace,
    cases: list[BenchCase],
    results: list[RunResult],
) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    by_case = {case.name: case for case in cases}
    for result in results:
        errors = []
        if result.returncode != 0:
            errors.append(f"pentect exited {result.returncode}: {result.stderr.strip()}")
        else:
            errors.extend(by_case[result.name].check(result))
        if args.fail_on_regression:
            limit = by_case[result.name].max_seconds * max(1.0, args.scale)
            if result.seconds > limit:
                errors.append(f"runtime {result.seconds:.3f}s exceeded {limit:.3f}s guardrail")
        if errors:
            out[result.name] = errors
    return out


def report(
    cases: list[BenchCase],
    results: list[RunResult],
    failures: dict[str, list[str]],
) -> dict[str, object]:
    by_case = {case.name: case for case in cases}
    return {
        "cases": [
            {
                "name": r.name,
                "bytes": r.bytes_in,
                "seconds": r.seconds,
                "mib_per_s": mib_per_s(r),
                "masked_count": r.masked_count,
                "max_seconds": by_case[r.name].max_seconds,
                "ok": r.name not in failures,
            }
            for r in results
        ],
        "failures": failures,
    }


def print_report(
    cases: list[BenchCase],
    results: list[RunResult],
    failures: dict[str, list[str]],
) -> None:
    by_case = {case.name: case for case in cases}
    print(
        f"{'case':<30} {'MiB':>8} {'sec':>8} {'MiB/s':>8} {'masked':>8} {'guard':>8} status"
    )
    for r in results:
        mib = r.bytes_in / (1024 * 1024)
        masked = "n/a" if r.masked_count is None else str(r.masked_count)
        status = "FAIL" if r.name in failures else "ok"
        print(
            f"{r.name:<30} {mib:8.2f} {r.seconds:8.3f} {mib_per_s(r):8.2f} "
            f"{masked:>8} {by_case[r.name].max_seconds:8.1f} {status}"
        )
    if failures:
        print("\nfailures:")
        for name, errors in failures.items():
            print(f"  {name}:")
            for error in errors:
                print(f"    - {error}")


def parse_masked_count(stderr: str) -> int | None:
    m = MASKED_RE.search(stderr)
    return int(m.group(1)) if m else None


def mib_per_s(result: RunResult) -> float:
    if result.seconds <= 0:
        return 0.0
    return result.bytes_in / (1024 * 1024) / result.seconds


def scaled(base: int, scale: float) -> int:
    return max(1, int(base * scale))


def fake_openai_key() -> str:
    return "sk-" + ("Ab3" * 14)


def pack_value(index: int) -> str:
    seed = f"TOK{index:03d}ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return seed[:32]


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
