#!/usr/bin/env python3
"""Evaluate Pentect on a hostile, real-world-ish masking corpus.

This is intentionally not a "make the current engine look good" benchmark.
It mixes structural secrets, shell/config/log contexts, encoded/fractured
values, low-entropy keyed values, and semantic PII that a deterministic core
should not pretend to understand. The goal is not a pass/fail target; it is a
gap corpus that makes today's misses obvious enough to prioritize.

No-cheat rule for using this corpus:
- Do not remove or weaken cases to improve the number.
- Do not hard-code generated values, names, addresses, counts, or case IDs.
- Only add detectors that generalize to a documented syntax, protocol, or
  defensible context pattern.
- Semantic PII should be handled by a general NER layer, not by copying names
  from this file into regexes.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Iterable


DEFAULT_BIN = (
    "target/release/pentect.exe"
    if sys.platform == "win32"
    else "target/release/pentect"
)


@dataclass(frozen=True)
class Target:
    value: str
    category: str
    note: str


@dataclass(frozen=True)
class Case:
    name: str
    text: str
    sensitive: tuple[Target, ...]
    benign: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvalResult:
    coverage: float
    utility: float
    sensitive_total: int
    sensitive_caught: int
    benign_total: int
    benign_preserved: int
    seconds: float
    bytes_in: int
    masked_stdout: str
    stderr: str
    by_category: dict[str, dict[str, int]]
    misses: list[dict[str, str]]
    overmasks: list[str]


def main() -> int:
    args = parse_args()
    cases = build_cases(args.scale)
    result = run_eval(args, cases)
    report = to_report(args, cases, result)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_report(report)
    if args.fail_under_coverage is not None and result.coverage < args.fail_under_coverage:
        return 1
    if args.fail_under_utility is not None and result.utility < args.fail_under_utility:
        return 1
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bin", default=DEFAULT_BIN, help="pentect binary path")
    p.add_argument("--profile", default="balanced")
    p.add_argument("--kind", default="text", choices=["text", "json", "env", "har"])
    p.add_argument("--scale", type=int, default=1, help="repeat corpus families N times")
    p.add_argument(
        "--pentect-arg",
        action="append",
        default=[],
        help="extra argument passed after `pentect mask` (repeatable), e.g. --pentect-arg=--semantic",
    )
    p.add_argument("--json", action="store_true")
    p.add_argument("--fail-under-coverage", type=float)
    p.add_argument("--fail-under-utility", type=float)
    p.add_argument("--sample-limit", type=int, default=25)
    return p.parse_args()


def build_cases(scale: int) -> list[Case]:
    scale = max(1, scale)
    cases: list[Case] = []
    for round_no in range(scale):
        cases.extend(structured_secret_cases(round_no))
        cases.extend(ops_log_cases(round_no))
        cases.extend(encoded_and_fragmented_cases(round_no))
        cases.extend(low_entropy_keyed_cases(round_no))
        cases.extend(semantic_pii_cases(round_no))
        cases.extend(benign_near_miss_cases(round_no))
    return cases


def structured_secret_cases(round_no: int) -> list[Case]:
    cases: list[Case] = []
    for i in range(80):
        n = round_no * 1000 + i
        openai = openai_key(n)
        github = github_token(n)
        runpod = runpod_key(n)
        aws = aws_access_key(n)
        stripe = stripe_key(n)
        card = card_number(i)
        iban = iban_number(i)
        email = f"ops.{n}@example-company.test"
        url = f"postgresql://svc_{n}:pAss-{n}-rotated@db-{i % 7}.internal:5432/app"
        text = "\n".join(
            [
                f"deploy[{n}] OPENAI_API_KEY={openai} GITHUB_TOKEN={github}",
                f"runner env RUNPOD_API_KEY={runpod} AWS_ACCESS_KEY_ID={aws}",
                f"billing stripe={stripe} card={card} iban={iban}",
                f"contact={email} dsn={url} retry={i % 5} build=8da1fcd",
            ]
        )
        cases.append(
            Case(
                f"structured_secret_{n}",
                text,
                (
                    target(openai, "vendor_secret", "OpenAI-style key"),
                    target(github, "vendor_secret", "GitHub token"),
                    target(runpod, "vendor_secret", "RunPod token"),
                    target(aws, "cloud_key", "AWS access key id"),
                    target(stripe, "vendor_secret", "Stripe key"),
                    target(card, "financial_id", "payment card"),
                    target(iban, "financial_id", "IBAN"),
                    target(email, "identity", "email address"),
                    target(url, "connection_secret", "database URL with credentials"),
                ),
                (
                    f"deploy[{n}]",
                    "retry=",
                    "build=8da1fcd",
                ),
            )
        )
    return cases


def ops_log_cases(round_no: int) -> list[Case]:
    cases: list[Case] = []
    for i in range(80):
        n = round_no * 1000 + i
        path_user = f"user{n:04d}"
        win_path = rf"C:\Users\{path_user}\Desktop\client-{i}\.env"
        unix_path = f"/home/{path_user}/.ssh/config"
        phone = phone_number(i)
        btc = btc_address(i)
        pem_body = f"MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT{n:04d}"
        pem = f"-----BEGIN RSA PRIVATE KEY-----\n{pem_body}\n-----END RSA PRIVATE KEY-----"
        text = "\n".join(
            [
                f"ERROR failed loading {win_path}; fallback={unix_path}",
                f"support phone {phone} wallet {btc}",
                pem,
                f"request_id=550e8400-e29b-41d4-a716-{n:012d} status=500 bytes=1048576",
            ]
        )
        cases.append(
            Case(
                f"ops_log_{n}",
                text,
                (
                    target(path_user, "local_context", "username in local path"),
                    target(phone, "phone", "phone number"),
                    target(btc, "crypto_address", "crypto wallet"),
                    target(pem_body, "private_key", "PEM body"),
                ),
                (
                    "status=500",
                    "bytes=1048576",
                    f"client-{i}",
                ),
            )
        )
    return cases


def encoded_and_fragmented_cases(round_no: int) -> list[Case]:
    cases: list[Case] = []
    for i in range(70):
        n = round_no * 1000 + i
        raw = openai_key(n)
        percent = raw.replace("-", "%2D")
        zero_width = raw[:3] + "\u200b" + raw[3:]
        spaced = raw[:2] + " " + raw[2:]
        quoted = raw.replace("-", "\\u002d")
        b64ish = b64_token(n)
        jwt = jwt_like(n)
        text = "\n".join(
            [
                f"proxy saw Authorization: Bearer {percent}",
                f"copy/paste artifact token={zero_width}",
                f"ticket says token maybe `{spaced}`",
                f"json escaped key=\"{quoted}\"",
                f"k8s secret data api-key: {b64ish}",
                f"cookie session={jwt}; SameSite=Lax",
            ]
        )
        cases.append(
            Case(
                f"encoded_fragmented_{n}",
                text,
                (
                    target(percent, "encoded_secret", "percent-encoded key"),
                    target(zero_width, "encoded_secret", "zero-width key"),
                    target(spaced, "fragmented_secret", "space-fragmented key"),
                    target(quoted, "encoded_secret", "JSON-escaped hyphen"),
                    target(b64ish, "encoded_secret", "base64-ish secret payload"),
                    target(jwt, "session_token", "JWT-like cookie"),
                ),
                (
                    "SameSite=Lax",
                    "copy/paste",
                ),
            )
        )
    return cases


def low_entropy_keyed_cases(round_no: int) -> list[Case]:
    cases: list[Case] = []
    for i in range(90):
        n = round_no * 1000 + i
        values = [
            f"summer-{2020 + (i % 9)}!",
            f"{100000 + n}",
            f"blue-team-{i % 13}",
            f"tenant-{i % 17}-trial",
            f"correct-horse-{i % 31}",
        ]
        labels = [
            "password",
            "otp",
            "shared_secret",
            "client_secret",
            "recovery_phrase",
        ]
        text = "\n".join(
            [
                f"Slack paste: {labels[0]} is {values[0]} for the demo box.",
                f"Helpdesk note: {labels[1]}={values[1]}, expires in 30s.",
                f"Legacy config has {labels[2]}: {values[2]}",
                f"OAuth app {labels[3]} '{values[3]}' rotated later.",
                f"Operator wrote {labels[4]} => {values[4]} in the runbook.",
                "benign: port=5432 workers=4 timeout_ms=30000 status=200",
            ]
        )
        cases.append(
            Case(
                f"low_entropy_keyed_{n}",
                text,
                tuple(
                    target(v, "low_entropy_keyed", f"{label} value")
                    for label, v in zip(labels, values)
                ),
                (
                    "port=5432",
                    "workers=4",
                    "timeout_ms=30000",
                    "status=200",
                ),
            )
        )
    return cases


def semantic_pii_cases(round_no: int) -> list[Case]:
    cases: list[Case] = []
    names = [
        "Alice Tanaka",
        "Bob Smith",
        "Carla Gomez",
        "Daisuke Sato",
        "Evelyn Chen",
        "Fatima Khan",
        "George Novak",
        "Hana Suzuki",
        "Ivan Petrov",
        "Julia Rossi",
    ]
    orgs = [
        "Northwind Security",
        "Aperture Labs",
        "Contoso Retail",
        "Kisaragi Clinic",
        "Bluefin Robotics",
    ]
    streets = [
        "1600 Amphitheatre Parkway, Mountain View CA",
        "1-1-2 Otemachi, Chiyoda-ku, Tokyo",
        "221B Baker Street, London",
        "350 Fifth Avenue, New York NY",
        "Unter den Linden 77, Berlin",
    ]
    japanese_name = "\u5c71\u7530\u592a\u90ce"
    japanese_addr = "\u6771\u4eac\u90fd\u6e0b\u8c37\u533a\u9053\u7384\u57421-2-3"
    for i in range(110):
        n = round_no * 1000 + i
        name = names[i % len(names)]
        org = orgs[i % len(orgs)]
        street = streets[i % len(streets)]
        patient_id = f"PT-{2026 + (i % 3)}-{100000 + n}"
        text = "\n".join(
            [
                f"Meeting note: {name} from {org} approved the pentest scope.",
                f"Ship the signed NDA to {street}; concierge has the badge.",
                f"Case {patient_id}: caller says their manager is {names[(i + 3) % len(names)]}.",
                f"JP note: owner={japanese_name} address={japanese_addr}",
                "benign: sprint=42 story=SEC-100482 estimate=8",
            ]
        )
        cases.append(
            Case(
                f"semantic_pii_{n}",
                text,
                (
                    target(name, "semantic_pii", "person name"),
                    target(org, "semantic_pii", "organization"),
                    target(street, "semantic_pii", "street address"),
                    target(patient_id, "case_identifier", "patient/customer case id"),
                    target(japanese_name, "semantic_pii", "Japanese person name"),
                    target(japanese_addr, "semantic_pii", "Japanese address"),
                ),
                (
                    "sprint=42",
                    "story=SEC-100482",
                    "estimate=8",
                ),
            )
        )
    return cases


def benign_near_miss_cases(round_no: int) -> list[Case]:
    cases: list[Case] = []
    for i in range(120):
        n = round_no * 1000 + i
        text = "\n".join(
            [
                f"build={n} sha=356a192b7913b04c54574d18c28d46e6395428ab",
                f"uuid=550e8400-e29b-41d4-a716-{n:012d} trace=00f067aa0ba902b7",
                "card_like=4242424242424241 iban_like=DE15804319371058294618",
                "jwt_like=aaa.bbb.ccc css=#aabbcc asset=app.8da1fcd.js",
                "invoice=INV90070183 amount_cents=1999 retry_after=30",
            ]
        )
        cases.append(
            Case(
                f"benign_near_miss_{n}",
                text,
                (),
                (
                    "356a192b7913b04c54574d18c28d46e6395428ab",
                    f"550e8400-e29b-41d4-a716-{n:012d}",
                    "4242424242424241",
                    "DE15804319371058294618",
                    "aaa.bbb.ccc",
                    "#aabbcc",
                    "INV90070183",
                ),
            )
        )
    return cases


def run_eval(args: argparse.Namespace, cases: list[Case]) -> EvalResult:
    text = render_corpus(cases)
    cmd = [
        args.bin,
        "mask",
        "--kind",
        args.kind,
        "--profile",
        args.profile,
        *args.pentect_arg,
    ]
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        input=text,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    seconds = time.perf_counter() - start
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(proc.returncode)
    masked_cases = split_case_outputs(proc.stdout, cases)

    by_category: dict[str, dict[str, int]] = {}
    misses: list[dict[str, str]] = []
    overmasks: list[str] = []
    sensitive_total = 0
    sensitive_caught = 0
    benign_total = 0
    benign_preserved = 0

    for case in cases:
        case_out = masked_cases.get(case.name, proc.stdout)
        for item in case.sensitive:
            sensitive_total += 1
            row = by_category.setdefault(item.category, {"total": 0, "caught": 0})
            row["total"] += 1
            if item.value in case_out:
                misses.append(
                    {
                        "case": case.name,
                        "category": item.category,
                        "note": item.note,
                        "value": display_value(item.value),
                    }
                )
            else:
                sensitive_caught += 1
                row["caught"] += 1
        for value in case.benign:
            benign_total += 1
            if value in case_out:
                benign_preserved += 1
            else:
                overmasks.append(f"{case.name}: {display_value(value)}")

    coverage = sensitive_caught / max(1, sensitive_total)
    utility = benign_preserved / max(1, benign_total)
    return EvalResult(
        coverage=coverage,
        utility=utility,
        sensitive_total=sensitive_total,
        sensitive_caught=sensitive_caught,
        benign_total=benign_total,
        benign_preserved=benign_preserved,
        seconds=seconds,
        bytes_in=len(text.encode("utf-8")),
        masked_stdout=proc.stdout,
        stderr=proc.stderr,
        by_category=by_category,
        misses=misses,
        overmasks=overmasks,
    )


def to_report(args: argparse.Namespace, cases: list[Case], result: EvalResult) -> dict[str, object]:
    by_category = []
    for category, row in sorted(result.by_category.items()):
        total = row["total"]
        caught = row["caught"]
        by_category.append(
            {
                "category": category,
                "caught": caught,
                "total": total,
                "coverage": caught / max(1, total),
            }
        )
    return {
        "profile": args.profile,
        "kind": args.kind,
        "pentect_args": args.pentect_arg,
        "cases": len(cases),
        "bytes": result.bytes_in,
        "seconds": result.seconds,
        "mib_per_s": result.bytes_in / (1024 * 1024) / max(result.seconds, 1e-9),
        "coverage": result.coverage,
        "sensitive": {
            "caught": result.sensitive_caught,
            "total": result.sensitive_total,
        },
        "utility": result.utility,
        "benign": {
            "preserved": result.benign_preserved,
            "total": result.benign_total,
        },
        "by_category": by_category,
        "miss_samples": result.misses[: args.sample_limit],
        "overmask_samples": result.overmasks[: args.sample_limit],
        "stderr": result.stderr.strip(),
    }


def print_report(report: dict[str, object]) -> None:
    print(
        "hostile real-world coverage "
        f"profile={report['profile']} kind={report['kind']} cases={report['cases']}"
    )
    print(
        f"bytes={report['bytes']} seconds={report['seconds']:.3f} "
        f"MiB/s={report['mib_per_s']:.2f}"
    )
    sensitive = report["sensitive"]
    benign = report["benign"]
    print(
        f"coverage={report['coverage']:.3f} "
        f"caught={sensitive['caught']}/{sensitive['total']}"
    )
    print(
        f"utility={report['utility']:.3f} "
        f"preserved={benign['preserved']}/{benign['total']}"
    )
    print("\nby category:")
    print(f"{'category':<24} {'caught':>8} {'total':>8} {'coverage':>9}")
    for row in report["by_category"]:
        print(
            f"{row['category']:<24} {row['caught']:>8} {row['total']:>8} "
            f"{row['coverage']:>9.3f}"
        )
    if report["miss_samples"]:
        print("\nmiss samples:")
        for miss in report["miss_samples"]:
            print(
                f"  - {miss['category']:<20} {miss['case']}: "
                f"{miss['note']} => {miss['value']}"
            )
    if report["overmask_samples"]:
        print("\novermask samples:")
        for sample in report["overmask_samples"]:
            print(f"  - {sample}")
    if report["stderr"]:
        print(f"\npentect: {report['stderr']}")


def render_corpus(cases: Iterable[Case]) -> str:
    chunks = []
    for case in cases:
        chunks.append(f"\n--- CASE {case.name} ---\n{case.text}\n")
    return "".join(chunks)


def split_case_outputs(masked: str, cases: Iterable[Case]) -> dict[str, str]:
    markers = [(case.name, f"--- CASE {case.name} ---") for case in cases]
    positions = []
    for name, marker in markers:
        pos = masked.find(marker)
        if pos >= 0:
            positions.append((pos, name, marker))
    positions.sort()
    out: dict[str, str] = {}
    for idx, (pos, name, marker) in enumerate(positions):
        start = pos + len(marker)
        end = positions[idx + 1][0] if idx + 1 < len(positions) else len(masked)
        out[name] = masked[start:end]
    return out


def target(value: str, category: str, note: str) -> Target:
    return Target(value=value, category=category, note=note)


def display_value(value: str) -> str:
    collapsed = value.replace("\n", "\\n").replace("\u200b", "\\u200b")
    if len(collapsed) <= 80:
        return collapsed
    return collapsed[:77] + "..."


def token_body(seed: int, length: int, alphabet: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijk") -> str:
    out = []
    x = seed * 1103515245 + 12345
    for _ in range(length):
        x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
        out.append(alphabet[x % len(alphabet)])
    return "".join(out)


def openai_key(seed: int) -> str:
    return "sk" + "-" + token_body(seed, 42)


def github_token(seed: int) -> str:
    return "ghp" + "_" + token_body(seed + 7, 36)


def runpod_key(seed: int) -> str:
    return "rpa" + "_" + token_body(seed + 13, 46)


def aws_access_key(seed: int) -> str:
    return "AKIA" + token_body(seed + 19, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def stripe_key(seed: int) -> str:
    return "sk" + "_live_" + token_body(seed + 23, 24)


def b64_token(seed: int) -> str:
    return token_body(seed + 29, 44, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") + "=="


def jwt_like(seed: int) -> str:
    return (
        token_body(seed + 31, 26, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        + "."
        + token_body(seed + 37, 42, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        + "."
        + token_body(seed + 41, 32, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    )


def card_number(index: int) -> str:
    cards = [
        "4242424242424242",
        "4012888888881881",
        "4111111111111111",
        "5555555555554444",
        "5105105105105100",
        "378282246310005",
        "6011111111111117",
        "3530111333300000",
    ]
    return cards[index % len(cards)]


def iban_number(index: int) -> str:
    ibans = [
        "DE15804319371058294617",
        "GB94804319371058294617",
        "FR7980431937105829461730528",
        "ES8280431937105829461730",
        "IT4680431937105829461730528",
        "NL3280431937105829",
        "CH1480431937105829461",
        "BE92804319371058",
    ]
    return ibans[index % len(ibans)]


def phone_number(index: int) -> str:
    phones = [
        "+14155552671",
        "+442071838750",
        "+81363849000",
        "+4930901820",
        "+33142685300",
        "+390612345678",
        "+34911234567",
        "+919876543210",
    ]
    return phones[index % len(phones)]


def btc_address(index: int) -> str:
    values = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "LXmteg8PyzybHdrywScarTEfieHWJbpAHy",
        "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
    ]
    return values[index % len(values)]


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
