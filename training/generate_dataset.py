"""Generate synthetic training samples that stress LLM-only detection.

The templates here are deliberately chosen to be *hard for regex-based detectors*:
- Custom in-house token formats that don't match known patterns (JWT/AWS/ghp_).
- Plain variable-name-less credentials assigned to opaque names (x, val, tmp).
- Internal hostnames without public TLD hints (single-label, kebab-case).
- Credentials embedded in code-like contexts (Python/TS/YAML fragments).
- Context-dependent user/resource identifiers (e.g., "customer #8842").
- Person names in prose (e.g., Japanese/English report sentences).

Regex can cover most of the "easy" cases (see engine/detectors/rule.py). This
dataset targets what regex *cannot* systematically catch, so an FT'd LLM has a
reason to exist.

Usage:
    python -m training.generate_dataset --out training/data/train.jsonl --n 800
"""
from __future__ import annotations

import argparse
import json
import random
import string
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Sample:
    input: str
    spans: list[dict]


def _rand(alphabet: str, n: int) -> str:
    return "".join(random.choices(alphabet, k=n))


# --- "hard" value generators (LLM-only territory) ----------------------------

def _gen_custom_token() -> str:
    """In-house token format: prefix + segments, nothing standard."""
    prefixes = ["TK", "HX", "CORP", "Z9", "IGT", "ZN"]
    segs = [_rand(string.ascii_uppercase + string.digits, random.randint(4, 8)) for _ in range(random.randint(2, 4))]
    return f"{random.choice(prefixes)}-{'-'.join(segs)}"


def _gen_opaque_cred() -> str:
    """Looks like random gibberish with no hint in the variable name."""
    return _rand(string.ascii_letters + string.digits, random.randint(14, 28))


def _gen_bare_internal_host() -> str:
    """Single-label or kebab-case internal service name without public TLD."""
    names = [
        "billing-svc", "auth-gateway", "orders", "warehouse-api", "ledger",
        "payments-core", "kyc-service", "reporting", "inventory", "fulfillment",
    ]
    return random.choice(names)


def _gen_inline_ip_no_context() -> str:
    """Private IP placed where a regex might not anchor (inside identifier-ish text)."""
    return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _gen_resource_id() -> str:
    return str(random.randint(1000, 999999))


def _gen_person_name_en() -> str:
    first = random.choice(["Alice", "Bob", "Carol", "Dan", "Eve", "Frank", "Grace", "Hank"])
    last = random.choice(["Smith", "Johnson", "Brown", "Davis", "Miller", "Wilson"])
    return f"{first} {last}"


def _gen_person_name_ja() -> str:
    # romanised Japanese-style names (kept ASCII to simplify tokenisation in PoC)
    firsts = ["Taro", "Hanako", "Yuki", "Ren", "Sakura", "Kenji", "Aoi"]
    lasts = ["Tanaka", "Sato", "Suzuki", "Takahashi", "Ito", "Watanabe"]
    return f"{random.choice(lasts)} {random.choice(firsts)}"


# --- templates: each produces a (text, spans) pair --------------------------

_TEMPLATES: list = [
    # 1. custom token in code-like assignment, no "secret=" hint
    ("config.token = \"{tok}\"  # provisioned by platform team", [("tok", "CREDENTIAL")]),
    ("CORP_TOKEN_V2: {tok}", [("tok", "CREDENTIAL")]),
    ("headers['X-Corp-Auth'] = '{tok}'", [("tok", "CREDENTIAL")]),

    # 2. opaque credential assigned to meaningless variable
    ("x = \"{opq}\"  # used by the billing worker", [("opq", "CREDENTIAL")]),
    ("val := '{opq}'  // injected at boot", [("opq", "CREDENTIAL")]),
    ("tmp = \"{opq}\"; sendAuth(tmp)", [("opq", "CREDENTIAL")]),

    # 3. bare internal host, no scheme, no public TLD
    ("connected to {host}:5432 successfully", [("host", "INTERNAL_URL")]),
    ("upstream host = {host}  # k8s service dns", [("host", "INTERNAL_URL")]),
    ("Retrying request to {host} after timeout", [("host", "INTERNAL_URL")]),

    # 4. cred in code-like context with identifier-looking constant name
    ("API_KEY: str = \"{opq}\"  # loaded from vault", [("opq", "CREDENTIAL")]),
    ("const SERVICE_SECRET = '{opq}';", [("opq", "CREDENTIAL")]),

    # 5. context-dependent resource id in prose
    ("customer #{rid} reported the incident", [("rid", "USER_ID")]),
    ("See ticket #{rid} for the stack trace", [("rid", "USER_ID")]),
    ("issue {rid} was closed after the rollback", [("rid", "USER_ID")]),

    # 6. person name in prose (PII_NAME)
    ("{name} confirmed the rollback at 03:12 JST", [("name", "PII_NAME")]),
    ("Reported by {name} after escalation from on-call", [("name", "PII_NAME")]),
    ("{name_ja}-san asked for access to the staging cluster", [("name_ja", "PII_NAME")]),

    # 7. mixed: bare host + opaque cred, no structured format
    (
        "proxy -> {host} with x-internal-token {opq} (expires 60m)",
        [("host", "INTERNAL_URL"), ("opq", "CREDENTIAL")],
    ),

    # 8. private IP with no surrounding quotes or JSON structure
    ("route add {ip} via gw-01 metric 10", [("ip", "INTERNAL_IP")]),
    ("node {host} ({ip}) joined the pool", [("host", "INTERNAL_URL"), ("ip", "INTERNAL_IP")]),

    # 9. custom token embedded mid-sentence
    (
        "the deploy used key {tok} issued by the platform ops for {name}",
        [("tok", "CREDENTIAL"), ("name", "PII_NAME")],
    ),

    # 10. resource id + person + host, report-style
    (
        "{name} opened #{rid} against {host} about the 500s",
        [("name", "PII_NAME"), ("rid", "USER_ID"), ("host", "INTERNAL_URL")],
    ),
]


def _add_span(spans: list[dict], text: str, value: str, category: str) -> None:
    idx = text.find(value)
    if idx < 0:
        return
    spans.append({"start": idx, "end": idx + len(value), "value": value, "category": category})


def _sample(template: tuple) -> Sample:
    tpl, slots = template
    values = {
        "tok": _gen_custom_token(),
        "opq": _gen_opaque_cred(),
        "host": _gen_bare_internal_host(),
        "ip": _gen_inline_ip_no_context(),
        "rid": _gen_resource_id(),
        "name": _gen_person_name_en(),
        "name_ja": _gen_person_name_ja(),
    }
    text = tpl.format(**values)

    spans: list[dict] = []
    for slot_key, category in slots:
        _add_span(spans, text, values[slot_key], category)
    return Sample(input=text, spans=spans)


def generate(n: int, seed: int = 42) -> list[Sample]:
    random.seed(seed)
    return [_sample(random.choice(_TEMPLATES)) for _ in range(n)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--n", type=int, default=800)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--split", type=float, default=0.1, help="Validation split ratio (0.0 - 0.5).")
    args = ap.parse_args()

    samples = generate(args.n, seed=args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    n_val = int(len(samples) * args.split)
    train, val = samples[n_val:], samples[:n_val]

    def _write(path: Path, items: list[Sample]) -> None:
        with path.open("w", encoding="utf-8") as f:
            for s in items:
                f.write(json.dumps({"input": s.input, "spans": s.spans}, ensure_ascii=False) + "\n")

    _write(args.out, train)
    if n_val > 0:
        val_path = args.out.with_name(args.out.stem + ".val" + args.out.suffix)
        _write(val_path, val)
        print(f"wrote train={len(train)} to {args.out}")
        print(f"wrote val={len(val)} to {val_path}")
    else:
        print(f"wrote {len(train)} samples to {args.out}")


if __name__ == "__main__":
    main()
