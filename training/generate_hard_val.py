"""Generate a HARD held-out validation set for Pentect.

Design goals (vs training/generate_dataset.py):
  A. Held-out templates: none of these templates appear in train.instruct.jsonl,
     so FT cannot memorise them.
  B. Natural prose: incident reports, post-mortems, Slack threads, code-review
     comments, YAML/Markdown docs. Fewer `x = "..."`-style assignments.
  C. Mixed language: Japanese prose with romanised names/identifiers,
     multi-turn dialogue, bilingual logs.

The hard set is intentionally difficult for regex (rule-only) and for both
a generic Presidio config and a vanilla prompted Gemma 3 4B, so the gap with
FT-LoRA becomes visible.

Usage:
    python -m training.generate_hard_val --out training/data/hard_val.jsonl --n 60
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


def _gen_custom_token() -> str:
    # New prefixes NOT used in train set (train used: TK/HX/CORP/Z9/IGT/ZN)
    prefixes = ["OPS", "SEC", "INFRA", "PLAT", "DEV", "BETA"]
    segs = [_rand(string.ascii_uppercase + string.digits, random.randint(4, 8))
            for _ in range(random.randint(2, 4))]
    return f"{random.choice(prefixes)}:{'-'.join(segs)}"


def _gen_opaque_cred() -> str:
    return _rand(string.ascii_letters + string.digits, random.randint(16, 32))


def _gen_internal_host() -> str:
    # service names NOT in train list
    names = [
        "metrics-collector", "event-bus", "feature-flags", "notification-hub",
        "search-api", "audit-log", "data-lake", "model-registry", "scheduler-v2",
        "risk-engine", "quota-svc",
    ]
    return random.choice(names)


def _gen_private_ip() -> str:
    # 10.x range (train used 172.16-31 range)
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _gen_resource_id() -> str:
    return str(random.randint(10000, 9999999))


def _gen_name_en() -> str:
    firsts = ["Olivia", "Liam", "Noah", "Emma", "Sophia", "Lucas", "Mia", "Ethan",
              "Isabella", "Mason", "Charlotte", "Logan"]
    lasts = ["Anderson", "Thomas", "Martinez", "Robinson", "Clark", "Lewis",
             "Walker", "Hall", "Young", "King"]
    return f"{random.choice(firsts)} {random.choice(lasts)}"


def _gen_name_ja_romaji() -> str:
    firsts = ["Haruto", "Yui", "Sora", "Mei", "Hina", "Riku", "Akari", "Kaito", "Nanami"]
    lasts = ["Nakamura", "Kobayashi", "Yamamoto", "Matsumoto", "Inoue", "Shimizu",
             "Hayashi", "Yamada", "Fujita"]
    return f"{random.choice(lasts)} {random.choice(firsts)}"


# ---------------------------------------------------------------------------
# Hard templates — must NOT overlap with training/generate_dataset.py._TEMPLATES
# ---------------------------------------------------------------------------

_TEMPLATES: list = [
    # ---------------------------
    # A1. Incident post-mortem prose (natural paragraphs)
    # ---------------------------
    (
        "Post-mortem: During the 02:14 incident, {name} noticed that {host} was returning 5xx. "
        "On-call rotated the pod and the upstream recovered within 8 minutes.",
        [("name", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),
    (
        "As part of the retro, {name_ja} summarised the timeline and flagged that the internal "
        "service {host} lacked circuit-breakers, which we'll address in Q3.",
        [("name_ja", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),
    (
        "At 10:42 JST, {name} bumped ticket #{rid} from P3 to P1 after confirming the outage was "
        "user-visible and that {host} hadn't recovered.",
        [("name", "PII_NAME"), ("rid", "USER_ID"), ("host", "INTERNAL_URL")],
    ),

    # ---------------------------
    # A2. Slack-style threads
    # ---------------------------
    (
        "{name}: hey, did the deploy finish? the token {tok} expired 3h ago and our bot stopped posting",
        [("name", "PII_NAME"), ("tok", "CREDENTIAL")],
    ),
    (
        "{name_ja}: can you rotate the shared secret {opq} ? someone committed it to the wiki on monday",
        [("name_ja", "PII_NAME"), ("opq", "CREDENTIAL")],
    ),
    (
        "{name}: ok i'll page {name_ja} — they own {host} this week and the latency is spiking",
        [("name", "PII_NAME"), ("name_ja", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),

    # ---------------------------
    # A3. Code-review / PR comments
    # ---------------------------
    (
        "nit: pls move {opq} out of the repo and into our secret store before merging, "
        "otherwise anyone with read access sees it",
        [("opq", "CREDENTIAL")],
    ),
    (
        "reviewer: this endpoint hits {host} without a timeout — we had an incident in Q1 "
        "exactly because of this pattern, see #{rid}",
        [("host", "INTERNAL_URL"), ("rid", "USER_ID")],
    ),
    (
        "LGTM once the log line at line 42 stops printing {ip}; that's our bastion IP and "
        "shouldn't leak to observability",
        [("ip", "INTERNAL_IP")],
    ),

    # ---------------------------
    # B1. YAML / Helm / k8s-style config (natural structured prose)
    # ---------------------------
    (
        "values.yaml:\n"
        "  upstream:\n"
        "    host: {host}\n"
        "    token: {tok}\n"
        "    audit_contact: {name}",
        [("host", "INTERNAL_URL"), ("tok", "CREDENTIAL"), ("name", "PII_NAME")],
    ),
    (
        "deployment annotations include `owner: {name_ja}` and the sidecar is configured to push "
        "metrics to {host} on port 9090",
        [("name_ja", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),

    # ---------------------------
    # B2. Markdown report
    # ---------------------------
    (
        "## Findings\n\n"
        "- A long-lived token `{tok}` was discovered in the build cache.\n"
        "- The related service `{host}` accepts it without IP allowlisting.\n"
        "- Reporter: {name}.",
        [("tok", "CREDENTIAL"), ("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),
    (
        "### Impact\n\n"
        "Customer #{rid} was exposed because {name} accidentally shared the dashboard link "
        "which embedded a signed cookie value {opq}.",
        [("rid", "USER_ID"), ("name", "PII_NAME"), ("opq", "CREDENTIAL")],
    ),

    # ---------------------------
    # C1. Japanese prose with romaji identifiers
    # ---------------------------
    (
        "インシデント報告: {name_ja}さんが発見した通り、社内サービス {host} に対して "
        "短命トークン {tok} が認証なしで有効化されていました。",
        [("name_ja", "PII_NAME"), ("host", "INTERNAL_URL"), ("tok", "CREDENTIAL")],
    ),
    (
        "事後対応として、顧客ID {rid} のアクセスログを {name} に展開し、影響範囲の確認を依頼しました。",
        [("rid", "USER_ID"), ("name", "PII_NAME")],
    ),
    (
        "ステージング環境 {host} ({ip}) でのみ再現したため、本番影響はなしと判断。"
        "担当: {name_ja}、チケット #{rid}。",
        [("host", "INTERNAL_URL"), ("ip", "INTERNAL_IP"),
         ("name_ja", "PII_NAME"), ("rid", "USER_ID")],
    ),

    # ---------------------------
    # C2. Bilingual log / dialogue
    # ---------------------------
    (
        "[ops] {name} escalated to {name_ja} at 03:12 — 内部ホスト {host} returning 502s, "
        "token {opq} rotated immediately.",
        [("name", "PII_NAME"), ("name_ja", "PII_NAME"),
         ("host", "INTERNAL_URL"), ("opq", "CREDENTIAL")],
    ),
    (
        "SRE memo: チケット #{rid} の root cause は {host} の設定漏れ。assigned to {name}.",
        [("rid", "USER_ID"), ("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),

    # ---------------------------
    # D. "hidden in plain sight" — no variable name, no quotes
    # ---------------------------
    (
        "Forgot to rotate: previous value was {opq}, new one is {tok} — please update your local .env",
        [("opq", "CREDENTIAL"), ("tok", "CREDENTIAL")],
    ),
    (
        "The bastion answered ping from {ip} exactly once, then went silent; {name} will investigate.",
        [("ip", "INTERNAL_IP"), ("name", "PII_NAME")],
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
        "host": _gen_internal_host(),
        "ip": _gen_private_ip(),
        "rid": _gen_resource_id(),
        "name": _gen_name_en(),
        "name_ja": _gen_name_ja_romaji(),
    }
    text = tpl.format(**values)
    spans: list[dict] = []
    for slot_key, category in slots:
        _add_span(spans, text, values[slot_key], category)
    return Sample(input=text, spans=spans)


def generate(n: int, seed: int = 7) -> list[Sample]:
    random.seed(seed)
    return [_sample(random.choice(_TEMPLATES)) for _ in range(n)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--n", type=int, default=60)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    samples = generate(args.n, seed=args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps({"input": s.input, "spans": s.spans}, ensure_ascii=False) + "\n")

    total_spans = sum(len(s.spans) for s in samples)
    by_cat: dict[str, int] = {}
    for s in samples:
        for sp in s.spans:
            by_cat[sp["category"]] = by_cat.get(sp["category"], 0) + 1
    print(f"wrote {len(samples)} samples ({total_spans} spans) to {args.out}")
    print(f"by category: {by_cat}")


if __name__ == "__main__":
    main()
