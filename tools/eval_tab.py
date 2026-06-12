#!/usr/bin/env python3
"""Evaluate Pentect on the Text Anonymization Benchmark (TAB).

Runs the pentect CLI on each ECHR test doc and computes ENTITY-LEVEL recall
(an identifier is concealed only if ALL its DIRECT/QUASI mentions disappear
from the masked output), broken down by entity type.

FINDINGS (echr_test.json, 127 docs):
  - Deterministic core alone: 0.0% on every type. NOT a bug — TAB is the
    WRONG DOMAIN: ECHR court prose is PERSON/ORG/LOC/DATETIME/QUANTITY/case-
    codes and contains ZERO API keys, cards, IBANs, or credentials, which is
    exactly what the deterministic core detects. TAB's per-span mask format
    fits a masking engine, but its CONTENT does not fit a secrets/technical-
    text tool. Pentect is not a court-document anonymizer.
  - With `--enable DATE_TIME`: DATETIME recall jumps to 73.2% (1719/2349),
    validating the date detector on real prose.
  - DIRECT identifiers (mostly PERSON names + codes): 0% — these need the NER
    sidecar (GLiNER), confirming the research recommendation.
Takeaway: evaluate Pentect on secrets-in-technical-text (SecretBench — gated
behind GCP BigQuery; ai4privacy structured PII; or the in-repo research-metric
corpus), not prose anonymization. Run:  python tools/eval_tab.py [BIN] [DATA] [flags...]
"""
import json
import subprocess
import sys
from collections import defaultdict

BIN = sys.argv[1] if len(sys.argv) > 1 else "target/debug/pentect.exe"
DATA = sys.argv[2] if len(sys.argv) > 2 else "target/tab/echr_test.json"
EXTRA = sys.argv[3:]  # extra engine flags, e.g. --enable DATE_TIME

docs = json.load(open(DATA, encoding="utf-8"))
by_type = defaultdict(lambda: [0, 0])  # entity_type -> [concealed, total]
direct = [0, 0]
quasi = [0, 0]

for doc in docs:
    text = doc["text"]
    masked = subprocess.run(
        [BIN, "mask", *EXTRA], input=text, capture_output=True, text=True, encoding="utf-8"
    ).stdout
    ann = next(iter(doc["annotations"].values()))  # first annotator
    # group mentions by entity_id, keep DIRECT/QUASI only
    ents = defaultdict(lambda: {"mentions": [], "type": "?", "idt": "?"})
    for m in ann["entity_mentions"]:
        if m["identifier_type"] not in ("DIRECT", "QUASI"):
            continue
        e = ents[m["entity_id"]]
        e["mentions"].append(m["span_text"])
        e["type"] = m["entity_type"]
        e["idt"] = m["identifier_type"]
    for e in ents.values():
        concealed = all(s not in masked for s in e["mentions"] if s.strip())
        by_type[e["type"]][1] += 1
        by_type[e["type"]][0] += concealed
        tgt = direct if e["idt"] == "DIRECT" else quasi
        tgt[1] += 1
        tgt[0] += concealed

def pct(c, t):
    return f"{100*c/t:.1f}% ({c}/{t})" if t else "n/a"

print(f"TAB ({len(docs)} docs) — entity-level recall, Pentect deterministic core:")
print(f"  DIRECT identifiers: {pct(*direct)}")
print(f"  QUASI  identifiers: {pct(*quasi)}")
print("  by entity_type:")
for t, (c, n) in sorted(by_type.items(), key=lambda kv: -kv[1][1]):
    print(f"    {t:14s} {pct(c, n)}")
