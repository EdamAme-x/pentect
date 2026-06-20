#!/usr/bin/env python3
"""Persistent semantic PII sidecar for Pentect.

Loads a spaCy model once, then serves requests over stdin/stdout (one JSON
request and one JSON response per line). Pentect's Rust `SemanticDetector`
spawns this and pipes region text through it.

Protocol (newline-delimited JSON, so text with newlines is escaped):
  request:  a JSON string  ->  "John Smith at Acme Corp"
  response: a JSON array   ->  [[0,10,"PERSON"],[14,23,"ORGANIZATION"]]
Offsets are BYTE offsets into the UTF-8 text, matching Rust's span ranges.

Provider: spaCy. Semantic detection is optional and not part of Pentect's
deterministic AI tool-boundary core.
"""
import json
import os
import re
import sys

SPACY_LABELS = {
    "PERSON": "PERSON",
    "ORG": "ORGANIZATION",
    "GPE": "LOCATION",
    "LOC": "LOCATION",
    "FAC": "LOCATION",
    "NORP": "NRP",
}

TECH_INDEX_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*\[\d+\]?$")
TECH_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-\[\]]{7,}$")

ADDRESS_PATTERNS = [
    # 1600 Amphitheatre Parkway, Mountain View CA
    # 221B Baker Street, London
    re.compile(
        r"""
        \b\d{1,6}[A-Za-z]?(?:[-/]\d{1,6}[A-Za-z]?){0,2}
        \s+
        (?:[A-Z][\w.'-]*\s+|[a-z][\w.'-]*\s+){0,6}
        (?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|
           Drive|Dr\.?|Lane|Ln\.?|Parkway|Pkwy\.?|Way|Court|Ct\.?|
           Place|Pl\.?|Square|Sq\.?|Terrace|Trail|Circle|Cir\.?)
        \b
        (?:,\s*[A-Z][\w.'-]*(?:\s+[A-Z][\w.'-]*){0,4}(?:\s+[A-Z]{2})?)?
        """,
        re.VERBOSE,
    ),
    # 1-1-2 Otemachi, Chiyoda-ku, Tokyo
    re.compile(
        r"""
        \b\d{1,4}(?:-\d{1,4}){1,3}
        \s+[A-Z][\w.'-]*
        (?:,\s*[A-Z][\w.'-]*(?:-[a-z]+)?){1,4}
        """,
        re.VERBOSE,
    ),
    # Japanese address-like runs. This is deliberately structural, not a list
    # of benchmark strings.
    re.compile(
        r"[\u3040-\u30ff\u3400-\u9fff]{2,}(?:都|道|府|県)"
        r"[\u3040-\u30ff\u3400-\u9fff0-9０-９\-ー丁目番地号区市町村郡]+"
    ),
]

CJK_PERSON_CONTEXT_RE = re.compile(
    r"(?i)(?:^|[\s,;])(?:owner|name|person|caller|manager|担当|氏名|名前|所有者)"
    r"[ \t:=：]{1,8}"
    r"([\u3040-\u30ff\u3400-\u9fff]{2,8})"
)


def is_probably_technical_entity(value: str) -> bool:
    s = value.strip(" \t\r\n'\"`.,;:()")
    if not s:
        return True
    # Multi-line or assignment-shaped spans are almost always log/config blobs,
    # not a single semantic person/org/location entity.
    if "\n" in s or "\r" in s or "=" in s:
        return True
    # Filesystem paths and URLs are structured data. Core rules handle the
    # sensitive path segment; NER should not mask the whole debug path as ORG.
    if "\\" in s or "/" in s:
        return True
    # deploy[42], worker-7, client-16, trace IDs, invalid IBAN-like fixtures.
    if TECH_INDEX_RE.fullmatch(s):
        return True
    if len(s) >= 8 and any(ch.isdigit() for ch in s) and TECH_TOKEN_RE.fullmatch(s):
        return True
    return False


def byte_offsets(text: str, start: int, end: int) -> tuple[int, int]:
    return (
        len(text[:start].encode("utf-8")),
        len(text[:end].encode("utf-8")),
    )


def collect_address_entities(text: str) -> list[tuple[int, int, str]]:
    out = []
    for pattern in ADDRESS_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span()
            value = text[start:end].strip()
            if value and not is_probably_technical_entity(value):
                out.append((start, end, "LOCATION"))
    return out


def collect_contextual_person_entities(text: str) -> list[tuple[int, int, str]]:
    out = []
    for match in CJK_PERSON_CONTEXT_RE.finditer(text):
        start, end = match.span(1)
        value = text[start:end].strip()
        if value and not is_probably_technical_entity(value):
            out.append((start, end, "PERSON"))
    return out


def load_spacy_detector():
    import spacy

    model = os.environ.get("PENTECT_SPACY_MODEL", "en_core_web_lg")
    nlp = spacy.load(model, disable=["lemmatizer", "tagger", "parser", "attribute_ruler"])

    def detect(text: str) -> list[tuple[int, int, str]]:
        out = []
        doc = nlp(text)
        for ent in doc.ents:
            label = SPACY_LABELS.get(ent.label_)
            if label is not None and not is_probably_technical_entity(ent.text):
                out.append((ent.start_char, ent.end_char, label))
        return out

    return detect


def encode_response(text: str, spans: list[tuple[int, int, str]]) -> list[list[object]]:
    response = []
    seen = set()
    for start, end, label in sorted(spans):
        if not (0 <= start < end <= len(text)):
            continue
        key = (start, end, label)
        if key in seen:
            continue
        seen.add(key)
        b_start, b_end = byte_offsets(text, start, end)
        response.append([b_start, b_end, label])
    return response


def main() -> None:
    detect = load_spacy_detector()
    # Signal readiness so the parent can block until the (slow) model load is done.
    sys.stdout.write("READY\n")
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue
        try:
            text = json.loads(line)
            out = detect(text)
            out.extend(collect_address_entities(text))
            out.extend(collect_contextual_person_entities(text))
            sys.stdout.write(json.dumps(encode_response(text, out)) + "\n")
        except Exception:  # never crash the loop on one bad request
            sys.stdout.write("[]\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
