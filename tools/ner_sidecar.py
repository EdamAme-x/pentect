#!/usr/bin/env python3
"""Persistent semantic PII sidecar for Pentect.

Loads a provider once, then serves requests over stdin/stdout (one JSON request
and one JSON response per line). Pentect's Rust `SemanticDetector` spawns this
and pipes region text through it.

Protocol (newline-delimited JSON, so text with newlines is escaped):
  request:  a JSON string  ->  "John Smith at Acme Corp"
  response: a JSON array   ->  [[0,10,"PERSON"],[14,23,"ORGANIZATION"]]
Offsets are BYTE offsets into the UTF-8 text, matching Rust's span ranges.

Provider: PENTECT_SEMANTIC_PROVIDER (spacy, gliner, presidio). spaCy is the
default because it is lightweight and already installed in many Python stacks;
GLiNER/Presidio are optional comparison adapters when their packages are
available. They are not required for Pentect's core AI tool-boundary flow.
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

PRESIDIO_LABELS = {
    "PERSON": "PERSON",
    "LOCATION": "LOCATION",
    "ORGANIZATION": "ORGANIZATION",
    "NRP": "NRP",
    "ADDRESS": "LOCATION",
}

GLINER_REQUEST_LABELS = [
    "PERSON",
    "ORGANIZATION",
    "LOCATION",
    "ADDRESS",
    "NRP",
]

GLINER_LABELS = {
    "PERSON": "PERSON",
    "ORGANIZATION": "ORGANIZATION",
    "LOCATION": "LOCATION",
    "ADDRESS": "LOCATION",
    "NRP": "NRP",
    "person": "PERSON",
    "full name": "PERSON",
    "organization": "ORGANIZATION",
    "company": "ORGANIZATION",
    "location": "LOCATION",
    "address": "LOCATION",
    "street address": "LOCATION",
    "nationality": "NRP",
    "religion": "NRP",
    "political group": "NRP",
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


def iter_text_chunks(text: str, max_chars: int) -> list[tuple[int, str]]:
    chunks = []
    start = 0
    current = []
    current_start = 0
    current_len = 0
    for line in text.splitlines(keepends=True):
        line_start = start
        start += len(line)
        if current and current_len + len(line) > max_chars:
            chunks.append((current_start, "".join(current)))
            current = []
            current_len = 0
        if not current:
            current_start = line_start
        if len(line) <= max_chars:
            current.append(line)
            current_len += len(line)
            continue
        if current:
            chunks.append((current_start, "".join(current)))
            current = []
            current_len = 0
        for off in range(0, len(line), max_chars):
            chunks.append((line_start + off, line[off : off + max_chars]))
    if current:
        chunks.append((current_start, "".join(current)))
    return chunks


def normalize_provider_name(raw: str) -> str:
    name = raw.strip().lower().replace("_", "-")
    aliases = {
        "ner": "spacy",
        "spacy-ner": "spacy",
        "gliner2": "gliner",
        "gliner2-pii": "gliner",
        "opf": "presidio",
        "presidio-analyzer": "presidio",
    }
    return aliases.get(name, name)


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


def load_gliner_detector():
    from gliner import GLiNER

    # This model uses GLiNER's native artifact layout. GLiNER2 PII checkpoints
    # may need a different runtime even when they are useful for research.
    model_name = os.environ.get(
        "PENTECT_GLINER_MODEL",
        "nvidia/gliner-PII",
    )
    threshold = float(os.environ.get("PENTECT_GLINER_THRESHOLD", "0.45"))
    max_chars = int(os.environ.get("PENTECT_GLINER_CHUNK_CHARS", "6000"))
    model = GLiNER.from_pretrained(model_name)
    labels = os.environ.get("PENTECT_GLINER_LABELS")
    if labels:
        labels = [item.strip() for item in labels.split(",") if item.strip()]
    else:
        labels = GLINER_REQUEST_LABELS

    def detect(text: str) -> list[tuple[int, int, str]]:
        out = []
        for base, chunk in iter_text_chunks(text, max_chars):
            for ent in model.predict_entities(chunk, labels, threshold=threshold):
                raw_label = str(ent.get("label", ""))
                label = GLINER_LABELS.get(raw_label) or GLINER_LABELS.get(raw_label.lower())
                start = ent.get("start")
                end = ent.get("end")
                if label is None or not isinstance(start, int) or not isinstance(end, int):
                    continue
                if not is_probably_technical_entity(chunk[start:end]):
                    out.append((base + start, base + end, label))
        return out

    return detect


def load_presidio_detector():
    from presidio_analyzer import AnalyzerEngine

    analyzer = AnalyzerEngine()
    language = os.environ.get("PENTECT_PRESIDIO_LANGUAGE", "en")

    def detect(text: str) -> list[tuple[int, int, str]]:
        out = []
        for ent in analyzer.analyze(text=text, language=language):
            label = PRESIDIO_LABELS.get(ent.entity_type)
            if label is not None and not is_probably_technical_entity(text[ent.start : ent.end]):
                out.append((ent.start, ent.end, label))
        return out

    return detect


def load_detector(provider: str):
    if provider == "spacy":
        return load_spacy_detector()
    if provider == "gliner":
        return load_gliner_detector()
    if provider == "presidio":
        return load_presidio_detector()
    raise RuntimeError(f"unknown semantic provider: {provider}")


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
    provider = normalize_provider_name(
        os.environ.get(
            "PENTECT_SEMANTIC_PROVIDER",
            os.environ.get("PENTECT_NER_PROVIDER", "spacy"),
        )
    )
    detect = load_detector(provider)
    # Signal readiness so the parent can block until the (slow) model load is done.
    sys.stdout.write(f"READY {provider}\n")
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
