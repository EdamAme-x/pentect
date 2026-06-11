#!/usr/bin/env python3
"""Persistent NER sidecar for Pentect.

Loads a spaCy model once, then serves requests over stdin/stdout (one JSON
request and one JSON response per line). Pentect's Rust `NerDetector` (the
`ner` feature) spawns this and pipes region text through it.

Protocol (newline-delimited JSON, so text with newlines is escaped):
  request:  a JSON string  ->  "John Smith at Acme Corp"
  response: a JSON array   ->  [[0,10,"PERSON"],[14,23,"ORGANIZATION"]]
Offsets are BYTE offsets into the UTF-8 text, matching Rust's span ranges.

Model: PENTECT_SPACY_MODEL (default en_core_web_lg — same family Presidio
uses). Swap to ai4privacy/DeBERTa later for a strict win over spaCy.
"""
import json
import os
import sys

# spaCy entity label -> Pentect NER label. Only identity-bearing types.
LABELS = {
    "PERSON": "PERSON",
    "ORG": "ORGANIZATION",
    "GPE": "LOCATION",
    "LOC": "LOCATION",
    "FAC": "LOCATION",
    "NORP": "NRP",
}


def main() -> None:
    import spacy

    model = os.environ.get("PENTECT_SPACY_MODEL", "en_core_web_lg")
    nlp = spacy.load(model, disable=["lemmatizer", "tagger", "parser", "attribute_ruler"])
    # Signal readiness so the parent can block until the (slow) model load is done.
    sys.stdout.write("READY\n")
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue
        try:
            text = json.loads(line)
            doc = nlp(text)
            out = []
            for ent in doc.ents:
                label = LABELS.get(ent.label_)
                if label is None:
                    continue
                # char offsets -> byte offsets into the UTF-8 text
                b_start = len(text[: ent.start_char].encode("utf-8"))
                b_end = len(text[: ent.end_char].encode("utf-8"))
                out.append([b_start, b_end, label])
            sys.stdout.write(json.dumps(out) + "\n")
        except Exception:  # never crash the loop on one bad request
            sys.stdout.write("[]\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
