import json
import re
import sys


def byte_span(text, start, end):
    return len(text[:start].encode("utf-8")), len(text[:end].encode("utf-8"))


def add(spans, text, match, label, category="pii", confidence="medium"):
    start, end = byte_span(text, match.start(1), match.end(1))
    spans.append(
        {
            "start": start,
            "end": end,
            "label": label,
            "category": category,
            "confidence": confidence,
        }
    )


request = json.load(sys.stdin)
text = request.get("text", "")
spans = []

patterns = [
    (re.compile(r"(?i)\b(?:name|full name|contact)\s*[:=]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})"), "PERSON_NAME"),
    (re.compile(r"(?i)\b(?:address|billing address|ship to)\s*[:=]\s*([0-9A-Za-z][^\r\n]{6,96})"), "POSTAL_ADDRESS"),
    (re.compile(r"(?:氏名|名前)\s*[:：]\s*([^\s,，]{2,16})"), "PERSON_NAME"),
]

for pattern, label in patterns:
    for match in pattern.finditer(text):
        add(spans, text, match, label)

print(json.dumps({"spans": spans}, ensure_ascii=False))

