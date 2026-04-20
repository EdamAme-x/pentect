"""HAR (HTTP Archive) parser.

Extracts fields that may contain secrets:
- request URL, headers, query string, body
- response headers, body
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class HarField:
    """One scannable field extracted from a HAR."""
    path: str          # e.g. "entries[0].request.url"
    text: str          # raw text to inspect


@dataclass
class ParsedHar:
    fields: list[HarField] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


def _collect_headers(prefix: str, headers: list[dict[str, Any]], out: list[HarField]) -> None:
    for i, h in enumerate(headers or []):
        name = h.get("name", "")
        value = h.get("value", "")
        if value:
            out.append(HarField(path=f"{prefix}[{i}].{name}", text=str(value)))


def parse_har(raw: str | dict[str, Any]) -> ParsedHar:
    """Parse a HAR string or dict into fields to scan."""
    if isinstance(raw, str):
        data = json.loads(raw)
    else:
        data = raw

    entries = (data.get("log", {}) or {}).get("entries", []) or []
    fields: list[HarField] = []

    for i, entry in enumerate(entries):
        req = entry.get("request", {}) or {}
        res = entry.get("response", {}) or {}

        url = req.get("url")
        if url:
            fields.append(HarField(path=f"entries[{i}].request.url", text=str(url)))

        _collect_headers(f"entries[{i}].request.headers", req.get("headers", []), fields)
        _collect_headers(f"entries[{i}].response.headers", res.get("headers", []), fields)

        for j, q in enumerate(req.get("queryString", []) or []):
            v = q.get("value")
            if v:
                fields.append(
                    HarField(path=f"entries[{i}].request.query[{j}].{q.get('name','')}", text=str(v))
                )

        for j, c in enumerate(req.get("cookies", []) or []):
            v = c.get("value")
            if v:
                fields.append(
                    HarField(path=f"entries[{i}].request.cookies[{j}].{c.get('name','')}", text=str(v))
                )
        for j, c in enumerate(res.get("cookies", []) or []):
            v = c.get("value")
            if v:
                fields.append(
                    HarField(path=f"entries[{i}].response.cookies[{j}].{c.get('name','')}", text=str(v))
                )

        post = req.get("postData", {}) or {}
        body_text = post.get("text")
        if body_text:
            fields.append(HarField(path=f"entries[{i}].request.postData.text", text=str(body_text)))

        content = res.get("content", {}) or {}
        res_text = content.get("text")
        if res_text:
            fields.append(HarField(path=f"entries[{i}].response.content.text", text=str(res_text)))

    return ParsedHar(fields=fields, raw=data)
