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


@dataclass
class HarEntryText:
    """One HAR entry rendered as a compact inspectable text block.

    Used by per-entry masking so each entry is a single in-distribution input
    for the FT LLM (short, single-request sized), while shared values across
    entries still collapse to the same placeholder via SHA-based hashing.
    """
    index: int
    text: str


_INTERESTING_HEADER_NAMES = {"authorization", "cookie", "x-api-key", "x-auth-token"}


def iter_entry_texts(raw: str | dict[str, Any]) -> list[HarEntryText]:
    """Render each HAR entry as a short inspectable text block.

    Format per entry (mirrors demo/juice/identify_vulns.py for consistency):
        METHOD URL
          body: <first 400 chars>
          Authorization: <first 300 chars>
          -> <status> <statusText>
          resp: <first 400 chars if looks interesting>
    """
    if isinstance(raw, str):
        data = json.loads(raw)
    else:
        data = raw

    entries = (data.get("log", {}) or {}).get("entries", []) or []
    out: list[HarEntryText] = []
    for i, entry in enumerate(entries):
        req = entry.get("request", {}) or {}
        res = entry.get("response", {}) or {}
        url = req.get("url") or ""
        method = req.get("method") or "GET"
        lines: list[str] = [f"{method} {url}"]

        body_text = (req.get("postData") or {}).get("text")
        if body_text:
            lines.append(f"  body: {body_text[:400]}")

        for h in req.get("headers", []) or []:
            n = str(h.get("name", "")).lower()
            if n in _INTERESTING_HEADER_NAMES:
                v = str(h.get("value", ""))[:300]
                lines.append(f"  {h.get('name')}: {v}")

        status = res.get("status")
        st_txt = res.get("statusText", "")
        if status:
            lines.append(f"  -> {status} {st_txt}".rstrip())

        res_body = (res.get("content") or {}).get("text") or ""
        if res_body and len(res_body) < 800 and any(
            k in res_body.lower() for k in ("error", "sqlite", "email", "admin", "token")
        ):
            lines.append(f"  resp: {res_body[:400]}")

        out.append(HarEntryText(index=i, text="\n".join(lines)))
    return out
