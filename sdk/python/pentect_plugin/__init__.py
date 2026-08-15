"""Small helpers for Pentect Command plugins."""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, Iterable, TextIO

SCHEMA = "pentect.plugin.v1"
Handler = Callable[[dict[str, Any]], dict[str, Any] | None]


def result(request: dict[str, Any], **values: Any) -> dict[str, Any]:
    """Build a response while preserving Pentect's protocol identity."""
    return {
        **values,
        "schema": SCHEMA,
        "id": request["id"],
        "type": "result",
        "action": values.get("action", "next"),
    }


def serve(
    handler: Handler,
    input: TextIO = sys.stdin,
    output: TextIO = sys.stdout,
) -> None:
    """Run one handler call per JSONL request until stdin closes."""
    for line in input:
        request_id: int | None = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("request must be an object")
            request_id = request.get("id")
            if (
                request.get("schema") != SCHEMA
                or type(request_id) is not int
                or request_id < 1
                or not isinstance(request.get("hook"), str)
                or "payload" not in request
            ):
                raise ValueError("invalid Pentect request")
            response = result(request, **(handler(request) or {}))
        except Exception:
            response = {
                "schema": SCHEMA,
                "id": request_id,
                "type": "result",
                "action": "next",
                "error": {"code": "handler_error"},
            }
        output.write(json.dumps(response, separators=(",", ":")) + "\n")
        output.flush()
