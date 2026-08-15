"""Small helpers for Pentect Command plugins."""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, Iterable, TextIO

SCHEMA = "pentect.plugin.v1"
HOOKS = frozenset({"prepare", "inspect", "finalize", "request", "response", "tool_call", "file"})
ACTIONS = frozenset({"next", "stop"})
Handler = Callable[[dict[str, Any]], dict[str, Any] | None]


def result(request: dict[str, Any], **values: Any) -> dict[str, Any]:
    """Build a response while preserving Pentect's protocol identity."""
    action = values.get("action", "next")
    if action not in ACTIONS:
        raise ValueError("invalid Pentect action")
    return {
        **values,
        "schema": SCHEMA,
        "id": request["id"],
        "type": "result",
        "action": action,
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
                or request.get("hook") not in HOOKS
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
        try:
            encoded = json.dumps(response, separators=(",", ":"))
        except (TypeError, ValueError):
            encoded = json.dumps({
                "schema": SCHEMA,
                "id": request_id,
                "type": "result",
                "action": "next",
                "error": {"code": "handler_error"},
            }, separators=(",", ":"))
        output.write(encoded + "\n")
        output.flush()
