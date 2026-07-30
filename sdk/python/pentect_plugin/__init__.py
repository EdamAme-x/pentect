"""Zero-dependency helpers for Pentect persistent stdio plugins."""

import json
import os
import sys

SCHEMA = "pentect.plugin.v1"


def config_path():
    """Approved config path, or None without config:read."""
    return os.environ.get("PENTECT_PLUGIN_CONFIG")


def cache_path():
    """Plugin cache path, or None without cache:write."""
    return os.environ.get("PENTECT_PLUGIN_CACHE_DIR")


def next_(request, *, payload=None, spans=None):
    response = {
        "schema": SCHEMA,
        "id": request["id"],
        "type": "result",
        "action": "next",
    }
    if payload is not None:
        response["payload"] = payload
    if spans is not None:
        response["spans"] = spans
    return response


def stop(request, outcome="block", *, payload=None, message=None):
    response = {
        "schema": SCHEMA,
        "id": request["id"],
        "type": "result",
        "action": "stop",
        "outcome": outcome,
    }
    if payload is not None:
        response["payload"] = payload
    if message is not None:
        response["message"] = message
    return response


def serve(handler):
    for line in sys.stdin:
        request = json.loads(line)
        if request.get("schema") != SCHEMA:
            raise ValueError("unsupported Pentect plugin schema")
        if request.get("type") == "initialize":
            response = {
                "schema": SCHEMA,
                "id": request["id"],
                "type": "initialized",
            }
        else:
            response = handler(request)
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()
