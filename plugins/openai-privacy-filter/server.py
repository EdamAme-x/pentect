#!/usr/bin/env python3
"""OpenAI Privacy Filter as a Pentect Command plugin."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

MAX_REQUEST_BYTES = 1024 * 1024
PROTOCOL_SCHEMA = "pentect.plugin.v1"


def _use_managed_python() -> None:
    root = Path.home() / ".pentect" / "openai-privacy-filter" / "venv"
    candidate = (
        root / "Scripts" / "python.exe"
        if os.name == "nt"
        else root / "bin" / "python"
    )
    if not candidate.is_file():
        return
    try:
        current = Path(sys.executable).resolve()
        managed = candidate.resolve()
    except OSError:
        return
    if current != managed:
        os.execv(str(managed), [str(managed), str(Path(__file__).resolve()), *sys.argv[1:]])


def _byte_offset(text: str, character_offset: int) -> int:
    if character_offset < 0 or character_offset > len(text):
        raise ValueError("Privacy Filter returned an invalid character offset")
    return len(text[:character_offset].encode("utf-8"))


def _label(value: object) -> tuple[str, str]:
    raw = str(value)
    label = "".join(
        character.upper() if character.isascii() and character.isalnum() else "_"
        for character in raw
    ).strip("_")
    return (label or "PII", "secret" if raw.lower() == "secret" else "pii")


def inspect_text(redactor: Any, text: str) -> list[dict[str, object]]:
    result = redactor.redact(text)
    if isinstance(result, str):
        raise TypeError("Privacy Filter must return structured output")
    if result.warning:
        raise ValueError(result.warning)
    spans = []
    for span in result.detected_spans:
        label, category = _label(span.label)
        spans.append(
            {
                "start": _byte_offset(text, int(span.start)),
                "end": _byte_offset(text, int(span.end)),
                "label": label,
                "category": category,
                "confidence": "medium",
            }
        )
    return spans


def handle_request(redactor: Any, request: object) -> dict[str, object]:
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    request_id = request.get("id")
    payload = request.get("payload")
    if (
        request.get("schema") != PROTOCOL_SCHEMA
        or request.get("hook") != "inspect"
        or not isinstance(request_id, int)
        or not isinstance(payload, dict)
        or not isinstance(payload.get("text"), str)
    ):
        raise ValueError("invalid Pentect plugin request")
    return {
        "schema": PROTOCOL_SCHEMA,
        "id": request_id,
        "type": "result",
        "action": "next",
        "spans": inspect_text(redactor, payload["text"]),
    }


def serve(redactor: Any) -> None:
    for line in sys.stdin.buffer:
        request_id: int | None = None
        try:
            if len(line) > MAX_REQUEST_BYTES:
                raise ValueError("request exceeds the plugin limit")
            request = json.loads(line)
            if isinstance(request, dict) and isinstance(request.get("id"), int):
                request_id = request["id"]
            response = handle_request(redactor, request)
        except Exception:
            response = {
                "schema": PROTOCOL_SCHEMA,
                "id": request_id,
                "type": "result",
                "action": "next",
                "error": {"code": "inference_failed"},
            }
        encoded = json.dumps(
            response, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        sys.stdout.buffer.write(encoded + b"\n")
        sys.stdout.buffer.flush()


def main() -> None:
    _use_managed_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument("--checkpoint", type=Path)
    args = parser.parse_args()

    from opf import OPF

    redactor = OPF(
        model=args.checkpoint,
        device=args.device,
        output_mode="typed",
        output_text_only=False,
    )
    redactor.get_runtime()
    serve(redactor)


if __name__ == "__main__":
    main()
