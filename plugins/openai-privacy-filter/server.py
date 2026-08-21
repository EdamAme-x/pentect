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
    managed_root = os.environ.get("PENTECT_OPF_ROOT")
    root = (
        Path(managed_root).expanduser()
        if managed_root
        else Path.home() / ".pentect" / "openai-privacy-filter"
    ) / "venv"
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
        # Execute through the venv path rather than its resolved interpreter.
        # Python discovers pyvenv.cfg from the executable path; bypassing the
        # symlink starts the base interpreter without the venv's packages.
        os.execv(
            str(candidate),
            [str(candidate), str(Path(__file__).resolve()), *sys.argv[1:]],
        )


def _selected_device(argument: str) -> str:
    if argument != "auto":
        return argument
    managed_root = os.environ.get("PENTECT_OPF_ROOT")
    root = (
        Path(managed_root).expanduser()
        if managed_root
        else Path.home() / ".pentect" / "openai-privacy-filter"
    )
    try:
        state = json.loads((root / "setup.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "cpu"
    device = state.get("device") if isinstance(state, dict) else None
    return device if device in {"cpu", "cuda"} else "cpu"


def _managed_checkpoint(argument: Path | None) -> Path | None:
    if argument is not None:
        return argument
    managed_root = os.environ.get("PENTECT_OPF_ROOT")
    root = (
        Path(managed_root).expanduser()
        if managed_root
        else Path.home() / ".pentect" / "openai-privacy-filter"
    )
    try:
        state = json.loads((root / "setup.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    configured = state.get("checkpoint") if isinstance(state, dict) else None
    if isinstance(configured, str) and configured:
        checkpoint = Path(configured).expanduser()
        if checkpoint.is_dir():
            return checkpoint
    checkpoint = root / "checkpoint"
    return checkpoint if checkpoint.is_dir() else None


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
    parser.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    parser.add_argument("--checkpoint", type=Path)
    args = parser.parse_args()

    from opf import OPF

    redactor = OPF(
        model=_managed_checkpoint(args.checkpoint),
        device=_selected_device(args.device),
        output_mode="typed",
        output_text_only=False,
    )
    redactor.get_runtime()
    serve(redactor)


if __name__ == "__main__":
    main()
