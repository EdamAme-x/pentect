#!/usr/bin/env python3
"""Local HTTP bridge between Pentect and OpenAI Privacy Filter."""

from __future__ import annotations

import argparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import threading
from typing import Any

MAX_REQUEST_BYTES = 1024 * 1024
SCHEMA = "pentect.openai-privacy-filter.v1"


def _byte_offset(text: str, character_offset: int) -> int:
    if character_offset < 0 or character_offset > len(text):
        raise ValueError("Privacy Filter returned an invalid character offset")
    return len(text[:character_offset].encode("utf-8"))


def inspect_text(redactor: Any, text: str) -> dict[str, object]:
    result = redactor.redact(text)
    if isinstance(result, str):
        raise TypeError("Privacy Filter must return structured output")
    if result.warning:
        raise ValueError(result.warning)
    spans = []
    for span in result.detected_spans:
        spans.append(
            {
                "start": _byte_offset(text, int(span.start)),
                "end": _byte_offset(text, int(span.end)),
                "label": str(span.label),
            }
        )
    return {"schema": SCHEMA, "spans": spans}


class FilterHandler(BaseHTTPRequestHandler):
    server_version = "PentectOpenAIPrivacyFilter/1"
    redactor: Any = None
    inference_lock = threading.Lock()

    def do_GET(self) -> None:
        if self.path != "/health":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        self._json(HTTPStatus.OK, {"schema": SCHEMA, "status": "ready"})

    def do_POST(self) -> None:
        if self.path != "/v1/inspect":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        content_type = self.headers.get_content_type().lower()
        if content_type != "application/json":
            self._json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {"error": "content_type_must_be_application_json"},
            )
            return
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_length"})
            return
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "invalid_size"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            text = payload.get("text") if isinstance(payload, dict) else None
            if not isinstance(text, str):
                raise ValueError("text must be a string")
            with self.inference_lock:
                response = inspect_text(self.redactor, text)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as error:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        except Exception:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "inference_failed"})
            return
        self._json(HTTPStatus.OK, response)

    def _json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.send_header("x-content-type-options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[openai-privacy-filter] {format % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument("--checkpoint", type=Path)
    args = parser.parse_args()

    from opf import OPF

    FilterHandler.redactor = OPF(
        model=args.checkpoint,
        device=args.device,
        output_mode="typed",
        output_text_only=False,
    )
    FilterHandler.redactor.get_runtime()
    # Inference is serial. A single-threaded server also avoids building an
    # unbounded queue of request threads on a developer machine.
    server = HTTPServer(("127.0.0.1", 8787), FilterHandler)
    print("OpenAI Privacy Filter ready at http://127.0.0.1:8787")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
