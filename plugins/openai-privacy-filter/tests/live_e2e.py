#!/usr/bin/env python3
"""Run Pentect and OpenAI Privacy Filter with the real local model."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any


SAMPLE = "Please contact Alice Example at alice@example.com or +1 415-555-0100."
EXPECTED_HANDLE_GROUPS = (
    ("PRIVATE_EMAIL", "EMAIL_ADDRESS"),
    ("PRIVATE_PHONE", "PHONE_NUMBER"),
)
CODEX_SAMPLE = "The synthetic test contact is alice@example.com. Reply exactly OK."
EMAIL_HANDLE = re.compile(rb"<<(?:PRIVATE_EMAIL|EMAIL_ADDRESS)_[0-9a-f]{16,64}>>")


def live_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "PENTECT_OPF_SETUP_FIXTURE",
        "GITHUB_ACTIONS",
        "GITHUB_WORKFLOW",
        "GITHUB_REPOSITORY",
    ):
        environment.pop(name, None)
    return environment


def run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: float,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def assert_live_setup(environment: dict[str, str]) -> None:
    root = Path(
        environment.get(
            "PENTECT_OPF_ROOT",
            str(Path.home() / ".pentect" / "openai-privacy-filter"),
        )
    ).expanduser()
    state = json.loads((root / "setup.json").read_text(encoding="utf-8"))
    if state.get("fixture") is True:
        raise RuntimeError("live E2E refused fixture setup state")
    configured = state.get("checkpoint")
    candidates = [root / "checkpoint", Path.home() / ".opf" / "privacy_filter"]
    if isinstance(configured, str) and configured:
        candidates.insert(0, Path(configured).expanduser())
    if not any(
        checkpoint.is_dir()
        and (checkpoint / "config.json").is_file()
        and any(checkpoint.glob("*.safetensors"))
        for checkpoint in candidates
    ):
        raise RuntimeError("live E2E setup has no real model checkpoint")


def mask_once(
    pentect: Path,
    plugin: Path,
    project: Path,
    environment: dict[str, str],
    timeout: float,
) -> float:
    started = time.monotonic()
    result = run(
        [str(pentect), "mask", "--plugins", str(plugin)],
        cwd=project,
        environment=environment,
        timeout=timeout,
        input_text=SAMPLE + "\n",
    )
    elapsed = time.monotonic() - started
    if result.returncode != 0:
        raise RuntimeError(
            f"Pentect mask failed ({result.returncode}): {result.stderr.strip()}"
        )
    for labels in EXPECTED_HANDLE_GROUPS:
        if not any(f"<<{label}_" in result.stdout for label in labels):
            raise RuntimeError(
                f"Pentect did not produce one of {labels!r}; "
                f"stdout={result.stdout.strip()!r}; stderr={result.stderr.strip()!r}"
            )
    if "alice@example.com" in result.stdout or "+1 415-555-0100" in result.stdout:
        raise RuntimeError("real OPF allowed synthetic PII through unchanged")
    if "preparing plugin 'openai-privacy-filter'" not in result.stderr:
        raise RuntimeError("Pentect did not prewarm the real OPF process")
    if "plugin 'openai-privacy-filter' is ready after" not in result.stderr:
        raise RuntimeError("Pentect did not report real OPF readiness")
    return elapsed


def inspect_plugin_once(
    plugin: Path,
    project: Path,
    environment: dict[str, str],
    timeout: float,
    profile: str,
) -> float:
    request = {
        "schema": "pentect.plugin.v1",
        "id": 1,
        "hook": "inspect",
        "payload": {"text": SAMPLE},
    }
    started = time.monotonic()
    result = run(
        [
            shutil.which("python3") or "python3",
            str(plugin / "server.py"),
            "--device",
            "cpu" if profile == "auto" else profile,
        ],
        cwd=project,
        environment=environment,
        timeout=timeout,
        input_text=json.dumps(request, separators=(",", ":")) + "\n",
    )
    elapsed = time.monotonic() - started
    if result.returncode != 0:
        raise RuntimeError(
            f"real OPF protocol probe failed ({result.returncode}): {result.stderr.strip()}"
        )
    try:
        response = json.loads(result.stdout.strip())
    except json.JSONDecodeError as error:
        raise RuntimeError(f"real OPF returned invalid protocol JSON: {error}") from error
    labels = {
        span.get("label")
        for span in response.get("spans", [])
        if isinstance(span, dict)
    }
    missing = {"PRIVATE_EMAIL", "PRIVATE_PHONE"} - labels
    if missing:
        raise RuntimeError(
            f"real OPF protocol probe missed {sorted(missing)!r}; response={response!r}"
        )
    return elapsed


class ProtectedUpstream:
    def __init__(self) -> None:
        self.request_seen = threading.Event()
        self.error: str | None = None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                body = json.dumps({"object": "list", "data": []}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                if b"alice@example.com" in body:
                    owner.error = "Codex upstream received synthetic email in plaintext"
                elif EMAIL_HANDLE.search(body) is None:
                    owner.error = "Codex upstream did not receive a protected email handle"
                owner.request_seen.set()
                encoded = _completed_response_stream()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, _format: str, *_args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}/v1"

    def __enter__(self) -> ProtectedUpstream:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _completed_response_stream() -> bytes:
    message = {
        "id": "msg_pentect_live_e2e",
        "type": "message",
        "status": "completed",
        "role": "assistant",
        "content": [{"type": "output_text", "text": "OK", "annotations": []}],
    }
    events = [
        (
            "response.output_item.added",
            {
                "type": "response.output_item.added",
                "output_index": 0,
                "item": {**message, "status": "in_progress", "content": []},
            },
        ),
        (
            "response.content_part.added",
            {
                "type": "response.content_part.added",
                "item_id": message["id"],
                "output_index": 0,
                "content_index": 0,
                "part": {"type": "output_text", "text": "", "annotations": []},
            },
        ),
        (
            "response.output_text.delta",
            {
                "type": "response.output_text.delta",
                "item_id": message["id"],
                "output_index": 0,
                "content_index": 0,
                "delta": "OK",
            },
        ),
        (
            "response.output_text.done",
            {
                "type": "response.output_text.done",
                "item_id": message["id"],
                "output_index": 0,
                "content_index": 0,
                "text": "OK",
            },
        ),
        (
            "response.content_part.done",
            {
                "type": "response.content_part.done",
                "item_id": message["id"],
                "output_index": 0,
                "content_index": 0,
                "part": message["content"][0],
            },
        ),
        (
            "response.output_item.done",
            {
                "type": "response.output_item.done",
                "output_index": 0,
                "item": message,
            },
        ),
        (
            "response.completed",
            {
                "type": "response.completed",
                "response": {
                    "id": "resp_pentect_live_e2e",
                    "object": "response",
                    "created_at": int(time.time()),
                    "status": "completed",
                    "error": None,
                    "incomplete_details": None,
                    "model": "pentect-live-e2e",
                    "output": [message],
                    "parallel_tool_calls": True,
                    "previous_response_id": None,
                    "reasoning": {"effort": None, "summary": None},
                    "store": False,
                    "text": {"format": {"type": "text"}},
                    "tool_choice": "auto",
                    "tools": [],
                    "truncation": "disabled",
                    "usage": {
                        "input_tokens": 1,
                        "output_tokens": 1,
                        "output_tokens_details": {"reasoning_tokens": 0},
                        "total_tokens": 2,
                    },
                    "metadata": {},
                },
            },
        ),
    ]
    return "".join(
        f"event: {event}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"
        for event, payload in events
    ).encode("utf-8")


def codex_once(
    pentect: Path,
    codex: Path,
    plugin: Path,
    project: Path,
    environment: dict[str, str],
    timeout: float,
    model: str,
) -> float:
    codex_environment = environment.copy()
    codex_environment["PATH"] = os.pathsep.join(
        [str(codex.parent), codex_environment.get("PATH", "")]
    )
    with ProtectedUpstream() as upstream:
        started = time.monotonic()
        result = run(
            [
                str(pentect),
                "codex",
                "--upstream",
                upstream.base_url,
                "--plugins",
                str(plugin),
                "--",
                "exec",
                "--ephemeral",
                "--skip-git-repo-check",
                "--json",
                "-m",
                model,
                CODEX_SAMPLE,
            ],
            cwd=project,
            environment=codex_environment,
            timeout=timeout,
        )
        elapsed = time.monotonic() - started
        if result.returncode != 0:
            raise RuntimeError(
                f"Pentect Codex E2E failed ({result.returncode}): "
                f"{result.stderr.strip()} {result.stdout.strip()}"
            )
        if not upstream.request_seen.is_set():
            raise RuntimeError("Pentect Codex E2E never reached the local upstream")
        if upstream.error is not None:
            raise RuntimeError(upstream.error)
        if "timed out" in result.stderr or "plugin 'openai-privacy-filter' skipped" in result.stderr:
            raise RuntimeError(f"real OPF did not remain active: {result.stderr.strip()}")
        if '"text":"OK"' not in result.stdout:
            raise RuntimeError("Codex did not consume the local upstream response")
        return elapsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pentect", type=Path, required=True)
    parser.add_argument(
        "--plugin",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--profile", choices=("auto", "cpu", "cuda"), default="cpu")
    parser.add_argument("--timeout-seconds", type=float, default=360.0)
    installed_codex = shutil.which("codex")
    parser.add_argument(
        "--codex",
        type=Path,
        default=Path(installed_codex) if installed_codex else None,
    )
    parser.add_argument("--model", default="gpt-5.6-luna")
    parser.add_argument("--skip-codex", action="store_true")
    args = parser.parse_args()

    pentect = args.pentect.expanduser().resolve()
    plugin = args.plugin.expanduser().resolve()
    environment = live_environment()
    with tempfile.TemporaryDirectory(prefix="pentect-opf-live-") as directory:
        project = Path(directory)
        setup = run(
            [
                str(pentect),
                "plugins",
                "setup",
                str(plugin),
                "--project",
                "--profile",
                args.profile,
                "--yes",
            ],
            cwd=project,
            environment=environment,
            timeout=args.timeout_seconds,
        )
        if setup.returncode != 0:
            raise RuntimeError(
                f"real OPF setup failed ({setup.returncode}): {setup.stderr.strip()}"
            )
        assert_live_setup(environment)
        plugin_seconds = inspect_plugin_once(
            plugin, project, environment, args.timeout_seconds, args.profile
        )
        cold_seconds = mask_once(
            pentect, plugin, project, environment, args.timeout_seconds
        )
        restart_seconds = mask_once(
            pentect, plugin, project, environment, args.timeout_seconds
        )
        codex_seconds = None
        if not args.skip_codex:
            if args.codex is None:
                raise RuntimeError("Codex is required; pass --codex or --skip-codex")
            codex_seconds = codex_once(
                pentect,
                args.codex.expanduser().absolute(),
                plugin,
                project,
                environment,
                args.timeout_seconds,
                args.model,
            )

    print(
        json.dumps(
            {
                "schema": "pentect.opf-live-e2e.v1",
                "profile": args.profile,
                "plugin_seconds": round(plugin_seconds, 3),
                "cold_seconds": round(cold_seconds, 3),
                "restart_seconds": round(restart_seconds, 3),
                "codex_seconds": (
                    None if codex_seconds is None else round(codex_seconds, 3)
                ),
                "status": "ok",
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
