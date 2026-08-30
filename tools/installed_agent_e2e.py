#!/usr/bin/env python3
"""Run paid-key-free installed-agent boundary tests against localhost fixtures."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import signal
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


HANDLE = re.compile(r"<<[A-Z][A-Z0-9_]*_[0-9a-f]{16}>>")
IMAGE_SECRET = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX"
IMAGE_PNG_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAASgAAAEoAQMAAADRyf5aAAAABlBMVEUAAAD///+l2Z/d"
    "AAAAAnRSTlP//8i138cAAAAJcEhZcwAACxIAAAsSAdLdfvwAAAF8SURBVGiB7ZrLrsIw"
    "EEP9/z/tq3beSSp1gXQX9VBKgbOypo4zAL4piPKSElFSIkpK/LMSsLrfXa95ZZ+KWpVg"
    "nG+1rsNUGwBEMZTArY+pVUrltSiclKC313XxrBdFMZSx5+i3XS+Kuspc/pbFNHvyL3ye"
    "suLyeFgf8Xkqqvk95hfjDb5OwSOEmb3nL/N9UdiVYFiW61XHsC6Kops4upOnVU3/oihm"
    "+6Ap5neo9dNoMohi3mfY8kJ6nSgM/0LEVGusSBO5ZojCsj6iDL9GE5laRXHZ6bB2jqFX"
    "ix6iMFMaaozTxIk1URQXJehd1SaG+RSFNbnTu6vdnO5hM7RCFLO72GNX3zP1vApR7BOv"
    "SqW1oRx+D1FZcbvlWtlCrCimEiivyqifEzBR3JSgnWuRTCM7zFchiqlSzHRO+Z6iuPyS"
    "wRgVeg/NIT5EYXQOfRlM3Y79RVFXxf8Acjt5f3jwL36esqpf0TK1bvMJiHpReANRVJSU"
    "iJISUVIi6pdK/AHPECxsuaPlLgAAAABJRU5ErkJggg=="
)


def response_object(response_id: str, output: list[dict[str, object]]) -> dict[str, object]:
    return {
        "id": response_id,
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "error": None,
        "incomplete_details": None,
        "instructions": None,
        "max_output_tokens": None,
        "model": "gpt-5.6-luna",
        "output": output,
        "parallel_tool_calls": True,
        "previous_response_id": None,
        "reasoning": {"effort": "none", "summary": None},
        "store": False,
        "temperature": None,
        "text": {"format": {"type": "text"}},
        "tool_choice": "auto",
        "tools": [],
        "top_p": None,
        "truncation": "disabled",
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "metadata": {},
    }


def sse(events: list[dict[str, object]]) -> bytes:
    return b"".join(
        f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n".encode()
        for event in events
    ) + b"data: [DONE]\n\n"


def shell_command(arguments: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(arguments)
    return shlex.join(arguments)


def tool_response(sequence: int, source: str) -> bytes:
    response_id = f"resp_e2e_{sequence}"
    item_id = f"ct_e2e_{sequence}"
    call_id = f"call_e2e_{sequence}"
    item = {
        "id": item_id,
        "type": "custom_tool_call",
        "status": "completed",
        "call_id": call_id,
        "name": "exec",
        "input": source,
    }
    pending = dict(item, status="in_progress", input="")
    return sse([
        {"type": "response.output_item.added", "response_id": response_id, "output_index": 0, "item": pending},
        {"type": "response.custom_tool_call_input.delta", "response_id": response_id, "item_id": item_id, "output_index": 0, "delta": source},
        {"type": "response.custom_tool_call_input.done", "response_id": response_id, "item_id": item_id, "output_index": 0, "call_id": call_id, "name": "exec", "input": source},
        {"type": "response.output_item.done", "response_id": response_id, "output_index": 0, "item": item},
        {"type": "response.completed", "response": response_object(response_id, [item])},
    ])


def text_response(sequence: int, text: str) -> bytes:
    response_id = f"resp_e2e_{sequence}"
    item_id = f"msg_e2e_{sequence}"
    item = {
        "id": item_id,
        "type": "message",
        "status": "completed",
        "role": "assistant",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    }
    return sse([
        {"type": "response.output_item.added", "response_id": response_id, "output_index": 0, "item": dict(item, status="in_progress", content=[])},
        {"type": "response.content_part.added", "response_id": response_id, "item_id": item_id, "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}},
        {"type": "response.output_text.delta", "response_id": response_id, "item_id": item_id, "output_index": 0, "content_index": 0, "delta": text},
        {"type": "response.output_text.done", "response_id": response_id, "item_id": item_id, "output_index": 0, "content_index": 0, "text": text},
        {"type": "response.content_part.done", "response_id": response_id, "item_id": item_id, "output_index": 0, "content_index": 0, "part": item["content"][0]},
        {"type": "response.output_item.done", "response_id": response_id, "output_index": 0, "item": item},
        {"type": "response.completed", "response": response_object(response_id, [item])},
    ])


def chat_sse(chunks: list[dict[str, object]]) -> bytes:
    return b"".join(
        f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n".encode()
        for chunk in chunks
    ) + b"data: [DONE]\n\n"


def chat_text_response(sequence: int, text: str) -> bytes:
    base = {
        "id": f"chatcmpl_e2e_{sequence}",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": "gpt-5.6-luna",
    }
    return chat_sse([
        dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": None}]),
        dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}]),
    ])


def chat_tool_response(sequence: int, command: str) -> bytes:
    base = {
        "id": f"chatcmpl_e2e_{sequence}",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": "gpt-5.6-luna",
    }
    call = {
        "index": 0,
        "id": f"call_e2e_{sequence}",
        "type": "function",
        "function": {
            "name": "bash",
            "arguments": json.dumps({"command": command}, separators=(",", ":")),
        },
    }
    return chat_sse([
        dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "tool_calls": [call]}, "finish_reason": None}]),
        dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]),
    ])


def anthropic_sse(events: list[dict[str, object]]) -> bytes:
    return b"".join(
        f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n".encode()
        for event in events
    )


def anthropic_message(sequence: int) -> dict[str, object]:
    return {
        "id": f"msg_e2e_{sequence}",
        "type": "message",
        "role": "assistant",
        "content": [],
        "model": "claude-sonnet-4-5",
        "stop_reason": None,
        "stop_sequence": None,
        "usage": {
            "input_tokens": 1,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "output_tokens": 1,
        },
    }


def anthropic_tool_response(sequence: int, command: str) -> bytes:
    return anthropic_sse([
        {"type": "message_start", "message": anthropic_message(sequence)},
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {
                "type": "tool_use",
                "id": f"toolu_e2e_{sequence}",
                "name": "Bash",
                "input": {},
            },
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {
                "type": "input_json_delta",
                "partial_json": json.dumps({"command": command}, separators=(",", ":")),
            },
        },
        {"type": "content_block_stop", "index": 0},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use", "stop_sequence": None},
            "usage": {"output_tokens": 1},
        },
        {"type": "message_stop"},
    ])


def anthropic_text_response(sequence: int, text: str) -> bytes:
    return anthropic_sse([
        {"type": "message_start", "message": anthropic_message(sequence)},
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": text},
        },
        {"type": "content_block_stop", "index": 0},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": None},
            "usage": {"output_tokens": 1},
        },
        {"type": "message_stop"},
    ])


class State:
    def __init__(self, valid: str, invalid: str, *, hold_model: bool = False) -> None:
        self.valid = valid
        self.invalid = invalid
        self.hold_model = hold_model
        self.model_request_seen = threading.Event()
        self.release_model_request = threading.Event()
        self.model_requests: list[str] = []
        self.service_attempts: list[str] = []
        self.anthropic_probe_responses = [0, 0]
        self.anthropic_actions: list[dict[str, object]] = []


class Handler(BaseHTTPRequestHandler):
    server: "FixtureServer"

    def do_GET(self) -> None:
        if self.path.startswith("/v1/models"):
            self._json({"object": "list", "data": []})
            return
        self.send_error(404)

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        if self.path == "/check":
            authorization = self.headers.get("authorization", "")
            self.server.state.service_attempts.append(authorization)
            status = 200 if authorization == f"Bearer {self.server.state.valid}" else 401
            self._json({"ok": status == 200}, status)
            return
        request_path = self.path.split("?", 1)[0]
        if request_path.endswith("/messages/count_tokens"):
            self._json({"input_tokens": 1})
            return
        if request_path.endswith("/messages"):
            request = body.decode("utf-8")
            self.server.state.model_requests.append(request)
            sequence = len(self.server.state.model_requests)
            parsed = json.loads(request)
            bash_enabled = any(
                isinstance(tool, dict) and tool.get("name") == "Bash"
                for tool in parsed.get("tools", [])
            )
            handles = anthropic_env_handles(parsed)
            attempts = len(self.server.state.service_attempts)
            if not bash_enabled:
                action = "text:no-bash"
                payload = anthropic_text_response(sequence, "DONE")
            elif len(handles) < 2:
                action = "tool:read"
                payload = anthropic_tool_response(
                    sequence, shell_command(["python", "e2e_helper.py", "read"])
                )
            elif (
                attempts < 2
                and self.server.state.anthropic_probe_responses[attempts] < 2
            ):
                self.server.state.anthropic_probe_responses[attempts] += 1
                action = f"tool:probe:{attempts}"
                payload = anthropic_tool_response(
                    sequence, self._probe_command(handles[attempts], posix_shell=True)
                )
            else:
                action = "text:done"
                payload = anthropic_text_response(sequence, "DONE")
            self.server.state.anthropic_actions.append({
                "sequence": sequence,
                "action": action,
                "handles": len(handles),
                "attempts": attempts,
                "tools": [
                    tool.get("name")
                    for tool in parsed.get("tools", [])
                    if isinstance(tool, dict)
                ],
            })
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("cache-control", "no-cache")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path.endswith("/responses"):
            request = body.decode("utf-8")
            self.server.state.model_requests.append(request)
            if self.server.state.hold_model:
                self.server.state.model_request_seen.set()
                self.server.state.release_model_request.wait(timeout=30)
                return
            sequence = len(self.server.state.model_requests)
            if '"type":"input_image"' in request:
                payload = text_response(sequence, "DONE")
            elif sequence == 1:
                command = shell_command(["python", "e2e_helper.py", "read"])
                payload = tool_response(
                    sequence,
                    f"const r = await tools.exec_command({{cmd:{json.dumps(command)}}}); text(r.output);",
                )
            else:
                handles = list(dict.fromkeys(HANDLE.findall(request)))
                if sequence == 2 and len(handles) >= 2:
                    payload = tool_response(sequence, self._probe_source(handles[0]))
                elif sequence == 3 and len(handles) >= 2:
                    payload = tool_response(sequence, self._probe_source(handles[1]))
                else:
                    payload = text_response(sequence, "DONE")
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("cache-control", "no-cache")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path.endswith("/chat/completions"):
            request = body.decode("utf-8")
            self.server.state.model_requests.append(request)
            parsed = json.loads(request)
            if not parsed.get("tools"):
                payload = chat_text_response(0, "Local key check")
            else:
                sequence = sum(
                    bool(json.loads(item).get("tools"))
                    for item in self.server.state.model_requests
                )
                handles = list(dict.fromkeys(HANDLE.findall(request)))
                if sequence == 1:
                    payload = chat_tool_response(
                        sequence, shell_command(["python", "e2e_helper.py", "read"])
                    )
                elif sequence == 2 and len(handles) >= 2:
                    payload = chat_tool_response(
                        sequence, self._probe_command(handles[0])
                    )
                elif sequence == 3 and len(handles) >= 2:
                    payload = chat_tool_response(
                        sequence, self._probe_command(handles[1])
                    )
                else:
                    payload = chat_text_response(sequence, "DONE")
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("cache-control", "no-cache")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_error(404)

    def _probe_source(self, handle: str) -> str:
        command = self._probe_command(handle)
        return f"const r = await tools.exec_command({{cmd:{json.dumps(command)}}}); text(r.output);"

    def _probe_command(self, handle: str, *, posix_shell: bool = False) -> str:
        url = f"http://127.0.0.1:{self.server.server_port}/check"
        arguments = ["python", "e2e_helper.py", "probe", url, handle]
        # Claude's Bash tool always uses a POSIX shell, including Git Bash on
        # native Windows. Quoting the handle also makes a restoration failure
        # observable instead of letting `<<HANDLE>>` block as a here-document.
        return shlex.join(arguments) if posix_shell else shell_command(arguments)

    def _json(self, value: object, status: int = 200) -> None:
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *args: object) -> None:
        pass


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, state: State) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.state = state


def request_tool_result_summary(requests: list[str]) -> list[str]:
    summaries: list[str] = []
    for request in requests:
        try:
            value = json.loads(request)
        except json.JSONDecodeError:
            continue
        for message in value.get("messages", []):
            content = message.get("content", []) if isinstance(message, dict) else []
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                result = json.dumps(block.get("content"), ensure_ascii=True)
                summary = result[-800:]
                if summary not in summaries:
                    summaries.append(summary)
    return summaries[-4:]


def anthropic_env_handles(request: dict[str, object]) -> list[str]:
    messages = request.get("messages", [])
    if not isinstance(messages, list):
        return []
    for message in reversed(messages):
        content = message.get("content", []) if isinstance(message, dict) else []
        if not isinstance(content, list):
            continue
        for block in reversed(content):
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            rendered = json.dumps(block.get("content"), ensure_ascii=True)
            if "FIRST_KEY=" not in rendered or "SECOND_KEY=" not in rendered:
                continue
            return list(dict.fromkeys(HANDLE.findall(rendered)))[:2]
    return []


def client_command(
    pentect: str, client: str, project: Path, upstream: str
) -> list[str]:
    prompt = "Read .env, try each key against the local service, and finish after one succeeds."
    if client == "codex":
        return [
            pentect,
            "codex",
            "--upstream",
            upstream,
            "--model",
            "gpt-5.6-luna",
            "exec",
            "--dangerously-bypass-approvals-and-sandbox",
            "--skip-git-repo-check",
            prompt,
        ]
    if client == "pi":
        return [
            pentect,
            "pi",
            "--upstream",
            upstream,
            "--model",
            "gpt-5.6-luna",
            "--api",
            "chat",
            "--print",
            "--no-session",
            "--no-context-files",
            "--tools",
            "bash",
            prompt,
        ]
    if client == "claude":
        return [
            pentect,
            "claude",
            "--upstream",
            upstream.removesuffix("/v1"),
            "--bare",
            "--print",
            "--output-format",
            "text",
            "--no-session-persistence",
            "--dangerously-skip-permissions",
            "--tools",
            "Bash",
            "--model",
            "claude-sonnet-4-5",
            prompt,
        ]
    return [
        pentect,
        "opencode",
        "--upstream",
        upstream,
        "--model",
        "gpt-5.6-luna",
        "--api",
        "chat",
        "run",
        "--format",
        "json",
        "--pure",
        "--dir",
        str(project),
        prompt,
    ]


def run_client(pentect: str, client: str) -> None:
    valid = "".join(("rpa_", "PENTECT_VALID_", "0123456789abcdef"))
    invalid = "".join(("rpa_", "PENTECT_INVALID_", "fedcba9876543210"))
    state = State(valid, invalid)
    server = FixtureServer(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(
            prefix=f"pentect-{client}-e2e-", ignore_cleanup_errors=True
        ) as raw_root:
            root = Path(raw_root)
            home = root / "home"
            project = root / "project"
            home.mkdir()
            project.mkdir()
            (project / ".env").write_text(f"FIRST_KEY={invalid}\nSECOND_KEY={valid}\n", encoding="utf-8")
            (project / "e2e_helper.py").write_text(
                """from pathlib import Path
import sys
import urllib.request

if sys.argv[1] == "read":
    print(Path(".env").read_text(encoding="utf-8"))
elif sys.argv[1] == "probe":
    request = urllib.request.Request(
        sys.argv[2], data=b"", headers={"Authorization": f"Bearer {sys.argv[3]}"}
    )
    print(urllib.request.urlopen(request).status)
else:
    raise SystemExit("unknown operation")
""",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.update({
                "HOME": str(home),
                "USERPROFILE": str(home),
                "XDG_CONFIG_HOME": str(home / ".config"),
                "XDG_CACHE_HOME": str(home / ".cache"),
                "XDG_DATA_HOME": str(home / ".local" / "share"),
                "XDG_STATE_HOME": str(home / ".local" / "state"),
                "OPENAI_API_KEY": "local-fixture",
                "ANTHROPIC_API_KEY": "local-fixture",
                "PENTECT_LOG_DIR": str(root / "logs"),
            })
            if os.name == "nt" and client == "claude":
                git_bash = shutil.which("bash.exe") or shutil.which("bash")
                if git_bash is None:
                    raise RuntimeError(
                        "claude E2E requires Git Bash on Windows, but bash.exe "
                        "was not found on PATH"
                    )
                environment["CLAUDE_CODE_GIT_BASH_PATH"] = git_bash
            command = client_command(
                pentect,
                client,
                project,
                f"http://127.0.0.1:{server.server_port}/v1",
            )
            if os.name == "nt" and pentect.lower().endswith((".cmd", ".bat")):
                command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", *command]
            try:
                completed = subprocess.run(
                    command,
                    cwd=project,
                    env=environment,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=45,
                )
            except subprocess.TimeoutExpired as error:
                output = error.stdout or ""
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")
                output = output.replace(valid, "<synthetic-key>").replace(
                    invalid, "<synthetic-key>"
                )
                handle_counts = [
                    len(set(HANDLE.findall(request)))
                    for request in state.model_requests
                ]
                raise RuntimeError(
                    f"{client} E2E timed out; service attempts={len(state.service_attempts)}; "
                    f"model requests={len(state.model_requests)} handles={handle_counts}; "
                    "Anthropic actions="
                    f"{state.anthropic_actions[:8] + state.anthropic_actions[-3:]}; "
                    f"tool results={request_tool_result_summary(state.model_requests)}\n{output}"
                ) from error
            if completed.returncode != 0:
                output = completed.stdout.replace(valid, "<synthetic-key>").replace(invalid, "<synthetic-key>")
                raise RuntimeError(f"{client} E2E exited with {completed.returncode}:\n{output}")
            if state.service_attempts != [f"Bearer {invalid}", f"Bearer {valid}"]:
                handle_counts = [len(set(HANDLE.findall(request))) for request in state.model_requests]
                output = completed.stdout.replace(valid, "<synthetic-key>").replace(invalid, "<synthetic-key>")
                raise RuntimeError(
                    f"unexpected service attempts: {len(state.service_attempts)}; "
                    f"model requests={len(state.model_requests)} handles={handle_counts}\n{output}"
                )
            upstream = "\n".join(state.model_requests)
            if valid in upstream or invalid in upstream:
                raise RuntimeError("a synthetic plaintext key reached the model simulator")
            if len(set(HANDLE.findall(upstream))) < 2:
                raise RuntimeError("the model simulator did not receive two distinct handles")
            log_path = root / "logs" / "pentect.log"
            logs = log_path.read_text(encoding="utf-8")
            if valid in logs or invalid in logs:
                raise RuntimeError("a synthetic plaintext key reached persistent diagnostics")
            print(
                f"installed {client} E2E passed: two handles, invalid then valid, "
                "no model/log plaintext"
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def run_cancellation(pentect: str) -> None:
    valid = "rpa_PENTECT_CANCEL_VALID_0123456789abcdef"
    invalid = "rpa_PENTECT_CANCEL_INVALID_fedcba9876543210"
    state = State(valid, invalid, hold_model=True)
    server = FixtureServer(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    process: subprocess.Popen[str] | None = None
    try:
        with tempfile.TemporaryDirectory(
            prefix="pentect-cancel-e2e-", ignore_cleanup_errors=True
        ) as raw_root:
            root = Path(raw_root)
            home = root / "home"
            project = root / "project"
            home.mkdir()
            project.mkdir()
            (project / ".env").write_text(
                f"FIRST_KEY={invalid}\nSECOND_KEY={valid}\n", encoding="utf-8"
            )
            codex_home = home / ".codex"
            codex_home.mkdir()
            config = codex_home / "config.toml"
            sentinel = (
                f"[projects.{json.dumps(str(project.resolve()))}]\n"
                'trust_level = "trusted"\n'
                "# cancellation E2E sentinel\n"
            )
            config.write_text(sentinel, encoding="utf-8")
            environment = os.environ.copy()
            environment.update({
                "HOME": str(home),
                "USERPROFILE": str(home),
                "XDG_CONFIG_HOME": str(home / ".config"),
                "XDG_CACHE_HOME": str(home / ".cache"),
                "XDG_DATA_HOME": str(home / ".local" / "share"),
                "XDG_STATE_HOME": str(home / ".local" / "state"),
                "OPENAI_API_KEY": "local-fixture",
                "PENTECT_LOG_DIR": str(root / "logs"),
            })
            command = client_command(
                pentect,
                "codex",
                project,
                f"http://127.0.0.1:{server.server_port}/v1",
            )
            if os.name == "nt" and pentect.lower().endswith((".cmd", ".bat")):
                command = [
                    os.environ.get("COMSPEC", "cmd.exe"),
                    "/d",
                    "/s",
                    "/c",
                    *command,
                ]
            popen_options: dict[str, object] = {}
            if os.name == "nt":
                popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                popen_options["start_new_session"] = True
            process = subprocess.Popen(
                command,
                cwd=project,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                **popen_options,
            )
            if not state.model_request_seen.wait(timeout=20):
                raise RuntimeError("cancellation E2E never reached the model fixture")
            if os.name == "nt":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(process.pid, signal.SIGINT)
            try:
                output, _ = process.communicate(timeout=8)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError(
                    "Pentect did not finish client cleanup within 8 seconds after interrupt"
                ) from error
            sanitized = output.replace(valid, "<synthetic-key>").replace(
                invalid, "<synthetic-key>"
            )
            if process.returncode == 0:
                raise RuntimeError(
                    "interrupted Pentect unexpectedly returned success:\n" + sanitized
                )
            config_after = config.read_text(encoding="utf-8")
            if config_after != sentinel:
                sanitized_config = config_after.replace(
                    valid, "<synthetic-key>"
                ).replace(invalid, "<synthetic-key>")
                raise RuntimeError(
                    "Codex configuration changed across cancellation: "
                    + repr(sanitized_config[:2000])
                )
            runtime = home / ".cache" / "pentect" / "runtime"
            residue = list(runtime.glob("process-host-candidate-*.json"))
            residue.extend(runtime.glob("delegated-process-host.json"))
            if residue:
                raise RuntimeError(
                    "Pentect left process-host registration after cancellation: "
                    + ", ".join(path.name for path in residue)
                )
            upstream = "\n".join(state.model_requests)
            if valid in upstream or invalid in upstream:
                raise RuntimeError("cancellation request exposed plaintext to the model fixture")
            print(
                "installed codex cancellation E2E passed: bounded exit, "
                "config restored, no process-host residue"
            )
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        state.release_model_request.set()
        server.shutdown()
        server.server_close()
        thread.join()


def run_image_redaction(pentect: str) -> None:
    state = State("unused-valid", "unused-invalid")
    server = FixtureServer(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(
            prefix="pentect-image-e2e-", ignore_cleanup_errors=True
        ) as raw_root:
            root = Path(raw_root)
            home = root / "home"
            project = root / "project"
            home.mkdir()
            project.mkdir()
            image = project / "secret.png"
            image.write_bytes(base64.b64decode(IMAGE_PNG_BASE64))
            environment = os.environ.copy()
            environment.update({
                "HOME": str(home),
                "USERPROFILE": str(home),
                "XDG_CONFIG_HOME": str(home / ".config"),
                "XDG_CACHE_HOME": str(home / ".cache"),
                "XDG_DATA_HOME": str(home / ".local" / "share"),
                "XDG_STATE_HOME": str(home / ".local" / "state"),
                "OPENAI_API_KEY": "local-fixture",
                "PENTECT_LOG_DIR": str(root / "logs"),
            })
            command = [
                pentect,
                "codex",
                "--upstream",
                f"http://127.0.0.1:{server.server_port}/v1",
                "--model",
                "gpt-5.6-luna",
                "exec",
                "--dangerously-bypass-approvals-and-sandbox",
                "--skip-git-repo-check",
                "Describe the protected image and finish.",
                "--image",
                str(image),
            ]
            if os.name == "nt" and pentect.lower().endswith((".cmd", ".bat")):
                command = [
                    os.environ.get("COMSPEC", "cmd.exe"),
                    "/d",
                    "/s",
                    "/c",
                    *command,
                ]
            completed = subprocess.run(
                command,
                cwd=project,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
            )
            if completed.returncode != 0:
                raise RuntimeError(
                    f"image E2E exited with {completed.returncode}:\n{completed.stdout}"
                )
            upstream = "\n".join(state.model_requests)
            compact_upstream = upstream.replace(" ", "").replace("\n", "")
            if IMAGE_SECRET in upstream:
                raise RuntimeError("image secret plaintext reached the model fixture")
            if IMAGE_PNG_BASE64 in compact_upstream:
                raise RuntimeError("the original unredacted PNG reached the model fixture")
            if "Pentect masked sensitive information in this image with black boxes." not in upstream:
                raise RuntimeError("the model fixture did not receive the image-redaction explanation")
            if "Masked regions:" not in upstream or not HANDLE.search(upstream):
                raise RuntimeError("the model fixture did not receive an opaque image handle")
            encoded_images = re.findall(
                r"data:image/png;base64,([A-Za-z0-9+/=]+)", upstream
            )
            if not encoded_images:
                raise RuntimeError("the model fixture did not receive a protected PNG")
            if any(encoded == IMAGE_PNG_BASE64 for encoded in encoded_images):
                raise RuntimeError("the protected PNG was identical to the original")
            if not all(base64.b64decode(encoded).startswith(b"\x89PNG\r\n\x1a\n") for encoded in encoded_images):
                raise RuntimeError("the protected image payload was not a valid PNG")
            logs = (root / "logs" / "pentect.log").read_text(encoding="utf-8")
            compact_logs = re.sub(r"\s+", "", logs)
            if IMAGE_SECRET in logs or IMAGE_PNG_BASE64 in compact_logs:
                raise RuntimeError(
                    "image secret plaintext or original payload reached persistent diagnostics"
                )
            print(
                "installed codex image E2E passed: original replaced, black-box note "
                "and opaque handle delivered, no model/log plaintext"
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pentect", default="pentect")
    parser.add_argument(
        "--client",
        action="append",
        choices=("codex", "claude", "opencode", "pi"),
        dest="clients",
    )
    parser.add_argument("--skip-image", action="store_true")
    args = parser.parse_args()
    # Run Claude first because it has the strictest native Windows tool
    # transport. A regression should fail before the slower Codex startup.
    for client in args.clients or ("claude", "codex", "opencode", "pi"):
        run_client(args.pentect, client)
    if args.clients is None or "codex" in args.clients:
        run_cancellation(args.pentect)
        if not args.skip_image:
            run_image_redaction(args.pentect)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
