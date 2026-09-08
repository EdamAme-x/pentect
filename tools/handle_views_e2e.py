#!/usr/bin/env python3
"""Black-box installed Claude handle-view roundtrip against localhost only.

The provider learns an opaque handle from an actually masked Read result. It
never resolves or remasks values; only the supplied Pentect binary may do so.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import importlib.util
import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

SYNTHETIC_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
HANDLE_PATTERN = re.compile(r"<<[A-Z][A-Z0-9_]*_[0-9a-f]{16}(?:_length_[A-Za-z0-9_]+)?>>")
MAX_HTTP = 8
MAX_BODY = 1_048_576
SCENARIO = "roundtrip"
_fixture_spec = importlib.util.spec_from_file_location("handle_views_fixture", Path(__file__).with_name("installed_agent_e2e.py"))
if _fixture_spec is None or _fixture_spec.loader is None:
    raise RuntimeError("installed fixture unavailable")
installed_fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(installed_fixture)


def sse(events: list[dict[str, Any]]) -> bytes:
    return b"".join(
        f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n".encode()
        for event in events
    )


def tool_response(calls: list[tuple[str, str, dict[str, str]]]) -> bytes:
    message = {
        "id": "msg_handle_views",
        "type": "message",
        "role": "assistant",
        "content": [],
        "model": "claude-sonnet-4-5",
        "stop_reason": None,
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    events: list[dict[str, Any]] = [{"type": "message_start", "message": message}]
    for index, (call_id, name, arguments) in enumerate(calls):
        events.extend(
            [
                {"type": "content_block_start", "index": index, "content_block": {"type": "tool_use", "id": call_id, "name": name, "input": {}}},
                {"type": "content_block_delta", "index": index, "delta": {"type": "input_json_delta", "partial_json": json.dumps(arguments, separators=(",", ":"))}},
                {"type": "content_block_stop", "index": index},
            ]
        )
    events.extend(
        [
            {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 1}},
            {"type": "message_stop"},
        ]
    )
    return sse(events)


def done_response() -> bytes:
    message = {
        "id": "msg_done",
        "type": "message",
        "role": "assistant",
        "content": [],
        "model": "claude-sonnet-4-5",
        "stop_reason": None,
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    return sse(
        [
            {"type": "message_start", "message": message},
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "DONE"}},
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 1}},
            {"type": "message_stop"},
        ]
    )


def tool_results(request: dict[str, Any]) -> dict[str, str]:
    found: dict[str, str] = {}
    messages = request.get("messages", [])
    if not isinstance(messages, list):
        return found
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        content = message.get("content", [])
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            call_id, value = block.get("tool_use_id"), block.get("content")
            if isinstance(call_id, str) and isinstance(value, str):
                found[call_id] = value
            elif isinstance(call_id, str) and isinstance(value, list):
                texts = [item.get("text") for item in value if isinstance(item, dict) and isinstance(item.get("text"), str)]
                found[call_id] = "\n".join(texts)
    return found


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, env_file: Path, ordinary: Path, encoded: Path, counter: Path):
        self.env_file, self.ordinary, self.encoded, self.counter = env_file, ordinary, encoded, counter
        self.http_count = 0
        self.http_statuses: list[int] = []
        self.request_hashes: list[str] = []
        self.plaintext_seen = False
        self.encoded_seen = False
        self.captured_handle: str | None = None
        self.read_result_observed = False
        self.output_ids: set[str] = set()
        self.batch_issued = False
        self.startup_requests = 0
        self.partial_batch_result = False
        self.bash_result_raw_handle = False
        self.bash_result_base64_handle = False
        self.handler_error = False
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), Handler)

    def claim(self) -> bool:
        with self.lock:
            self.http_count += 1
            return self.http_count <= MAX_HTTP

    def handle_error(self, _request: Any, _address: Any) -> None:
        self.handler_error = True


class Handler(http.server.BaseHTTPRequestHandler):
    server: Server

    def do_POST(self) -> None:  # noqa: N802
        self.connection.settimeout(8)
        if not self.server.claim():
            self.send_error(429)
            return
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if length < 0 or length > MAX_BODY:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        encoded_key = base64.b64encode(SYNTHETIC_KEY.encode()).decode()
        self.server.plaintext_seen |= SYNTHETIC_KEY.encode() in body
        self.server.encoded_seen |= encoded_key.encode() in body
        self.server.request_hashes.append(hashlib.sha256(body).hexdigest())
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400)
            return
        if not isinstance(request, dict):
            self.send_error(400)
            return
        results = tool_results(request)
        self.server.output_ids.update(results)
        tool_names = {
            tool.get("name") for tool in request.get("tools", [])
            if isinstance(tool, dict) and isinstance(tool.get("name"), str)
        }
        if not {"Read", "Write", "Bash"}.issubset(tool_names):
            self.server.startup_requests += 1
            self._send(200, done_response(), "text/event-stream")
            return

        if "read_synthetic_env" not in results:
            payload = tool_response([("read_synthetic_env", "Read", {"file_path": str(self.server.env_file)})])
        else:
            self.server.read_result_observed = True
            matches = HANDLE_PATTERN.findall(results["read_synthetic_env"])
            if len(set(matches)) != 1:
                error = b'{"error":{"type":"invalid_request_error","message":"expected one opaque handle"}}'
                self._send(422, error, "application/json")
                return
            handle = matches[0]
            self.server.captured_handle = handle
            completed = {"write_ordinary", "bash_base64"}.intersection(results)
            if completed and len(completed) != 2:
                self.server.partial_batch_result = True
                self.send_error(409)
                return
            if {"write_ordinary", "bash_base64"}.issubset(results):
                b64_handle = handle.replace(">>", "|base64>>")
                bash_result = results["bash_base64"]
                self.server.bash_result_raw_handle |= handle in bash_result
                self.server.bash_result_base64_handle |= b64_handle in bash_result
                payload = done_response()
            else:
                base64_handle = handle.replace(">>", "|unknown>>" if SCENARIO == "late-invalid" else "|base64>>")
                script = "import base64,pathlib,sys;d=base64.b64decode(sys.argv[1],validate=True);pathlib.Path(sys.argv[2]).write_bytes(d);pathlib.Path(sys.argv[3]).open('ab').write(b'1\\n');sys.stdout.write(d.decode());print(sys.argv[1])"
                command = shlex.join(["python3", "-c", script, base64_handle, str(self.server.encoded), str(self.server.counter)])
                payload = tool_response(
                    [
                        ("write_ordinary", "Write", {"file_path": str(self.server.ordinary), "content": handle}),
                        ("bash_base64", "Bash", {"command": command}),
                    ]
                )
                self.server.batch_issued = True
        self._send(200, payload, "text/event-stream")

    def _send(self, status: int, payload: bytes, kind: str) -> None:
        self.server.http_statuses.append(status)
        self.send_response(status)
        self.send_header("content-type", kind)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args: Any) -> None:
        pass


def chat_sse(chunks: list[dict[str, Any]]) -> bytes:
    return b"".join(("data: " + json.dumps(x, separators=(",", ":")) + "\n\n").encode() for x in chunks) + b"data: [DONE]\n\n"


def chat_tools(calls: list[tuple[str, str, dict[str, str]]]) -> bytes:
    tool_calls = [{"index": index, "id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(arguments, separators=(",", ":"))}} for index, (call_id, name, arguments) in enumerate(calls)]
    base = {"id": "chat_views", "object": "chat.completion.chunk", "model": "gpt-5.6-luna"}
    return chat_sse([dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "tool_calls": tool_calls}, "finish_reason": None}]), dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "tool_calls"}])])


def chat_done() -> bytes:
    return chat_sse([{"id": "chat_done", "object": "chat.completion.chunk", "model": "gpt-5.6-luna", "choices": [{"index": 0, "delta": {"role": "assistant", "content": "DONE"}, "finish_reason": "stop"}]}])


class PiServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, env_file: Path, ordinary: Path, encoded: Path, counter: Path):
        self.env_file, self.ordinary, self.encoded, self.counter = env_file, ordinary, encoded, counter
        self.http_count = 0; self.statuses: list[int] = []; self.handle: str | None = None
        self.raw_seen = self.encoded_seen = self.partial = self.handler_error = False
        self.output_raw_handle = self.output_base64_handle = False
        self.outputs: dict[str, str] = {}; self.lock = threading.Lock()
        self.batch_issued = False
        super().__init__(("127.0.0.1", 0), PiHandler)

    def handle_error(self, _request: Any, _address: Any) -> None:
        self.handler_error = True


class PiHandler(http.server.BaseHTTPRequestHandler):
    server: PiServer

    def do_POST(self) -> None:  # noqa: N802
        self.connection.settimeout(8)
        with self.server.lock:
            self.server.http_count += 1
            if self.server.http_count > MAX_HTTP:
                self.send_error(429); return
        length = int(self.headers.get("content-length", "0"))
        if length < 0 or length > MAX_BODY:
            self.send_error(413); return
        body = self.rfile.read(length); encoded_value = base64.b64encode(SYNTHETIC_KEY.encode()).decode()
        self.server.raw_seen |= SYNTHETIC_KEY.encode() in body; self.server.encoded_seen |= encoded_value.encode() in body
        request = json.loads(body); messages = request.get("messages", [])
        for message in messages if isinstance(messages, list) else []:
            if isinstance(message, dict) and message.get("role") == "tool" and isinstance(message.get("tool_call_id"), str) and isinstance(message.get("content"), str):
                self.server.outputs[message["tool_call_id"]] = message["content"]
        tool_names = {tool.get("function", {}).get("name") for tool in request.get("tools", []) if isinstance(tool, dict) and isinstance(tool.get("function"), dict)}
        if not {"read", "write", "bash"}.issubset(tool_names):
            payload = chat_done()
        elif "read_env" not in self.server.outputs:
            payload = chat_tools([("read_env", "read", {"path": str(self.server.env_file)})])
        else:
            matches = HANDLE_PATTERN.findall(self.server.outputs["read_env"])
            if len(set(matches)) != 1:
                self.send_error(422); return
            self.server.handle = matches[0]; completed = {"write_raw", "bash_b64"}.intersection(self.server.outputs)
            if completed and len(completed) != 2:
                self.server.partial = True; self.send_error(409); return
            if len(completed) == 2:
                view = self.server.handle.replace(">>", "|unknown>>" if SCENARIO == "late-invalid" else "|base64>>")
                bash_result = self.server.outputs["bash_b64"]
                self.server.output_raw_handle |= self.server.handle in bash_result
                self.server.output_base64_handle |= view in bash_result
                payload = chat_done()
            else:
                view = self.server.handle.replace(">>", "|unknown>>" if SCENARIO == "late-invalid" else "|base64>>")
                script = "import base64,pathlib,sys;d=base64.b64decode(sys.argv[1],validate=True);pathlib.Path(sys.argv[2]).write_bytes(d);pathlib.Path(sys.argv[3]).open('ab').write(b'1\\n');sys.stdout.write(d.decode());print(sys.argv[1])"
                payload = chat_tools([("write_raw", "write", {"path": str(self.server.ordinary), "content": self.server.handle}), ("bash_b64", "bash", {"command": shlex.join(["python3", "-c", script, view, str(self.server.encoded), str(self.server.counter)])})])
                self.server.batch_issued = True
        self.server.statuses.append(200); self.send_response(200); self.send_header("content-type", "text/event-stream"); self.send_header("content-length", str(len(payload))); self.end_headers(); self.wfile.write(payload)

    def log_message(self, *_args: Any) -> None:
        pass


class OpenCodeServer(PiServer):
    def __init__(self, env_file: Path, ordinary: Path, encoded: Path, counter: Path):
        super().__init__(env_file, ordinary, encoded, counter)
        self.RequestHandlerClass = OpenCodeHandler


class OpenCodeHandler(PiHandler):
    server: OpenCodeServer

    def do_POST(self) -> None:  # noqa: N802
        self.connection.settimeout(8)
        with self.server.lock:
            self.server.http_count += 1
            if self.server.http_count > MAX_HTTP:
                self.send_error(429); return
        length = int(self.headers.get("content-length", "0"))
        if length < 0 or length > MAX_BODY:
            self.send_error(413); return
        body = self.rfile.read(length)
        encoded_value = base64.b64encode(SYNTHETIC_KEY.encode()).decode()
        self.server.raw_seen |= SYNTHETIC_KEY.encode() in body; self.server.encoded_seen |= encoded_value.encode() in body
        request = json.loads(body); messages = request.get("messages", [])
        for message in messages if isinstance(messages, list) else []:
            if isinstance(message, dict) and message.get("role") == "tool" and isinstance(message.get("tool_call_id"), str) and isinstance(message.get("content"), str):
                self.server.outputs[message["tool_call_id"]] = message["content"]
        tool_names = {tool.get("function", {}).get("name") for tool in request.get("tools", []) if isinstance(tool, dict) and isinstance(tool.get("function"), dict)}
        if "bash" not in tool_names:
            payload = chat_done()
        elif "read_env" not in self.server.outputs:
            payload = chat_tools([("read_env", "bash", {"command": shlex.join(["python3", "-c", "import pathlib,sys;sys.stdout.write(pathlib.Path(sys.argv[1]).read_text())", str(self.server.env_file)])})])
        else:
            matches = HANDLE_PATTERN.findall(self.server.outputs["read_env"])
            if len(set(matches)) != 1:
                self.send_error(422); return
            self.server.handle = matches[0]; completed = {"bash_raw", "bash_b64"}.intersection(self.server.outputs)
            if completed and len(completed) != 2:
                self.server.partial = True; self.send_error(409); return
            if len(completed) == 2:
                view = self.server.handle.replace(">>", "|unknown>>" if SCENARIO == "late-invalid" else "|base64>>")
                bash_result = self.server.outputs["bash_b64"]
                self.server.output_raw_handle |= self.server.handle in bash_result
                self.server.output_base64_handle |= view in bash_result
                payload = chat_done()
            else:
                view = self.server.handle.replace(">>", "|unknown>>" if SCENARIO == "late-invalid" else "|base64>>")
                raw_script = "import pathlib,sys;pathlib.Path(sys.argv[2]).write_bytes(sys.argv[1].encode())"
                b64_script = "import base64,pathlib,sys;d=base64.b64decode(sys.argv[1],validate=True);pathlib.Path(sys.argv[2]).write_bytes(d);pathlib.Path(sys.argv[3]).open('ab').write(b'1\\n');sys.stdout.write(d.decode());print(sys.argv[1])"
                payload = chat_tools([("bash_raw", "bash", {"command": shlex.join(["python3", "-c", raw_script, self.server.handle, str(self.server.ordinary)])}), ("bash_b64", "bash", {"command": shlex.join(["python3", "-c", b64_script, view, str(self.server.encoded), str(self.server.counter)])})])
                self.server.batch_issued = True
        self.server.statuses.append(200); self.send_response(200); self.send_header("content-type", "text/event-stream"); self.send_header("content-length", str(len(payload))); self.end_headers(); self.wfile.write(payload)


def late_invalid_checks(process: subprocess.Popen[str], timed_out: bool, server: Any, paths: list[Path], ids: set[str]) -> dict[str, bool]:
    outputs = set(server.outputs) if hasattr(server, "outputs") else server.output_ids
    raw_seen = getattr(server, "raw_seen", getattr(server, "plaintext_seen", False))
    partial = getattr(server, "partial", getattr(server, "partial_batch_result", False))
    captured = getattr(server, "handle", getattr(server, "captured_handle", None))
    return {"client_completed": not timed_out, "read_handle_captured": captured is not None, "invalid_batch_issued": server.batch_issued, "all_side_effects_absent": not any(path.exists() for path in paths), "batch_results_absent": not ids.intersection(outputs), "provider_raw_absent": not raw_seen, "provider_encoded_absent": not server.encoded_seen, "no_partial": not partial, "bounded": server.http_count <= MAX_HTTP, "handler_clean": not server.handler_error}


def run_opencode(args: argparse.Namespace, pentect: Path, binary_hash: str) -> int:
    version = ""
    with tempfile.TemporaryDirectory(prefix="pentect-opencode-handle-views-") as temporary:
        root = Path(temporary); home, project, config, tmp = root / "home", root / "project", root / "home/.config/opencode", root / "tmp"
        for directory in (config, project, tmp): directory.mkdir(parents=True)
        (project / ".git").mkdir(); (config / "opencode.json").write_text('{"plugin":[]}\n')
        env_file = project / ".env"; env_file.write_text(f"OPENAI_API_KEY={SYNTHETIC_KEY}\n")
        ordinary, encoded, counter = project / "ordinary.bin", project / "base64.bin", project / "count.txt"
        server = OpenCodeServer(env_file, ordinary, encoded, counter); thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        env = {"PATH": os.environ["PATH"], "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"), "XDG_DATA_HOME": str(home / ".local/share"), "XDG_CACHE_HOME": str(home / ".cache"), "XDG_STATE_HOME": str(home / ".local/state"), "TMPDIR": str(tmp), "OPENAI_API_KEY": "synthetic-local-fixture", "PENTECT_DISABLE_UPDATE_CHECK": "1", "NO_COLOR": "1"}
        version = subprocess.run(["/home/edamame/.local/bin/opencode", "--version"], env=env, capture_output=True, text=True, timeout=8, check=False).stdout.strip()
        command = [str(pentect), "opencode", "--upstream", f"http://127.0.0.1:{server.server_port}/v1", "--model", "gpt-5.6-luna", "--api", "chat", "run", "--auto", "--format", "json", "--dir", str(project), "Run supplied tools, then finish."]
        process = subprocess.Popen(command, cwd=project, env=env, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True); timed_out = False
        try: stdout, _ = process.communicate(timeout=60)
        except subprocess.TimeoutExpired: timed_out = True; os.killpg(process.pid, signal.SIGKILL); stdout, _ = process.communicate()
        finally: server.shutdown(); server.server_close(); thread.join(timeout=8)
        raw_exact = ordinary.exists() and ordinary.read_bytes() == SYNTHETIC_KEY.encode(); b64_exact = encoded.exists() and encoded.read_bytes() == SYNTHETIC_KEY.encode()
        checks = {"client_succeeded": process.returncode == 0 and not timed_out, "ordinary_exact": raw_exact, "provider_raw_absent": not server.raw_seen, "provider_encoded_absent": not server.encoded_seen, "base64_exact": b64_exact, "base64_once": counter.exists() and counter.read_bytes() == b"1\n", "both_outputs": {"bash_raw", "bash_b64"}.issubset(server.outputs), "bash_raw_output_remasked": server.output_raw_handle, "bash_base64_output_remasked": server.output_base64_handle, "no_partial": not server.partial, "bounded": server.http_count <= MAX_HTTP, "handler_clean": not server.handler_error}
        if SCENARIO == "late-invalid": checks = late_invalid_checks(process, timed_out, server, [ordinary, encoded, counter], {"bash_raw", "bash_b64"})
        result = {"client": "opencode", "pentect_sha256": binary_hash, "opencode_version": version, "client_exit_code": process.returncode, "timed_out": timed_out, "http_count": server.http_count, "http_statuses": server.statuses, "ordinary_file_exact": raw_exact, "base64_file_exact": b64_exact, "stdout_nonempty": bool(stdout.strip()), "checks": checks, "passed": all(checks.values()), "patch_scope": "not asserted; patch newline behavior is separate"}
    if args.output: args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True)); return 0 if result["passed"] else 2


def run_pi(args: argparse.Namespace, pentect: Path, binary_hash: str) -> int:
    version = subprocess.run(["pi", "--version"], capture_output=True, text=True, timeout=8, check=False).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="pentect-pi-handle-views-") as temporary:
        root = Path(temporary); home, config, data, cache, agent = (root / x for x in ("home", "config", "data", "cache", "agent"))
        for directory in (home, config, data, cache, agent): directory.mkdir()
        env_file = root / ".env"; env_file.write_text(f"OPENAI_API_KEY={SYNTHETIC_KEY}\n")
        ordinary, encoded, counter = root / "ordinary.bin", root / "base64.bin", root / "count.txt"
        server = PiServer(env_file, ordinary, encoded, counter); thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        env = {"PATH": os.environ["PATH"], "HOME": str(home), "XDG_CONFIG_HOME": str(config), "XDG_DATA_HOME": str(data), "XDG_CACHE_HOME": str(cache), "PI_CODING_AGENT_DIR": str(agent), "PI_OFFLINE": "1", "OPENAI_API_KEY": "synthetic-local-fixture"}
        command = [str(pentect), "pi", "--upstream", f"http://127.0.0.1:{server.server_port}/v1", "--model", "gpt-5.6-luna", "--api", "chat", "--no-session", "--mode", "json", "--tools", "read,write,bash", "--print", "Run supplied tools, then finish."]
        process = subprocess.Popen(command, cwd=root, env=env, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True); timed_out = False
        try: stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired: timed_out = True; os.killpg(process.pid, signal.SIGKILL); stdout, stderr = process.communicate()
        finally: server.shutdown(); server.server_close(); thread.join(timeout=8)
        raw_exact = ordinary.exists() and ordinary.read_bytes() == SYNTHETIC_KEY.encode(); b64_exact = encoded.exists() and encoded.read_bytes() == SYNTHETIC_KEY.encode()
        checks = {"client_succeeded": process.returncode == 0 and not timed_out, "ordinary_exact": raw_exact, "provider_raw_absent": not server.raw_seen, "provider_encoded_absent": not server.encoded_seen, "base64_exact": b64_exact, "base64_once": counter.exists() and counter.read_bytes() == b"1\n", "both_outputs": {"write_raw", "bash_b64"}.issubset(server.outputs), "bash_raw_output_remasked": server.output_raw_handle, "bash_base64_output_remasked": server.output_base64_handle, "no_partial": not server.partial, "bounded": server.http_count <= MAX_HTTP, "handler_clean": not server.handler_error}
        if SCENARIO == "late-invalid": checks = late_invalid_checks(process, timed_out, server, [ordinary, encoded, counter], {"write_raw", "bash_b64"})
        result = {"client": "pi", "pentect_sha256": binary_hash, "pi_version": version, "client_exit_code": process.returncode, "timed_out": timed_out, "http_count": server.http_count, "http_statuses": server.statuses, "ordinary_file_exact": raw_exact, "base64_file_exact": b64_exact, "stdout_nonempty": bool(stdout.strip()), "stderr_line_count": len(stderr.splitlines()), "checks": checks, "passed": all(checks.values())}
    if args.output: args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True)); return 0 if result["passed"] else 2


def codex_source(command: list[str]) -> str:
    return f"const r = await tools.exec_command({json.dumps({'cmd': shlex.join(command)}, separators=(',', ':'))}); text(r.output);"


def responses_two_tools(sources: list[str], ids: list[str]) -> bytes:
    response_id = "resp_handle_views"
    items = [{"id": f"ct_handle_{i}", "type": "custom_tool_call", "status": "completed", "call_id": call_id, "name": "exec", "input": source} for i, (call_id, source) in enumerate(zip(ids, sources, strict=True))]
    events: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        events.extend([{"type": "response.output_item.added", "response_id": response_id, "output_index": index, "item": dict(item, status="in_progress", input="")}, {"type": "response.custom_tool_call_input.delta", "response_id": response_id, "item_id": item["id"], "output_index": index, "delta": item["input"]}, {"type": "response.custom_tool_call_input.done", "response_id": response_id, "item_id": item["id"], "output_index": index, "call_id": item["call_id"], "name": "exec", "input": item["input"]}, {"type": "response.output_item.done", "response_id": response_id, "output_index": index, "item": item}])
    events.append({"type": "response.completed", "response": installed_fixture.response_object(response_id, items)})
    return installed_fixture.sse(events)


class CodexServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, env_file: Path, ordinary: Path, encoded: Path, counter: Path):
        self.env_file, self.ordinary, self.encoded, self.counter = env_file, ordinary, encoded, counter
        self.http_count = 0; self.outputs: dict[str, str] = {}; self.handle: str | None = None
        self.raw_seen = self.encoded_seen = self.partial = self.handler_error = False
        self.output_raw_handle = self.output_base64_handle = False
        self.batch_issued = False
        super().__init__(("127.0.0.1", 0), CodexHandler)

    def handle_error(self, _request: Any, _address: Any) -> None: self.handler_error = True


class CodexHandler(http.server.BaseHTTPRequestHandler):
    server: CodexServer

    def do_POST(self) -> None:  # noqa: N802
        self.connection.settimeout(8)
        if self.server.http_count >= MAX_HTTP: self.send_error(429); return
        self.server.http_count += 1
        length = int(self.headers.get("content-length", "0"))
        if length < 0 or length > MAX_BODY: self.send_error(413); return
        body = self.rfile.read(length); encoded_value = base64.b64encode(SYNTHETIC_KEY.encode()).decode()
        self.server.raw_seen |= SYNTHETIC_KEY.encode() in body; self.server.encoded_seen |= encoded_value.encode() in body
        request = json.loads(body); inputs = request.get("input", [])
        for item in inputs if isinstance(inputs, list) else []:
            if isinstance(item, dict) and item.get("type") == "custom_tool_call_output" and isinstance(item.get("call_id"), str):
                value = item.get("output", ""); self.server.outputs[item["call_id"]] = value if isinstance(value, str) else json.dumps(value)
        if "read_env" not in self.server.outputs:
            source = codex_source(["python3", "-c", "import pathlib,sys;sys.stdout.write(pathlib.Path(sys.argv[1]).read_text())", str(self.server.env_file)])
            payload = responses_two_tools([source], ["read_env"])
        else:
            matches = HANDLE_PATTERN.findall(self.server.outputs["read_env"])
            if len(set(matches)) != 1: self.send_error(422); return
            self.server.handle = matches[0]; completed = {"codex_raw", "codex_b64"}.intersection(self.server.outputs)
            if completed and len(completed) != 2: self.server.partial = True; self.send_error(409); return
            if len(completed) == 2:
                view = self.server.handle.replace(">>", "|base64>>"); output = self.server.outputs["codex_b64"]
                self.server.output_raw_handle |= self.server.handle in output; self.server.output_base64_handle |= view in output
                payload = installed_fixture.text_response(self.server.http_count, "DONE")
            else:
                view = self.server.handle.replace(">>", "|unknown>>" if SCENARIO == "late-invalid" else "|base64>>")
                raw = codex_source(["python3", "-c", "import pathlib,sys;pathlib.Path(sys.argv[2]).write_bytes(sys.argv[1].encode())", self.server.handle, str(self.server.ordinary)])
                b64 = codex_source(["python3", "-c", "import base64,pathlib,sys;d=base64.b64decode(sys.argv[1],validate=True);pathlib.Path(sys.argv[2]).write_bytes(d);pathlib.Path(sys.argv[3]).open('ab').write(b'1\\n');sys.stdout.write(d.decode());print(sys.argv[1])", view, str(self.server.encoded), str(self.server.counter)])
                payload = responses_two_tools([raw, b64], ["codex_raw", "codex_b64"])
                self.server.batch_issued = True
        self.send_response(200); self.send_header("content-type", "text/event-stream"); self.send_header("content-length", str(len(payload))); self.end_headers(); self.wfile.write(payload)

    def log_message(self, *_args: Any) -> None: pass


def run_codex(args: argparse.Namespace, pentect: Path, binary_hash: str) -> int:
    version = subprocess.run(["codex", "--version"], capture_output=True, text=True, timeout=8, check=False).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="pentect-codex-handle-views-") as temporary:
        root = Path(temporary); home, codex_home, project, tmp = root / "home", root / "home/.codex", root / "project", root / "tmp"
        for directory in (codex_home, project, tmp): directory.mkdir(parents=True)
        (project / ".git").mkdir(); (codex_home / "config.toml").write_text("approval_policy = 'never'\nsandbox_mode = 'danger-full-access'\n[features]\nhooks = false\n")
        env_file = project / ".env"; env_file.write_text(f"OPENAI_API_KEY={SYNTHETIC_KEY}\n"); ordinary, encoded, counter = project / "ordinary.bin", project / "base64.bin", project / "count.txt"
        server = CodexServer(env_file, ordinary, encoded, counter); thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        env = {"PATH": os.environ["PATH"], "HOME": str(home), "CODEX_HOME": str(codex_home), "TMPDIR": str(tmp), "OPENAI_API_KEY": "synthetic-local-fixture", "PENTECT_DISABLE_UPDATE_CHECK": "1", "NO_COLOR": "1"}
        command = [str(pentect), "codex", "--upstream", f"http://127.0.0.1:{server.server_port}/v1", "--model", "gpt-5.6-luna", "exec", "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check", "Run supplied tools, then finish."]
        process = subprocess.Popen(command, cwd=project, env=env, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True); timed_out = False
        try: stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired: timed_out = True; os.killpg(process.pid, signal.SIGKILL); stdout, stderr = process.communicate()
        finally: server.shutdown(); server.server_close(); thread.join(timeout=8)
        raw_exact = ordinary.exists() and ordinary.read_bytes() == SYNTHETIC_KEY.encode(); b64_exact = encoded.exists() and encoded.read_bytes() == SYNTHETIC_KEY.encode()
        checks = {"client_succeeded": process.returncode == 0 and not timed_out, "ordinary_exact": raw_exact, "base64_exact": b64_exact, "base64_once": counter.exists() and counter.read_bytes() == b"1\n", "provider_raw_absent": not server.raw_seen, "provider_encoded_absent": not server.encoded_seen, "both_outputs": {"codex_raw", "codex_b64"}.issubset(server.outputs), "bash_raw_output_remasked": server.output_raw_handle, "bash_base64_output_remasked": server.output_base64_handle, "no_partial": not server.partial, "bounded": server.http_count <= MAX_HTTP, "handler_clean": not server.handler_error}
        if SCENARIO == "late-invalid": checks = late_invalid_checks(process, timed_out, server, [ordinary, encoded, counter], {"codex_raw", "codex_b64"})
        result = {"client": "codex", "pentect_sha256": binary_hash, "codex_version": version, "client_exit_code": process.returncode, "timed_out": timed_out, "http_count": server.http_count, "ordinary_file_exact": raw_exact, "base64_file_exact": b64_exact, "stdout_nonempty": bool(stdout.strip()), "stderr_line_count": len(stderr.splitlines()), "checks": checks, "passed": all(checks.values()), "patch_scope": "not asserted; patch newline behavior is separate"}
    if args.output: args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True)); return 0 if result["passed"] else 2


def main() -> int:
    global SCENARIO
    parser = argparse.ArgumentParser()
    parser.add_argument("--pentect", type=Path, required=True)
    parser.add_argument("--client", choices=("claude", "pi", "opencode", "codex"), default="claude")
    parser.add_argument("--scenario", choices=("roundtrip", "late-invalid"), default="roundtrip")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    SCENARIO = args.scenario
    pentect = args.pentect.resolve()
    binary_hash = hashlib.sha256(pentect.read_bytes()).hexdigest()
    if not args.execute:
        print(json.dumps({"status": "draft", "pentect_sha256": binary_hash, "client": args.client, "max_http": MAX_HTTP, "max_seconds": 60}))
        return 0

    if args.client == "pi":
        return run_pi(args, pentect, binary_hash)
    if args.client == "opencode":
        return run_opencode(args, pentect, binary_hash)
    if args.client == "codex":
        return run_codex(args, pentect, binary_hash)

    version = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=8, check=False).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="pentect-handle-views-e2e-") as temporary:
        root = Path(temporary)
        home, config, cache, project = root / "home", root / "config", root / "cache", root / "project"
        for directory in (home, config, cache, project):
            directory.mkdir()
        (project / ".git").mkdir()
        env_file = project / ".env"
        env_file.write_text(f"OPENAI_API_KEY={SYNTHETIC_KEY}\n")
        ordinary, encoded, counter = project / "ordinary.bin", project / "base64.bin", project / "base64-count.txt"
        server = Server(env_file, ordinary, encoded, counter)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        settings = root / "settings.json"
        settings.write_text("{}\n")
        environment = {"PATH": os.environ["PATH"], "HOME": str(home), "USERPROFILE": str(home), "XDG_CONFIG_HOME": str(config), "XDG_CACHE_HOME": str(cache), "ANTHROPIC_API_KEY": "synthetic-local-fixture", "PENTECT_DISABLE_UPDATE_CHECK": "1", "NO_COLOR": "1"}
        command = [str(pentect), "claude", "--upstream", f"http://127.0.0.1:{server.server_port}", "--settings", str(settings), "--print", "--output-format", "text", "--dangerously-skip-permissions", "--tools", "Read,Write,Bash", "--model", "claude-sonnet-4-5", "Run the supplied local tools, then finish."]
        process = subprocess.Popen(command, cwd=project, env=environment, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=8)

        ordinary_exact = ordinary.exists() and ordinary.read_bytes() == SYNTHETIC_KEY.encode()
        base64_exact = encoded.exists() and encoded.read_bytes() == SYNTHETIC_KEY.encode()
        checks = {
            "client_succeeded": process.returncode == 0 and not timed_out,
            "request_bound_respected": server.http_count <= MAX_HTTP,
            "fixture_handler_clean": not server.handler_error,
            "no_partial_batch_result": not server.partial_batch_result,
            "read_result_observed": server.read_result_observed,
            # This exact ordinary roundtrip establishes the detector mapping
            # before any encoded-view assertion is considered.
            "detector_mapping_exact_via_ordinary_write": ordinary_exact,
            "plaintext_absent_from_provider_requests": not server.plaintext_seen,
            "encoded_value_absent_from_provider_requests": not server.encoded_seen,
            "base64_view_decoded_exact": base64_exact,
            "base64_side_effect_once": counter.exists() and counter.read_bytes() == b"1\n",
            "both_tool_results_returned": {"write_ordinary", "bash_base64"}.issubset(server.output_ids),
            "bash_raw_output_remasked_to_ordinary_handle": server.bash_result_raw_handle,
            "bash_encoded_output_remasked_to_base64_handle": server.bash_result_base64_handle,
        }
        if SCENARIO == "late-invalid":
            checks = late_invalid_checks(process, timed_out, server, [ordinary, encoded, counter], {"write_ordinary", "bash_base64"})
        result = {
            "pentect_sha256": binary_hash,
            "claude_version": version,
            "client_exit_code": process.returncode,
            "timed_out": timed_out,
            "http_count": server.http_count,
            "http_statuses": server.http_statuses,
            "startup_requests_without_native_tools": server.startup_requests,
            "provider_request_sha256": server.request_hashes,
            "captured_handle_present": server.captured_handle is not None,
            "ordinary_file_exists": ordinary.exists(),
            "ordinary_file_exact": ordinary_exact,
            "base64_file_exists": encoded.exists(),
            "base64_file_exact": base64_exact,
            "base64_count_exists": counter.exists(),
            "stdout_nonempty": bool(stdout.strip()),
            "stderr_line_count": len(stderr.splitlines()),
            "checks": checks,
            "passed": all(checks.values()),
            "pending_scope": ["unsafe edge values through a controlled memory-session seam", "patch unsupported", "unknown and late batch", "cancellation"],
        }

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
