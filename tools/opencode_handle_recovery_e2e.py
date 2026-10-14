#!/usr/bin/env python3
"""Exercise a rejected handle and continued work in the real OpenCode client."""
from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import shlex
import subprocess
import tempfile
import threading
from pathlib import Path

SECRET = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
HANDLE = re.compile(r"<<[A-Z][A-Z0-9_]*_[0-9a-f]{16}(?:_length_[A-Za-z0-9_]+)?>>")


def shell_command(code: str) -> str:
    args = ["python", "-c", code]
    return subprocess.list2cmdline(args) if os.name == "nt" else shlex.join(args)


def response(calls: list[tuple[str, str]] | None = None) -> bytes:
    base = {"id": "chat_recovery_fixture", "object": "chat.completion.chunk", "model": "fixture"}
    if calls:
        tool_calls = [
            {"index": i, "id": call_id, "type": "function", "function": {"name": "bash", "arguments": json.dumps({"command": command})}}
            for i, (call_id, command) in enumerate(calls)
        ]
        chunks = [
            dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "tool_calls": tool_calls}, "finish_reason": None}]),
            dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]),
        ]
    else:
        chunks = [dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "content": "DONE"}, "finish_reason": "stop"}])]
    return b"".join(("data: " + json.dumps(chunk) + "\n\n").encode() for chunk in chunks) + b"data: [DONE]\n\n"


class Fixture(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, source: Path, marker: Path, rejected_marker: Path):
        super().__init__(("127.0.0.1", 0), Handler)
        self.source, self.marker, self.rejected_marker = source, marker, rejected_marker
        self.requests = 0
        self.rejected = 0
        self.saw_escalation = False
        self.saw_no_parallel = False
        self.saw_secret = False
        self.saw_result = False
        self.saw_final = False
        self.handler_error = False
        self.events: list[str] = []
        self.lock = threading.Lock()

    def handle_error(self, _request: object, _address: object) -> None:
        self.handler_error = True


class Handler(http.server.BaseHTTPRequestHandler):
    server: Fixture

    def do_POST(self) -> None:  # noqa: N802
        self.connection.settimeout(10)
        length = int(self.headers.get("content-length", "0"))
        if not 0 < length <= 1_048_576:
            self.send_error(413)
            return
        raw = self.rfile.read(length)
        with self.server.lock:
            self.server.requests += 1
            count = self.server.requests
        if count > 12:
            self.send_error(429)
            return
        self.server.saw_secret |= SECRET.encode() in raw
        request = json.loads(raw)
        messages = request.get("messages", [])
        outputs = {
            item.get("tool_call_id"): item.get("content", "")
            for item in messages
            if isinstance(item, dict) and item.get("role") == "tool"
        }
        notices = [
            item.get("content", "")
            for item in messages
            if isinstance(item, dict) and item.get("role") == "user"
            and isinstance(item.get("content"), str)
            and "Pentect could not restore" in item["content"]
        ]
        self.server.events.append(f"request:{count}:source={int('source_read' in outputs)}:fresh={int('recovery_read' in outputs)}:notice={len(notices)}")
        if "recovery_read" in outputs:
            self.server.saw_result = True
            if "recovery_finish" in outputs:
                self.server.saw_final = True
                body = response()
            else:
                code = f"from pathlib import Path;Path({str(self.server.marker)!r}).write_text('continued')"
                body = response([("recovery_finish", shell_command(code))])
        elif "source_read" in outputs:
            handles = set(HANDLE.findall(outputs["source_read"]))
            if len(handles) != 1:
                self.send_error(422)
                return
            handle = handles.pop()
            if self.server.rejected < 3:
                # A syntactically valid but unknown handle must be rejected.
                hash_part = re.search(r"_[0-9a-f]{16}(?=\||_length_|>>)", handle)
                if hash_part is None:
                    self.send_error(422)
                    return
                index = hash_part.start() + 1
                corrupt = handle[:index] + ("0" if handle[index] != "0" else "1") + handle[index + 1:]
                code = f"from pathlib import Path;Path({str(self.server.rejected_marker)!r}).write_text({corrupt!r})"
                self.server.rejected += 1
                body = response([("invalid_handle", shell_command(code))])
            else:
                self.server.saw_escalation = any("First make one tool call to reread" in n for n in notices)
                self.server.saw_no_parallel = request.get("parallel_tool_calls") is False
                code = f"from pathlib import Path;print(Path({str(self.server.source)!r}).read_text())"
                body = response([("recovery_read", shell_command(code))])
        else:
            code = f"from pathlib import Path;print(Path({str(self.server.source)!r}).read_text())"
            body = response([("source_read", shell_command(code))])
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pentect", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pentect-opencode-recovery-") as temporary:
        root = Path(temporary)
        home, project = root / "home", root / "project"
        (home / ".config" / "opencode").mkdir(parents=True)
        (home / ".config" / "opencode" / "opencode.json").write_text('{"plugin":[]}\n')
        project.mkdir()
        (project / ".git").mkdir()
        (project / ".env").write_text(f"OPENAI_API_KEY={SECRET}\n")
        (project / ".pentect").mkdir()
        (project / ".pentect" / "config.toml").write_text("[update]\ncheck = false\n")
        marker, rejected_marker = project / "continued.txt", project / "rejected.txt"
        server = Fixture(project / ".env", marker, rejected_marker)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        env = dict(os.environ)
        env.update({
            "HOME": str(home), "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_STATE_HOME": str(home / ".local" / "state"),
            "OPENAI_API_KEY": "synthetic-local-fixture",
            "PENTECT_DISABLE_UPDATE_CHECK": "1", "NO_COLOR": "1",
        })
        command = [str(args.pentect), "opencode", "--upstream", f"http://127.0.0.1:{server.server_port}/v1", "--model", "gpt-5.6-luna", "--api", "chat", "run", "--auto", "--format", "json", "--dir", str(project), "Run the supplied tools, then finish."]
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        process = subprocess.Popen(command, cwd=project, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=flags)
        try:
            stdout, stderr = process.communicate(timeout=90)
            timed_out = False
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            timed_out = True
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        checks = {
            "client_succeeded": process.returncode == 0 and not timed_out,
            "invalid_proposals_rejected": server.rejected >= 3 and not rejected_marker.exists(),
            "fresh_read_executed": server.saw_result,
            "continued_work_executed": marker.read_text() == "continued" if marker.exists() else False,
            "finished": server.saw_final and "DONE" in stdout,
            "escalated_feedback": server.saw_escalation,
            "parallel_calls_disabled": server.saw_no_parallel,
            "secret_absent_upstream": not server.saw_secret,
            "bounded": server.requests <= 12 and not server.handler_error,
        }
        result = {"checks": checks, "requests": server.requests, "events": server.events, "passed": all(checks.values()), "stderr_tail": stderr[-500:] if process.returncode else ""}
        print(json.dumps(result, sort_keys=True))
        return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
