#!/usr/bin/env python3
"""Bounded black-box restart recovery probe using installed native clients.

The localhost provider only records opaque handles and emits deterministic tool
calls.  It never resolves a handle or reads the trusted source file.
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

MAX_HTTP = 8
MAX_BODY = 1_048_576
MAX_SECONDS = 60
VALUE = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
VIEW = "raw"
HANDLE = re.compile(r"<<[A-Z][A-Z0-9_]*_[0-9a-f]{16}(?:_length_[A-Za-z0-9_]+)?>>")

_spec = importlib.util.spec_from_file_location(
    "handle_views_e2e", Path(__file__).with_name("handle_views_e2e.py")
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("handle views fixture unavailable")
hv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hv)


def codex_source(argv: list[str]) -> str:
    command = shlex.join(argv)
    return f"const r = await tools.exec_command({json.dumps({'cmd': command}, separators=(',', ':'))}); text(r.output);"


class ProbeServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, client: str, phase: str, source: Path, destination: Path, old_handle: str | None):
        self.client, self.phase = client, phase
        self.source, self.destination, self.old_handle = source, destination, old_handle
        self.http_count = 0
        self.statuses: list[int] = []
        self.handle: str | None = None
        self.call_issued = False
        self.result_seen = False
        self.result_remasked = False
        self.raw_seen = False
        self.handler_error = False
        self.outputs: dict[str, str] = {}
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), ProbeHandler)

    def handle_error(self, _request: Any, _address: Any) -> None:
        self.handler_error = True


class ProbeHandler(http.server.BaseHTTPRequestHandler):
    server: ProbeServer

    def do_POST(self) -> None:  # noqa: N802
        self.connection.settimeout(8)
        with self.server.lock:
            self.server.http_count += 1
            if self.server.http_count > MAX_HTTP:
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
        self.server.raw_seen |= VALUE.encode() in body
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400)
            return
        self._collect_outputs(request)
        payload = self._next_payload(request)
        self.server.statuses.append(200)
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _collect_outputs(self, request: dict[str, Any]) -> None:
        client = self.server.client
        if client == "claude":
            self.server.outputs.update(hv.tool_results(request))
            return
        if client in {"pi", "opencode"}:
            for message in request.get("messages", []):
                if not isinstance(message, dict) or message.get("role") != "tool":
                    continue
                call_id, content = message.get("tool_call_id"), message.get("content")
                if isinstance(call_id, str) and isinstance(content, str):
                    self.server.outputs[call_id] = content
            return
        for item in request.get("input", []):
            if not isinstance(item, dict) or item.get("type") != "custom_tool_call_output":
                continue
            call_id, output = item.get("call_id"), item.get("output")
            if isinstance(call_id, str):
                self.server.outputs[call_id] = output if isinstance(output, str) else json.dumps(output)

    def _next_payload(self, request: dict[str, Any]) -> bytes:
        call_id = "register_read" if self.server.phase == "register" else "recover_write"
        if call_id in self.server.outputs:
            self.server.result_seen = True
            if self.server.phase == "recover" and self.server.old_handle is not None:
                self.server.result_remasked = self.server.old_handle in self.server.outputs[call_id]
            if self.server.phase == "register":
                found = sorted(set(HANDLE.findall(self.server.outputs[call_id])))
                if len(found) == 1:
                    self.server.handle = found[0]
            return self._done()
        self.server.call_issued = True
        if self.server.phase == "register":
            return self._read_call(call_id)
        assert self.server.old_handle is not None
        tool_handle = self.server.old_handle
        if VIEW == "base64":
            tool_handle = tool_handle.replace(">>", "|base64>>")
        return self._write_call(call_id, tool_handle)

    def _read_call(self, call_id: str) -> bytes:
        path = str(self.server.source)
        if self.server.client == "claude":
            return hv.tool_response([(call_id, "Read", {"file_path": path})])
        if self.server.client == "pi":
            return hv.chat_tools([(call_id, "read", {"path": path})])
        argv = ["python3", "-c", "import pathlib,sys;sys.stdout.write(pathlib.Path(sys.argv[1]).read_text())", path]
        if self.server.client == "opencode":
            return hv.chat_tools([(call_id, "bash", {"command": shlex.join(argv)})])
        return hv.responses_two_tools([codex_source(argv)], [call_id])

    def _write_call(self, call_id: str, handle: str) -> bytes:
        path = str(self.server.destination)
        if VIEW == "base64":
            script = "import base64,pathlib,sys;d=base64.b64decode(sys.argv[1],validate=True);pathlib.Path(sys.argv[2]).write_bytes(d);sys.stdout.write(d.decode())"
        else:
            script = "import pathlib,sys;pathlib.Path(sys.argv[2]).write_bytes(sys.argv[1].encode());sys.stdout.write(sys.argv[1])"
        argv = ["python3", "-c", script, handle, path]
        if self.server.client == "claude":
            return hv.tool_response([(call_id, "Bash", {"command": shlex.join(argv)})])
        if self.server.client == "pi":
            return hv.chat_tools([(call_id, "bash", {"command": shlex.join(argv)})])
        if self.server.client == "opencode":
            return hv.chat_tools([(call_id, "bash", {"command": shlex.join(argv)})])
        return hv.responses_two_tools([codex_source(argv)], [call_id])

    def _done(self) -> bytes:
        if self.server.client == "claude":
            return hv.done_response()
        if self.server.client in {"pi", "opencode"}:
            return hv.chat_done()
        return hv.installed_fixture.text_response(self.server.http_count, "DONE")

    def log_message(self, *_args: Any) -> None:
        pass


def isolated_env(root: Path, client: str) -> dict[str, str]:
    home, tmp = root / "home", root / "tmp"
    home.mkdir(); tmp.mkdir()
    env = {
        "PATH": os.environ["PATH"], "HOME": str(home), "USERPROFILE": str(home),
        "TMPDIR": str(tmp), "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local/share"), "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_STATE_HOME": str(home / ".local/state"), "PENTECT_DISABLE_UPDATE_CHECK": "1", "NO_COLOR": "1",
    }
    if client == "claude": env["ANTHROPIC_API_KEY"] = "synthetic-local-fixture"
    else: env["OPENAI_API_KEY"] = "synthetic-local-fixture"
    return env


def command_for(client: str, pentect: Path, upstream: str, project: Path, root: Path) -> list[str]:
    prompt = "Run the supplied local tool once, then finish."
    if client == "claude":
        settings = root / "settings.json"; settings.write_text("{}\n")
        return [str(pentect), "claude", "--upstream", upstream, "--settings", str(settings), "--print", "--output-format", "text", "--dangerously-skip-permissions", "--tools", "Read,Write,Bash", "--model", "claude-sonnet-4-5", prompt]
    if client == "pi":
        return [str(pentect), "pi", "--upstream", upstream + "/v1", "--model", "gpt-5.6-luna", "--api", "chat", "--no-session", "--mode", "json", "--tools", "read,write,bash", "--print", prompt]
    if client == "opencode":
        config = root / "home/.config/opencode"; config.mkdir(parents=True, exist_ok=True)
        (config / "opencode.json").write_text('{"plugin":[]}\n')
        return [str(pentect), "opencode", "--upstream", upstream + "/v1", "--model", "gpt-5.6-luna", "--api", "chat", "run", "--auto", "--format", "json", "--dir", str(project), prompt]
    codex_home = root / "home/.codex"; codex_home.mkdir(parents=True, exist_ok=True)
    (codex_home / "config.toml").write_text("approval_policy = 'never'\nsandbox_mode = 'danger-full-access'\n[features]\nhooks = false\n")
    return [str(pentect), "codex", "--upstream", upstream + "/v1", "--model", "gpt-5.6-luna", "exec", "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check", prompt]


def run_phase(client: str, phase: str, pentect: Path, root: Path, project: Path, env: dict[str, str], source: Path, destination: Path, handle: str | None) -> dict[str, Any]:
    server = ProbeServer(client, phase, source, destination, handle)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    upstream = f"http://127.0.0.1:{server.server_port}"
    command = command_for(client, pentect, upstream, project, root)
    if client == "codex": env = dict(env, CODEX_HOME=str(root / "home/.codex"))
    if client == "pi": env = dict(env, PI_CODING_AGENT_DIR=str(root / "pi-agent"), PI_OFFLINE="1")
    Path(env.get("PI_CODING_AGENT_DIR", root / "unused")).mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(command, cwd=project, env=env, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    timed_out = False
    try: stdout, stderr = process.communicate(timeout=MAX_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True; os.killpg(process.pid, signal.SIGKILL); stdout, stderr = process.communicate()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=8)
    return {"exit_code": process.returncode, "timed_out": timed_out, "http_count": server.http_count,
            "statuses": server.statuses, "call_issued": server.call_issued, "result_seen": server.result_seen,
            "result_remasked": server.result_remasked,
            "handle": server.handle, "provider_raw_seen": server.raw_seen, "handler_error": server.handler_error,
            "stdout_nonempty": bool(stdout.strip()), "stderr_lines": len(stderr.splitlines())}


def register_with_pentect_read(pentect: Path, project: Path, env: dict[str, str], source: Path) -> dict[str, Any]:
    process = subprocess.run(
        [str(pentect), "read", str(source)], cwd=project, env=env,
        capture_output=True, text=True, timeout=MAX_SECONDS, check=False,
    )
    found = sorted(set(HANDLE.findall(process.stdout)))
    return {
        "exit_code": process.returncode, "timed_out": False, "http_count": 0, "statuses": [],
        "call_issued": True, "result_seen": process.returncode == 0,
        "handle": found[0] if len(found) == 1 else None,
        "provider_raw_seen": False, "handler_error": False,
        "stdout_nonempty": bool(process.stdout.strip()), "stderr_lines": len(process.stderr.splitlines()),
        "registration_route": "pentect read trusted local file",
    }


def main() -> int:
    global VALUE, VIEW
    parser = argparse.ArgumentParser()
    parser.add_argument("--pentect", type=Path, required=True)
    parser.add_argument("--client", choices=("claude", "pi", "opencode", "codex"), required=True)
    parser.add_argument("--registration", choices=("client", "pentect-read"), default="client")
    parser.add_argument("--value", choices=("detected", "low-entropy"), default="detected")
    parser.add_argument("--source-state", choices=("unchanged", "changed", "deleted"), default="unchanged")
    parser.add_argument("--remember", choices=("enabled", "disabled"), default="enabled")
    parser.add_argument("--scope", choices=("same-project", "different-project"), default="same-project")
    parser.add_argument("--expect", choices=("auto", "recovered", "blocked", "registration-missing"), default="auto")
    parser.add_argument("--view", choices=("auto", "raw", "base64"), default="auto")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(); pentect = args.pentect.resolve()
    VALUE = "local fixture phrase!?" if args.value == "low-entropy" else "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
    VIEW = "base64" if args.view == "base64" or (args.view == "auto" and args.value == "low-entropy") else "raw"
    binary_hash = hashlib.sha256(pentect.read_bytes()).hexdigest()
    if not args.execute:
        print(json.dumps({"status": "draft", "client": args.client, "pentect_sha256": binary_hash, "max_http_per_phase": MAX_HTTP, "max_seconds_per_phase": MAX_SECONDS}))
        return 0
    with tempfile.TemporaryDirectory(prefix=f"pentect-native-file-{args.client}-") as temporary:
        root = Path(temporary); project = root / "project"; project.mkdir(); (project / ".git").mkdir()
        pentect_dir = project / ".pentect"; pentect_dir.mkdir()
        remember = "true" if args.remember == "enabled" else "false"
        (pentect_dir / "config.toml").write_text(f"[files]\nremember = {remember}\n[update]\ncheck = false\n")
        source, destination = project / ".env", project / "recovered.bin"
        source.write_text(f"PASSWORD={VALUE}\n" if args.value == "low-entropy" else f"OPENAI_API_KEY={VALUE}\n")
        env = isolated_env(root, args.client)
        bare_low_entropy_not_detected = True
        if args.value == "low-entropy":
            bare = subprocess.run(
                [str(pentect), "mask"], cwd=project, env=env, input=VALUE,
                capture_output=True, text=True, timeout=8, check=False,
            )
            bare_low_entropy_not_detected = (
                bare.returncode == 0 and bare.stdout == VALUE and not HANDLE.search(bare.stdout)
            )
        if args.registration == "pentect-read":
            registered = register_with_pentect_read(pentect, project, env, source)
        else:
            registered = run_phase(args.client, "register", pentect, root, project, env, source, destination, None)
        handle = registered["handle"]
        # Snapshot immediately after A exits, before starting B.  This proves B
        # cannot create the files used to claim registration succeeded.
        pointer_files_after_registration = sorted(
            p.name for p in (pentect_dir / "file-pointer-manager").glob("*")
        )
        pentect_files_after_registration = sorted(
            str(p.relative_to(root)) for p in root.rglob("*")
            if p.is_file() and ".pentect" in p.parts
        )
        if args.source_state == "changed":
            source.write_text("PASSWORD=changed\n")
        elif args.source_state == "deleted":
            source.unlink()
        recovery_project = project
        if args.scope == "different-project":
            recovery_project = root / "other-project"; recovery_project.mkdir(); (recovery_project / ".git").mkdir()
            other_config = recovery_project / ".pentect"; other_config.mkdir()
            (other_config / "config.toml").write_text(f"[files]\nremember = {remember}\n[update]\ncheck = false\n")
            destination = recovery_project / "recovered.bin"
        recovered = run_phase(args.client, "recover", pentect, root, recovery_project, env, source, destination, handle) if isinstance(handle, str) else {}
        exact = destination.exists() and destination.read_bytes() == VALUE.encode()
        literal_handle_written = (
            destination.exists() and isinstance(handle, str) and destination.read_text(errors="replace") == handle
        )
        common_checks = {
            "registration_call_issued": registered["call_issued"], "registration_result_seen": registered["result_seen"],
            "opaque_handle_captured": isinstance(handle, str), "registration_provider_plaintext_absent": not registered["provider_raw_seen"],
            "registration_process_completed": not registered["timed_out"] and registered["exit_code"] == 0,
            "low_entropy_bare_not_detected": bare_low_entropy_not_detected,
            "recovery_call_issued": bool(recovered.get("call_issued")),
            "recovery_provider_plaintext_absent": not recovered.get("provider_raw_seen", True), "recovery_process_completed": recovered.get("timed_out") is False,
            "handlers_clean": not registered["handler_error"] and not recovered.get("handler_error", True),
            "bounded": registered["http_count"] <= MAX_HTTP and recovered.get("http_count", MAX_HTTP + 1) <= MAX_HTTP,
        }
        pointer_present = {"index.bin", "key.bin"}.issubset(pointer_files_after_registration)
        expected = args.expect
        if expected == "auto":
            if args.registration == "client": expected = "registration-missing"
            elif args.source_state != "unchanged" or args.remember == "disabled" or args.scope != "same-project": expected = "blocked"
            else: expected = "recovered"
        outcome_checks = {
            "recovered": {"persistent_pointer_files_present_after_a": pointer_present, "recovery_result_seen": bool(recovered.get("result_seen")), "recovery_result_remasked": bool(recovered.get("result_remasked")), "recovered_file_exact": exact},
            "blocked": {"registration_state_as_expected": (not pointer_present if args.remember == "disabled" else pointer_present), "tool_result_withheld": not recovered.get("result_seen", False), "tool_side_effect_absent": not destination.exists()},
            "registration-missing": {"persistent_pointer_files_absent_after_a": not pointer_present, "tool_result_withheld": not recovered.get("result_seen", False), "tool_side_effect_absent": not destination.exists()},
        }[expected]
        checks = {**common_checks, **outcome_checks}
        client_executable = shutil.which(args.client if args.client != "opencode" else "opencode", path=env["PATH"])
        if client_executable is None: raise RuntimeError(f"{args.client} executable unavailable")
        version_command = [client_executable, "--version"]
        version = subprocess.run(version_command, env=env, capture_output=True, text=True, timeout=8, check=False).stdout.strip()
        result = {"client": args.client, "client_version": version, "pentect_sha256": binary_hash, "registration": registered, "recovery": recovered,
                  "registration_mode": args.registration,
                  "value_case": args.value, "view": VIEW, "source_state": args.source_state, "remember": args.remember, "scope_case": args.scope, "expected_outcome": expected,
                  "pointer_file_names_after_registration": pointer_files_after_registration,
                  "pentect_file_paths_after_registration": pentect_files_after_registration,
                  "destination_exists": destination.exists(), "destination_exact": exact,
                  "destination_literal_handle": literal_handle_written,
                  "recovery_outcome": "exact" if exact else "literal_handle" if literal_handle_written else "missing" if not destination.exists() else "wrong_bytes",
                  "checks": checks, "passed": all(checks.values()),
                  "scope": {"source": args.source_state, "project": args.scope, "note": "different-project does not copy the registered index; it tests an unregistered project reference, not identity-key mismatch", "provider": "deterministic localhost; no resolve/remask"}}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True)); return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
