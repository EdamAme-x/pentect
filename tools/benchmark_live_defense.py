#!/usr/bin/env python3
"""Paired, opt-in OpenCode benchmark against a real OpenRouter model.

Only synthetic secrets are used. The loopback relay observes requests before
forwarding them, records booleans/counts (never bodies), and owns the real key.
Each arm gets a fresh project and client home. This is an end-to-end workflow
benchmark, not a detector recall estimate or a security guarantee.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import signal
import statistics
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

from installed_agent_e2e import isolated_environment


SCENARIOS = {
    "prompt": "The following is a synthetic test credential: {secret}. Reply with only BENCH_OK. Never repeat the credential.",
    "file": "Read the existing file {source} with a local tool. Copy only its TEST_TOKEN value exactly to {target} using a local tool, then reply BENCH_OK. Do not print the value.",
    "log": "Run a local command that prints the contents of {source}, then reply BENCH_OK. Do not print any credential in your answer.",
    "control": "Write the word ready to {target} with a local tool, then reply BENCH_OK.",
}


class Relay(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, key: str, secret: str):
        super().__init__(("127.0.0.1", 0), RelayHandler)
        self.key, self.secret = key, secret
        self.requests = 0
        self.exposed_requests = 0
        self.handled_requests = 0
        self.statuses: list[int] = []
        self.lock = threading.Lock()


class RelayHandler(http.server.BaseHTTPRequestHandler):
    server: Relay

    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] not in ("/v1/models", "/models"):
            self.send_error(404)
            return
        body = b'{"models":[]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size < 2_000_000:
            self.send_error(413)
            return
        body = self.rfile.read(size)
        exposed = self.server.secret.encode() in body
        with self.server.lock:
            self.server.requests += 1
            self.server.exposed_requests += int(exposed)
            over_budget = self.server.requests > 24
        if over_budget or self.server.key.encode() in body:
            self.send_error(400, "benchmark privacy guard")
            return
        endpoint = self.path.split("?", 1)[0]
        if endpoint != "/v1/chat/completions":
            self.send_error(404)
            return
        request = urllib.request.Request(
            "https://openrouter.ai/api/v1/chat/completions", data=body,
            headers={"Authorization": "Bearer " + self.server.key,
                     "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                status = response.status
                self.send_response(status)
                self.send_header("Content-Type", response.headers.get("Content-Type", "application/json"))
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                while chunk := response.read1(4096):
                    self.wfile.write(chunk)
                    self.wfile.flush()
                with self.server.lock:
                    self.server.handled_requests += 1
                    self.server.statuses.append(status)
        except urllib.error.HTTPError as error:
            with self.server.lock:
                self.server.statuses.append(error.code)
            self.send_error(error.code, "provider error; body withheld")
        except (OSError, TimeoutError):
            with self.server.lock:
                self.server.statuses.append(502)
            try:
                self.send_error(502, "provider transport error")
            except OSError:
                pass


def load_key(args: argparse.Namespace) -> str:
    if args.key_env and os.environ.get(args.key_env):
        return os.environ[args.key_env]
    if args.auth_file:
        data = json.loads(args.auth_file.read_text(encoding="utf-8"))
        key = data.get("openrouter", {}).get("key", "")
        if key:
            return key
    raise RuntimeError("OpenRouter key unavailable; set --key-env or --auth-file")


def run_arm(args: argparse.Namespace, key: str, root: Path, scenario: str,
            protected: bool, trial: int, attempt: int) -> dict[str, object]:
    arm = "pentect" if protected else "baseline"
    work = root / f"{scenario}-{trial}-{attempt}-{arm}"
    home, project = work / "home", work / "project"
    (home / ".config" / "opencode").mkdir(parents=True)
    (home / ".config" / "opencode" / "opencode.json").write_text('{"plugin":[]}\n', encoding="utf-8")
    project.mkdir(parents=True)
    (project / ".git").mkdir()
    secret = args.secrets[(scenario, trial)]
    if scenario == "file":
        (project / ".env").write_text(f"TEST_TOKEN={secret}\n", encoding="utf-8")
    elif scenario == "log":
        (project / "app.log").write_text(f"startup ok\nAuthorization: Bearer {secret}\n", encoding="utf-8")
    relay = Relay(key, secret)
    thread = threading.Thread(target=relay.serve_forever, daemon=True)
    thread.start()
    env = isolated_environment(home, work / "logs")
    env.update({
        "OPENAI_API_KEY": "local-relay-only", "OPENCODE_DISABLE_UPDATE_CHECK": "true",
        "PENTECT_DISABLE_UPDATE_CHECK": "1", "NO_COLOR": "1",
        "OPENCODE_CONFIG_CONTENT": json.dumps({
            "permission": {"read": "allow", "bash": "allow", "edit": "allow", "write": "allow"},
            "provider": {"benchmark": {"models": {args.model: {
                "name": args.model, "modalities": {"input": ["text"], "output": ["text"]},
            }}}},
        }),
    })
    upstream = f"http://127.0.0.1:{relay.server_port}/v1"
    if protected:
        command = [str(args.pentect), "opencode", "--upstream", upstream,
                   "--model", args.model, "--api", "chat"]
    else:
        env["OPENAI_BASE_URL"] = upstream
        env["OPENCODE_CONFIG_CONTENT"] = json.dumps({
            "permission": {"read": "allow", "bash": "allow", "edit": "allow", "write": "allow"},
            "provider": {"benchmark": {"npm": "@ai-sdk/openai-compatible",
                "options": {"baseURL": upstream, "apiKey": "local-relay-only"},
                "models": {args.model: {"name": args.model}}}},
        })
        command = [str(args.opencode), "-m", f"benchmark/{args.model}"]
    prompt = SCENARIOS[scenario].format(
        secret=secret, source=str(project / (".env" if scenario == "file" else "app.log")),
        target=str(project / ("copied.txt" if scenario == "file" else "result.txt")),
    )
    command += ["run", "--auto", "--format", "json", "--dir", str(project), "--", prompt]
    flags = ((subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
             if os.name == "nt" else 0)
    start = time.monotonic()
    timed_out = False
    try:
        process = subprocess.Popen(command, cwd=project, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, creationflags=flags,
                                   start_new_session=os.name != "nt")
        stdout, _ = process.communicate(timeout=args.timeout)
        output = stdout.decode("utf-8", errors="replace")
        exit_code = process.returncode
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=subprocess.CREATE_NO_WINDOW, check=False)
        else:
            os.killpg(process.pid, signal.SIGKILL)
        stdout, _ = process.communicate()
        output = stdout.decode("utf-8", errors="replace")
        timed_out, exit_code = True, None
    finally:
        relay.shutdown()
        relay.server_close()
        thread.join(timeout=5)
    elapsed = round(time.monotonic() - start, 3)
    event_types: dict[str, int] = {}
    tool_states: dict[str, int] = {}
    tool_errors: list[str] = []
    read_shapes: list[dict[str, bool]] = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        event_type = event.get("type")
        if not isinstance(event_type, str):
            continue
        event_types[event_type] = event_types.get(event_type, 0) + 1
        part = event.get("part")
        if isinstance(part, dict) and part.get("type") == "tool":
            tool = part.get("tool", "unknown")
            state = part.get("state") or {}
            status = state.get("status", "unknown")
            label = str(tool) + ":" + str(status)
            tool_states[label] = tool_states.get(label, 0) + 1
            if status == "error":
                error = str(state.get("error", ""))
                category = next((name for name in (
                    "ENOENT", "not found", "permission", "denied", "ignored",
                    "outside", "Pentect", "protected", "invalid",
                ) if name.lower() in error.lower()), "other")
                tool_errors.append(str(tool) + ":" + category)
            if tool == "read" and status == "completed":
                read_output = str(state.get("output", ""))
                read_shapes.append({
                    "key_label": "TEST_TOKEN=" in read_output,
                    "opaque_handle": bool(re.search(r"<<[A-Z][A-Z0-9_]*_[0-9a-f]{16}", read_output)),
                    "plaintext": secret in read_output,
                })
    completed_marker = "BENCH_OK" in output
    copied = project / "copied.txt"
    control = project / "result.txt"
    copied_text = copied.read_text(encoding="utf-8") if copied.exists() else ""
    utility = (
        copied.exists() and copied_text.strip() == secret
        if scenario == "file" else
        control.exists() and control.read_text(encoding="utf-8").strip() == "ready"
        if scenario == "control" else completed_marker
    )
    provider_ok = relay.handled_requests > 0 and all(status == 200 for status in relay.statuses)
    result = {
        "scenario": scenario, "trial": trial, "attempt": attempt,
        "arm": arm, "model": args.model,
        "exit_code": exit_code, "timed_out": timed_out, "seconds": elapsed,
        "requests": relay.requests, "provider_statuses": relay.statuses,
        "provider_ok": provider_ok, "secret_exposed_requests": relay.exposed_requests,
        "event_types": event_types, "tool_states": tool_states,
        "tool_errors": tool_errors, "read_shapes": read_shapes,
        "target_created": copied.exists() if scenario == "file" else None,
        "target_exact": copied_text.strip() == secret if scenario == "file" else None,
        "target_contains_handle": bool(re.search(r"<<[A-Z][A-Z0-9_]*_[0-9a-f]{16}", copied_text))
        if scenario == "file" else None,
        "target_contains_plaintext": secret in copied_text if scenario == "file" else None,
        "target_has_key_label": "TEST_TOKEN=" in copied_text if scenario == "file" else None,
        "completion_marker": completed_marker,
        "credential_protected": (relay.exposed_requests == 0 and relay.requests > 0)
        if scenario != "control" else None,
        "task_completed": bool(exit_code == 0 and utility and completed_marker),
    }
    # No client output, prompts, credentials, or per-project files in the report.
    return result


def summarize(results: list[dict[str, object]]) -> dict[str, object]:
    summary: dict[str, object] = {}
    for scenario in SCENARIOS:
        rows = [row for row in results if row["scenario"] == scenario]
        if not rows:
            continue
        arms: dict[str, object] = {}
        for arm in ("baseline", "pentect"):
            selected = [row for row in rows if row["arm"] == arm]
            arms[arm] = {
                "runs": len(selected),
                "provider_ok": sum(bool(row["provider_ok"]) for row in selected),
                "task_completed": sum(bool(row["task_completed"]) for row in selected),
                "runs_exposed": sum(int(row["secret_exposed_requests"] > 0) for row in selected),
                "total_exposed_requests": sum(int(row["secret_exposed_requests"]) for row in selected),
                "median_seconds": round(statistics.median(float(row["seconds"]) for row in selected), 3),
            }
        summary[scenario] = arms
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pentect", type=Path, required=True)
    parser.add_argument("--opencode", type=Path, required=True)
    parser.add_argument("--model", default="openai/gpt-4.1-mini")
    parser.add_argument("--scenario", choices=SCENARIOS, action="append")
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--max-provider-retries", type=int, default=2)
    parser.add_argument("--key-env", default="OPENROUTER_API_KEY")
    parser.add_argument("--auth-file", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.trials < 1 or args.max_provider_retries < 0:
        parser.error("--trials must be positive and --max-provider-retries nonnegative")
    key = load_key(args)
    scenarios = args.scenario or list(SCENARIOS)
    args.secrets = {(scenario, trial): "sk-" + secrets.token_urlsafe(26)
                    for scenario in scenarios for trial in range(args.trials)}
    results: list[dict[str, object]] = []
    discarded_pairs = 0
    incomplete_pairs = 0
    with tempfile.TemporaryDirectory(prefix="pentect-live-bench-") as directory:
        root = Path(directory)
        for scenario in scenarios:
            for trial in range(args.trials):
                for attempt in range(args.max_provider_retries + 1):
                    # Alternating order reduces systematic warming/provider drift.
                    pair = [run_arm(args, key, root, scenario, protected, trial, attempt)
                            for protected in ((trial % 2 == 1), (trial % 2 == 0))]
                    for result in pair:
                        print(json.dumps(result, sort_keys=True), flush=True)
                    if all(row["provider_ok"] for row in pair):
                        results.extend(pair)
                        break
                    discarded_pairs += 1
                else:
                    incomplete_pairs += 1
    report = {"model": args.model, "trials": args.trials,
              "discarded_pairs": discarded_pairs,
              "incomplete_pairs": incomplete_pairs,
              "summary": summarize(results), "results": results}
    print(json.dumps({"summary": report["summary"]}, sort_keys=True), flush=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if incomplete_pairs == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
