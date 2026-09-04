#!/usr/bin/env python3
"""Run paid-key-free installed-agent boundary tests against localhost fixtures."""

from __future__ import annotations

import argparse
import base64
import csv
import io
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
PLUGIN_HANDLE = re.compile(r"<<PLUGIN_E2E_[0-9a-f]{16}>>")
PLUGIN_PLAINTEXT = "PENTECT-PLUGIN-E2E-VALUE"
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


def pentect_command(pentect: str, arguments: list[str]) -> list[str]:
    command = [pentect, *arguments]
    if os.name == "nt" and pentect.lower().endswith((".cmd", ".bat")):
        return [
            os.environ.get("COMSPEC", "cmd.exe"),
            "/d",
            "/s",
            "/c",
            subprocess.list2cmdline(command),
        ]
    return command


def run_pentect(
    pentect: str,
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    stdin: str | None = None,
    timeout: float = 30,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        pentect_command(pentect, arguments),
        cwd=cwd,
        env=environment,
        input=stdin,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if completed.returncode != 0:
        output = completed.stdout.replace(PLUGIN_PLAINTEXT, "<plugin-fixture>")
        raise RuntimeError(
            f"Pentect {' '.join(arguments[:3])} exited with "
            f"{completed.returncode}:\n{output}"
        )
    return completed


def install_detector_plugin(
    pentect: str,
    root: Path,
    project: Path,
    environment: dict[str, str],
) -> Path:
    plugin = root / "plugin"
    plugin.mkdir()
    (plugin / "plugin.toml").write_text(
        """schema = "pentect.plugin.v1"
name = "agent-e2e-plugin"

[[detector]]
label = "PLUGIN_E2E"
pattern = '''PENTECT-PLUGIN-E2E-VALUE'''
category = "identifier"
confidence = "high"
""",
        encoding="utf-8",
    )
    inspected = run_pentect(
        pentect,
        ["plugins", "inspect", str(plugin), "--json"],
        cwd=project,
        environment=environment,
    )
    inspection = json.loads(inspected.stdout)
    if (
        inspection.get("name") != "agent-e2e-plugin"
        or inspection.get("form") != "manifest"
        or len(inspection.get("configs", [])) != 1
    ):
        raise RuntimeError("plugin inspect did not describe the fixture: " + inspected.stdout)
    tested = run_pentect(
        pentect,
        ["plugins", "test", str(plugin), "--json"],
        cwd=project,
        environment=environment,
    )
    checks = json.loads(tested.stdout).get("checks", [])
    if not checks or any(check.get("status") != "ok" for check in checks):
        raise RuntimeError("plugin test did not validate the fixture: " + tested.stdout)
    added = run_pentect(
        pentect,
        ["plugins", "add", str(plugin), "--project", "--yes"],
        cwd=project,
        environment=environment,
    )
    if "verified: manifest-only plugin" not in added.stdout or "enabled:" not in added.stdout:
        raise RuntimeError(
            "plugin add did not verify and enable the fixture:\n" + added.stdout
        )
    listed = run_pentect(
        pentect,
        ["plugins", "list"],
        cwd=project,
        environment=environment,
    )
    if "agent-e2e-plugin: project ok configs=1 binary=no" not in listed.stdout:
        raise RuntimeError("installed project plugin was not active")
    setup = run_pentect(
        pentect,
        ["plugins", "setup", str(plugin), "--project", "--yes"],
        cwd=project,
        environment=environment,
    )
    if "verified: manifest-only plugin" not in setup.stdout:
        raise RuntimeError("plugin setup did not verify the installed fixture")
    updated = run_pentect(
        pentect,
        ["plugins", "update", str(plugin), "--project", "--yes"],
        cwd=project,
        environment=environment,
    )
    if "update: refreshed manifest for agent-e2e-plugin" not in updated.stdout:
        raise RuntimeError("plugin update did not refresh the installed fixture")
    reinstalled = run_pentect(
        pentect,
        ["plugins", "add", str(plugin), "--project", "--yes"],
        cwd=project,
        environment=environment,
    )
    if "enabled:" not in reinstalled.stdout:
        raise RuntimeError("plugin reinstall did not remain idempotent")
    listed = run_pentect(
        pentect,
        ["plugins", "list"],
        cwd=project,
        environment=environment,
    )
    if listed.stdout.count("agent-e2e-plugin: project ok configs=1 binary=no") != 1:
        raise RuntimeError("plugin reinstall duplicated project state")
    return plugin


def remove_detector_plugin(
    pentect: str,
    project: Path,
    environment: dict[str, str],
) -> None:
    run_pentect(
        pentect,
        ["plugins", "remove", "agent-e2e-plugin", "--project"],
        cwd=project,
        environment=environment,
    )
    listed = run_pentect(
        pentect,
        ["plugins", "list"],
        cwd=project,
        environment=environment,
    )
    if "agent-e2e-plugin:" in listed.stdout:
        raise RuntimeError("removed project plugin remained active")
    masked = run_pentect(
        pentect,
        ["mask"],
        cwd=project,
        environment=environment,
        stdin=PLUGIN_PLAINTEXT,
    )
    if PLUGIN_PLAINTEXT not in masked.stdout or PLUGIN_HANDLE.search(masked.stdout):
        raise RuntimeError(
            "removed project plugin still changed masking output: "
            + repr(masked.stdout.strip())
        )


def isolated_environment(home: Path, log_dir: Path) -> dict[str, str]:
    environment = os.environ.copy()
    original_home_value = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    original_home = Path(original_home_value) if original_home_value else None
    environment.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
        "PENTECT_LOG_DIR": str(log_dir),
    })
    if original_home is not None:
        for variable, directory in (
            ("CARGO_HOME", ".cargo"),
            ("RUSTUP_HOME", ".rustup"),
        ):
            candidate = original_home / directory
            if variable not in environment and candidate.is_dir():
                environment[variable] = str(candidate)
    if os.name == "nt":
        local_app_data = home / "AppData" / "Local"
        roaming_app_data = home / "AppData" / "Roaming"
        local_app_data.mkdir(parents=True)
        roaming_app_data.mkdir(parents=True)
        environment.update({
            "LOCALAPPDATA": str(local_app_data),
            "APPDATA": str(roaming_app_data),
        })
    return environment


def snapshot_regular_files(*roots: Path) -> dict[str, bytes]:
    snapshot: dict[str, bytes] = {}
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file():
                snapshot[f"{root.name}/{path.relative_to(root)}"] = path.read_bytes()
    return snapshot


def verify_user_scope_lifecycle(
    pentect: str,
    plugin: Path,
    project: Path,
    environment: dict[str, str],
) -> None:
    project_before = snapshot_regular_files(project)
    run_pentect(
        pentect,
        ["plugins", "add", str(plugin), "--yes"],
        cwd=project,
        environment=environment,
    )
    listed = run_pentect(
        pentect,
        ["plugins", "list"],
        cwd=project,
        environment=environment,
    )
    if "agent-e2e-plugin: user ok configs=1 binary=no" not in listed.stdout:
        raise RuntimeError("installed user plugin was not active")
    masked = run_pentect(
        pentect,
        ["mask"],
        cwd=project,
        environment=environment,
        stdin=PLUGIN_PLAINTEXT,
    )
    if PLUGIN_PLAINTEXT in masked.stdout or not PLUGIN_HANDLE.search(masked.stdout):
        raise RuntimeError("installed user plugin did not protect its fixture")
    run_pentect(
        pentect,
        ["plugins", "remove", "agent-e2e-plugin"],
        cwd=project,
        environment=environment,
    )
    listed = run_pentect(
        pentect,
        ["plugins", "list"],
        cwd=project,
        environment=environment,
    )
    if "agent-e2e-plugin:" in listed.stdout:
        raise RuntimeError("removed user plugin remained active")
    if snapshot_regular_files(project) != project_before:
        raise RuntimeError("user plugin lifecycle changed project-scoped files")


def verify_failed_setup_rolls_back(
    pentect: str,
    root: Path,
    home: Path,
    project: Path,
    environment: dict[str, str],
) -> None:
    plugin = root / "failed-setup-plugin"
    plugin.mkdir()
    (plugin / "plugin.toml").write_text(
        '''schema = "pentect.plugin.v1"
name = "failed-setup-e2e"
command = ["python", "-c", "import sys; sys.exit(0)"]
hooks = ["inspect"]

[setup]
command = ["python", "-c", "import sys; sys.exit(17)"]
''',
        encoding="utf-8",
    )
    before = snapshot_regular_files(home, project)
    completed = subprocess.run(
        pentect_command(
            pentect,
            ["plugins", "add", str(plugin), "--project", "--yes"],
        ),
        cwd=project,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    if (
        completed.returncode == 0
        or "plugin environment setup failed with exit 17" not in completed.stdout
    ):
        raise RuntimeError(
            "failed plugin setup did not report its exit status:\n" + completed.stdout
        )
    after = snapshot_regular_files(home, project)
    if after != before:
        changed = sorted(set(before) ^ set(after))
        changed.extend(
            path for path in sorted(set(before) & set(after)) if before[path] != after[path]
        )
        raise RuntimeError(
            "failed plugin setup left partial persistent state: " + ", ".join(changed)
        )
    listed = run_pentect(
        pentect,
        ["plugins", "list"],
        cwd=project,
        environment=environment,
    )
    if "failed-setup-e2e:" in listed.stdout:
        raise RuntimeError("failed plugin setup remained enabled")


def verify_home_rooted_project_storage_boundary(pentect: str) -> None:
    with tempfile.TemporaryDirectory(
        prefix="pentect-plugin-e2e-home-project-", ignore_cleanup_errors=True
    ) as raw_home:
        home = Path(raw_home)
        (home / ".git").mkdir()
        plugin = home / "optional-home-plugin"
        plugin.mkdir()
        manifest = plugin / "plugin.toml"
        script = plugin / "server.py"
        manifest_source = '''schema = "pentect.plugin.v1"
name = "optional-home-storage-e2e"
command = ["python", "{plugin}/server.py"]
hooks = ["inspect"]
required = false
'''
        manifest.write_text(manifest_source, encoding="utf-8")
        script.write_text("raise SystemExit(0)\n", encoding="utf-8")
        config_dir = home / ".pentect"
        config_dir.mkdir()
        (config_dir / "config.toml").write_text(
            f"plugins = [{json.dumps(str(plugin))}]\n", encoding="utf-8"
        )
        environment = isolated_environment(home, home / "logs")
        ordinary = "ordinary HOME-rooted project fixture"
        optional = run_pentect(
            pentect,
            ["mask"],
            cwd=home,
            environment=environment,
            stdin=ordinary,
        )
        if (
            ordinary not in optional.stdout
            or "optional plugin 'optional-home-storage-e2e' skipped during startup"
            not in optional.stdout
            or "Pentect plugin data directory must be outside the project"
            not in optional.stdout
        ):
            raise RuntimeError(
                "optional HOME-rooted project plugin did not fail open with its reason:\n"
                + optional.stdout
            )

        manifest.write_text(
            manifest_source.replace("required = false", "required = true"),
            encoding="utf-8",
        )
        required = subprocess.run(
            pentect_command(pentect, ["mask"]),
            cwd=home,
            env=environment,
            input=ordinary,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
        if (
            required.returncode == 0
            or "Pentect plugin data directory must be outside the project"
            not in required.stdout
        ):
            raise RuntimeError(
                "required HOME-rooted project plugin did not fail closed with its reason:\n"
                + required.stdout
            )


def verify_interrupted_setup_rolls_back(
    pentect: str,
    root: Path,
    home: Path,
    project: Path,
    environment: dict[str, str],
) -> None:
    plugin = root / "interrupted-setup-plugin"
    plugin.mkdir()
    setup = plugin / "setup.py"
    setup.write_text(
        '''import os
import time

with open("setup-pid.txt", "w", encoding="utf-8") as marker:
    marker.write(str(os.getpid()))
while True:
    time.sleep(1)
''',
        encoding="utf-8",
    )
    (plugin / "server.py").write_text(
        '''import json
import sys

for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({
        "schema": "pentect.plugin.v1",
        "id": request["id"],
        "type": "result",
        "action": "next",
        "spans": [],
    }, separators=(",", ":")), flush=True)
''',
        encoding="utf-8",
    )
    (plugin / "plugin.toml").write_text(
        '''schema = "pentect.plugin.v1"
name = "interrupted-setup-e2e"
command = ["python", "{plugin}/server.py"]
hooks = ["inspect"]

[setup]
command = ["python", "{plugin}/setup.py"]
''',
        encoding="utf-8",
    )
    before = snapshot_regular_files(home, project)
    popen_options: dict[str, object] = {}
    if os.name == "nt":
        popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_options["start_new_session"] = True
    process = subprocess.Popen(
        pentect_command(
            pentect,
            ["plugins", "add", str(plugin), "--project", "--yes"],
        ),
        cwd=project,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        **popen_options,
    )
    marker = plugin / "setup-pid.txt"
    deadline = time.monotonic() + 10
    while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    if not marker.exists():
        process.kill()
        output, _ = process.communicate(timeout=5)
        raise RuntimeError("plugin setup did not reach its interrupt fixture:\n" + output)
    setup_pid = int(marker.read_text(encoding="utf-8"))
    if os.name == "nt":
        process.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        os.kill(process.pid, signal.SIGINT)
    try:
        output, _ = process.communicate(timeout=8)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        raise RuntimeError("interrupted plugin setup did not exit within 8 seconds") from error
    if process.returncode == 0 or "plugin environment setup was interrupted" not in output:
        raise RuntimeError("interrupted plugin setup did not report interruption:\n" + output)
    if not wait_for_process_exit(setup_pid, timeout=2.0):
        raise RuntimeError(f"interrupted plugin setup process {setup_pid} was not terminated")
    if snapshot_regular_files(home, project) != before:
        raise RuntimeError("interrupted plugin setup left partial persistent state")
    listed = run_pentect(
        pentect,
        ["plugins", "list"],
        cwd=project,
        environment=environment,
    )
    if "interrupted-setup-e2e:" in listed.stdout:
        raise RuntimeError("interrupted plugin setup remained enabled")

    setup.write_text("raise SystemExit(0)\n", encoding="utf-8")
    run_pentect(
        pentect,
        ["plugins", "add", str(plugin), "--project", "--yes"],
        cwd=project,
        environment=environment,
    )
    run_pentect(
        pentect,
        ["mask"],
        cwd=project,
        environment=environment,
        stdin="ordinary recovered setup fixture",
    )
    run_pentect(
        pentect,
        ["plugins", "remove", "interrupted-setup-e2e", "--project"],
        cwd=project,
        environment=environment,
    )


def verify_forced_setup_termination_is_clean(
    pentect: str,
    root: Path,
    home: Path,
    project: Path,
    environment: dict[str, str],
) -> None:
    plugin = root / "forced-setup-plugin"
    plugin.mkdir()
    setup = plugin / "setup.py"
    setup.write_text(
        '''import json
import os
import time

with open("setup-pid.txt", "w", encoding="utf-8") as marker:
    json.dump({"setup": os.getpid(), "supervisor": os.getppid()}, marker)
while True:
    time.sleep(1)
''',
        encoding="utf-8",
    )
    (plugin / "server.py").write_text(
        '''import json
import sys

for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({
        "schema": "pentect.plugin.v1",
        "id": request["id"],
        "type": "result",
        "action": "next",
        "spans": [],
    }, separators=(",", ":")), flush=True)
''',
        encoding="utf-8",
    )
    (plugin / "plugin.toml").write_text(
        '''schema = "pentect.plugin.v1"
name = "forced-setup-e2e"
command = ["python", "{plugin}/server.py"]
hooks = ["inspect"]

[setup]
command = ["python", "{plugin}/setup.py"]
''',
        encoding="utf-8",
    )
    before = snapshot_regular_files(home, project)
    process = subprocess.Popen(
        pentect_command(
            pentect,
            ["plugins", "add", str(plugin), "--project", "--yes"],
        ),
        cwd=project,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    marker = plugin / "setup-pid.txt"
    deadline = time.monotonic() + 10
    while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    if not marker.exists():
        process.kill()
        output, _ = process.communicate(timeout=5)
        raise RuntimeError("plugin setup did not reach its forced-termination fixture:\n" + output)
    setup_processes = json.loads(marker.read_text(encoding="utf-8"))
    setup_pid = int(setup_processes["setup"])
    supervisor_pid = int(setup_processes["supervisor"])
    if supervisor_pid == process.pid:
        process.kill()
        process.communicate(timeout=5)
        raise RuntimeError("plugin setup did not run below a distinct supervisor")
    process.kill()
    process.communicate(timeout=5)
    if not wait_for_process_exit(setup_pid, timeout=3.0):
        raise RuntimeError(f"forced plugin setup process {setup_pid} survived its Pentect owner")
    if not wait_for_process_exit(supervisor_pid, timeout=3.0):
        raise RuntimeError(
            f"forced plugin setup supervisor {supervisor_pid} survived its Pentect owner"
        )
    if snapshot_regular_files(home, project) != before:
        raise RuntimeError("forced plugin setup termination left partial persistent state")
    listed = run_pentect(
        pentect,
        ["plugins", "list"],
        cwd=project,
        environment=environment,
    )
    if "forced-setup-e2e:" in listed.stdout:
        raise RuntimeError("forced plugin setup termination left the plugin enabled")

    setup.write_text("raise SystemExit(0)\n", encoding="utf-8")
    run_pentect(
        pentect,
        ["plugins", "add", str(plugin), "--project", "--yes"],
        cwd=project,
        environment=environment,
    )
    run_pentect(
        pentect,
        ["plugins", "remove", "forced-setup-e2e", "--project"],
        cwd=project,
        environment=environment,
    )


def verify_failed_update_preserves_command_runtime(
    pentect: str,
    root: Path,
    home: Path,
    project: Path,
    environment: dict[str, str],
) -> None:
    plugin = root / "failed-update-plugin"
    plugin.mkdir()
    manifest = plugin / "plugin.toml"
    server = plugin / "server.py"
    manifest_source = '''schema = "pentect.plugin.v1"
name = "failed-update-e2e"
command = ["python", "{plugin}/server.py"]
hooks = ["inspect"]
required = true

[setup]
command = ["python", "-c", "raise SystemExit(0)"]
'''
    server.write_text(
        r'''import json
import sys

for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({
        "schema": "pentect.plugin.v1",
        "id": request["id"],
        "type": "result",
        "action": "next",
        "spans": [],
    }, separators=(",", ":")), flush=True)
''',
        encoding="utf-8",
    )
    manifest.write_text(manifest_source, encoding="utf-8")
    run_pentect(
        pentect,
        ["plugins", "add", str(plugin), "--project", "--yes"],
        cwd=project,
        environment=environment,
    )
    ordinary = "ordinary failed update fixture"
    run_pentect(
        pentect,
        ["mask"],
        cwd=project,
        environment=environment,
        stdin=ordinary,
    )
    before = snapshot_regular_files(home, project)
    manifest.write_text(
        manifest_source.replace(
            'required = true\n', 'required = true\ndescription = "updated"\n'
        ).replace("raise SystemExit(0)", "raise SystemExit(17)"),
        encoding="utf-8",
    )
    failed = subprocess.run(
        pentect_command(
            pentect,
            ["plugins", "update", str(plugin), "--project", "--yes"],
        ),
        cwd=project,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    if (
        failed.returncode == 0
        or "plugin environment setup failed with exit 17" not in failed.stdout
    ):
        raise RuntimeError(
            "failed plugin update did not expose its setup failure:\n" + failed.stdout
        )
    if snapshot_regular_files(home, project) != before:
        raise RuntimeError("failed plugin update changed approved persistent state")

    # A local source is owned by the user and is not rewritten by Pentect. Once
    # that source is restored, the previously approved runtime must work without
    # another setup. Remote sources restore this side through the cache rollback.
    manifest.write_text(manifest_source, encoding="utf-8")
    recovered = run_pentect(
        pentect,
        ["mask"],
        cwd=project,
        environment=environment,
        stdin=ordinary,
    )
    if ordinary not in recovered.stdout:
        raise RuntimeError(
            "previously approved plugin did not recover after failed update:\n"
            + recovered.stdout
        )
    run_pentect(
        pentect,
        ["plugins", "remove", "failed-update-e2e", "--project"],
        cwd=project,
        environment=environment,
    )


def verify_command_runtime_concurrency_and_restart(
    pentect: str,
    root: Path,
    project: Path,
    environment: dict[str, str],
) -> None:
    plugin = root / "concurrent-command-plugin"
    plugin.mkdir()
    workers = plugin / "workers"
    workers.mkdir()
    script = plugin / "server.py"
    (plugin / "plugin.toml").write_text(
        '''schema = "pentect.plugin.v1"
name = "concurrent-command-e2e"
command = ["python", "{plugin}/server.py"]
hooks = ["inspect"]
required = true

[execution]
timeout_ms = 10000
startup_timeout_ms = 10000
''',
        encoding="utf-8",
    )
    script.write_text(
        r'''import json
import os
import sys
import time
from pathlib import Path

workers = Path(__file__).parent / "workers"
workers.mkdir(exist_ok=True)
leader_file = workers / "leader"
try:
    descriptor = os.open(leader_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
except FileExistsError:
    role = "follower"
else:
    os.close(descriptor)
    role = "leader"
marker = workers / f"{os.getpid()}.worker"
marker.write_text(json.dumps({"parent": os.getppid(), "role": role}), encoding="utf-8")
deadline = time.monotonic() + 5
while len(list(workers.glob("*.worker"))) < 2 and time.monotonic() < deadline:
    time.sleep(0.02)
if len(list(workers.glob("*.worker"))) < 2:
    raise SystemExit(23)
if role == "follower":
    release = workers / "release"
    release_deadline = time.monotonic() + 15
    while not release.exists() and time.monotonic() < release_deadline:
        time.sleep(0.02)
    if not release.exists():
        raise SystemExit(24)

for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({
        "schema": "pentect.plugin.v1",
        "id": request["id"],
        "type": "result",
        "action": "next",
        "spans": [],
    }, separators=(",", ":")), flush=True)
''',
        encoding="utf-8",
    )
    run_pentect(
        pentect,
        ["plugins", "add", str(plugin), "--project", "--yes"],
        cwd=project,
        environment=environment,
    )
    ordinary = "ordinary concurrent command fixture"

    def invoke() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            pentect_command(pentect, ["mask"]),
            cwd=project,
            env=environment,
            input=ordinary,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )

    processes = [
        subprocess.Popen(
            pentect_command(pentect, ["mask"]),
            cwd=project,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for _ in range(2)
    ]
    for process in processes:
        assert process.stdin is not None
        process.stdin.write(ordinary)
        process.stdin.close()
        process.stdin = None
    deadline = time.monotonic() + 5
    while len(list(workers.glob("*.worker"))) < 2 and time.monotonic() < deadline:
        if any(process.poll() is not None for process in processes):
            break
        time.sleep(0.02)
    marker_paths = list(workers.glob("*.worker"))
    if len(marker_paths) != 2:
        for process in processes:
            process.kill()
        outputs = [process.communicate()[0] for process in processes]
        raise RuntimeError(
            "concurrent Pentect processes did not start two plugin workers:\n"
            + "\n".join(outputs)
        )
    markers = {
        int(path.stem): json.loads(path.read_text(encoding="utf-8"))
        for path in marker_paths
    }
    leaders = [(pid, data) for pid, data in markers.items() if data["role"] == "leader"]
    followers = [(pid, data) for pid, data in markers.items() if data["role"] == "follower"]
    if len(leaders) != 1 or len(followers) != 1:
        raise RuntimeError("concurrent command workers did not elect one leader and one follower")
    processes_by_pid = {process.pid: process for process in processes}
    _, leader_data = leaders[0]
    follower_worker, follower_data = followers[0]
    leader = processes_by_pid.get(leader_data["parent"])
    follower = processes_by_pid.get(follower_data["parent"])
    if leader is None or follower is None:
        raise RuntimeError("command worker markers did not identify their Pentect parents")
    leader_output, _ = leader.communicate(timeout=15)
    if leader.returncode != 0 or ordinary not in leader_output:
        raise RuntimeError("leading concurrent command invocation failed:\n" + leader_output)
    if follower.poll() is not None or not process_exists(follower_worker):
        follower_output, _ = follower.communicate(timeout=5)
        raise RuntimeError(
            "ending one Pentect process terminated the other plugin worker:\n"
            + follower_output
        )
    (workers / "release").write_text("continue\n", encoding="utf-8")
    follower_output, _ = follower.communicate(timeout=15)
    if follower.returncode != 0 or ordinary not in follower_output:
        raise RuntimeError("following concurrent command invocation failed:\n" + follower_output)
    first_workers = sorted(markers)
    for pid in first_workers:
        if not wait_for_process_exit(pid, timeout=2.0):
            raise RuntimeError(f"concurrent command plugin worker {pid} survived its Pentect process")

    restarted = invoke()
    if restarted.returncode != 0 or ordinary not in restarted.stdout:
        raise RuntimeError("restarted installed command invocation failed:\n" + restarted.stdout)
    all_workers = sorted(int(path.stem) for path in workers.glob("*.worker"))
    if len(all_workers) != 3 or not set(first_workers).issubset(all_workers):
        raise RuntimeError("restarted Pentect did not create exactly one new plugin worker")
    restarted_pid = next(pid for pid in all_workers if pid not in first_workers)
    if not wait_for_process_exit(restarted_pid, timeout=2.0):
        raise RuntimeError(
            f"restarted command plugin worker {restarted_pid} survived its Pentect process"
        )
    run_pentect(
        pentect,
        ["plugins", "remove", "concurrent-command-e2e", "--project"],
        cwd=project,
        environment=environment,
    )


def verify_long_setup_and_waiter_complete(
    pentect: str,
    root: Path,
    project: Path,
    environment: dict[str, str],
) -> None:
    plugin = root / "concurrent-setup-plugin"
    plugin.mkdir()
    runs = plugin / "setup-runs"
    runs.mkdir()
    manifest = plugin / "plugin.toml"
    server = plugin / "server.py"
    setup = plugin / "setup.py"
    manifest_source = '''schema = "pentect.plugin.v1"
name = "concurrent-setup-e2e"
command = ["python", "{plugin}/server.py"]
hooks = ["inspect"]
required = true

[execution]
timeout_ms = 1000
startup_timeout_ms = 1000
'''
    server.write_text(
        r'''import json
import sys

for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({
        "schema": "pentect.plugin.v1",
        "id": request["id"],
        "type": "result",
        "action": "next",
        "spans": [],
    }, separators=(",", ":")), flush=True)
''',
        encoding="utf-8",
    )
    setup.write_text(
        r'''import json
import os
import time
from pathlib import Path

runs = Path(__file__).parent / "setup-runs"
first_file = runs / "first"
try:
    descriptor = os.open(first_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
except FileExistsError:
    role = "fast"
else:
    os.close(descriptor)
    role = "slow"
(runs / f"{os.getpid()}.setup").write_text(
    json.dumps({"parent": os.getppid(), "role": role}), encoding="utf-8"
)
if role == "slow":
    time.sleep(6)
''',
        encoding="utf-8",
    )
    manifest.write_text(manifest_source, encoding="utf-8")
    run_pentect(
        pentect,
        ["plugins", "add", str(plugin), "--project", "--yes"],
        cwd=project,
        environment=environment,
    )
    manifest.write_text(
        manifest_source
        + '''
[setup]
command = ["python", "{plugin}/setup.py"]
''',
        encoding="utf-8",
    )
    started = time.monotonic()
    processes = [
        subprocess.Popen(
            pentect_command(
                pentect,
                ["plugins", "setup", str(plugin), "--project", "--yes"],
            ),
            cwd=project,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for _ in range(2)
    ]
    deadline = time.monotonic() + 5
    while len(list(runs.glob("*.setup"))) < 1 and time.monotonic() < deadline:
        if any(process.poll() is not None for process in processes):
            break
        time.sleep(0.02)
    initial_markers = list(runs.glob("*.setup"))
    if len(initial_markers) != 1 or any(process.poll() is not None for process in processes):
        for process in processes:
            process.kill()
        outputs = [process.communicate()[0] for process in processes]
        raise RuntimeError(
            "concurrent setup was not serialized before the first setup completed:\n"
            + "\n".join(outputs)
        )
    first_data = json.loads(initial_markers[0].read_text(encoding="utf-8"))
    if first_data["role"] != "slow":
        raise RuntimeError("first concurrent setup did not enter the long-running fixture")
    outputs = {process.pid: process.communicate(timeout=20)[0] for process in processes}
    elapsed = time.monotonic() - started
    markers = {
        int(path.stem): json.loads(path.read_text(encoding="utf-8"))
        for path in runs.glob("*.setup")
    }
    if len(markers) != 2:
        raise RuntimeError(f"serialized setup started {len(markers)} setup children, expected 2")
    supervisor_pids = {data["parent"] for data in markers.values()}
    if len(supervisor_pids) != 2 or supervisor_pids & {process.pid for process in processes}:
        raise RuntimeError("setup child markers did not identify distinct setup supervisors")
    if {data["role"] for data in markers.values()} != {"slow", "fast"}:
        raise RuntimeError("serialized setup did not run one slow and one fast setup child")
    for process in processes:
        if process.returncode != 0 or "setup: complete" not in outputs[process.pid]:
            raise RuntimeError(
                "long-running serialized setup did not complete:\n" + outputs[process.pid]
            )
    waiting = [
        output
        for output in outputs.values()
        if "waiting for another plugin operation to finish" in output
    ]
    if len(waiting) != 1:
        raise RuntimeError("exactly one concurrent setup did not wait for the mutation lock")
    if elapsed < 5.5:
        raise RuntimeError("long-running setup fixture did not exercise its six-second operation")
    for setup_pid in markers:
        if not wait_for_process_exit(setup_pid, timeout=2.0):
            raise RuntimeError(f"serialized setup child {setup_pid} survived completion")
    for supervisor_pid in supervisor_pids:
        if not wait_for_process_exit(supervisor_pid, timeout=2.0):
            raise RuntimeError(
                f"serialized setup supervisor {supervisor_pid} survived completion"
            )

    ordinary = "ordinary long-running setup fixture"
    recovered = run_pentect(
        pentect,
        ["mask"],
        cwd=project,
        environment=environment,
        stdin=ordinary,
    )
    if ordinary not in recovered.stdout:
        raise RuntimeError("plugin was unusable after long-running serialized setup completed")
    run_pentect(
        pentect,
        ["plugins", "remove", "concurrent-setup-e2e", "--project"],
        cwd=project,
        environment=environment,
    )


def run_plugin_lifecycle(pentect: str) -> None:
    with tempfile.TemporaryDirectory(
        prefix="pentect-plugin-e2e-project-", ignore_cleanup_errors=True
    ) as raw_root, tempfile.TemporaryDirectory(
        prefix="pentect-plugin-e2e-home-", ignore_cleanup_errors=True
    ) as raw_home:
        root = Path(raw_root)
        home = Path(raw_home)
        project = root / "project"
        project.mkdir()
        (project / ".git").mkdir()
        environment = isolated_environment(home, root / "logs")
        plugin = install_detector_plugin(pentect, root, project, environment)
        masked = run_pentect(
            pentect,
            ["mask"],
            cwd=project,
            environment=environment,
            stdin=PLUGIN_PLAINTEXT,
        )
        if PLUGIN_PLAINTEXT in masked.stdout or not PLUGIN_HANDLE.search(masked.stdout):
            raise RuntimeError("installed project plugin did not protect its fixture")
        logs = (root / "logs" / "pentect.log").read_text(encoding="utf-8")
        if PLUGIN_PLAINTEXT in logs:
            raise RuntimeError("plugin fixture plaintext reached persistent diagnostics")
        remove_detector_plugin(pentect, project, environment)
        verify_user_scope_lifecycle(pentect, plugin, project, environment)
        verify_failed_setup_rolls_back(
            pentect, root, home, project, environment
        )
        verify_interrupted_setup_rolls_back(
            pentect, root, home, project, environment
        )
        verify_forced_setup_termination_is_clean(
            pentect, root, home, project, environment
        )
        verify_failed_update_preserves_command_runtime(
            pentect, root, home, project, environment
        )
        verify_command_runtime_concurrency_and_restart(
            pentect, root, project, environment
        )
        verify_long_setup_and_waiter_complete(
            pentect, root, project, environment
        )
        verify_installed_command_failure_boundaries(pentect, root, project, environment)
        verify_installed_wasm_failure_boundaries(pentect, root, project, environment)
        verify_home_rooted_project_storage_boundary(pentect)
        print(
            "installed plugin lifecycle E2E passed: inspect, test, project/user "
            "add/setup/update/reinstall/remove, failed/interrupted/forced-setup and failed-update rollback, "
            "Command runtime concurrency/restart, long-running serialized setup completion, "
            "Command fail-closed boundaries and process cleanup, installed Wasm trap/timeout/"
            "malformed/oversized required/optional boundaries, HOME-rooted optional/required "
            "storage boundaries, no log plaintext"
        )


def verify_installed_wasm_failure_boundaries(
    pentect: str,
    root: Path,
    project: Path,
    environment: dict[str, str],
) -> None:
    plugin = root / "wasm-failure-plugin"
    source = plugin / "src"
    source.mkdir(parents=True)
    repository = Path(__file__).resolve().parents[1]
    sdk = repository / "sdk" / "rust" / "pentect-plugin"
    if not sdk.is_dir():
        raise RuntimeError(f"Pentect Rust plugin SDK is unavailable: {sdk}")
    (plugin / "Cargo.toml").write_text(
        f'''[package]
name = "wasm-failure-e2e"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
pentect-plugin = {{ path = {json.dumps(sdk.as_posix())} }}

[workspace]
''',
        encoding="utf-8",
    )
    manifest = plugin / "plugin.toml"
    manifest_source = '''schema = "pentect.plugin.v1"
name = "wasm-failure-e2e"
wasm = "wasm-failure-e2e.wasm"
required = true

[execution]
timeout_ms = 1000
max_output_bytes = 1024
'''
    manifest.write_text(manifest_source, encoding="utf-8")
    (source / "lib.rs").write_text(
        r'''use pentect_plugin::__serde_json as serde_json;
use pentect_plugin::__serde_json::{json, Value};

#[no_mangle]
pub extern "C" fn pentect_alloc(len: i32) -> i32 {
    let input = vec![0_u8; usize::try_from(len).expect("negative input length")]
        .into_boxed_slice();
    Box::into_raw(input) as *mut u8 as i32
}

#[no_mangle]
pub unsafe extern "C" fn pentect_inspect(pointer: i32, len: i32) -> i64 {
    let pointer = usize::try_from(pointer).expect("negative input pointer");
    let len = usize::try_from(len).expect("negative input length");
    let input = unsafe {
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer as *mut u8, len))
    };
    let request: Value = serde_json::from_slice(&input).expect("invalid fixture input");
    let text = request["payload"]["text"].as_str().unwrap_or_default();
    if text.contains("WASM_TIMEOUT") {
        loop {
            std::hint::spin_loop();
        }
    }
    if text.contains("WASM_TRAP") {
        panic!("intentional installed Wasm E2E trap");
    }
    let output = if text.contains("WASM_MALFORMED") {
        b"not-json".to_vec()
    } else if text.contains("WASM_OVERSIZED") {
        vec![b'x'; 2048]
    } else {
        serde_json::to_vec(&json!({
            "schema": "pentect.plugin.v1",
            "id": request["id"],
            "type": "result",
            "action": "next"
        }))
        .expect("fixture response serialization failed")
    }
    .into_boxed_slice();
    let output_len = u32::try_from(output.len()).expect("fixture output too large");
    let output_pointer = Box::into_raw(output) as *mut u8 as u32;
    (((output_pointer as u64) << 32) | u64::from(output_len)) as i64
}
''',
        encoding="utf-8",
    )
    config_dir = project / ".pentect"
    created_config_dir = not config_dir.exists()
    config_dir.mkdir(exist_ok=True)
    config = config_dir / "config.toml"
    previous_config = config.read_text(encoding="utf-8") if config.exists() else None
    config.write_text(
        f"plugins = [{json.dumps(plugin.as_posix())}]\n",
        encoding="utf-8",
    )
    wasm_environment = environment.copy()
    wasm_environment["CARGO_TARGET_DIR"] = str(repository / "target")
    wasm_environment["CARGO_NET_OFFLINE"] = "true"

    def activate() -> None:
        activated = run_pentect(
            pentect,
            ["plugins", "dev", str(plugin), "--yes"],
            cwd=project,
            environment=wasm_environment,
            timeout=180,
        )
        if "active: local development build" not in activated.stdout:
            raise RuntimeError(
                "Wasm development plugin did not activate:\n" + activated.stdout
            )

    def invoke(text: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            pentect_command(pentect, ["mask"]),
            cwd=project,
            env=wasm_environment,
            input=text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )

    try:
        activate()
        for text, reason in (
            ("WASM_TRAP", "execution failed"),
            ("WASM_TIMEOUT", "timed out"),
            ("WASM_MALFORMED", "returned invalid JSON"),
            ("WASM_OVERSIZED", "returned too much output"),
        ):
            completed = invoke(text)
            if completed.returncode == 0 or reason not in completed.stdout:
                raise RuntimeError(
                    f"required installed Wasm plugin did not fail closed with {reason!r}:\n"
                    + completed.stdout
                )

        manifest.write_text(
            manifest_source.replace("required = true", "required = false"),
            encoding="utf-8",
        )
        activate()
        for text, reason in (
            ("WASM_TRAP", "execution failed"),
            ("WASM_TIMEOUT", "timed out"),
            ("WASM_MALFORMED", "returned invalid JSON"),
            ("WASM_OVERSIZED", "returned too much output"),
        ):
            completed = invoke(text)
            if (
                completed.returncode != 0
                or text not in completed.stdout
                or "optional plugin 'wasm-failure-e2e' skipped" not in completed.stdout
                or reason not in completed.stdout
            ):
                raise RuntimeError(
                    f"optional installed Wasm plugin did not fail open with {reason!r}:\n"
                    + completed.stdout
                )
    finally:
        if previous_config is None:
            config.unlink(missing_ok=True)
        else:
            config.write_text(previous_config, encoding="utf-8")
        if created_config_dir:
            shutil.rmtree(config_dir, ignore_errors=True)


def verify_installed_command_failure_boundaries(
    pentect: str,
    root: Path,
    project: Path,
    environment: dict[str, str],
) -> None:
    plugin = root / "command-failure-plugin"
    plugin.mkdir()
    manifest = plugin / "plugin.toml"
    script = plugin / "server.py"
    manifest_source = '''schema = "pentect.plugin.v1"
name = "command-failure-e2e"
command = ["python", "{plugin}/server.py"]
hooks = ["inspect"]
required = true

[execution]
timeout_ms = 1000
startup_timeout_ms = 1000
max_output_bytes = 1024
'''
    script_source = r'''import json
import os
import subprocess
import sys
import time

for line in sys.stdin:
    request = json.loads(line)
    mode = request.get("config", {}).get("mode", "valid")
    if mode == "invalid-json":
        print("not-json", flush=True)
    elif mode == "oversized":
        print("x" * 2048, flush=True)
    elif mode == "timeout":
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        with open("timeout-pids.json", "w", encoding="utf-8") as marker:
            json.dump([os.getpid(), child.pid], marker)
        time.sleep(30)
    elif mode == "exit":
        sys.exit(17)
    else:
        print(json.dumps({
            "schema": "pentect.plugin.v1",
            "id": request["id"],
            "type": "result",
            "action": "next",
            "spans": [],
        }, separators=(",", ":")), flush=True)
'''
    manifest.write_text(manifest_source, encoding="utf-8")
    script.write_text(script_source, encoding="utf-8")
    run_pentect(
        pentect,
        ["plugins", "add", str(plugin), "--project", "--yes"],
        cwd=project,
        environment=environment,
    )

    def set_mode(mode: str) -> None:
        run_pentect(
            pentect,
            ["plugins", "config", "command-failure-e2e", f"mode={mode}", "--project"],
            cwd=project,
            environment=environment,
        )

    def expect_mask_failure(reason: str) -> None:
        completed = subprocess.run(
            pentect_command(pentect, ["mask"]),
            cwd=project,
            env=environment,
            input="ordinary command plugin fixture",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
        if completed.returncode == 0 or reason not in completed.stdout:
            raise RuntimeError(
                f"required command plugin did not fail closed with {reason!r}:\n"
                + completed.stdout
            )

    set_mode("valid")
    run_pentect(
        pentect,
        ["mask"],
        cwd=project,
        environment=environment,
        stdin="ordinary command plugin fixture",
    )
    for mode, reason in (
        ("invalid-json", "returned invalid JSON"),
        ("oversized", "response exceeds its limit"),
        ("exit", "closed stdout"),
        ("timeout", "command startup timed out"),
    ):
        set_mode(mode)
        expect_mask_failure(reason)

    timeout_pids = json.loads((plugin / "timeout-pids.json").read_text(encoding="utf-8"))
    for pid in timeout_pids:
        if not wait_for_process_exit(pid, timeout=2.0):
            raise RuntimeError(f"timed-out command plugin process {pid} was not terminated")

    set_mode("valid")
    manifest.write_text(
        manifest_source.replace(
            'name = "command-failure-e2e"\n',
            'name = "command-failure-e2e"\ndescription = "changed"\n',
        ),
        encoding="utf-8",
    )
    expect_mask_failure("changed after approval")
    manifest.write_text(manifest_source, encoding="utf-8")

    script.write_text(script_source + "\n# changed after setup\n", encoding="utf-8")
    expect_mask_failure("changed after setup")
    script.write_text(script_source, encoding="utf-8")
    script.unlink()
    expect_mask_failure("is unavailable")

    run_pentect(
        pentect,
        ["plugins", "remove", "command-failure-e2e", "--project"],
        cwd=project,
        environment=environment,
    )

    optional = root / "optional-command-failure-plugin"
    optional.mkdir()
    optional_manifest = manifest_source.replace(
        'name = "command-failure-e2e"',
        'name = "optional-command-failure-e2e"',
    ).replace("required = true", "required = false")
    (optional / "plugin.toml").write_text(optional_manifest, encoding="utf-8")
    optional_script = optional / "server.py"
    optional_script.write_text(script_source, encoding="utf-8")
    run_pentect(
        pentect,
        ["plugins", "add", str(optional), "--project", "--yes"],
        cwd=project,
        environment=environment,
    )
    optional_script.unlink()
    completed = run_pentect(
        pentect,
        ["mask"],
        cwd=project,
        environment=environment,
        stdin="ordinary optional command plugin fixture",
    )
    if (
        "optional plugin 'optional-command-failure-e2e' skipped during startup"
        not in completed.stdout
        or "is unavailable" not in completed.stdout
    ):
        raise RuntimeError(
            "optional installed command failure did not expose its reason:\n"
            + completed.stdout
        )
    run_pentect(
        pentect,
        ["plugins", "remove", "optional-command-failure-e2e", "--project"],
        cwd=project,
        environment=environment,
    )


def process_exists(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True
    completed = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    return any(
        len(row) > 1 and row[1] == str(pid)
        for row in csv.reader(io.StringIO(completed.stdout))
    )


def wait_for_process_exit(pid: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while process_exists(pid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


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
            (project / "plugin-input.txt").write_text(
                PLUGIN_PLAINTEXT + "\n", encoding="utf-8"
            )
            (project / "e2e_helper.py").write_text(
                """from pathlib import Path
import sys
import urllib.request

if sys.argv[1] == "read":
    print(Path(".env").read_text(encoding="utf-8"))
    print(Path("plugin-input.txt").read_text(encoding="utf-8"))
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
            environment = isolated_environment(home, root / "logs")
            environment.update({
                "OPENAI_API_KEY": "local-fixture",
                "ANTHROPIC_API_KEY": "local-fixture",
            })
            if os.name == "nt" and client == "claude":
                git_bash = shutil.which("bash.exe") or shutil.which("bash")
                if git_bash is None:
                    raise RuntimeError(
                        "claude E2E requires Git Bash on Windows, but bash.exe "
                        "was not found on PATH"
                    )
                environment["CLAUDE_CODE_GIT_BASH_PATH"] = git_bash
            install_detector_plugin(pentect, root, project, environment)
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
            if PLUGIN_PLAINTEXT in upstream:
                raise RuntimeError("plugin fixture plaintext reached the model simulator")
            if len(set(HANDLE.findall(upstream))) < 2:
                raise RuntimeError("the model simulator did not receive two distinct handles")
            if not PLUGIN_HANDLE.search(upstream):
                raise RuntimeError("the model simulator did not receive the plugin handle")
            log_path = root / "logs" / "pentect.log"
            logs = log_path.read_text(encoding="utf-8")
            if valid in logs or invalid in logs or PLUGIN_PLAINTEXT in logs:
                raise RuntimeError("a synthetic plaintext key reached persistent diagnostics")
            remove_detector_plugin(pentect, project, environment)
            print(
                f"installed {client} E2E passed: project plugin "
                "inspect/test/add/setup/update/reinstall/mask/remove, two key handles, "
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
            try:
                completed = subprocess.run(
                    command,
                    cwd=project,
                    env=environment,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=90,
                )
            except subprocess.TimeoutExpired as error:
                output = error.stdout or ""
                if isinstance(output, bytes):
                    output = output.decode(errors="replace")
                raise RuntimeError(
                    f"image E2E did not finish within 90 seconds:\n{output}"
                ) from error
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
    parser.add_argument("--plugin-lifecycle-only", action="store_true")
    args = parser.parse_args()
    candidate = Path(args.pentect)
    if candidate.is_file():
        args.pentect = str(candidate.resolve())
    if args.plugin_lifecycle_only:
        run_plugin_lifecycle(args.pentect)
        return 0
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
