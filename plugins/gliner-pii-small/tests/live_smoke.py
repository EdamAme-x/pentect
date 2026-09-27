"""Explicit real-model smoke in the same minimal environment as Pentect."""
import json
import os
from pathlib import Path
import subprocess
import sys

plugin = Path(__file__).resolve().parents[1]
keep = {"HOME", "USERPROFILE", "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL"}
env = {key: value for key, value in os.environ.items() if key.upper() in keep}
request = {"schema": "pentect.plugin.v1", "id": 1, "hook": "inspect",
           "payload": {"text": "Contact Alice at alice@example.test"}}
result = subprocess.run([sys.executable, str(plugin / "server.py")], env=env, cwd=plugin,
    input=json.dumps(request) + "\n", text=True, capture_output=True, timeout=120,
    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
if result.returncode or not result.stdout:
    print(result.stderr)
    python = Path.home() / ".pentect/gliner-pii-small/venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    diagnostic = "import json; from pathlib import Path; from server import Detector; s=json.loads((Path.home()/'.pentect/gliner-pii-small/setup.json').read_text()); Detector(s['checkpoint'])"
    probe = subprocess.run([str(python), "-c", diagnostic], env=env, cwd=plugin,
        text=True, capture_output=True, timeout=120,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    print(probe.stderr)
    raise SystemExit("Real model subprocess failed")
response = json.loads(result.stdout)
assert response["id"] == 1 and response["action"] == "next"
assert {s["label"] for s in response["spans"]} >= {"PERSON", "EMAIL"}
assert "alice@example.test" not in result.stdout
print("Real offline model + sanitized environment + protocol: passed")
