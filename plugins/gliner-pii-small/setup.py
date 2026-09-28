"""Explicit setup only: download pinned weights, then verify offline loading."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

MODEL = "knowledgator/gliner-pii-small-v1.0"
REVISION = "d21aad5b4a7ec82b3d0970fd1ac74a12c087d85e"
ROOT = Path.home() / ".pentect" / "gliner-pii-small"

def run(argv):
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, encoding="utf-8", errors="replace",
                          creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0) as process:
        for line in process.stdout:
            print(line, end="", flush=True)
        if process.wait():
            raise RuntimeError("Setup subprocess failed")

def main():
    os.chdir(Path(__file__).resolve().parent)
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=["cpu", "cuda"], default="cpu")
    parser.add_argument("--prepare", action="store_true")
    args = parser.parse_args()
    if not (3, 10) <= sys.version_info[:2] < (3, 14):
        raise SystemExit("Python 3.10 through 3.13 is required by the pinned runtime")
    if args.prepare:
        os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
        from huggingface_hub import snapshot_download
        checkpoint = ROOT / ("checkpoint-" + REVISION)
        from gliner import GLiNER
        model = GLiNER.from_pretrained(MODEL, revision=REVISION, trust_remote_code=False)
        model.save_pretrained(checkpoint, safe_serialization=True)
        state = {"device": args.profile, "model": MODEL, "revision": REVISION, "checkpoint": str(checkpoint)}
        # Child process starts with offline flags set before importing the runtime.
        os.environ["HF_HUB_OFFLINE"] = "1"
        code = "from server import Detector; d=Detector(str(checkpoint), device=DEVICE); d.inspect('No private information here.')"
        code = code.replace("str(checkpoint)", repr(str(checkpoint)))
        code = code.replace("DEVICE", repr(args.profile))
        # The approved plugin directory must not gain __pycache__ files.
        run([sys.executable, "-B", "-c", code])
        temporary = ROOT / "setup.json.tmp"
        temporary.write_text(json.dumps(state), encoding="utf-8")
        os.replace(temporary, ROOT / "setup.json")
        return
    ROOT.mkdir(parents=True, exist_ok=True)
    python = ROOT / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.exists():
        run([sys.executable, "-m", "venv", str(ROOT / "venv")])
    wheel_suffix = "" if sys.platform == "darwin" else ("+cu124" if args.profile == "cuda" else "+cpu")
    torch_args = [str(python), "-m", "pip", "install", "torch==2.6.0" + wheel_suffix]
    if sys.platform != "darwin":
        torch_args += ["--index-url", "https://download.pytorch.org/whl/" + ("cu124" if args.profile == "cuda" else "cpu")]
    elif args.profile == "cuda":
        raise SystemExit("CUDA is not supported on macOS")
    run(torch_args)
    run([str(python), "-m", "pip", "install", "transformers==4.57.1",
         "huggingface-hub==0.36.2", "sentencepiece==0.2.1", "gliner==0.2.21"])
    os.chdir(Path(__file__).resolve().parent)
    run([str(python), str(Path(__file__).resolve()), "--prepare", "--profile", args.profile])
    print("Setup complete. Runtime inspection is offline.")

if __name__ == "__main__":
    main()
