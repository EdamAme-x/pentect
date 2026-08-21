#!/usr/bin/env python3
"""Install and select a managed OpenAI Privacy Filter runtime for Pentect."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from typing import Any


OPF_REVISION = "f7f00ca7fb869683eb732c010299d901457f19c3"
OPF_SOURCE = f"git+https://github.com/openai/privacy-filter.git@{OPF_REVISION}"
CUDA_INDEXES = ((580, "cu130"), (525, "cu126"))
DEPENDENCIES = ("huggingface_hub", "numpy", "packaging", "safetensors", "tiktoken")


def managed_root() -> Path:
    override = os.environ.get("PENTECT_OPF_ROOT")
    return Path(override).expanduser() if override else Path.home() / ".pentect" / "openai-privacy-filter"


def managed_python(root: Path) -> Path:
    return root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def valid_checkpoint(path: Path) -> bool:
    return path.is_dir() and (path / "config.json").is_file() and any(path.glob("*.safetensors"))


def shared_checkpoint(root: Path) -> Path:
    managed = root / "checkpoint"
    legacy = Path.home() / ".opf" / "privacy_filter"
    if valid_checkpoint(managed):
        return managed
    if valid_checkpoint(legacy):
        return legacy
    return managed


def read_state(root: Path) -> dict[str, Any]:
    try:
        value = json.loads((root / "setup.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def nvidia_driver_major() -> int | None:
    executable = shutil.which("nvidia-smi")
    if not executable:
        return None
    try:
        output = subprocess.check_output(
            [executable, "--query-gpu=driver_version", "--format=csv,noheader"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
        return max(int(line.strip().split(".", 1)[0]) for line in output.splitlines() if line.strip())
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def cuda_wheel(driver_major: int | None) -> str | None:
    if platform.system() == "Darwin" or driver_major is None:
        return None
    if platform.system() == "Windows" and driver_major < 528:
        return None
    for minimum, wheel in CUDA_INDEXES:
        if driver_major >= minimum:
            return wheel
    return None


def resolve_requested_profile(requested: str, state: dict[str, Any]) -> str:
    if requested != "keep":
        return requested
    previous = state.get("requested_profile")
    return previous if previous in {"auto", "cpu", "cuda"} else "auto"


def build_plan(requested: str, state: dict[str, Any]) -> dict[str, Any]:
    requested = resolve_requested_profile(requested, state)
    driver = nvidia_driver_major()
    wheel = cuda_wheel(driver)
    if requested == "cuda" and wheel is None:
        detail = "no NVIDIA driver was detected" if driver is None else f"NVIDIA driver {driver} is too old"
        raise RuntimeError(f"CUDA profile is unavailable: {detail}; use --profile cpu")
    device = "cuda" if requested == "cuda" or (requested == "auto" and wheel) else "cpu"
    wheel = wheel if device == "cuda" else "cpu"
    return {
        "schema": "pentect.opf-setup.v1",
        "requested_profile": requested,
        "device": device,
        "nvidia_driver_major": driver,
        "torch_index": f"https://download.pytorch.org/whl/{wheel}",
        "torch_wheel": wheel,
        "opf_revision": OPF_REVISION,
    }


def run(argv: list[str]) -> None:
    print("+", " ".join(argv), flush=True)
    subprocess.run(argv, check=True)


def runtime_matches(python: Path, plan: dict[str, Any]) -> bool:
    if not python.is_file():
        return False
    code = (
        "import opf, torch; "
        + ("assert torch.cuda.is_available()" if plan["device"] == "cuda" else "assert not torch.version.cuda")
    )
    try:
        subprocess.run(
            [str(python), "-c", code],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def write_state(root: Path, plan: dict[str, Any]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    temporary = root / f"setup.json.tmp-{os.getpid()}"
    temporary.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, root / "setup.json")


def controlled_fixture() -> bool:
    if os.environ.get("PENTECT_OPF_SETUP_FIXTURE") == "1":
        return True
    return (
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_WORKFLOW") == "Release"
        and os.environ.get("GITHUB_REPOSITORY") == "EdamAme-x/pentect"
    )


def install(root: Path, plan: dict[str, Any]) -> None:
    active = managed_python(root)
    current = read_state(root)
    identity = ("requested_profile", "device", "torch_index", "opf_revision")
    if all(current.get(key) == plan.get(key) for key in identity) and runtime_matches(active, plan):
        print(f"OpenAI Privacy Filter environment is already ready ({plan['device']}).")
        return
    if not current and runtime_matches(active, plan):
        write_state(root, plan)
        print(f"Adopted the existing OpenAI Privacy Filter environment ({plan['device']}).")
        return

    root.mkdir(parents=True, exist_ok=True)
    staged = root / f"venv.staged-{os.getpid()}"
    backup = root / f"venv.previous-{os.getpid()}"
    shutil.rmtree(staged, ignore_errors=True)
    shutil.rmtree(backup, ignore_errors=True)
    try:
        run([sys.executable, "-m", "venv", str(staged)])
        python = staged / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run([str(python), "-m", "pip", "install", "--upgrade", "pip"])
        run([str(python), "-m", "pip", "install", "torch", "--index-url", plan["torch_index"]])
        run([str(python), "-m", "pip", "install", *DEPENDENCIES])
        run([str(python), "-m", "pip", "install", "--no-deps", OPF_SOURCE])
        checkpoint = shared_checkpoint(root)
        plan["checkpoint"] = str(checkpoint)
        checkpoint_setup = r"""
from pathlib import Path
import os
import shutil
import sys
from huggingface_hub import snapshot_download

target = Path(sys.argv[1])
def valid(path):
    return path.is_dir() and (path / "config.json").is_file() and any(path.glob("*.safetensors"))
if valid(target):
    raise SystemExit(0)
staged = target.with_name(target.name + f".staged-{os.getpid()}")
shutil.rmtree(staged, ignore_errors=True)
snapshot_download(repo_id="openai/privacy-filter", local_dir=str(staged), allow_patterns=["original/*"])
original = staged / "original"
if not original.is_dir():
    raise RuntimeError("downloaded checkpoint has no original directory")
for source in original.iterdir():
    shutil.move(str(source), staged / source.name)
original.rmdir()
if not valid(staged):
    raise RuntimeError("downloaded checkpoint is incomplete")
if target.exists():
    shutil.rmtree(target)
os.replace(staged, target)
"""
        run([str(python), "-c", checkpoint_setup, str(checkpoint)])
        warmup = (
            "from opf import OPF; "
            f"OPF(model={str(checkpoint)!r}, device={plan['device']!r}, "
            "output_mode='typed', output_text_only=False).get_runtime()"
        )
        run([str(python), "-c", warmup])
        active_dir = root / "venv"
        if active_dir.exists():
            os.replace(active_dir, backup)
        os.replace(staged, active_dir)
        write_state(root, plan)
        shutil.rmtree(backup, ignore_errors=True)
    except Exception:
        shutil.rmtree(staged, ignore_errors=True)
        if backup.exists() and not (root / "venv").exists():
            os.replace(backup, root / "venv")
        raise


def main() -> None:
    if sys.version_info < (3, 10):
        raise SystemExit("OpenAI Privacy Filter requires Python 3.10 or newer")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("keep", "auto", "cpu", "cuda"), default="keep")
    args = parser.parse_args()
    root = managed_root()
    try:
        plan = build_plan(args.profile, read_state(root))
    except RuntimeError as error:
        raise SystemExit(str(error)) from error
    print(
        f"OpenAI Privacy Filter plan: profile={plan['requested_profile']} "
        f"device={plan['device']} torch={plan['torch_wheel']}"
    )
    print("Expected checkpoint: about 2.5 GB download / 2.8 GB disk (shared by profiles).")
    if controlled_fixture():
        plan["fixture"] = True
        write_state(root, plan)
        print("Fixture mode: setup plan validated without downloading model assets.")
        return
    try:
        install(root, plan)
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"OpenAI Privacy Filter setup failed: {error}") from error
    print(f"OpenAI Privacy Filter is ready on {plan['device']}.")


if __name__ == "__main__":
    main()
