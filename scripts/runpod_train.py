"""Run a Pentect FT job on a Runpod GPU pod, then bring the checkpoint home.

Usage:
  RUNPOD_API_KEY=... HF_TOKEN=... python scripts/runpod_train.py \
      --backend opf --epochs 3

The script:
  1. Creates an On-Demand pod (default: A100 80GB PCIe).
  2. Waits for ssh to come up.
  3. rsyncs the local repo to /workspace/pentect (excludes data/runs/.git/.venv).
  4. Installs deps inside the pod and runs the chosen training command.
  5. rsyncs the produced training/runs/<run_name> back to local.
  6. Terminates the pod (unless --keep is passed).

Why a script and not just `runpodctl` shells: this preserves the exact env
(HF_TOKEN, repo state) and gives one-shot reproducibility — useful for the
未踏 demo where re-running the FT must be a single command.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional


REPO = Path(__file__).resolve().parents[1]


def _need_env(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        raise SystemExit(f"missing env {key}")
    return val


def _runpod():
    import runpod  # local import so the script can be read without runpod installed

    runpod.api_key = _need_env("RUNPOD_API_KEY")
    return runpod


def _wait_for_ssh(pod_id: str, timeout: int = 600) -> dict:
    rp = _runpod()
    print(f"[runpod] waiting for pod {pod_id} to come up (ssh) ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        pod = rp.get_pod(pod_id)
        rt = pod.get("runtime") or {}
        ports = rt.get("ports") or []
        ssh = next((p for p in ports if p.get("privatePort") == 22 and p.get("isIpPublic")), None)
        if ssh and ssh.get("ip") and ssh.get("publicPort"):
            print(f"[runpod] ready: ssh root@{ssh['ip']} -p {ssh['publicPort']}")
            return {"ip": ssh["ip"], "port": int(ssh["publicPort"]), "pod": pod}
        time.sleep(5)
    raise SystemExit(f"pod {pod_id} did not expose ssh within {timeout}s")


def _ssh_cmd(host: dict) -> list[str]:
    return [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ServerAliveInterval=30",
        "-p", str(host["port"]),
        f"root@{host['ip']}",
    ]


def _ssh_run(host: dict, remote_cmd: str, *, stream: bool = True) -> int:
    cmd = _ssh_cmd(host) + [remote_cmd]
    print(f"[runpod] $ {remote_cmd}")
    if stream:
        return subprocess.call(cmd)
    return subprocess.run(cmd, check=False).returncode


def _rsync_push(host: dict) -> None:
    print("[runpod] rsync push: local repo -> pod:/workspace/pentect")
    rsh = (
        "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-p {host['port']}"
    )
    excludes = [
        ".git", ".venv", "node_modules", "ui/node_modules",
        "training/runs", "training/data/raw", "training/data/cache",
        "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
        ".playwright-mcp", "demo/juice/answer_*.md",  # local outputs
    ]
    excl = sum([["--exclude", e] for e in excludes], [])
    cmd = [
        "rsync", "-az", "--delete", "-e", rsh,
        *excl,
        f"{REPO}/", f"root@{host['ip']}:/workspace/pentect/",
    ]
    rc = subprocess.call(cmd)
    if rc != 0:
        raise SystemExit(f"rsync push failed: {rc}")


def _rsync_pull(host: dict, run_name: str) -> Path:
    dst = REPO / "training" / "runs" / run_name
    dst.parent.mkdir(parents=True, exist_ok=True)
    print(f"[runpod] rsync pull: pod:/workspace/pentect/training/runs/{run_name} -> {dst}")
    rsh = (
        "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-p {host['port']}"
    )
    cmd = [
        "rsync", "-az", "-e", rsh,
        f"root@{host['ip']}:/workspace/pentect/training/runs/{run_name}/",
        f"{dst}/",
    ]
    rc = subprocess.call(cmd)
    if rc != 0:
        raise SystemExit(f"rsync pull failed: {rc}")
    return dst


def _build_remote_script(args: argparse.Namespace, run_name: str) -> str:
    """Compose the remote shell sequence: deps + training command."""
    if args.backend == "opf":
        train_cmd = (
            "opf train training/data/opf/train.jsonl "
            "--validation-dataset training/data/opf/hard_val.jsonl "
            "--label-space-json training/data/opf/label_space.json "
            f"--output-dir training/runs/{run_name} "
            f"--device cuda --epochs {args.epochs} "
            f"--batch-size {args.batch_size} "
            f"--learning-rate {args.lr} "
            "--overwrite-output"
        )
        install = (
            "pip install -q -e . && "
            "pip install -q 'git+https://github.com/openai/privacy-filter.git'"
        )
    elif args.backend == "gemma":
        # train_lora.py is the existing Gemma 3 4B LoRA driver. Pass through
        # epochs/batch/lr; output dir is hardcoded inside the script — we
        # symlink it to the run_name we want for the rsync pull.
        train_cmd = (
            f"python -m training.train_lora --epochs {args.epochs} "
            f"--batch-size {args.batch_size} --lr {args.lr} && "
            f"ln -sfn $(pwd)/training/runs/gemma3_4b_lora training/runs/{run_name}"
        )
        install = (
            "pip install -q -e '.[llm]'"
        )
    else:
        raise ValueError(args.backend)

    hf = os.environ.get("HF_TOKEN", "")
    parts = [
        "set -eu",
        "cd /workspace/pentect",
        f"export HF_TOKEN={shlex.quote(hf)}" if hf else ":",
        "export HUGGING_FACE_HUB_TOKEN=$HF_TOKEN",
        # Faster pip
        "export PIP_DISABLE_PIP_VERSION_CHECK=1",
        install,
        train_cmd,
        # Print final summary so it ends up in the streamed log
        f"ls -la training/runs/{run_name} || true",
    ]
    return " && ".join(parts)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["opf", "gemma"], required=True)
    ap.add_argument("--gpu", default="NVIDIA A100 80GB PCIe",
                    help="GPU type id (see runpod.get_gpus()). Default: A100 80GB PCIe.")
    ap.add_argument("--image", default="runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04",
                    help="Container image.")
    ap.add_argument("--volume-gb", type=int, default=80)
    ap.add_argument("--container-disk-gb", type=int, default=80)
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--run-name", default=None,
                    help="Output directory under training/runs/ (default: opf_pentect_runpod_<ts>)")
    ap.add_argument("--keep", action="store_true",
                    help="Don't terminate the pod on success.")
    ap.add_argument("--cloud", default="SECURE", choices=["SECURE", "COMMUNITY", "ALL"],
                    help="Cloud type. SECURE is more reliable, COMMUNITY is cheaper.")
    args = ap.parse_args()

    rp = _runpod()
    ts = time.strftime("%Y%m%d_%H%M%S")
    run_name = args.run_name or f"{args.backend}_pentect_runpod_{ts}"

    print(f"[runpod] creating pod (gpu={args.gpu}, cloud={args.cloud}) ...")
    pod = rp.create_pod(
        name=f"pentect-{args.backend}-{ts}",
        image_name=args.image,
        gpu_type_id=args.gpu,
        cloud_type=args.cloud,
        gpu_count=1,
        volume_in_gb=args.volume_gb,
        container_disk_in_gb=args.container_disk_gb,
        ports="22/tcp",
        volume_mount_path="/workspace",
        support_public_ip=True,
        start_ssh=True,
        env={"PUBLIC_KEY": _read_pubkey()},
    )
    pod_id = pod["id"]
    print(f"[runpod] pod created: {pod_id}")

    try:
        host = _wait_for_ssh(pod_id)
        # Wait a few extra seconds for the ssh daemon to fully accept connections
        time.sleep(10)

        _rsync_push(host)
        remote = _build_remote_script(args, run_name)
        rc = _ssh_run(host, f"bash -lc {shlex.quote(remote)}")
        if rc != 0:
            raise SystemExit(f"remote training failed: rc={rc}")

        _rsync_pull(host, run_name)
        print(f"[runpod] checkpoint at: training/runs/{run_name}")
    finally:
        if args.keep:
            print(f"[runpod] keeping pod {pod_id} (--keep)")
        else:
            print(f"[runpod] terminating pod {pod_id}")
            try:
                rp.terminate_pod(pod_id)
            except Exception as e:  # noqa: BLE001
                print(f"[runpod] WARN: terminate failed: {e}")


def _read_pubkey() -> str:
    """Read an ssh public key for the pod to install in authorized_keys."""
    candidates = [
        os.environ.get("RUNPOD_SSH_PUBKEY_FILE"),
        str(Path.home() / ".ssh" / "id_ed25519.pub"),
        str(Path.home() / ".ssh" / "id_rsa.pub"),
    ]
    for c in candidates:
        if not c:
            continue
        p = Path(c)
        if p.is_file():
            return p.read_text().strip()
    raise SystemExit(
        "no ssh public key found. set RUNPOD_SSH_PUBKEY_FILE or generate "
        "~/.ssh/id_ed25519 with: ssh-keygen -t ed25519"
    )


if __name__ == "__main__":
    main()
