#!/usr/bin/env python3
"""Pin CredSweeper, sync embedded assets, and validate the native Rust port."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


UPSTREAM = "https://github.com/Samsung/CredSweeper.git"
TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
ASSETS = {
    "LICENSE": "LICENSE",
    "credsweeper/common/keyword_checklist.txt": "common/keyword_checklist.txt",
    "credsweeper/common/morpheme_checklist.txt": "common/morpheme_checklist.txt",
    "credsweeper/ml_model/ml_config.json": "ml_model/ml_config.json",
    "credsweeper/ml_model/ml_model.onnx": "ml_model/ml_model.onnx",
    "credsweeper/rules/config.yaml": "rules/config.yaml",
    "credsweeper/secret/config.json": "secret/config.json",
}
SIDECAR_PATCH = Path("tools/credsweeper-sidecar/patches/lazy-imports.patch")


def run(*args: str, cwd: Path, capture: bool = False) -> str:
    command = list(args)
    print("+", " ".join(command), flush=True)
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return completed.stdout.strip() if capture else ""


def remote_tag(repo: Path, requested: str | None = None) -> tuple[str, str]:
    output = run(
        "git",
        "ls-remote",
        "--tags",
        "--refs",
        UPSTREAM,
        *([f"refs/tags/{requested}"] if requested else []),
        cwd=repo,
        capture=True,
    )
    tags = []
    for line in output.splitlines():
        commit = line.split(maxsplit=1)[0]
        tag = line.rsplit("refs/tags/", 1)[-1]
        match = TAG_RE.fullmatch(tag)
        if match:
            tags.append((tuple(map(int, match.groups())), tag, commit))
    if not tags:
        suffix = f" {requested}" if requested else ""
        raise RuntimeError(f"CredSweeper did not publish semantic-version tag{suffix}")
    _, tag, commit = max(tags)
    return tag, commit


def installed_release(submodule: Path, assets: Path) -> tuple[str, str]:
    """Return the pinned release without relying on locally fetched git tags."""
    head = run("git", "rev-parse", "HEAD", cwd=submodule, capture=True)
    try:
        source = json.loads((assets / "SOURCE.json").read_text(encoding="utf-8"))
        version = source["version"]
        commit = source["commit"]
    except (FileNotFoundError, KeyError, json.JSONDecodeError, TypeError):
        return head[:7], head
    if TAG_RE.fullmatch(version) and commit == head:
        return version, commit
    return f"{version}@{head[:7]}", head


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.pentect-update")
    shutil.copyfile(source, temporary)
    os.replace(temporary, destination)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sync_assets(submodule: Path, destination: Path, tag: str, commit: str) -> None:
    hashes = {}
    for source_name, destination_name in ASSETS.items():
        source = submodule / source_name
        target = destination / destination_name
        if not source.is_file():
            raise RuntimeError(f"upstream asset is missing: {source_name}")
        atomic_copy(source, target)
        hashes[destination_name] = sha256(target)
    manifest = {
        "upstream": UPSTREAM,
        "version": tag,
        "commit": commit,
        "assets": dict(sorted(hashes.items())),
    }
    manifest_path = destination / "SOURCE.json"
    temporary = manifest_path.with_name(".SOURCE.json.pentect-update")
    temporary.write_bytes((json.dumps(manifest, indent=2) + "\n").encode("utf-8"))
    os.replace(temporary, manifest_path)


def sync_runtime_requirements(submodule: Path, destination: Path) -> None:
    source = submodule / "requirements.txt"
    lines = source.read_text(encoding="utf-8").splitlines()
    try:
        start = lines.index("# Common requirements") + 1
        end = lines.index("# Auxiliary packages for development")
    except ValueError as error:
        raise RuntimeError(
            "CredSweeper requirements.txt no longer exposes the runtime dependency section"
        ) from error
    runtime = [line.rstrip() for line in lines[start:end]]
    while runtime and not runtime[-1]:
        runtime.pop()
    temporary = destination.with_name(f".{destination.name}.pentect-update")
    temporary.write_text("\n".join(runtime) + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, destination)


def sync_sidecar_patch(repo: Path, tag: str) -> None:
    patch = repo / SIDECAR_PATCH
    text = patch.read_text(encoding="utf-8")
    replacement = f' __version__ = "{tag.removeprefix("v")}"'
    updated, count = re.subn(
        r'^ __version__ = "[0-9]+\.[0-9]+\.[0-9]+"$',
        replacement,
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise RuntimeError("CredSweeper sidecar patch has no unique version context")
    patch.write_text(updated, encoding="utf-8", newline="\n")
    run("git", "apply", "--check", str(patch.resolve()), cwd=repo / "crates/pentect-core/vendors/CredSweeper")


def sync_license_bundle(repo: Path) -> None:
    run(sys.executable, "tools/generate_licenses.py", cwd=repo)


def validate(repo: Path) -> None:
    run("cargo", "check", "-p", "pentect-core", cwd=repo)
    run("cargo", "test", "-p", "pentect-core", "migration_coverage_is_explicit", cwd=repo)
    run(
        "cargo",
        "test",
        "-p",
        "pentect-core",
        "translated_credsweeper_rules_are_active",
        cwd=repo,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "version",
        nargs="?",
        default="latest",
        help="semantic version tag such as v1.17.1 (default: latest)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="only report the installed and requested versions",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="sync without running the Rust compatibility checks",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(__file__).resolve().parents[1]
    submodule = repo / "crates/pentect-core/vendors/CredSweeper"
    assets = repo / "crates/pentect-core/vendors/credsweeper-assets"
    runtime_requirements = repo / "tools/credsweeper-sidecar/runtime-requirements.txt"
    if args.version == "latest":
        requested, requested_commit = remote_tag(repo)
    else:
        requested = args.version
        requested_commit = ""
    if not TAG_RE.fullmatch(requested):
        raise RuntimeError(f"invalid CredSweeper version: {requested!r}")
    if not requested_commit:
        _, requested_commit = remote_tag(repo, requested)

    if not args.check or not (submodule / ".git").exists():
        run(
            "git",
            "submodule",
            "update",
            "--init",
            "--",
            "crates/pentect-core/vendors/CredSweeper",
            cwd=repo,
        )
    installed, installed_commit = installed_release(submodule, assets)
    print(f"CredSweeper: installed={installed} requested={requested}")
    if args.check:
        return 0 if (installed, installed_commit) == (requested, requested_commit) else 2
    if run("git", "status", "--porcelain", cwd=submodule, capture=True):
        raise RuntimeError("CredSweeper submodule has local changes")

    run(
        "git",
        "fetch",
        "--force",
        "--depth=1",
        UPSTREAM,
        f"refs/tags/{requested}:refs/tags/{requested}",
        cwd=submodule,
    )
    run("git", "checkout", "--detach", requested, cwd=submodule)
    commit = run("git", "rev-parse", "HEAD", cwd=submodule, capture=True)
    sync_assets(submodule, assets, requested, commit)
    sync_runtime_requirements(submodule, runtime_requirements)
    sync_sidecar_patch(repo, requested)
    sync_license_bundle(repo)
    if not args.skip_validation:
        validate(repo)
    print(f"CredSweeper {requested} synced at {commit}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
