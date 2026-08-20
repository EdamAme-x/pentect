#!/usr/bin/env python3
"""Install the portable client matrix, selecting an actually downloadable Codex."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request


ALLOW_SCRIPTS = (
    "@anthropic-ai/claude-code,cline,opencode-ai,@github/keytar,node-pty,"
    "@google/genai,protobufjs"
)

LATEST_CLIENTS = (
    "@anthropic-ai/claude-code@latest",
    "opencode-ai@latest",
    "@earendil-works/pi-coding-agent@latest",
    "@continuedev/cli@latest",
    "cline@latest",
    "@google/gemini-cli@latest",
)

RELEASE_CLIENTS = (
    "@anthropic-ai/claude-code@2.1.237",
    "opencode-ai@1.18.19",
    "@earendil-works/pi-coding-agent@0.84.2",
    "@continuedev/cli@1.5.47",
    "cline@3.0.55",
    "@google/gemini-cli@0.56.0",
)


def npm_command(*args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    npm = shutil.which("npm")
    if not npm:
        raise RuntimeError("npm is not on PATH")
    command = [npm, *args]
    if os.name == "nt" and npm.lower().endswith((".cmd", ".bat")):
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", *command]
    return subprocess.run(
        command,
        check=True,
        text=True,
        capture_output=capture,
    )


def codex_platform_suffix() -> str | None:
    operating_system = {
        "linux": "linux",
        "darwin": "darwin",
        "win32": "win32",
    }.get(sys.platform)
    architecture = {
        "x86_64": "x64",
        "amd64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine().lower())
    if operating_system and architecture:
        return f"{operating_system}-{architecture}"
    return None


def tarball_exists(url: str) -> bool:
    request = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError):
        return False


def latest_installable_codex() -> str:
    suffix = codex_platform_suffix()
    if suffix is None:
        return "@openai/codex@latest"

    raw_versions = npm_command(
        "view", "@openai/codex", "versions", "--json", capture=True
    ).stdout
    versions = json.loads(raw_versions)
    stable = [
        version
        for version in versions
        if re.fullmatch(r"\d+\.\d+\.\d+", version)
    ]
    stable.sort(key=lambda value: tuple(map(int, value.split("."))), reverse=True)

    for version in stable[:20]:
        variant = f"@openai/codex@{version}-{suffix}"
        try:
            tarball = npm_command("view", variant, "dist.tarball", capture=True).stdout.strip()
        except subprocess.CalledProcessError:
            continue
        if tarball and tarball_exists(tarball):
            newest = stable[0] if stable else version
            if version != newest:
                print(
                    f"Codex {newest} is published incompletely for {suffix}; "
                    f"using newest downloadable {version}",
                    file=sys.stderr,
                )
            return f"@openai/codex@{version}"
    raise RuntimeError(f"no downloadable Codex build found for {suffix}")


def install(specification: str) -> None:
    print(f"Installing {specification}", flush=True)
    npm_command(
        "install",
        "--global",
        "--include=optional",
        f"--allow-scripts={ALLOW_SCRIPTS}",
        specification,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("latest", "release"), default="latest")
    parser.add_argument("--only", choices=("codex",), help=argparse.SUPPRESS)
    args = parser.parse_args()

    codex = latest_installable_codex() if args.mode == "latest" else "@openai/codex@0.148.0"
    install(codex)
    if args.only != "codex":
        for client in LATEST_CLIENTS if args.mode == "latest" else RELEASE_CLIENTS:
            install(client)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"portable client installation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
