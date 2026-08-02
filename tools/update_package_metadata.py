#!/usr/bin/env python3
"""Generate Homebrew and Nix metadata from a verified GitHub Release."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.parse
from pathlib import Path

REPOSITORY = "EdamAme-x/pentect"
ASSETS = {
    "x86_64-linux": "pentect-linux-x86_64",
    "aarch64-linux": "pentect-linux-aarch64",
    "x86_64-darwin": "pentect-macos-x86_64",
    "aarch64-darwin": "pentect-macos-aarch64",
}
VERSION_RE = re.compile(r"^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def request(url: str, *, authenticated: bool = False) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError("package metadata requests require an HTTPS URL")
    if authenticated and parsed.hostname != "api.github.com":
        raise RuntimeError("authenticated package metadata requests require api.github.com")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "pentect-package-metadata",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    request = urllib.request.Request(url, headers=headers)
    if authenticated and (token := os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")):
        # Unredirected headers are not copied to GitHub's release-asset CDN.
        request.add_unredirected_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def release_metadata(tag: str | None) -> dict[str, object]:
    endpoint = "latest" if tag is None else f"tags/{tag}"
    release = json.loads(
        request(
            f"https://api.github.com/repos/{REPOSITORY}/releases/{endpoint}",
            authenticated=True,
        )
    )
    if release.get("draft") or release.get("prerelease"):
        raise SystemExit("refusing to package a draft or prerelease")
    match = VERSION_RE.fullmatch(str(release.get("tag_name", "")))
    if not match:
        raise SystemExit(f"invalid release tag: {release.get('tag_name')}")
    assets = {asset["name"]: asset for asset in release.get("assets", [])}
    systems: dict[str, dict[str, str]] = {}
    for system, name in ASSETS.items():
        asset = assets.get(name)
        if asset is None:
            if system == "aarch64-linux":
                continue
            raise SystemExit(f"release is missing {name}")
        digest = str(asset.get("digest") or "")
        sha256 = digest.removeprefix("sha256:")
        if not SHA256_RE.fullmatch(sha256):
            checksum = assets.get(f"{name}.sha256")
            if checksum is None:
                raise SystemExit(f"release is missing a digest for {name}")
            value = request(checksum["browser_download_url"]).decode("ascii").split()[0].lower()
            if not SHA256_RE.fullmatch(value):
                raise SystemExit(f"release has an invalid digest for {name}")
            sha256 = value
        systems[system] = {
            "asset": name,
            "url": asset["browser_download_url"],
            "sha256": sha256,
        }
    return {"version": match.group(1), "tag": release["tag_name"], "systems": systems}


def ruby_platform_block(name: str, entries: dict[str, dict[str, str]]) -> list[str]:
    architecture = "darwin" if name == "macos" else "linux"
    arm = entries.get(f"aarch64-{architecture}")
    intel = entries.get(f"x86_64-{architecture}")
    if not arm and not intel:
        return []
    lines = [f"  on_{name} do"]
    if arm:
        lines.extend(
            [
                "    on_arm do",
                f'      url "{arm["url"]}"',
                f'      sha256 "{arm["sha256"]}"',
                "    end",
            ]
        )
    if intel:
        lines.extend(
            [
                "    on_intel do",
                f'      url "{intel["url"]}"',
                f'      sha256 "{intel["sha256"]}"',
                "    end",
            ]
        )
    lines.append("  end")
    return lines


def homebrew_formula(metadata: dict[str, object]) -> str:
    systems = metadata["systems"]
    assert isinstance(systems, dict)
    lines = [
        "class Pentect < Formula",
        '  desc "Local secret masking boundary for AI agents"',
        '  homepage "https://github.com/EdamAme-x/pentect"',
        f'  version "{metadata["version"]}"',
        '  license "MIT"',
        "",
    ]
    lines.extend(ruby_platform_block("macos", systems))
    lines.append("")
    lines.extend(ruby_platform_block("linux", systems))
    lines.extend(
        [
            "",
            "  def install",
            '    binary = Dir["pentect-*"].first',
            '    bin.install binary => "pentect"',
            '    (bin/".pentect-managed-install.json").write <<~JSON',
            '      {"version":1,"manager":"homebrew","update":"brew upgrade EdamAme-x/pentect/pentect","uninstall":"brew uninstall EdamAme-x/pentect/pentect"}',
            "    JSON",
            "  end",
            "",
            "  test do",
            '    assert_match version.to_s, shell_output("#{bin}/pentect version")',
            "  end",
            "end",
            "",
        ]
    )
    return "\n".join(lines)


def serialized(metadata: dict[str, object]) -> dict[Path, str]:
    root = Path(__file__).resolve().parent.parent
    return {
        root / "packaging" / "release.json": json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        root / "packaging" / "homebrew" / "Formula" / "pentect.rb": homebrew_formula(metadata),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag")
    parser.add_argument("--metadata-file", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.tag and args.metadata_file:
        parser.error("--tag and --metadata-file cannot be combined")
    metadata = (
        json.loads(args.metadata_file.read_text(encoding="utf-8"))
        if args.metadata_file
        else release_metadata(args.tag)
    )
    failed = False
    for path, content in serialized(metadata).items():
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                print(f"out of date: {path.relative_to(Path.cwd())}", file=sys.stderr)
                failed = True
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
            print(path.relative_to(Path.cwd()))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
