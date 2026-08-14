#!/usr/bin/env python3
"""Generate the release third-party license bundle from Cargo metadata."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "THIRD_PARTY_LICENSES.txt"
RELEASE_PACKAGE = "pentect-cli"
LICENSE_NAMES = ("license", "copying", "notice", "copyright")
SPDX_OPERATORS = {"AND", "OR", "WITH"}
APPROVED_LICENSE_IDS = {
    "0BSD",
    "Apache-2.0",
    "BSD-1-Clause",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BlueOak-1.0.0",
    "BSL-1.0",
    "CC0-1.0",
    "ISC",
    "LGPL-2.1-or-later",
    "LLVM-exception",
    "MIT",
    "MPL-2.0",
    "Unicode-3.0",
    "Unlicense",
    "Zlib",
}
REVIEW_EXCEPTIONS = {
    ("dyn-eq", "MPL-2.0"),
}


def cargo_metadata() -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return json.loads(result.stdout)


def release_dependencies(metadata: dict) -> list[dict]:
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = [
        package["id"]
        for package in metadata["packages"]
        if package["name"] == RELEASE_PACKAGE
        and package["id"] in metadata["workspace_members"]
    ]
    if len(roots) != 1:
        raise RuntimeError(f"expected one {RELEASE_PACKAGE} workspace package")

    visited: set[str] = set()
    queue = deque(roots)
    while queue:
        package_id = queue.popleft()
        if package_id in visited:
            continue
        visited.add(package_id)
        for dependency in nodes[package_id]["deps"]:
            if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"]):
                queue.append(dependency["pkg"])

    workspace = set(metadata["workspace_members"])
    return sorted(
        (packages[package_id] for package_id in visited - workspace),
        key=lambda package: (package["name"].casefold(), package["version"]),
    )


def validate_license_policy(packages: list[dict]) -> None:
    failures: list[str] = []
    for package in packages:
        expression = package.get("license") or ""
        if not expression:
            failures.append(f"{package['name']} {package['version']}: no license declaration")
            continue
        identifiers = set(re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", expression)) - SPDX_OPERATORS
        unknown = identifiers - APPROVED_LICENSE_IDS
        if unknown:
            failures.append(
                f"{package['name']} {package['version']}: unknown license identifiers "
                + ", ".join(sorted(unknown))
            )
            continue
        weak_copyleft = identifiers & {"LGPL-2.1-or-later", "MPL-2.0"}
        if not weak_copyleft or (package["name"], expression) in REVIEW_EXCEPTIONS:
            continue
        # A disjunctive permissive option is selected for packages such as
        # r-efi (`MIT OR Apache-2.0 OR LGPL-2.1-or-later`).
        if " OR " in expression and ("MIT" in expression or "Apache-2.0" in expression):
            continue
        failures.append(
            f"{package['name']} {package['version']}: {expression} requires explicit review"
        )
    if failures:
        raise RuntimeError("unapproved release licenses:\n" + "\n".join(failures))


def license_files(package: dict) -> list[Path]:
    package_root = Path(package["manifest_path"]).parent
    paths: list[Path] = []
    declared = package.get("license_file")
    if declared:
        path = package_root / declared
        if path.is_file():
            paths.append(path)
    for path in sorted(package_root.iterdir(), key=lambda item: item.name.casefold()):
        if path.is_file() and path.name.casefold().startswith(LICENSE_NAMES):
            paths.append(path)
    return list(dict.fromkeys(path.resolve() for path in paths))


def read_text(path: Path) -> str:
    return path.read_bytes().decode("utf-8", errors="replace").replace("\r\n", "\n").strip()


def mit_fallback_text() -> str:
    project_license = read_text(ROOT / "LICENSE")
    grant = "Permission is hereby granted"
    if grant not in project_license:
        raise RuntimeError("project MIT license template is malformed")
    return (
        "MIT License\n\n"
        "The package did not include a separate copyright notice; see its "
        "author and source metadata above.\n\n"
        + project_license[project_license.index(grant) :]
    )


def fallback_license_document(package: dict) -> str:
    expression = package.get("license") or ""
    authors = ", ".join(package.get("authors") or []) or "Not declared in Cargo metadata"
    source = package.get("repository") or package.get("homepage") or "https://crates.io/"
    prefix = "\n".join(
        [
            f"Package: {package['name']} {package['version']}",
            f"Authors: {authors}",
            f"Source: {source}",
            f"Declared license expression: {expression}",
            "",
        ]
    )
    if " AND " in expression:
        raise RuntimeError(
            f"{package['name']} {package['version']} has no packaged license file "
            f"for compound expression {expression!r}"
        )
    # Cargo historically used `MIT/Apache-2.0` for the same disjunctive choice
    # that modern SPDX writes as `MIT OR Apache-2.0`.
    choices = [choice.strip(" ()") for choice in re.split(r"\s+OR\s+|/", expression)]
    if "MIT" in choices:
        return prefix + mit_fallback_text()
    if "Apache-2.0" in choices:
        return prefix + read_text(ROOT / "research/pii-ner/LICENSE-APACHE-2.0.txt")
    if expression == "CC0-1.0":
        return prefix + (
            "This package is dedicated under Creative Commons CC0 1.0 Universal.\n"
            "Legal code: https://creativecommons.org/publicdomain/zero/1.0/legalcode"
        )
    raise RuntimeError(
        f"{package['name']} {package['version']} has no packaged license file "
        f"and no supported fallback for {expression!r}"
    )


def generate() -> str:
    packages = release_dependencies(cargo_metadata())
    validate_license_policy(packages)
    documents: dict[str, str] = {}
    document_packages: dict[str, set[str]] = defaultdict(set)

    for package in packages:
        label = f"{package['name']} {package['version']} ({package.get('license') or 'UNDECLARED'})"
        paths = license_files(package)
        if not paths:
            content = fallback_license_document(package)
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            documents[digest] = content
            document_packages[digest].add(label)
            continue
        for path in paths:
            content = read_text(path)
            if not content:
                continue
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            documents[digest] = content
            document_packages[digest].add(label)

    credsweeper_source = json.loads(
        (ROOT / "crates/pentect-core/vendors/credsweeper-assets/SOURCE.json").read_text(
            encoding="utf-8"
        )
    )
    credsweeper_version = credsweeper_source["version"]
    credsweeper_commit = credsweeper_source["commit"]

    bundled_documents = [
        (
            f"CredSweeper {credsweeper_version} detection assets (MIT)",
            ROOT / "crates/pentect-core/vendors/credsweeper-assets/LICENSE",
        ),
        (
            "Ocrs bundled RTen models (CC-BY-SA-4.0 attribution)",
            ROOT / "crates/pentect-runtime/assets/ocr/NOTICE.txt",
        ),
    ]
    for label, path in bundled_documents:
        content = read_text(path)
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        documents[digest] = content
        document_packages[digest].add(label)

    lines = [
        "PENTECT THIRD-PARTY LICENSES AND ATTRIBUTIONS",
        "================================================",
        "",
        "Generated by tools/generate_licenses.py from the locked release dependency graph.",
        "Do not edit this file manually.",
        "",
        "BUNDLED DATA AND MODELS",
        "-----------------------",
        "",
        "CredSweeper detection assets",
        "Source: https://github.com/Samsung/CredSweeper",
        f"Version: {credsweeper_version} (commit {credsweeper_commit})",
        "Copyright (c) 2021 SAMSUNG",
        "License: MIT. The full MIT text appears below in the Cargo license documents.",
        "",
        "Ocrs RTen text detection and recognition models",
        "Creator and source: Robert Knight, https://huggingface.co/robertknight/ocrs",
        "License: Creative Commons Attribution-ShareAlike 4.0 International",
        "License URI: https://creativecommons.org/licenses/by-sa/4.0/",
        "Changes: The distributed RTen model files are unmodified upstream model artifacts.",
        "The models remain licensed separately under CC BY-SA 4.0; Pentect code is MIT licensed.",
        "",
        "MPL SOURCE AVAILABILITY",
        "-----------------------",
        "",
        "dyn-eq 0.1.3 is distributed under MPL-2.0 and is included through tract-onnx.",
        "Its source is available at https://github.com/Rayzeq/dyn-eq and in the Cargo registry.",
        "Any Pentect modifications to MPL-covered files would be published under MPL-2.0.",
        "Pentect currently uses the upstream crate without source modifications.",
        "",
        "CARGO PACKAGES",
        "--------------",
        "",
        f"{len(packages)} non-workspace release dependency packages are covered below.",
        "Package labels show the license expression declared in Cargo metadata.",
        "",
    ]

    ordered_documents = sorted(
        documents,
        key=lambda digest: sorted(document_packages[digest], key=str.casefold)[0].casefold(),
    )
    for index, digest in enumerate(ordered_documents, start=1):
        labels = sorted(document_packages[digest], key=str.casefold)
        lines.extend(
            [
                f"DOCUMENT {index}",
                "~" * (9 + len(str(index))),
                "Applies to:",
                *(f"- {label}" for label in labels),
                "",
                documents[digest],
                "",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    generated = generate()
    if sys.argv[1:] == ["--check"]:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else ""
        if current.replace("\r\n", "\n") != generated:
            raise SystemExit(
                "THIRD_PARTY_LICENSES.txt is stale; run `python tools/generate_licenses.py`"
            )
        return
    if sys.argv[1:]:
        raise SystemExit("usage: python tools/generate_licenses.py [--check]")
    OUTPUT.write_text(generated, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
