#!/usr/bin/env python3
"""Verify release automation updates both AUR package metadata sets."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    metadata = json.loads((ROOT / "packaging/release.json").read_text(encoding="utf-8"))
    metadata["version"] = "9.8.7"
    metadata["tag"] = "v9.8.7"

    with tempfile.TemporaryDirectory(prefix="pentect-package-metadata-") as temporary:
        test_root = Path(temporary)
        tools = test_root / "tools"
        tools.mkdir()
        shutil.copy2(ROOT / "tools/update_package_metadata.py", tools)
        metadata_file = test_root / "release-input.json"
        metadata_file.write_text(json.dumps(metadata), encoding="utf-8")

        subprocess.run(
            [
                sys.executable,
                str(tools / "update_package_metadata.py"),
                "--metadata-file",
                str(metadata_file),
            ],
            cwd=test_root,
            check=True,
            capture_output=True,
            text=True,
        )

        git_pkgbuild = test_root / "packaging/aur/pentect-git/PKGBUILD"
        git_srcinfo = test_root / "packaging/aur/pentect-git/.SRCINFO"
        assert "pkgver=9.8.7\n" in git_pkgbuild.read_text(encoding="utf-8")
        assert "\tpkgver = 9.8.7\n" in git_srcinfo.read_text(encoding="utf-8")
        assert "\tprovides = pentect=9.8.7\n" in git_srcinfo.read_text(encoding="utf-8")

    release_workflow = (ROOT / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    for path in (
        "packaging/aur/pentect-git/PKGBUILD",
        "packaging/aur/pentect-git/.SRCINFO",
    ):
        assert path in release_workflow
    assert 'git diff --quiet -- "${metadata_paths[@]}"' in release_workflow
    assert 'git add "${metadata_paths[@]}"' in release_workflow


if __name__ == "__main__":
    main()
