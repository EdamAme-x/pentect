#!/usr/bin/env python3
"""Verify release automation updates both AUR package metadata sets."""

from __future__ import annotations

import json
from pathlib import Path
import re
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

        bin_pkgbuild = test_root / "packaging/aur/pentect-bin/PKGBUILD"
        bin_srcinfo = test_root / "packaging/aur/pentect-bin/.SRCINFO"
        bin_pkgbuild_text = bin_pkgbuild.read_text(encoding="utf-8")
        bin_srcinfo_text = bin_srcinfo.read_text(encoding="utf-8")
        assert "pkgver=9.8.7\n" in bin_pkgbuild_text
        assert 'provides=("pentect=$pkgver")\n' in bin_pkgbuild_text
        assert "\tpkgver = 9.8.7\n" in bin_srcinfo_text
        assert "\tprovides = pentect=9.8.7\n" in bin_srcinfo_text

        git_pkgbuild = test_root / "packaging/aur/pentect-git/PKGBUILD"
        git_srcinfo = test_root / "packaging/aur/pentect-git/.SRCINFO"
        git_pkgbuild_text = git_pkgbuild.read_text(encoding="utf-8")
        git_srcinfo_text = git_srcinfo.read_text(encoding="utf-8")
        match = re.search(r"^pkgver=(.+)$", git_pkgbuild_text, re.MULTILINE)
        assert match is not None
        vcs_version = match.group(1)
        assert vcs_version != "9.8.7"
        assert re.fullmatch(
            r"(?:\d+\.\d+\.\d+\.r\d+\.g[0-9a-f]{7}|r\d+\.[0-9a-f]{7})",
            vcs_version,
        )
        assert f"\tpkgver = {vcs_version}\n" in git_srcinfo_text
        assert f"\tprovides = pentect={vcs_version}\n" in git_srcinfo_text
        assert "makedepends=('cargo' 'git' 'perl')\n" in git_pkgbuild_text
        assert "\tmakedepends = perl\n" in git_srcinfo_text

    release_workflow = (ROOT / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    for path in (
        "packaging/aur/pentect-bin/PKGBUILD",
        "packaging/aur/pentect-bin/.SRCINFO",
        "packaging/aur/pentect-git/PKGBUILD",
        "packaging/aur/pentect-git/.SRCINFO",
    ):
        assert path in release_workflow
    assert 'git diff --quiet -- "${metadata_paths[@]}"' in release_workflow
    assert 'git add "${metadata_paths[@]}"' in release_workflow
    assert "needs: package-metadata" in release_workflow
    assert "main_sha: ${{ steps.metadata.outputs.main_sha }}" in release_workflow
    assert "needs.package-metadata.outputs.main_sha" in release_workflow
    assert "sh tools/dispatch_package_site.sh" in release_workflow
    assert (
        '"$GITHUB_REPOSITORY" "$GITHUB_REF_NAME" "$GITHUB_SHA" "$MAIN_SHA"'
        in release_workflow
    )
    assert "actions/deploy-pages@" not in release_workflow
    assert (
        "run: |\n"
        "          sh tools/download_recent_stable_debs.sh debs 2\n"
        "          test -n \"$(find debs -name 'pentect_*.deb' -print -quit)\""
        in release_workflow
    )


if __name__ == "__main__":
    main()
