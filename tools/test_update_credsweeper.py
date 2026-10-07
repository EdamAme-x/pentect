from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from tools.update_credsweeper import DETECTOR_DOCS, SIDECAR_PATCH, sync_detector_docs, sync_sidecar_patch


class SidecarPatchTests(unittest.TestCase):
    def test_patch_applies_to_pinned_sources_and_new_import_context(self) -> None:
        repo = Path(__file__).resolve().parents[1]
        vendor = repo / "crates/pentect-core/vendors/CredSweeper"
        if not (vendor / "credsweeper/app.py").is_file():
            self.skipTest("CredSweeper submodule is not initialized")
        patch = (repo / SIDECAR_PATCH).read_text(encoding="utf-8")
        # Test a clean copy: never patch the working submodule.
        paths = re.findall(r"^--- a/(.+)$", patch, re.MULTILINE)
        version = re.search(r'^__version__ = "([^"]+)"',
            (vendor / "credsweeper/__init__.py").read_text(encoding="utf-8"), re.MULTILINE).group(1)
        for case in ("pinned", "changed_context", "changed_semantics"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "crates/pentect-core/vendors/CredSweeper"
                source.mkdir(parents=True)
                subprocess.run(["git", "init", "--quiet", str(source)], check=True)
                for name in paths:
                    content = (vendor / name).read_text(encoding="utf-8")
                    if case == "changed_context":
                        if name == "credsweeper/app.py":
                            content = content.replace("from credsweeper.scanner.scanner import Scanner",
                                "from credsweeper.logger.logger import SILENCE, TRACE\n"
                                "from credsweeper.scanner.scanner import Scanner")
                        elif name == "credsweeper/logger/logger.py":
                            content = content.replace("\n\nclass Logger:",
                                "\nTRACE = 5\nSILENCE = 60\n\nclass Logger:")
                        elif name == "credsweeper/scanner/scanner.py":
                            content = content.replace("Generator, Set", "Generator")
                    if case == "changed_semantics" and name == "credsweeper/app.py":
                        content = content.replace("APP_PATH = Path(__file__).resolve().parent",
                            "APP_PATH = Path(__file__).resolve().parent.parent")
                    target = source / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(content, encoding="utf-8", newline="\n")
                target_patch = root / SIDECAR_PATCH
                target_patch.parent.mkdir(parents=True)
                target_patch.write_text(patch, encoding="utf-8", newline="\n")
                if case == "changed_semantics":
                    with self.assertRaises(subprocess.CalledProcessError):
                        sync_sidecar_patch(root, f"v{version}")
                else:
                    sync_sidecar_patch(root, f"v{version}")



class SyncDetectorDocsTests(unittest.TestCase):
    def test_replaces_the_unique_pinned_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            path = repo / DETECTOR_DOCS
            path.parent.mkdir(parents=True)
            path.write_text(
                "before Samsung CredSweeper `v1.17.4`, commit "
                "`c7ad63b95ce0941954465a3b759046b14b88807b`; after\n",
                encoding="utf-8",
            )

            sync_detector_docs(repo, "v1.18.1", "a" * 40)

            self.assertEqual(
                path.read_text(encoding="utf-8"),
                f"before Samsung CredSweeper `v1.18.1`, commit `{'a' * 40}`; after\n",
            )

    def test_rejects_missing_source_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            path = repo / DETECTOR_DOCS
            path.parent.mkdir(parents=True)
            path.write_text("no pinned source here\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "no unique CredSweeper"):
                sync_detector_docs(repo, "v1.18.1", "a" * 40)


if __name__ == "__main__":
    unittest.main()
