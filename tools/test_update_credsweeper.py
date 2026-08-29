from pathlib import Path
import tempfile
import unittest

from tools.update_credsweeper import DETECTOR_DOCS, sync_detector_docs


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
