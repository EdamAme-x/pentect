from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.verify_credsweeper_evidence import verify


ROOT = Path(__file__).resolve().parent.parent


class VerifyCredSweeperEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "SOURCE.json"
        self.snapshot = self.root / "snapshot.json"
        self.evidence = self.root / "evidence.json"
        self.write(self.source, {"version": "v1.2.3", "commit": "b" * 40})
        self.write(self.snapshot, {"1" * 64: "https://example.test/repository"})
        self.valid = {
            "schema": 3,
            "generated_at": "2026-08-30T00:00:00Z",
            "pentect": {"commit": "a" * 40, "ref": "v9.8.7"},
            "reference": {
                "name": "CredSweeper",
                "version": "v1.2.3",
                "commit": "b" * 40,
            },
            "corpus": {
                "name": "CredData",
                "commit": "c" * 40,
                "repositories": 1,
                "metadata_files": 2,
            },
            "environment": {"os": "Linux", "architecture": "X64"},
            "workflow_run": "https://github.com/example/project/actions/runs/123",
            "gates": {
                "full_creddata_parity": True,
                "full_filter_inventory_parity": True,
                "whole_pipeline_fixtures": True,
            },
            "shards": 16,
            "repositories": 1,
            "metadata_files": 2,
            "credsweeper_version": "v1.2.3",
            "ml_probability_max_delta": 0.00001,
            "ml_probability_tolerance": 0.0001,
            "ml_probability_within_tolerance": True,
            "rust": 1,
            "oracle": 1,
            "common": 1,
            "missing": 0,
            "extra": 0,
            "by_rule": {
                "Test Rule": {
                    "rust": 1,
                    "oracle": 1,
                    "common": 1,
                    "missing": 0,
                    "extra": 0,
                }
            },
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_accepts_exact_release_evidence(self) -> None:
        self.write(self.evidence, self.valid)
        self.verify()

    def test_rejects_a_different_release_commit(self) -> None:
        self.write(self.evidence, self.valid)
        with self.assertRaisesRegex(SystemExit, "commit or ref"):
            verify(
                self.evidence,
                self.source,
                self.snapshot,
                pentect_commit="d" * 40,
                tested_ref="v9.8.7",
                creddata_commit="c" * 40,
            )

    def test_rejects_a_rule_gap(self) -> None:
        self.valid["by_rule"]["Test Rule"]["missing"] = 1
        self.write(self.evidence, self.valid)
        with self.assertRaisesRegex(SystemExit, "differ for rule"):
            self.verify()

    def test_rejects_unapproved_fields_that_could_contain_values(self) -> None:
        self.valid["examples"] = ["not-safe-for-release"]
        self.write(self.evidence, self.valid)
        with self.assertRaisesRegex(SystemExit, "unapproved data"):
            self.verify()

    def test_release_workflow_requires_and_publishes_exact_commit_evidence(self) -> None:
        regression = (ROOT / ".github/workflows/credsweeper-regression.yml").read_text(
            encoding="utf-8"
        )
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        guard = (ROOT / ".github/workflows/release-guard.yml").read_text(encoding="utf-8")
        self.assertIn("sync_latest:", regression)
        self.assertIn("name: credsweeper-compatibility-evidence", regression)
        self.assertIn("-f sync_latest=false", release)
        self.assertIn(
            "needs: [build, compatibility-cli, package-deb, credsweeper-evidence]",
            release,
        )
        self.assertIn("name: credsweeper-compatibility-evidence", release)
        self.assertIn("pentect-credsweeper-compatibility.json", guard)

    def verify(self) -> None:
        verify(
            self.evidence,
            self.source,
            self.snapshot,
            pentect_commit="a" * 40,
            tested_ref="v9.8.7",
            creddata_commit="c" * 40,
        )

    @staticmethod
    def write(path: Path, value: object) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
