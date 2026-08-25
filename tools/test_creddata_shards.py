from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools import creddata_shards


class CredDataShardsTest(unittest.TestCase):
    def test_prepare_and_summarize_cover_every_repository_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            source = workspace / "source"
            (source / "meta").mkdir(parents=True)
            snapshot = {
                f"{value:064x}": f"https://example.test/{value}"
                for value in range(1, 8)
            }
            self.write_json(source / "snapshot.json", snapshot)
            for repo_id in snapshot:
                (source / "meta" / f"{creddata_shards.short_id(repo_id)}.csv").write_text(
                    "header\n", encoding="utf-8"
                )

            artifacts = workspace / "artifacts"
            for index in range(3):
                shard_root = workspace / f"root-{index}"
                self.copy_dataset(source, shard_root)
                shard_artifact = artifacts / f"shard-{index}"
                creddata_shards.prepare(
                    shard_root,
                    index=index,
                    count=3,
                    manifest=shard_artifact / "manifest.json",
                    version="v1.2.3",
                )
                repository_count = len(
                    json.loads((shard_artifact / "manifest.json").read_text())["repositories"]
                )
                self.write_json(
                    shard_artifact / "report.json",
                    {
                        "rust": repository_count,
                        "oracle": repository_count,
                        "common": repository_count,
                        "missing": 0,
                        "extra": 0,
                        "ml_probability_within_tolerance": True,
                    },
                )

            output = workspace / "summary.json"
            creddata_shards.summarize(source, artifacts, count=3, output=output)
            summary = json.loads(output.read_text())
            self.assertEqual(summary["repositories"], len(snapshot))
            self.assertEqual(summary["shards"], 3)
            self.assertEqual(summary["credsweeper_version"], "v1.2.3")
            self.assertEqual(summary["missing"], 0)
            self.assertEqual(summary["extra"], 0)

    @staticmethod
    def copy_dataset(source: Path, destination: Path) -> None:
        (destination / "meta").mkdir(parents=True)
        (destination / "snapshot.json").write_bytes((source / "snapshot.json").read_bytes())
        for path in (source / "meta").glob("*.csv"):
            (destination / "meta" / path.name).write_bytes(path.read_bytes())

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
