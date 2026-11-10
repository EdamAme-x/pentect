"""Offline checks for live benchmark scoring and credential loading."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark_live_defense import load_key, summarize  # noqa: E402


class BenchmarkTests(unittest.TestCase):
    def test_summary_keeps_leakage_and_utility_separate(self) -> None:
        rows = [
            {"scenario": "file", "arm": "baseline", "provider_ok": True,
             "task_completed": True, "secret_exposed_requests": 2, "seconds": 4.0},
            {"scenario": "file", "arm": "pentect", "provider_ok": True,
             "task_completed": False, "secret_exposed_requests": 0, "seconds": 5.0},
        ]
        result = summarize(rows)["file"]
        self.assertEqual(result["baseline"]["runs_exposed"], 1)
        self.assertEqual(result["pentect"]["runs_exposed"], 0)
        self.assertEqual(result["pentect"]["task_completed"], 0)
        self.assertEqual(result["pentect"]["median_seconds"], 5.0)

    def test_auth_key_is_loaded_without_being_added_to_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.json"
            path.write_text(json.dumps({"openrouter": {"key": "synthetic-key"}}))
            args = argparse.Namespace(key_env="UNSET_BENCHMARK_TEST_KEY", auth_file=path)
            self.assertEqual(load_key(args), "synthetic-key")


if __name__ == "__main__":
    unittest.main()
