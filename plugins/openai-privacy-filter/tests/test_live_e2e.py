#!/usr/bin/env python3

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


LIVE_PATH = Path(__file__).with_name("live_e2e.py")
SPEC = importlib.util.spec_from_file_location("pentect_opf_live_e2e", LIVE_PATH)
assert SPEC is not None and SPEC.loader is not None
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)


class LiveE2ETests(unittest.TestCase):
    def test_protocol_probe_rejects_a_mismatched_response_id(self) -> None:
        response = '{"id":2,"spans":[]}'
        with self.assertRaisesRegex(RuntimeError, "mismatched protocol response ID"):
            LIVE._validate_protocol_response(response, 1)

    def test_protocol_probe_reuses_one_worker_for_two_requests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin = root / "plugin"
            plugin.mkdir()
            (plugin / "server.py").write_text(
                """\
import json
import os
import sys

served = 0
for line in sys.stdin:
    request = json.loads(line)
    served += 1
    response = {
        "schema": "pentect.plugin.v1",
        "id": request["id"],
        "pid": os.getpid(),
        "served": served,
        "spans": [
            {"start": 0, "end": 1, "label": "PRIVATE_EMAIL"},
            {"start": 2, "end": 3, "label": "PRIVATE_PHONE"},
        ],
    }
    print(json.dumps(response), flush=True)
""",
                encoding="utf-8",
            )
            responses = []
            startup, warm = LIVE.inspect_plugin_twice(
                plugin,
                root,
                os.environ.copy(),
                5.0,
                "cpu",
                responses.append,
            )
            self.assertGreaterEqual(startup, 0)
            self.assertGreaterEqual(warm, 0)
            self.assertEqual([response["served"] for response in responses], [1, 2])
            self.assertEqual(len({response["pid"] for response in responses}), 1)

    def test_child_failure_does_not_copy_captured_output(self) -> None:
        result = subprocess.CompletedProcess(
            ["fixture"],
            17,
            stdout=LIVE.SAMPLE,
            stderr=LIVE.CODEX_SAMPLE,
        )
        with self.assertRaisesRegex(RuntimeError, "exit code 17") as caught:
            LIVE.require_success(result, "fixture operation")
        message = str(caught.exception)
        for value in LIVE.fixture_plaintext():
            self.assertNotIn(value.decode(), message)

    def test_log_scan_rejects_fixture_plaintext_without_repeating_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = LIVE.fixture_plaintext()[0]
            (root / "pentect.log").write_bytes(b"prefix " + value + b" suffix")
            with self.assertRaisesRegex(RuntimeError, "contain fixture plaintext") as caught:
                LIVE.assert_value_free_logs({"PENTECT_LOG_DIR": directory})
            self.assertNotIn(value.decode(), str(caught.exception))

    def test_log_scan_accepts_handles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pentect.log").write_text(
                "<<PRIVATE_EMAIL_0123456789abcdef>>\n", encoding="utf-8"
            )
            LIVE.assert_value_free_logs({"PENTECT_LOG_DIR": directory})

    def test_log_scan_can_require_the_configured_directory(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "not configured"):
            LIVE.assert_value_free_logs({}, must_exist=True)
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            with self.assertRaisesRegex(RuntimeError, "is missing"):
                LIVE.assert_value_free_logs(
                    {"PENTECT_LOG_DIR": str(missing)}, must_exist=True
                )
            with self.assertRaisesRegex(RuntimeError, "contains no logs"):
                LIVE.assert_value_free_logs(
                    {"PENTECT_LOG_DIR": directory}, must_exist=True
                )


if __name__ == "__main__":
    unittest.main()
