import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SERVER_PATH = Path(__file__).parents[1] / "server.py"
SPEC = importlib.util.spec_from_file_location("pentect_opf_server", SERVER_PATH)
SERVER = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(SERVER)


class Redactor:
    def redact(self, _text: str) -> SimpleNamespace:
        span = SimpleNamespace(start=1, end=2, label="private_person")
        return SimpleNamespace(detected_spans=(span,), warning=None)


class ServerTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "symlink behavior is covered on POSIX")
    def test_managed_python_executes_through_venv_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            runtime = home / "runtime" / "python"
            runtime.parent.mkdir()
            runtime.touch()
            candidate = (
                home
                / ".pentect"
                / "openai-privacy-filter"
                / "venv"
                / "bin"
                / "python"
            )
            candidate.parent.mkdir(parents=True)
            candidate.symlink_to(runtime)

            with (
                mock.patch.object(SERVER.Path, "home", return_value=home),
                mock.patch.object(SERVER.sys, "executable", "/usr/bin/python3"),
                mock.patch.object(SERVER.os, "execv") as execv,
            ):
                SERVER._use_managed_python()

            executable, arguments = execv.call_args.args
            self.assertEqual(executable, str(candidate))
            self.assertEqual(arguments[0], str(candidate))

    def test_offsets_are_utf8_bytes(self) -> None:
        result = SERVER.inspect_text(Redactor(), "AéZ")
        self.assertEqual(
            result,
            [{
                "start": 1,
                "end": 3,
                "label": "PRIVATE_PERSON",
                "category": "pii",
                "confidence": "medium",
            }],
        )

    def test_out_of_range_offset_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SERVER._byte_offset("short", 6)

    def test_device_comes_from_persisted_setup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "setup.json").write_text('{"device":"cuda"}', encoding="utf-8")
            with mock.patch.dict(os.environ, {"PENTECT_OPF_ROOT": str(root)}):
                self.assertEqual(SERVER._selected_device("auto"), "cuda")
                self.assertEqual(SERVER._selected_device("cpu"), "cpu")

    def test_missing_setup_state_fails_safe_to_cpu(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PENTECT_OPF_ROOT": directory}):
                self.assertEqual(SERVER._selected_device("auto"), "cpu")

    def test_command_protocol_response_matches_request(self) -> None:
        result = SERVER.handle_request(
            Redactor(),
            {
                "schema": SERVER.PROTOCOL_SCHEMA,
                "id": 7,
                "hook": "inspect",
                "payload": {"kind": "text", "text": "AéZ"},
                "metadata": None,
            },
        )
        self.assertEqual(result["id"], 7)
        self.assertEqual(result["type"], "result")
        self.assertEqual(result["action"], "next")
        self.assertEqual(len(result["spans"]), 1)


if __name__ == "__main__":
    unittest.main()
