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
                mock.patch.dict(SERVER.os.environ, {"PENTECT_OPF_ROOT": ""}),
                mock.patch.object(SERVER.Path, "home", return_value=home),
                mock.patch.object(SERVER.sys, "executable", "/usr/bin/python3"),
                mock.patch.object(SERVER.sys, "prefix", "/usr"),
                mock.patch.object(SERVER.os, "execv") as execv,
            ):
                SERVER._use_managed_python()

            executable, arguments = execv.call_args.args
            self.assertEqual(executable, str(candidate))
            self.assertEqual(arguments[0], str(candidate))

    def test_managed_python_does_not_reexec_inside_venv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / ".pentect" / "openai-privacy-filter" / "venv"
            candidate = root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            candidate.parent.mkdir(parents=True)
            candidate.touch()
            with (
                mock.patch.dict(SERVER.os.environ, {"PENTECT_OPF_ROOT": ""}),
                mock.patch.object(SERVER.Path, "home", return_value=Path(directory)),
                mock.patch.object(SERVER.sys, "prefix", str(root)),
                mock.patch.object(SERVER.os, "execv") as execv,
            ):
                SERVER._use_managed_python()
            execv.assert_not_called()

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

    def test_fixture_setup_state_is_rejected_at_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "setup.json").write_text(
                '{"device":"cpu","fixture":true}', encoding="utf-8"
            )
            with mock.patch.dict(os.environ, {"PENTECT_OPF_ROOT": str(root)}):
                with self.assertRaisesRegex(RuntimeError, "fixture setup"):
                    SERVER._selected_device("auto")

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

    def test_cpu_runtime_uses_bounded_moe_batches(self) -> None:
        mlps = [SimpleNamespace(torch_ops_batch=None) for _ in range(2)]
        runtime = SimpleNamespace(
            model=SimpleNamespace(
                block=[SimpleNamespace(mlp=mlp) for mlp in mlps]
            )
        )
        redactor = mock.Mock()
        redactor.get_runtime.return_value = runtime

        with mock.patch.dict(os.environ, {}, clear=True):
            result = SERVER.configure_runtime(redactor, "cpu")

        self.assertIs(result, runtime)
        self.assertEqual(
            [mlp.torch_ops_batch for mlp in mlps],
            [SERVER.DEFAULT_CPU_MOE_BATCH_SIZE] * 2,
        )

    def test_cpu_batch_override_can_disable_chunking(self) -> None:
        mlp = SimpleNamespace(torch_ops_batch=32)
        runtime = SimpleNamespace(
            model=SimpleNamespace(block=[SimpleNamespace(mlp=mlp)])
        )
        redactor = mock.Mock()
        redactor.get_runtime.return_value = runtime

        with mock.patch.dict(
            os.environ, {"PENTECT_OPF_CPU_MOE_BATCH_SIZE": "0"}, clear=True
        ):
            SERVER.configure_runtime(redactor, "cpu")

        self.assertEqual(mlp.torch_ops_batch, 32)

    def test_gpu_runtime_is_not_modified(self) -> None:
        mlp = SimpleNamespace(torch_ops_batch=32)
        runtime = SimpleNamespace(
            model=SimpleNamespace(block=[SimpleNamespace(mlp=mlp)])
        )
        redactor = mock.Mock()
        redactor.get_runtime.return_value = runtime

        SERVER.configure_runtime(redactor, "cuda")

        self.assertEqual(mlp.torch_ops_batch, 32)

    def test_invalid_cpu_batch_override_is_rejected(self) -> None:
        with mock.patch.dict(
            os.environ, {"PENTECT_OPF_CPU_MOE_BATCH_SIZE": "many"}, clear=True
        ):
            with self.assertRaisesRegex(ValueError, "non-negative integer"):
                SERVER._cpu_moe_batch_size()


if __name__ == "__main__":
    unittest.main()
