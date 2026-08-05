import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest


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
    def test_offsets_are_utf8_bytes(self) -> None:
        result = SERVER.inspect_text(Redactor(), "AéZ")
        self.assertEqual(
            result,
            {
                "schema": SERVER.SCHEMA,
                "spans": [{"start": 1, "end": 3, "label": "private_person"}],
            },
        )

    def test_out_of_range_offset_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SERVER._byte_offset("short", 6)


if __name__ == "__main__":
    unittest.main()
