import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("gliner_bridge", Path(__file__).parents[1] / "server.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class BridgeTests(unittest.TestCase):
    def test_utf8(self):
        spans = bridge.convert("🙂山田さん", [{"start": 1, "end": 3, "text": "山田", "label": "name"}])
        self.assertEqual(spans[0]["start"], 4)
        self.assertEqual(spans[0]["end"], 10)
        self.assertEqual(spans[0]["category"], "pii")
        self.assertNotIn("text", spans[0])

    def test_invalid_spans(self):
        for start, end, text in [(True, 2, "ab"), (-1, 2, "ab"), (0, 3, "abc"), (0, 1, "b"), (1, 1, "")]:
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                bridge.convert("ab", [{"start": start, "end": end, "text": text, "label": "name"}])

    def test_unknown_label(self):
        with self.assertRaises(KeyError):
            bridge.convert("ab", [{"start": 0, "end": 2, "text": "ab", "label": "unknown"}])

    def test_protocol_validation(self):
        class Fake:
            def inspect(self, text):
                return []
        request = {"schema": bridge.SCHEMA, "hook": "inspect", "id": 1, "payload": {"text": "safe"}}
        self.assertEqual(bridge.handle(Fake(), request)["spans"], [])
        with self.assertRaises(ValueError):
            bridge.handle(Fake(), dict(request, id=True))


if __name__ == "__main__":
    unittest.main()
