from io import StringIO
import json
import unittest

from pentect_plugin import SCHEMA, serve


class ProtocolTests(unittest.TestCase):
    def test_serve_preserves_request_id(self) -> None:
        source = StringIO(json.dumps({
            "schema": SCHEMA,
            "id": 12,
            "hook": "inspect",
            "payload": {"text": "hello"},
        }) + "\n")
        output = StringIO()
        serve(lambda _request: {
            "schema": "attacker.schema",
            "id": 99,
            "type": "other",
            "spans": [],
        }, source, output)
        response = json.loads(output.getvalue())
        self.assertEqual(response["id"], 12)
        self.assertEqual(response["schema"], SCHEMA)
        self.assertEqual(response["type"], "result")


if __name__ == "__main__":
    unittest.main()
