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

    def test_unknown_hooks_and_invalid_actions_are_rejected(self) -> None:
        source = StringIO("\n".join(json.dumps(request) for request in [
            {"schema": SCHEMA, "id": 13, "hook": "unknown", "payload": {}},
            {"schema": SCHEMA, "id": 14, "hook": "inspect", "payload": {}},
        ]) + "\n")
        output = StringIO()
        serve(lambda _request: {"action": "continue"}, source, output)
        for line in output.getvalue().splitlines():
            self.assertEqual(json.loads(line)["error"]["code"], "handler_error")

    def test_serialization_failures_become_protocol_errors(self) -> None:
        source = StringIO(json.dumps({
            "schema": SCHEMA,
            "id": 15,
            "hook": "inspect",
            "payload": {},
        }) + "\n")
        output = StringIO()
        serve(lambda _request: {"payload": {"not-json"}}, source, output)
        self.assertEqual(json.loads(output.getvalue())["error"]["code"], "handler_error")


if __name__ == "__main__":
    unittest.main()
