"""Value-free relay failure classification; never contacts a real provider."""
import io
import json
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from live_portable_client_e2e import Handler


class RelayTests(unittest.TestCase):
    def handler(self):
        raw = json.dumps({'model': 'fixture', 'messages': []}).encode()
        handler = object.__new__(Handler)
        handler.rfile = io.BytesIO(raw)
        handler.headers = {'Content-Length': str(len(raw))}
        handler.path = '/v1/chat/completions'
        handler.server = SimpleNamespace(records=[], failures=[], key='fixture-only',
                                         original_image='', lock=threading.Lock())
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.send_error = Mock()
        handler.wfile = Mock()
        return handler

    def run_response(self, handler):
        response = Mock(status=200, headers={'Content-Type': 'text/event-stream'})
        response.read1.side_effect = [b'data: [DONE]\n\n', b'']
        with patch('live_portable_client_e2e.urllib.request.urlopen') as open_url:
            open_url.return_value.__enter__.return_value = response
            handler.do_POST()

    def test_body_cancellation_is_not_an_upstream_failure(self):
        handler = self.handler()
        handler.wfile.write.side_effect = ConnectionAbortedError()
        self.run_response(handler)
        self.assertEqual(handler.server.failures, [])
        self.assertTrue(handler.server.records[0]['client_disconnected'])
        self.assertFalse(handler.server.records[0].get('response_complete', False))
        handler.send_error.assert_not_called()

    def test_header_cancellation_is_not_an_upstream_failure(self):
        handler = self.handler()
        handler.end_headers.side_effect = BrokenPipeError()
        self.run_response(handler)
        self.assertEqual(handler.server.failures, [])
        self.assertTrue(handler.server.records[0]['client_disconnected'])
        handler.send_error.assert_not_called()

    def test_completed_response_is_recorded(self):
        handler = self.handler()
        self.run_response(handler)
        self.assertEqual(handler.server.failures, [])
        self.assertTrue(handler.server.records[0]['response_complete'])
        self.assertEqual(handler.server.records[0]['response_chunks'], 1)

    def test_codex_and_claude_endpoints_are_forwarded_without_protocol_translation(self):
        for path, endpoint in [('/responses', 'responses'), ('/v1/responses', 'responses'),
                               ('/v1/messages?beta=true', 'messages')]:
            with self.subTest(path=path):
                handler = self.handler()
                handler.path = path
                response = Mock(status=200, headers={})
                response.read1.side_effect = [b'event: done\n\n', b'']
                with patch('live_portable_client_e2e.urllib.request.urlopen') as open_url:
                    open_url.return_value.__enter__.return_value = response
                    handler.do_POST()
                    request = open_url.call_args.args[0]
                self.assertEqual(request.full_url, 'https://openrouter.ai/api/v1/' + endpoint)
                self.assertEqual(json.loads(request.data), {'model': 'fixture', 'messages': []})
                self.assertTrue(handler.server.records[0]['response_complete'])

    def test_anthropic_base64_image_is_recognized(self):
        handler = self.handler()
        raw = json.dumps({'model': 'fixture', 'messages': [{'content': [{'type': 'image',
            'source': {'type': 'base64', 'media_type': 'image/png', 'data': 'fixture'}}]}]}).encode()
        handler.rfile = io.BytesIO(raw)
        handler.headers['Content-Length'] = str(len(raw))
        handler.path = '/v1/messages'
        self.run_response(handler)
        self.assertTrue(handler.server.records[0]['has_image'])

    def test_unsupported_endpoint_is_never_forwarded(self):
        handler = self.handler()
        handler.path = '/unexpected'
        with patch('live_portable_client_e2e.urllib.request.urlopen') as open_url:
            handler.do_POST()
            open_url.assert_not_called()
        self.assertEqual(handler.server.failures, ['unexpected-endpoint'])

    def test_upstream_timeout_remains_a_failure_when_client_disconnected(self):
        handler = self.handler()
        handler.send_error.side_effect = ConnectionResetError()
        with patch('live_portable_client_e2e.urllib.request.urlopen', side_effect=TimeoutError()):
            handler.do_POST()
        self.assertEqual(handler.server.failures, ['provider-transport'])
        self.assertFalse(handler.server.records[0].get('response_complete', False))


if __name__ == '__main__':
    unittest.main()
