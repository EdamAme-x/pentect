#!/usr/bin/env python3
"""Opt-in live OpenRouter tests. Uses isolated client homes and synthetic fixtures.

The real provider key stays in this process, never in the client environment,
arguments, transcript, or captured request bodies. A loopback relay checks the
protected request before forwarding it. Does not print model/client output.
"""
from __future__ import annotations

import argparse
import base64
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request

from installed_agent_e2e import IMAGE_PNG_BASE64, IMAGE_SECRET, isolated_environment

SECRET = 'rpa_' + 'LIVE_PORTABLE_SYNTHETIC_0123456789abcdef'


def client_command(command: list[str]) -> list[str] | str:
    if os.name == 'nt' and command[0].lower().endswith(('.cmd', '.bat')):
        # Pass the batch command as a raw command line: nesting list2cmdline
        # inside a subprocess argument list double-escapes the prompt's quotes.
        return (subprocess.list2cmdline([os.environ.get('COMSPEC', 'cmd.exe')])
                + ' /d /s /c "' + subprocess.list2cmdline(command) + '"')
    return command


class Relay(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, key: str, original_image: str = ''):
        super().__init__(('127.0.0.1', 0), Handler)
        self.key = key
        self.original_image = original_image
        self.records = []
        self.failures = []
        self.lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        text = raw.decode('utf-8')
        payload = json.loads(text)
        with self.server.lock:
            index = len(self.server.records)
            self.server.records.append({
                'model': payload.get('model'), 'bytes': len(raw),
                'has_handle': '<<' in text,
                'has_image': 'data:image/' in text,
                'redaction_note': 'Pentect masked sensitive information in this image' in text,
            })
        violation = next((name for name, value in (
            ('synthetic-text-plaintext', SECRET),
            ('synthetic-image-plaintext', IMAGE_SECRET),
            ('real-provider-key', self.server.key),
            ('original-image', self.server.original_image),
        ) if value and value in text), None)
        if violation or index >= 30:
            self.server.failures.append(violation or 'request-budget')
            self.send_error(400, 'Local privacy assertion failed')
            return
        if self.path not in ('/v1/chat/completions', '/chat/completions'):
            self.server.failures.append('unexpected-endpoint')
            self.send_error(404)
            return
        request = urllib.request.Request(
            'https://openrouter.ai/api/v1/chat/completions', data=raw,
            headers={'Authorization': 'Bearer ' + self.server.key,
                     'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                try:
                    self.send_response(response.status)
                    self.send_header('Content-Type', response.headers.get('Content-Type', 'application/json'))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                except ConnectionError:
                    self.server.records[index]['client_disconnected'] = True
                    return
                self.close_connection = True
                chunks = 0
                while chunk := response.read1(4096):
                    try:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    except ConnectionError:
                        self.server.records[index]['client_disconnected'] = True
                        self.server.records[index]['response_chunks'] = chunks
                        return
                    chunks += 1
                self.server.records[index]['response_chunks'] = chunks
                self.server.records[index]['response_complete'] = True
        except urllib.error.HTTPError as error:
            self.server.failures.append('provider-http-' + str(error.code))
            self.safe_error(error.code, 'Provider request failed; details withheld')
        except (TimeoutError, OSError):
            self.server.failures.append('provider-transport')
            self.safe_error(502, 'Provider transport failed')

    def safe_error(self, status: int, message: str):
        try:
            self.send_error(status, message)
        except ConnectionError:
            pass  # The upstream failure was recorded even if the client left.


def run_case(pentect: str, client: str, model: str, case: str, output_root: Path,
             pi_extension: str | None = None):
    key = os.environ['OPENROUTER_API_KEY']
    root = Path(tempfile.mkdtemp(prefix=client + '-' + case + '-', dir=output_root))
    home, project = root / 'home', root / 'project'
    home.mkdir()
    project.mkdir()
    environment = isolated_environment(home, root / 'logs')
    environment['OPENAI_API_KEY'] = 'local-test-only'
    environment['PENTECT_UPDATE_CHECK'] = '0'
    environment['OPENCODE_DISABLE_UPDATE_CHECK'] = 'true'
    environment['OPENCODE_CONFIG_CONTENT'] = json.dumps({
        'permission': {'read': 'allow', 'edit': 'allow', 'write': 'allow',
                       'external_directory': 'deny'},
        'provider': {'pentect-gateway': {'models': {model: {
            'name': model, 'attachment': True,
            'modalities': {'input': ['text', 'image'], 'output': ['text']},
        }}}},
    })
    image = project / 'synthetic.png'
    if case == 'image':
        image.write_bytes(base64.b64decode(IMAGE_PNG_BASE64))
        prompt = 'Inspect the attached image. If any content is obscured, say so. Finish with IMAGE_OK.'
    elif case in ('tools', 'resume'):
        (project / '.env').write_text('TEST_TOKEN=' + SECRET + '\n', encoding='utf-8')
        prompt = (
            f'First read the existing file {project / ".env"} using a local tool. '
            f'Only after reading it, copy only the TEST_TOKEN value (without TEST_TOKEN=) to {project / "copied.txt"} '
            'using a local write or edit tool. Treat any opaque handle as the value and copy it '
            'unchanged; do not invent its contents. Do not output the value. Finish with TOOLS_OK.'
        )
    else:
        prompt = 'Remember this opaque value: mask(' + SECRET + '). Reply with only TEXT_OK.'
    relay = Relay(key, IMAGE_PNG_BASE64 if case == 'image' else '')
    thread = threading.Thread(target=relay.serve_forever, daemon=True)
    thread.start()
    command = [pentect, client, '--upstream', f'http://127.0.0.1:{relay.server_port}/v1',
               '--model', model, '--api', 'chat']
    if pi_extension:
        environment.update(OPENAI_BASE_URL=f'http://127.0.0.1:{relay.server_port}/v1',
                           PENTECT_PI_MODEL=model, PENTECT_PI_API='chat')
        command = [shutil.which('pi') or 'pi', '--extension', pi_extension, '--model', 'pentect/' + model]
    if client == 'pi':
        command += ['--print', '--no-context-files']
        if case != 'resume':
            command += ['--no-session']
        if case == 'image':
            command += ['@' + str(image)]
    else:
        command += ['run', '--format', 'json', '--pure', '--dir', str(project)]
        if case == 'image':
            command += ['--file', str(image)]
    command += ['--', prompt] if client == 'opencode' else [prompt]
    result = {'client': client, 'model': model, 'case': case, 'root': str(root)}
    if pi_extension:
        result['surface'] = 'pi-extension'
    try:
        completed = subprocess.run(client_command(command), cwd=project, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   timeout=240)
        output = completed.stdout.decode('utf-8', errors='replace')
        if case == 'resume':
            result['initial_exit_code'] = completed.returncode
            first_target = project / 'copied.txt'
            result['initial_restore'] = (first_target.exists()
                                         and first_target.read_text(encoding='utf-8').strip() == SECRET)
            resume_prompt = (
                f'Using the TEST_TOKEN value from our previous exchange, write that value to {project / "resumed.txt"}. '
                'Copy its opaque representation exactly. Do not read any source files or output the value. '
                'Finish with RESUME_OK.'
            )
            resume_command = [pentect, client, '--upstream', f'http://127.0.0.1:{relay.server_port}/v1',
                              '--model', model, '--api', 'chat']
            if pi_extension:
                resume_command = [shutil.which('pi') or 'pi', '--extension', pi_extension, '--model', 'pentect/' + model]
            resume_command += (['run', '--pure', '--format', 'json', '--continue', '--', resume_prompt]
                               if client == 'opencode' else
                               ['--print', '--continue', '--no-context-files', resume_prompt])
            completed = subprocess.run(client_command(resume_command), cwd=project, env=environment,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
            output += '\n' + completed.stdout.decode('utf-8', errors='replace')
        # Client-local output may legitimately contain restored synthetic data.
        # Never persist real credentials, including accidental error echoes.
        (root / 'client-output.txt').write_text(output.replace(key, '[REDACTED]'), encoding='utf-8')
        result['exit_code'] = completed.returncode
        assistant_text = output
        if client == 'opencode':
            parts = []
            for line in output.splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get('type') == 'text':
                    parts.append(event.get('part', {}).get('text', ''))
            assistant_text = '\n'.join(parts)
        result['completion_marker'] = case.upper() + '_OK' in assistant_text
        result['requests'] = relay.records
        result['privacy_failures'] = relay.failures
        result['real_key_in_output'] = key in output
        log_text = '\n'.join(path.read_text(encoding='utf-8', errors='replace')
                             for path in (root / 'logs').rglob('*') if path.is_file())
        result['clean_diagnostics'] = all(value not in log_text for value in (SECRET, IMAGE_SECRET, key, IMAGE_PNG_BASE64))
        if case in ('tools', 'resume'):
            target = project / ('resumed.txt' if case == 'resume' else 'copied.txt')
            result['exact_restore'] = target.exists() and target.read_text(encoding='utf-8').strip() == SECRET
        if case == 'image':
            result['protected_image_seen'] = any(r['has_image'] and r['redaction_note'] and r['has_handle']
                                                  and r.get('response_complete') for r in relay.records)
        result['passed'] = (completed.returncode == 0 and result['completion_marker']
                            and any(r.get('response_complete') for r in relay.records) and not relay.failures
                            and not result['real_key_in_output'] and result['clean_diagnostics']
                            and result.get('exact_restore', True)
                            and result.get('initial_exit_code', 0) == 0
                            and result.get('initial_restore', True)
                            and result.get('protected_image_seen', True))
    except subprocess.TimeoutExpired:
        result.update(passed=False, error='client-timeout', requests=relay.records, privacy_failures=relay.failures)
    finally:
        relay.shutdown()
        relay.server_close()
        thread.join()
    (root / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pentect', required=True)
    parser.add_argument('--client', choices=['opencode', 'pi'], action='append')
    parser.add_argument('--case', choices=['text', 'tools', 'image', 'resume'], action='append')
    parser.add_argument('--model', default='openai/gpt-4.1-mini')
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--pi-extension', help='Test an installed Pi extension instead of the launcher')
    args = parser.parse_args()
    if args.pi_extension and args.client != ['pi']:
        parser.error('--pi-extension requires --client pi')
    args.output_root.mkdir(parents=True, exist_ok=True)
    results = [run_case(args.pentect, client, args.model, case, args.output_root, args.pi_extension)
               for client in args.client or ['opencode', 'pi']
               for case in args.case or ['text', 'tools', 'image', 'resume']]
    return 0 if all(result['passed'] for result in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
