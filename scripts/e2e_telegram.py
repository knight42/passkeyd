#!/usr/bin/env python3
"""Run setup-telegram end to end with real CLI/config code and a local Bot API.

The test executable compiles the production sources unchanged, prepending only
URLProtocol registration and a temporary-home safety check to main.swift. The
fixture redirects Telegram HTTP requests; no bot or user Keychain is touched.
"""
import http.server
import json
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def check(value, message):
    if not value:
        raise RuntimeError(message)


def run_case(binary, home, mode, old_command=None):
    config = home / 'Library/Application Support/passkeyd/config.json'
    config.parent.mkdir(parents=True)
    previous = {'telegramToken': 'FAKE_TEST_TOKEN', 'telegramChatId': 555,
                'allowedRps': ['github.com'], 'remoteTimeoutSec': 120,
                'maxApprovalsPerHour': 30, 'forceRemote': False}
    if mode == 'rebind':
        config.write_text(json.dumps(previous))
    elif mode == 'save-failure':
        config.mkdir()
    state = {'polls': 0, 'command': None, 'error': None}
    command_ready = threading.Event()

    def unchanged():
        if mode == 'rebind':
            check(json.loads(config.read_text()) == previous, 'unverified message changed existing pairing')
        elif mode == 'save-failure':
            check(config.is_dir(), 'unexpected config mutation')
        else:
            check(not config.exists(), 'unverified message created config')

    def message(command, cid=777, sender=777, kind='private', bot=False, date=None):
        return {'message': {'text': command, 'date': int(time.time()) if date is None else date,
                            'chat': {'id': cid, 'type': kind}, 'from': {'id': sender, 'is_bot': bot}}}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                params = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                if self.path.endswith('/getMe'):
                    result = {'username': 'local_fixture_bot'}
                else:
                    check(self.path.endswith('/getUpdates'), 'unexpected Telegram method')
                    check(params.get('allowed_updates') == ['message'], 'setup must request message updates')
                    state['polls'] += 1
                    check(command_ready.wait(10), 'CLI did not print pairing command')
                    unchanged()
                    command = state['command']
                    if state['polls'] == 1:
                        result = [message('queued stranger', cid=666, sender=666),
                                  message(old_command or '/pair old-session', cid=666, sender=666)]
                    elif state['polls'] == 2:
                        check(params.get('offset') == 3, 'queued updates were not advanced')
                        result = [message(command, date=int(time.time()) - 3600),
                                  message(command, kind='group'), message(command, bot=True),
                                  message(command, sender=666)]
                    else:
                        check(state['polls'] == 3, 'valid pairing was not accepted')
                        check(params.get('offset') == 7, 'invalid updates were not advanced')
                        result = [message(command)]
                    first = 1 if state['polls'] == 1 else (3 if state['polls'] == 2 else 7)
                    for index, update in enumerate(result, first):
                        update['update_id'] = index
                body = json.dumps({'ok': True, 'result': result}).encode()
            except Exception as error:
                state['error'] = str(error)
                body = json.dumps({'ok': False, 'description': 'local fixture failed'}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    master, slave = pty.openpty()
    env = dict(os.environ, CFFIXED_USER_HOME=str(home), PASSKEYD_TEST_HOME=str(home),
               TELEGRAM_BOT_TOKEN='FAKE_TEST_TOKEN',
               PASSKEYD_TEST_ENDPOINT=f'http://127.0.0.1:{server.server_port}')
    proc = subprocess.Popen([str(binary), 'setup-telegram'], env=env,
                            stdin=subprocess.DEVNULL, stdout=slave, stderr=slave)
    os.close(slave)
    output = b''
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.2)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output += chunk
                match = re.search(rb'/pair [0-9a-f]{32}', output)
                if match:
                    state['command'] = match.group().decode()
                    command_ready.set()
            if proc.poll() is not None:
                break
        proc.wait(timeout=2)
        check(state['error'] is None, f'fixture failure: {state["error"]}')
        check(state['polls'] == 3, 'CLI did not reject all invalid messages before pairing: ' +
              re.sub(r'/pair [0-9a-f]{32}', '/pair [redacted]', output.decode(errors='replace')))
        if mode == 'save-failure':
            check(proc.returncode == 1, 'save failure must exit unsuccessfully')
            check(b'could not save Telegram pairing' in output and b' saved to ' not in output,
                  'save failure incorrectly reported success')
        else:
            check(proc.returncode == 0, 'pairing CLI failed')
            saved = json.loads(config.read_text())
            check(saved['telegramChatId'] == 777, 'wrong approval identity saved')
            check(saved['telegramToken'] == 'FAKE_TEST_TOKEN', 'token not saved')
            check(config.stat().st_mode & 0o777 == 0o600, 'config permissions are not 0600')
            if mode == 'rebind':
                check(saved['allowedRps'] == previous['allowedRps'], 'pairing changed unrelated config')
        print(f'TELEGRAM CLI E2E PASS ({mode})')
        return state['command']
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        os.close(master)
        server.shutdown()
        server.server_close()


def main():
    with tempfile.TemporaryDirectory(prefix='passkeyd-telegram-e2e-') as tmp:
        work = Path(tmp).resolve()
        main_source = (ROOT / 'Sources/passkeyd/main.swift').read_text()
        bootstrap = '''import Foundation
let testHome = ProcessInfo.processInfo.environment["PASSKEYD_TEST_HOME"]!
guard FileManager.default.homeDirectoryForCurrentUser.resolvingSymlinksInPath().path ==
      URL(fileURLWithPath: testHome).resolvingSymlinksInPath().path else {
    fatalError("test home isolation failed")
}
URLProtocol.registerClass(TelegramFixture.self)
'''
        (work / 'main.swift').write_text(bootstrap + main_source)
        sources = sorted(str(p) for p in (ROOT / 'Sources/passkeyd').glob('*.swift') if p.name != 'main.swift')
        binary = work / 'passkeyd-fixture'
        subprocess.run(['swiftc', *sources, str(ROOT / 'scripts/TelegramFixture.swift'),
                        str(work / 'main.swift'), '-o', str(binary)], check=True)
        old = run_case(binary, work / 'first-home', 'initial')
        run_case(binary, work / 'second-home', 'rebind', old)
        run_case(binary, work / 'failure-home', 'save-failure')


if __name__ == '__main__':
    main()
