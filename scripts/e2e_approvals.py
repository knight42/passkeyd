#!/usr/bin/env python3
"""Real approval CLI processes against a controlled local Telegram transport."""
import http.server
import json
import os
import struct
from pathlib import Path
import subprocess
import tempfile
import threading
from e2e_telegram import build_fixture, check


def run_case(binary, home, decision):
    config = home / 'Library/Application Support/passkeyd/config.json'
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({'telegramToken': 'FAKE_TOKEN', 'telegramChatId': 777,
        'allowedRps': ['github.com', 'webauthn.io'], 'remoteTimeoutSec': 0 if decision == 'expired' else 10,
        'maxApprovalsPerHour': 30, 'forceRemote': True}))
    polling = threading.Event()
    release = threading.Event()
    state = {'sends': 0, 'nonce': '', 'answered': [], 'polls': 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            params = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
            method = self.path.rsplit('/', 1)[-1]
            result = True
            if method == 'getMe':
                result = {'username': 'fixture_bot'}
            elif method == 'sendMessage':
                state['sends'] += 1
                state['nonce'] = params['reply_markup']['inline_keyboard'][0][0]['callback_data'][2:]
                result = {'message_id': 100}
            elif method == 'getUpdates':
                state['polls'] += 1
                polling.set()
                release.wait(10)
                def callback(cid, data, sender=777, message=100, chat=777):
                    return {'update_id': cid, 'callback_query': {'id': str(cid), 'data': data,
                        'from': {'id': sender}, 'message': {'message_id': message, 'chat': {'id': chat}}}}
                yes = 'a:' + state['nonce']
                no = 'd:' + state['nonce']
                result = [callback(1, yes, sender=666), callback(2, 'a:wrong-nonce'),
                          callback(3, yes, message=999), callback(4, yes, chat=888),
                          callback(5, yes if decision == 'approve' else no), callback(6, yes)]
            elif method == 'answerCallbackQuery':
                state['answered'].append(params['callback_query_id'])
            body = json.dumps({'ok': True, 'result': result}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                pass

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = dict(os.environ, CFFIXED_USER_HOME=str(home), PASSKEYD_TEST_HOME=str(home),
               PASSKEYD_TEST_ENDPOINT=f'http://127.0.0.1:{server.server_port}')
    proc = subprocess.Popen([str(binary), 'test-approval', '--remote'], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if decision != 'expired':
            check(polling.wait(10), 'first approval did not start polling')
            other = subprocess.run([str(binary), 'test-approval', '--remote'], env=env,
                                   capture_output=True, text=True, timeout=10)
            check(other.returncode == 1 and 'denied' in other.stdout, 'competing approval was not denied')
            setup = subprocess.run([str(binary), 'setup-telegram'], env=env,
                                   capture_output=True, text=True, timeout=10)
            check(setup.returncode == 1 and 'polling busy' in setup.stdout, 'setup competed for updates')
            check(state['sends'] == 1 and state['polls'] == 1, 'competing process sent or consumed updates')
            release.set()
        stdout, stderr = proc.communicate(timeout=15)
        expected = 0 if decision == 'approve' else 1
        check(proc.returncode == expected, f'wrong approval outcome: {stdout} {stderr}')
        if decision != 'expired':
            check(state['answered'] == ['5'], 'wrong-user, wrong-nonce or repeat callback accepted')
        else:
            check(state['polls'] == 0 and state['answered'] == [], 'expired request accepted a callback')
        # Completion releases the process-wide lease; a subsequent request works.
        release.set()
        retry = subprocess.run([str(binary), 'test-approval', '--remote'], env=env,
                               capture_output=True, text=True, timeout=15)
        check(retry.returncode == expected and state['sends'] == 2, 'polling lease leaked after completion')
        if decision == 'deny':
            # Even a same-RP exclusion must not be disclosed before approval.
            (config.parent / 'credentials.json').write_text(json.dumps([{
                'id': 'known-github', 'rpId': 'github.com', 'userName': 'fixture',
                'userHandle': 'YQ', 'backend': 'software', 'createdAt': '2026-01-01T00:00:00Z'}]))
            sends = state['sends']
            for rp, excluded in [('webauthn.io', 'known-github'), ('webauthn.io', 'unknown'),
                                 ('github.com', 'known-github')]:
                request = json.dumps({'op': 'create', 'rpId': rp, 'origin': 'https://' + rp,
                    'user': {'name': 'fixture', 'id': 'YQ'}, 'excludeIds': [excluded]}).encode()
                native = subprocess.run([str(binary), '--stdio'], env=env,
                    input=struct.pack('<I', len(request)) + request, capture_output=True, timeout=15)
                check(native.returncode == 0, 'native fixture failed')
                size = struct.unpack('<I', native.stdout[:4])[0]
                response = json.loads(native.stdout[4:4+size])
                check(response.get('error') == 'not approved', 'exclusion disclosed before consent')
            check(state['sends'] == sends + 3, 'exclusion skipped approval')
            print('EXCLUSION PROTOCOL E2E PASS (foreign/absent/same-RP IDs all require approval)')
        print(f'APPROVAL CLI E2E PASS ({decision}; concurrent approval/setup excluded; lease released)')
    finally:
        release.set()
        if proc.poll() is None:
            proc.kill(); proc.wait()
        server.shutdown(); server.server_close()


def main():
    with tempfile.TemporaryDirectory(prefix='passkeyd-approval-e2e-') as tmp:
        work = Path(tmp).resolve()
        binary = build_fixture(work)
        for decision in ['approve', 'deny', 'expired']:
            run_case(binary, work / decision, decision)


if __name__ == '__main__':
    main()
