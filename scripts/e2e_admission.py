#!/usr/bin/env python3
"""Real Chrome admission checks with a barrier-controlled, keyless native host."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from e2e_browser import find_chrome, EXT_ID, ROOT, check

PAGE = b'''<!doctype html><script>
let seq=0;
function request() {
  const reqId=--seq;
  return new Promise(resolve=>{
    const receive=ev=>{
      if(ev.source!==window || ev.data?.__passkeyd_resp?.reqId!==reqId)return;
      window.removeEventListener('message',receive);resolve(ev.data.__passkeyd_resp);
    };
    window.addEventListener('message',receive);
    window.postMessage({__passkeyd_req:{reqId,op:'has',rpId:'localhost'}},window.origin);
  });
}
window.addEventListener('load',async()=>{
  const first=request();
  await fetch('/ready');
  const flood=await Promise.all(Array.from({length:100},request));
  await fetch('/release');
  const initial=await first;
  const sequential=[];
  for(let i=0;i<19;i++)sequential.push(await request());
  const limited=await request();
  let denied;
  try {
    await navigator.credentials.get({publicKey:{rpId:'localhost',challenge:new Uint8Array(32)}});
    denied={name:'unexpected success'};
  } catch(e) { denied={name:e.name,message:e.message}; }
  await fetch('/result',{method:'POST',body:JSON.stringify({flood,initial,sequential,limited,denied})});
});
</script>'''


def main():
    with tempfile.TemporaryDirectory(prefix='passkeyd-admission-e2e-') as tmp:
        work = Path(tmp)
        started = threading.Event(); release = threading.Event(); done = threading.Event()
        state = {'pids': [], 'before_release': None, 'result': None}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'OK'
                if self.path.startswith('/host/'):
                    state['pids'].append(self.path.split('/')[-1])
                    started.set()
                    release.wait(20)
                elif self.path == '/ready':
                    started.wait(20)
                elif self.path == '/release':
                    state['before_release'] = len(state['pids'])
                    release.set()
                else:
                    body = PAGE
                self.send_response(200); self.end_headers(); self.wfile.write(body)

            def do_POST(self):
                state['result'] = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                self.send_response(200); self.end_headers(); done.set()

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        host = work / 'host.py'
        host.write_text('''#!/usr/bin/python3
import json,os,struct,sys,urllib.request
header=sys.stdin.buffer.read(4)
if len(header)!=4: sys.exit(1)
json.loads(sys.stdin.buffer.read(struct.unpack('<I',header)[0]))
urllib.request.urlopen("http://127.0.0.1:PORT/host/"+str(os.getpid()),timeout=25).read()
body=json.dumps({"ok":True,"has":False}).encode()
sys.stdout.buffer.write(struct.pack('<I',len(body))+body);sys.stdout.buffer.flush()
'''.replace('PORT', str(server.server_port)))
        host.chmod(0o700)
        profile = work / 'profile'; manifests = profile / 'NativeMessagingHosts'; manifests.mkdir(parents=True)
        (manifests / 'com.zack.passkeyd.json').write_text(json.dumps({
            'name': 'com.zack.passkeyd', 'description': 'admission E2E fixture', 'path': str(host),
            'type': 'stdio', 'allowed_origins': [f'chrome-extension://{EXT_ID}/']}))
        with (work / 'chrome.log').open('w') as log:
            chrome = subprocess.Popen([find_chrome(), '--headless', '--use-mock-keychain',
                f'--user-data-dir={profile}', f'--load-extension={os.path.join(ROOT, "extension")}',
                '--no-first-run', '--disable-sync', '--disable-background-networking',
                f'http://localhost:{server.server_port}/'], stdout=subprocess.DEVNULL, stderr=log)
            try:
                check(done.wait(45), 'browser admission fixture did not finish')
                r = state['result']
                check(state['before_release'] == 1, 'flood launched extra hosts while one was pending')
                check(len(r['flood']) == 100 and all(x.get('errorCode') == 'busy' for x in r['flood']), 'flood was queued or admitted')
                check(r['initial'].get('ok') and all(x.get('ok') for x in r['sequential']), 'normal requests broke')
                check(r['limited'].get('errorCode') == 'rate_limited', 'sequential flood was not limited')
                check(r['denied']['name'] == 'NotAllowedError' and 'rate limit' in r['denied']['message'], 'limited lookup fell through to native WebAuthn')
                check(len(state['pids']) == 20, 'native host launch budget was exceeded')
                print('ADMISSION BROWSER E2E PASS (100-request flood opens no extra hosts; sequential budget enforced)')
            finally:
                release.set(); chrome.terminate(); chrome.wait(timeout=10)
                server.shutdown(); server.server_close()


if __name__ == '__main__':
    main()
