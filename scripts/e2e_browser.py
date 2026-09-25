#!/usr/bin/env python3
"""Browser-level e2e: real Chrome (headless) + the unpacked extension + the native
messaging host, against a local test page. Registers a credential over the host
protocol first, then lets the page's navigator.credentials.get() flow through
content-main -> content-isolated -> service worker -> native host -> signature,
and verifies the assertion with openssl against the registered public key.

Prereqs: debug build (`swift build`) and a playwright-cached Chrome for Testing.
The host manifest is written into the throwaway user-data-dir, and
PASSKEYD_SKIP_APPROVAL=1 is exported to Chrome so the spawned host inherits it.

Uses check() instead of assert: this environment sets PYTHONOPTIMIZE=1, which
silently strips assert statements.
"""
import base64
import hashlib
import http.server
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, ".build/debug/passkeyd")
PORT = 8399
TOKEN = uuid.uuid4().hex
# Pinned by the "key" entry in extension/manifest.json (generated per machine
# by scripts/setup_extension.py; ensure_manifest creates it if missing).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from setup_extension import ensure_manifest

EXT_ID = ensure_manifest()


def find_chrome():
    """Branded Chrome >= 137 ignores --load-extension; use the playwright-cached
    Chrome for Testing binary (it also reads native messaging manifests from
    <user-data-dir>/NativeMessagingHosts, so the run needs no global install)."""
    import glob
    import re
    candidates = glob.glob(os.path.expanduser(
        "~/Library/Caches/ms-playwright/chromium-*/chrome-mac-*/"
        "Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
    ))
    if not candidates:
        raise RuntimeError("no playwright Chrome for Testing found; run: "
                           "npx --yes playwright@latest install chromium")
    # Sort by the numeric build id, not lexically: "chromium-1000" sorts before
    # "chromium-999" as a string.
    def build_id(p):
        m = re.search(r"/chromium-(\d+)/", p)
        return int(m.group(1)) if m else -1
    return max(candidates, key=build_id)


def check(cond, msg):
    if not cond:
        raise RuntimeError(f"FAIL: {msg}")


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def host_call(proc, msg):
    body = json.dumps(msg).encode()
    proc.stdin.write(struct.pack("<I", len(body)) + body)
    proc.stdin.flush()
    while True:
        hdr = proc.stdout.read(4)
        check(len(hdr) == 4, "host died")
        (n,) = struct.unpack("<I", hdr)
        resp = json.loads(proc.stdout.read(n))
        if resp.get("type") == "ping":
            continue
        return resp


def register_credential():
    env = dict(os.environ, PASSKEYD_SKIP_APPROVAL="1")
    p = subprocess.Popen([BIN, "--stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
    resp = host_call(p, {
        "reqId": 1, "op": "create", "rpId": "localhost", "origin": f"http://localhost:{PORT}",
        "user": {"id": b64u(b"e2e-browser"), "name": "e2e-browser@example", "displayName": "e2e"},
        "algs": [-7], "excludeIds": [],
    })
    p.stdin.close()
    p.wait(timeout=5)
    check(resp.get("ok"), f"create failed: {resp}")
    return resp["id"], b64u_decode(resp["publicKey"])


result = {}
result_ready = threading.Event()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        page = open(os.path.join(ROOT, "scripts/e2e_page.html"), "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        print(f"POST /result ({n} bytes): {body[:300]!r}", flush=True)
        try:
            data = json.loads(body)
        except Exception:
            data = None
        if isinstance(data, dict) and data.get("token") == TOKEN:
            result.update(data)
            result_ready.set()
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def main():
    cred_id, spki = register_credential()
    print(f"registered {cred_id[:12]}…", flush=True)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    udd = tempfile.mkdtemp(prefix="passkeyd-e2e-chrome-")
    nmh_dir = os.path.join(udd, "NativeMessagingHosts")
    os.makedirs(nmh_dir)
    with open(os.path.join(nmh_dir, "com.zack.passkeyd.json"), "w") as f:
        json.dump({
            "name": "com.zack.passkeyd",
            "description": "passkeyd native messaging host (e2e, debug build)",
            "path": BIN,
            "type": "stdio",
            "allowed_origins": [f"chrome-extension://{EXT_ID}/"],
        }, f)
    env = dict(os.environ, PASSKEYD_SKIP_APPROVAL="1")
    chrome = subprocess.Popen([
        # --use-mock-keychain is required: without it Chrome for Testing blocks
        # on a macOS Keychain (Chrome Safe Storage) prompt before ever
        # navigating, and headless has no way to answer it.
        find_chrome(), "--headless", "--use-mock-keychain",
        f"--user-data-dir={udd}",
        f"--load-extension={os.path.join(ROOT, 'extension')}",
        "--no-first-run", "--disable-sync", "--disable-background-networking",
        f"http://localhost:{PORT}/?token={TOKEN}",
    ], env=env, stdout=subprocess.DEVNULL,
       stderr=open("/tmp/passkeyd-e2e-chrome.log", "w"))

    # First launch initializes the throwaway profile; give it headroom.
    ok = result_ready.wait(timeout=90)
    chrome.terminate()
    server.shutdown()
    shutil.rmtree(udd, ignore_errors=True)
    subprocess.run([BIN, "delete", cred_id], check=True, capture_output=True)

    check(ok, "no result from page (chrome/extension/host chain broken)")
    check(result.get("ok"), f"page reported failure: {json.dumps(result, indent=2)}")
    check(result["id"] == cred_id, f"credential id mismatch: {result['id']}")
    check(result.get("isPKC"), "instanceof PublicKeyCredential failed")
    check(result.get("abortName") == "AbortError",
          f"pre-aborted get: expected AbortError, got {result.get('abortName')}")
    # Message pins the rejection to our guard: the headless native stack would
    # also say NotAllowedError, but not before the first request resolves.
    check(result.get("overlapName") == "NotAllowedError"
          and "already pending" in (result.get("overlapMessage") or ""),
          f"overlapping get: {result.get('overlapName')}: {result.get('overlapMessage')}")

    cdj = b64u_decode(result["clientDataJSON"])
    cd = json.loads(cdj)
    check(cd["type"] == "webauthn.get", "clientData type")
    check(cd["challenge"] == result["challenge"], "challenge mismatch")
    check(cd["origin"] == f"http://localhost:{PORT}", "origin mismatch")

    auth_data = b64u_decode(result["authenticatorData"])
    check(auth_data[:32] == hashlib.sha256(b"localhost").digest(), "rpIdHash")
    check(auth_data[32] == 0x05, "flags != UP|UV")

    j = result.get("json") or {}
    check(j.get("response", {}).get("signature") == result["signature"], "toJSON mismatch")

    with tempfile.TemporaryDirectory() as d:
        open(f"{d}/spki.der", "wb").write(spki)
        open(f"{d}/msg.bin", "wb").write(auth_data + hashlib.sha256(cdj).digest())
        open(f"{d}/sig.der", "wb").write(b64u_decode(result["signature"]))
        subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER",
                        "-in", f"{d}/spki.der", "-out", f"{d}/spki.pem"], check=True)
        out = subprocess.run(["openssl", "dgst", "-sha256", "-verify", f"{d}/spki.pem",
                              "-signature", f"{d}/sig.der", f"{d}/msg.bin"],
                             capture_output=True, text=True)
        check("Verified OK" in out.stdout, f"signature verify failed: {out.stdout} {out.stderr}")

    print("BROWSER E2E PASS (real Chrome -> extension -> native host -> signature verified)")


if __name__ == "__main__":
    sys.exit(main())
