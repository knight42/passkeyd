#!/usr/bin/env python3
"""Protocol-level e2e: speak Chrome's native-messaging framing to `passkeyd --stdio`,
run create -> has -> get, then verify the assertion signature against the
registration's public key with openssl. Requires PASSKEYD_SKIP_APPROVAL=1 (debug build).

Uses check() instead of assert: this environment sets PYTHONOPTIMIZE=1, which
silently strips assert statements.
"""
import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, ".build/debug/passkeyd")


def check(cond, msg):
    if not cond:
        raise RuntimeError(f"FAIL: {msg}")


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class Host:
    def __init__(self):
        env = dict(os.environ, PASSKEYD_SKIP_APPROVAL="1")
        self.p = subprocess.Popen([BIN, "--stdio"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, env=env)

    def call(self, msg):
        body = json.dumps(msg).encode()
        self.p.stdin.write(struct.pack("<I", len(body)) + body)
        self.p.stdin.flush()
        while True:
            hdr = self.p.stdout.read(4)
            check(len(hdr) == 4, "host died")
            (n,) = struct.unpack("<I", hdr)
            resp = json.loads(self.p.stdout.read(n))
            if resp.get("type") == "ping":
                continue
            return resp

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=5)


def verify_signature(spki_der, message, sig_der):
    with tempfile.TemporaryDirectory() as d:
        open(f"{d}/spki.der", "wb").write(spki_der)
        open(f"{d}/msg.bin", "wb").write(message)
        open(f"{d}/sig.der", "wb").write(sig_der)
        subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER",
                        "-in", f"{d}/spki.der", "-out", f"{d}/spki.pem"], check=True)
        out = subprocess.run(["openssl", "dgst", "-sha256", "-verify", f"{d}/spki.pem",
                              "-signature", f"{d}/sig.der", f"{d}/msg.bin"],
                             capture_output=True, text=True)
        check("Verified OK" in out.stdout, f"openssl verify: {out.stdout} {out.stderr}")


def main():
    host = Host()
    origin = "http://localhost:8399"
    rp = "localhost"

    # register
    challenge = b64u(os.urandom(32))
    user_handle = b64u(b"e2e-user")
    create = host.call({
        "reqId": 1, "op": "create", "rpId": rp, "origin": origin,
        "user": {"id": user_handle, "name": "e2e@example", "displayName": "e2e"},
        "algs": [-7], "excludeIds": [],
    })
    check(create.get("ok"), f"create failed: {create}")
    check(create.get("reqId") == 1, "reqId echo broken")
    cred_id = create["id"]
    check(isinstance(cred_id, str) and len(b64u_decode(cred_id)) == 32, "credential id shape")
    spki = b64u_decode(create["publicKey"])

    # registration authData sanity
    auth = b64u_decode(create["authenticatorData"])
    check(auth[:32] == hashlib.sha256(rp.encode()).digest(), "rpIdHash mismatch")
    check(auth[32] == 0x45, f"registration flags {auth[32]:#x} != UP|UV|AT")
    att = b64u_decode(create["attestationObject"])
    check(att.startswith(b"\xa3cfmtdnonegattStmt\xa0hauthData"), "attestation object shape")

    # has
    has = host.call({"reqId": 2, "op": "has", "rpId": rp, "origin": origin, "allow": []})
    check(has.get("ok") and has.get("has"), f"has failed: {has}")

    # assert with allowCredentials
    client_data = json.dumps({"type": "webauthn.get", "challenge": challenge,
                              "origin": origin, "crossOrigin": False}).encode()
    cd_hash = hashlib.sha256(client_data).digest()
    get = host.call({"reqId": 3, "op": "get", "rpId": rp, "origin": origin,
                     "clientDataHash": b64u(cd_hash), "allow": [cred_id]})
    check(get.get("ok"), f"get failed: {get}")
    check(get["id"] == cred_id, "assertion returned wrong credential id")
    check(get["userHandle"] == user_handle, "userHandle mismatch")
    auth_data = b64u_decode(get["authenticatorData"])
    check(auth_data[:32] == hashlib.sha256(rp.encode()).digest(), "assertion rpIdHash")
    check(auth_data[32] == 0x05, "assertion flags != UP|UV")

    # unknown rp must be rejected without approval
    bad = host.call({"reqId": 4, "op": "get", "rpId": "evil.com", "origin": "https://evil.com",
                     "clientDataHash": b64u(cd_hash), "allow": []})
    check(not bad.get("ok"), "evil rp accepted!")

    host.close()

    verify_signature(spki, auth_data + cd_hash, b64u_decode(get["signature"]))

    subprocess.run([BIN, "delete", cred_id], check=True, capture_output=True)
    print(f"PROTOCOL E2E PASS (cred {cred_id[:12]}…, sig verified by openssl)")


if __name__ == "__main__":
    sys.exit(main())
