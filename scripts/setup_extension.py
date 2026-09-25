#!/usr/bin/env python3
"""Write extension/manifest.json from the template with a freshly generated
"key", which pins the unpacked extension's ID on this machine. The RSA pair
is only a source of ID bits — the private half would matter only for Web
Store publishing and is discarded. Idempotent: if the manifest already
exists, just prints its extension ID (install.sh consumes that).
"""
import base64
import hashlib
import json
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "extension", "manifest.json")
TEMPLATE = MANIFEST + ".tmpl"


def ext_id(spki_der):
    # Chrome derives unpacked-extension IDs from the key: first 16 bytes of
    # sha256(SPKI DER), hex digits mapped 0-f -> a-p.
    digest = hashlib.sha256(spki_der).hexdigest()[:32]
    return "".join(chr(ord("a") + int(c, 16)) for c in digest)


def ensure_manifest():
    if os.path.exists(MANIFEST):
        key = json.load(open(MANIFEST))["key"]
        return ext_id(base64.b64decode(key))
    priv = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA",
         "-pkeyopt", "rsa_keygen_bits:2048", "-outform", "DER"],
        capture_output=True, check=True).stdout
    spki = subprocess.run(
        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=priv, capture_output=True, check=True).stdout
    manifest = json.load(open(TEMPLATE))
    manifest["key"] = base64.b64encode(spki).decode()
    with open(MANIFEST, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    return ext_id(spki)


if __name__ == "__main__":
    print(ensure_manifest())
