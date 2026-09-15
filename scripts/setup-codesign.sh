#!/bin/bash
set -euo pipefail
# One-time setup: create a stable self-signed code-signing identity
# ("passkeyd-codesign") in the login keychain. When it exists, install.sh
# signs the release binary with it, so the binary's designated requirement —
# and therefore the keychain ACL's "Always Allow" — survives rebuilds.
# (Ad-hoc signatures change with every build, forcing a re-prompt each time.)
#
# Expect two GUI prompts: an admin/password dialog from add-trusted-cert, and
# a keychain prompt when codesign first uses the new key (click Always Allow).
NAME="passkeyd-codesign"
KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"

if security find-identity -v -p codesigning | grep -q "$NAME"; then
  echo "identity '$NAME' already present:"
  security find-identity -v -p codesigning | grep "$NAME"
  exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/req.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $NAME
[ext]
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
basicConstraints = critical,CA:FALSE
EOF

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 3650 -config "$TMP/req.cnf"
# -legacy: macOS `security import` only understands legacy PKCS12 encryption;
# OpenSSL 3 defaults to AES/SHA-256 which fails with "MAC verification failed".
openssl pkcs12 -export -legacy -out "$TMP/id.p12" -inkey "$TMP/key.pem" \
  -in "$TMP/cert.pem" -passout pass:passkeyd

# -T pre-authorizes codesign to use the private key without prompting.
security import "$TMP/id.p12" -k "$KEYCHAIN" -P passkeyd -T /usr/bin/codesign
# Trust the cert for code signing (user trust domain; triggers an auth dialog).
security add-trusted-cert -p codeSign -k "$KEYCHAIN" "$TMP/cert.pem"

security find-identity -v -p codesigning | grep "$NAME"
echo "done — run scripts/install.sh <ext-id> to install a signed binary"
