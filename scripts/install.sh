#!/bin/bash
set -euo pipefail
# usage: scripts/install.sh <chrome-extension-id>
cd "$(dirname "$0")/.."
EXT_ID="${1:?usage: install.sh <chrome-extension-id>}"

swift build -c release
BIN_DIR="$HOME/Library/Application Support/passkeyd/bin"
mkdir -p "$BIN_DIR"
# Install to a fresh inode (cp to temp + mv). cp over the existing file keeps
# the inode, and the kernel's code-signature cache for that vnode then
# SIGKILLs every subsequent exec of the updated binary.
cp .build/release/passkeyd "$BIN_DIR/passkeyd.new"
# Sign with the stable self-signed identity when present (scripts/setup-codesign.sh)
# so the keychain ACL's "Always Allow" survives rebuilds.
if security find-identity -v -p codesigning | grep -q "passkeyd-codesign"; then
  codesign -f -s passkeyd-codesign -i com.zack.passkeyd "$BIN_DIR/passkeyd.new"
fi
mv -f "$BIN_DIR/passkeyd.new" "$BIN_DIR/passkeyd"

MANIFEST_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
mkdir -p "$MANIFEST_DIR"
sed -e "s|__BINARY__|$BIN_DIR/passkeyd|" -e "s|__EXTENSION_ID__|$EXT_ID|" \
    host/com.zack.passkeyd.json.tmpl > "$MANIFEST_DIR/com.zack.passkeyd.json"

echo "installed: $MANIFEST_DIR/com.zack.passkeyd.json -> $BIN_DIR/passkeyd"

# The binary is ad-hoc signed, so the keychain treats every new build as a
# new app: the first key access re-prompts for authorization. Trigger that
# now, while someone is at the Mac — otherwise the prompt pops invisibly
# behind a locked screen during a remote sign-in and hangs it.
if "$BIN_DIR/passkeyd" list | grep -q .; then
  echo 'exercising stored keys — click "Always Allow" on the keychain prompt:'
  "$BIN_DIR/passkeyd" test-sign
fi
echo "restart Chrome for the native host to be picked up"
