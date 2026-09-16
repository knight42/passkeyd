# AGENTS.md — constraints and conventions for working on passkeyd

passkeyd is a personal WebAuthn authenticator: Swift native-messaging host
(`Sources/passkeyd`) + Chrome MV3 extension (`extension/`). Security posture
matters more than features here. Read this before changing anything.

## Hard security invariants — do not weaken

1. **RP ID validation** (`Sources/passkeyd/RpId.swift`): rpId must be a
   registrable suffix of the origin host, origin must be https (or localhost),
   and rpId must match the allowlist. This is the anti-phishing boundary and is
   enforced in BOTH the daemon and `extension/content-main.js`. Never remove
   either side; never loosen without tests in `Tests/passkeydTests/RpIdTests.swift`.
2. **Every assertion goes through `Approver.approve`** — Touch ID locally,
   Telegram remotely, deny by default on timeout. No silent signing paths.
   The only bypass is `PASSKEYD_SKIP_APPROVAL=1`, which must stay inside
   `#if DEBUG` and must never ship in release code paths.
3. **SE key access control stays `.privateKeyUsage` only.** Adding
   `.userPresence`/`.biometryAny` deadlocks the remote-approval path (the ACL
   prompt can only be answered locally).
4. **Approval nonces are one-shot** (`Waiter.resolve` ignores repeats), TTL'd,
   and the Telegram handler only accepts callbacks from the configured chat id.
5. **Never log secrets**: no private keys, no clientDataHash payload bodies,
   no Telegram token. Log rpId, credential id prefix, outcome.
6. The config file and credential store are written with 0600 — keep it that way.

## Protocol conventions

- Native messaging framing: 4-byte little-endian length + JSON, both directions.
- `reqId` is the caller's correlation id and is echoed verbatim; `id` in a
  response is always the credential id. Do not conflate them (this was a real
  bug once).
- Host → extension `{"type":"ping"}` every 15 s keeps the MV3 service worker
  alive during long approvals; the extension must keep ignoring pings.
- All binary fields cross the protocol as base64url without padding
  (`B64URL` / `b64u` helpers).
- Sign count is constant 0 (Apple-synced-passkey convention); BE/BS flags are 0
  (device-bound credential — do not claim backup eligibility).
- Attestation is `fmt: "none"`, zero AAGUID. Don't fake attestation.

## Environment gotchas (this machine)

- **`PYTHONOPTIMIZE=1` is set globally: Python `assert` is silently stripped.**
  Never use bare `assert` in test/e2e scripts — use the `check()` helper.
- Branded Google Chrome ≥137 ignores `--load-extension`; automated browser e2e
  uses the playwright-cached **Chrome for Testing** binary, which reads native
  messaging manifests from `<user-data-dir>/NativeMessagingHosts` (the real
  Chrome reads `~/Library/Application Support/Google/Chrome/NativeMessagingHosts`),
  so the e2e writes its own manifest into the throwaway profile.
  `--disable-features=DisableLoadExtensionCommandLineSwitch` does NOT bring the
  switch back on branded Chrome 152 — it was tried and the extension still
  never injected.
- **Chrome for Testing needs `--use-mock-keychain`**, or it blocks on a macOS
  Keychain prompt (Chrome Safe Storage, `userCanceledErr -128`) before it ever
  navigates — headless has no way to answer that prompt and the run just hangs.
- **The Touch ID panel does not block the browser.** It is drawn by the system
  agent `coreautha`, which becomes the frontmost app while an approval is
  pending, but it holds no input grab: measured by posting real HID events at a
  Chrome window with a panel up, the page still received them. Exactly the
  first click is swallowed re-activating the browser window, so a person who
  clicks once and sees nothing happen concludes the panel is modal — it isn't,
  the second click lands. This means the page can navigate (Okta's "Verify with
  something else") while passkeyd is still waiting for approval, by hand as
  well as from a userscript; the extension must stay correct under that.
- Unsigned binaries can't use the Secure Enclave / data-protection keychain
  (`errSecMissingEntitlement`); the daemon auto-falls back to software keys.
  Don't "fix" the SE probe by removing `kSecUseDataProtectionKeychain`.
- **An ad-hoc-signed rebuild invalidates the keychain ACL** (new CDHash →
  new app → re-prompt on first key access, invisibly if the screen is
  locked). Fixed on this machine by the stable self-signed identity
  `passkeyd-codesign` (`scripts/setup-codesign.sh`, one-time): install.sh
  signs the binary with it, so the ACL survives rebuilds — verified by
  signing a different build and accessing the key with no prompt. Keep the
  `passkeyd test-sign` step in install.sh anyway as the safety net, and
  never reinstall the release binary without install.sh.
- Never install the binary by `cp` over the existing file: the kernel's
  per-vnode code-signature cache then SIGKILLs every exec. `install.sh`
  copies to a temp name and `mv`s into place — keep it that way.

## Testing requirements

One-time setup for the browser e2e (idempotent; skips the download if the
browser is already cached):

```
npx --yes playwright@latest install chromium   # Chrome for Testing -> ~/Library/Caches/ms-playwright
```

Any recent Chrome for Testing works — the constraint is that it must NOT be
branded Chrome (see the `--load-extension` gotcha above). `find_chrome()` in
`scripts/e2e_browser.py` picks the highest-numbered cached build.

Any change must pass, in order:

```
swift build                         # e2e runs the debug binary
swift test                          # unit: CBOR/authData/rpId/store/approve-http
python3 scripts/e2e_protocol.py    # protocol e2e incl. openssl signature verify
python3 scripts/e2e_browser.py     # full chain in Chrome for Testing
```

New CTAP/WebAuthn byte-layout code needs a golden-bytes unit test
(see `AuthDataTests`). Signature-producing changes need an openssl (or
CryptoKit) verification round-trip, not just "no error".

## Code conventions

- Swift: no external dependencies. `PasskeydError`/`fail()` for errors.
  Synchronous code with semaphores over async/await (the host is a short-lived
  per-request process; keep it simple).
- Extension: no build step, plain JS, MV3. `content-main.js` runs in the page's
  MAIN world — it must not use `chrome.*` APIs; relay through
  `content-isolated.js` via `window.postMessage`.
- Unknown requests must **fall through to the browser's native WebAuthn**
  (return `ORIG.get`/`ORIG.create`), never break the page. **One deliberate
  exception**: a modal request arriving while another is already inside
  passkeyd is rejected with `NotAllowedError`, never forwarded — forwarding it
  pops the platform (iCloud Keychain) sheet next to our own approval prompt.
  That is what the `interceptingGet`/`interceptingCreate` guards are for; do
  not "simplify" them back into the single reentrancy flag they replaced.
  `forwardingGet`/`forwardingCreate` are the separate, genuinely re-entrant
  case (a wrapper in the ORIG chain calling back into us) and must stay
  narrow — never hold either across a passkeyd round-trip.
- Conditional-mediation (`mediation: "conditional"`) requests pass through
  unguarded and stay pending for the life of the page; no flag may span them.
- Keep the extension allowlist (`manifest.json` matches) in sync with
  `allowedRps` in the daemon config.
