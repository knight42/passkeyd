# passkeyd

Your personal passkey authenticator for macOS — sign in to websites with a
passkey **you** hold, approve from your Mac with Touch ID, or **from your phone
when you're away**.

## What it does

- **Passkeys for allowlisted sites** (Okta, webauthn.io, …) served by a local
  daemon through a small Chrome extension. Keys live in the Secure Enclave when
  available (signed binary), otherwise in your login keychain.
- **At your Mac**: every sign-in asks for Touch ID (or your password). One
  prompt, nothing else.
- **Away from your Mac**: the sign-in request lands in Telegram with full
  context (site, account, machine) and ✅ Approve / ❌ Deny buttons. A tap
  unblocks whatever was waiting — for example an agent logging in to Okta on
  your machine. The daemon long-polls Telegram for your tap, so it needs no
  inbound connectivity. Works with the screen locked.
- **Everything else stays untouched**: sites not on your allowlist, conditional
  autofill, and your native iCloud Keychain passkeys keep working exactly as
  before. If passkeyd has no credential for a site, the request falls through
  to the browser.

## Install

1. Recommended one-time step: `scripts/setup-codesign.sh` creates a
   self-signed code-signing identity (`passkeyd-codesign`). With it,
   `install.sh` signs the binary, so the keychain's **Always Allow** survives
   rebuilds; without it, every reinstall re-asks once.
2. `scripts/install.sh` — builds (and signs) the release binary, generates
   `extension/manifest.json` on first run (with a fresh `key` that pins your
   machine's extension ID), and installs the native messaging host manifest.
   If you already have credentials, a keychain prompt can appear at the end —
   click **Always Allow**. The install script deliberately exercises every
   stored key while you're at the Mac, so the prompt can never hang a remote
   sign-in behind a locked screen.
3. Load the extension: `chrome://extensions` → Developer mode →
   *Load unpacked* → the `extension/` directory. Restart Chrome.
4. Telegram approvals:
   `TELEGRAM_BOT_TOKEN=<token> "$HOME/Library/Application Support/passkeyd/bin/passkeyd" setup-telegram`
   then send the exact `/pair …` command printed locally to your bot in a
   **private chat** within 120 seconds. Each setup run generates a fresh
   one-shot challenge; queued messages, groups, and old commands cannot enroll
   an approver. Unmatched or expired challenges leave the previous identity intact.
   The offline setup flow can be tested with `python3 scripts/e2e_telegram.py`
   (local Bot API fixture and isolated config; no real bot needed).
5. Check it works: `passkeyd test-approval` (Touch ID) and
   `passkeyd test-approval --remote` (Telegram).

Existing credentials and config remain compatible. The per-origin quota uses
a new `approvals-by-origin.json` file; the old global attempt history is not
carried over. After updating, run `scripts/install.sh`, reload the extension,
and restart Chrome so older native hosts are no longer running.

Config lives in `~/Library/Application Support/passkeyd/config.json`
(`allowedRps`, timeouts, rate limit, `forceRemote`). Logs:
`~/Library/Logs/passkeyd.log`.

## Register a passkey

Registration capture is **off by default**: adding a passkey behaves natively
(browser/iCloud) even on allowlisted sites. To register a passkey **into
passkeyd**, click the extension icon and check **Capture passkey
registrations** first, then add a security key / passkey on the site as usual
(Touch ID confirms). The toggle is persistent — turn it back off afterwards if
you want later enrollments to stay native. Sign-ins are unaffected by the
toggle: passkeyd serves them whenever it holds a credential for the site, and
falls through to the browser otherwise. Keep a native iCloud Keychain passkey
enrolled as a backup — passkeyd credentials are device-bound and don't sync.

## CLI

```
passkeyd list                 # stored credentials
passkeyd delete <cred-id>     # remove credential + key
passkeyd probe                # which key backend is active
passkeyd setup-telegram       # pair your private Telegram chat using a fresh challenge
passkeyd test-approval        # one approval round-trip
```

## Security model (short)

- The signing key never leaves the daemon (Secure Enclave when signed;
  software P-256 in the login keychain otherwise). The browser only ever sees
  signatures.
- Every assertion requires an approval: Touch ID locally, Telegram remotely.
  Approvals are bound to a single request (one-shot nonce, 120 s TTL,
  deny-by-default). `maxApprovalsPerHour` limits attempts **per origin**; one
  site cannot consume another site's quota. Updates are locked across processes.
- Browser requests are bounded: one outstanding request per origin, four
  overall, and 20 native requests per minute per origin (a sign-in usually uses
  a lookup plus an assertion). Busy or limited requests fail immediately.
- Only one remote approval or setup session per bot may poll on this Mac.
  A concurrent request is denied; retry after the pending request finishes.
- Credential writes reload under a cross-process lock. Exclusion checks are
  scoped to the requesting RP and are disclosed only after approval.
- The extension service worker derives the origin from Chrome sender metadata,
  validates RP ID binding, and constructs the signed client data. Page-provided
  origins and hashes are ignored. The daemon independently checks RP ID binding
  and the configured allowlist. Only top-level browser documents are supported.
- Residual risk: malware running as your user could talk to the keychain
  directly. Signing the binary with a developer identity and Secure Enclave
  keys raises that bar. This tool is for personal use on a machine you trust.

## Known risks — read before adopting

- **A Telegram tap mints a "user verified" assertion.** Remote approvals set
  the WebAuthn UV flag with no biometric at signing time. Sites believe the
  user was verified; in reality, whoever controls your Telegram session (an
  unlocked phone, a leaked bot token) can approve sign-ins whenever the
  daemon is reachable. Guard your phone and bot token accordingly, and give
  the bot its own dedicated token. The local polling lock cannot coordinate
  another machine or an unrelated application consuming the same bot.
- **Software keys are extractable.** Without a paid developer identity the
  binary can't use the Secure Enclave, so keys are ordinary login-keychain
  items: anything running as your user that can answer (or has ACL access to)
  the keychain can sign with — or export — them. The approval gate is policy,
  not a hardware boundary.
- **The daemon trusts its caller's origin claim.** Chrome enforces which
  extension may launch the native host, but any local process can run the
  binary directly and claim an allowlisted origin. Approvals (Touch ID /
  Telegram, with the site name in the prompt) are the backstop; read the
  prompt before tapping.
- **Local callers remain trusted.** Browser requests use Chrome-provided origin
  metadata, but this does not authenticate a process invoking the native host
  directly. The native protocol remains a local trust boundary.
- The per-origin hourly limit is prompt-fatigue protection. An attacker
  executing scripts within a legitimate origin can still exhaust that origin's
  budget; this does not authorize signing or consume other origins' quotas.
- Credentials are device-bound and don't sync. Losing the Mac (or the
  keychain) loses them — keep a native iCloud Keychain passkey enrolled as a
  backup on every important account.

## Development

```
swift build && swift test           # unit tests
python3 scripts/e2e_protocol.py     # native-messaging protocol e2e
python3 scripts/e2e_browser.py      # full browser e2e (Chrome for Testing)
node --test Tests/extension/*.test.cjs  # origin/client-data security checks
python3 scripts/e2e_state.py        # multiprocess credential and quota updates
python3 scripts/e2e_telegram.py     # pairing CLI with local Bot API fixture
python3 scripts/e2e_approvals.py    # approvals, polling ownership, exclusion privacy
python3 scripts/e2e_admission.py    # browser flood limits with keyless native host
```

See [AGENTS.md](AGENTS.md) for constraints and conventions.
