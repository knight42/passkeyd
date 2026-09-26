import Foundation

let args = CommandLine.arguments

func usage() -> Never {
    print("""
    passkeyd — personal WebAuthn authenticator (Chrome native messaging host)

    usage:
      passkeyd --stdio             run as native messaging host (Chrome invokes this)
      passkeyd setup-telegram      pair your private Telegram chat and write config
      passkeyd probe               print which key backend is active
      passkeyd list                list stored credentials
      passkeyd delete <cred-id>    delete a credential (metadata + key)
      passkeyd test-approval       run one approval round-trip (touch id or telegram)
      passkeyd test-approval --remote   force the telegram path
      passkeyd test-sign           sign test bytes with every stored key (triggers
                                   the keychain ACL prompt — click "Always Allow")
    """)
    exit(2)
}

func makeService() -> Service {
    do { return try Service() } catch {
        Log.info("fatal: \(error)")
        exit(1)
    }
}

func setupTelegram() -> Never {
    var cfg = Config.load()
    if let t = ProcessInfo.processInfo.environment["TELEGRAM_BOT_TOKEN"], !t.isEmpty {
        cfg.telegramToken = t
    }
    guard !cfg.telegramToken.isEmpty else {
        print("no token: set TELEGRAM_BOT_TOKEN or put telegramToken in \(Config.path.path)")
        exit(1)
    }
    let tg = Telegram(token: cfg.telegramToken)
    guard let me = tg.api("getMe"), me["ok"] as? Bool == true,
          let r = me["result"] as? [String: Any], let uname = r["username"] as? String else {
        print("token rejected by telegram")
        exit(1)
    }
    let pairing: TelegramPairing
    do { pairing = try TelegramPairing() } catch {
        print("pairing setup failed: \(error)")
        exit(1)
    }
    print("bot ok: @\(uname)")
    print("send this command in a PRIVATE chat with @\(uname) within 120 seconds:")
    print(pairing.command)
    // Print the secret only to the local operator, never to Telegram or Log.
    var offset: Int64 = 0
    while Date() < pairing.deadline {
        guard let r = tg.api("getUpdates", ["timeout": 20, "offset": offset,
                                           "allowed_updates": ["message"]], timeout: 30) else { continue }
        guard r["ok"] as? Bool == true else {
            // e.g. 409 Conflict: another process (webhook or long-poll) owns this
            // bot and is eating its updates — passkeyd needs its own bot token.
            print("telegram getUpdates error: \(r["description"] as? String ?? "\(r)")")
            exit(1)
        }
        guard let updates = r["result"] as? [[String: Any]] else { continue }
        for u in updates {
            if let id = u["update_id"] as? Int64 { offset = max(offset, id + 1) }
            if let cid = pairing.accept(u) {
                cfg.telegramChatId = cid
                do { try cfg.save() } catch {
                    print("could not save Telegram pairing: \(error)")
                    exit(1)
                }
                print("chat id \(cid) saved to \(Config.path.path)")
                exit(0)
            }
        }
    }
    print("pairing expired without a matching private-chat command; run again")
    exit(1)
}

if args.contains("--stdio") || args.contains(where: { $0.hasPrefix("chrome-extension://") }) {
    NativeHost.run(service: makeService())
}

guard args.count >= 2 else { usage() }

switch args[1] {
case "probe":
    print(probeBackend { print($0) }.name)
case "list":
    for c in makeService().store.credentials {
        print("\(c.id)  \(c.rpId)  \(c.userName)  \(c.backend)  \(c.createdAt)")
    }
case "delete":
    guard args.count == 3 else { usage() }
    let s = makeService()
    guard let c = s.store.credentials.first(where: { $0.id == args[2] }) else {
        print("not found")
        exit(1)
    }
    s.backendFor(c.backend).destroy(tag: c.id)
    try? s.store.remove(id: c.id)
    print("deleted \(c.id) (\(c.rpId))")
case "setup-telegram":
    setupTelegram()
case "test-sign":
    // The keychain ACL is bound to the binary's code signature, and this
    // binary is only ad-hoc signed — after every update the keychain treats
    // it as a new app and prompts on first key access. Run this right after
    // installing (install.sh does), while someone is at the Mac, so the
    // prompt never hangs an invisible sign-in behind a locked screen.
    var failed = false
    let s = makeService()
    for c in s.store.credentials {
        do {
            let key = try s.backendFor(c.backend).load(tag: c.id)
            _ = try key.signDER(Data("passkeyd test-sign".utf8))
            print("ok    \(c.id)  \(c.rpId)")
        } catch {
            failed = true
            print("FAIL  \(c.id)  \(c.rpId): \(error)")
        }
    }
    exit(failed ? 1 : 0)
case "test-approval":
    let s = makeService()
    let req = ApprovalRequest(rpId: "example.com", userName: "test", operation: "test")
    let ok: Bool
    if args.contains("--remote") {
        ok = RemoteApproval(cfg: s.cfg).request(req)
    } else {
        ok = s.approver.approve(req)
    }
    print(ok ? "approved" : "denied")
    exit(ok ? 0 : 1)
default:
    usage()
}
