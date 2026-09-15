import Foundation
import Network
import Security

final class Waiter {
    private let sem = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private(set) var decision: Bool?

    func resolve(_ v: Bool) {
        lock.lock()
        defer { lock.unlock() }
        guard decision == nil else { return }
        decision = v
        sem.signal()
    }

    func wait(until deadline: Date) -> Bool? {
        _ = sem.wait(timeout: .now() + max(0, deadline.timeIntervalSinceNow))
        return decision
    }
}

final class Telegram {
    let token: String

    init(token: String) { self.token = token }

    func api(_ method: String, _ params: [String: Any] = [:], timeout: TimeInterval = 15) -> [String: Any]? {
        guard let url = URL(string: "https://api.telegram.org/bot\(token)/\(method)") else { return nil }
        var req = URLRequest(url: url, timeoutInterval: timeout)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: params)
        let sem = DispatchSemaphore(value: 0)
        var result: [String: Any]?
        URLSession.shared.dataTask(with: req) { data, _, _ in
            if let d = data {
                result = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any]
            }
            sem.signal()
        }.resume()
        sem.wait()
        return result
    }
}

/// Secondary approval path: a tiny HTTP listener that only answers for the current
/// nonce, reachable over the tailnet while a request is pending. WireGuard is the
/// transport security; the source-address check keeps it off the LAN/internet.
final class ApproveHTTP {
    private var listener: NWListener?
    private let port: UInt16
    private let nonce: String
    private let waiter: Waiter

    init(port: UInt16, nonce: String, waiter: Waiter) {
        self.port = port
        self.nonce = nonce
        self.waiter = waiter
    }

    func start() {
        guard let p = NWEndpoint.Port(rawValue: port), let l = try? NWListener(using: .tcp, on: p) else {
            Log.info("approve http: port \(port) unavailable")
            return
        }
        l.newConnectionHandler = { [self] conn in
            conn.start(queue: .global())
            conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, _ in
                var status = "404 Not Found"
                var body = "unknown"
                if let d = data,
                   let line = String(data: d, encoding: .utf8)?.components(separatedBy: "\r\n").first,
                   self.allowed(conn) {
                    if line.hasPrefix("GET /a/\(self.nonce) ") {
                        self.waiter.resolve(true)
                        status = "200 OK"
                        body = "approved"
                    } else if line.hasPrefix("GET /d/\(self.nonce) ") {
                        self.waiter.resolve(false)
                        status = "200 OK"
                        body = "denied"
                    }
                }
                let resp = "HTTP/1.1 \(status)\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
                conn.send(content: Data(resp.utf8), completion: .contentProcessed { _ in conn.cancel() })
            }
        }
        l.start(queue: .global())
        listener = l
    }

    func stop() { listener?.cancel() }

    private func allowed(_ conn: NWConnection) -> Bool {
        guard case let .hostPort(host, _)? = conn.currentPath?.remoteEndpoint else { return false }
        let h = "\(host)"
        if h.hasPrefix("127.") || h.hasPrefix("::1") { return true }
        let parts = h.split(separator: ".")
        if parts.count == 4, parts[0] == "100", let b = Int(parts[1]), (64...127).contains(b) {
            return true  // tailscale CGNAT range 100.64.0.0/10
        }
        return h.hasPrefix("fd7a:115c:a1e0")  // tailscale IPv6 range
    }
}

final class RemoteApproval {
    private let cfg: Config

    init(cfg: Config) { self.cfg = cfg }

    func request(_ req: ApprovalRequest) -> Bool {
        guard !cfg.telegramToken.isEmpty, cfg.telegramChatId != 0 else {
            Log.info("remote approval unavailable: run `passkeyd setup-telegram` first")
            return false
        }
        var nonceBytes = Data(count: 16)
        _ = nonceBytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        let nonce = nonceBytes.map { String(format: "%02x", $0) }.joined()

        let waiter = Waiter()
        let http = ApproveHTTP(port: cfg.approvePort, nonce: nonce, waiter: waiter)
        http.start()
        defer { http.stop() }

        let tg = Telegram(token: cfg.telegramToken)
        let host = ProcessInfo.processInfo.hostName
        let linkHost = cfg.tailnetHost.isEmpty ? Net.tailscaleIPv4() : cfg.tailnetHost
        var text = """
        🔐 passkey approval
        \(req.operation): \(req.rpId)
        user: \(req.userName)
        from: \(host)
        """
        if let linkHost {
            text += "\nfallback: http://\(linkHost):\(cfg.approvePort)/a/\(nonce)"
        }
        let markup: [String: Any] = ["inline_keyboard": [[
            ["text": "✅ Approve", "callback_data": "a:\(nonce)"],
            ["text": "❌ Deny", "callback_data": "d:\(nonce)"],
        ]]]
        guard let resp = tg.api("sendMessage", ["chat_id": cfg.telegramChatId,
                                                "text": text, "reply_markup": markup]),
              resp["ok"] as? Bool == true,
              let msg = resp["result"] as? [String: Any],
              let msgId = msg["message_id"] as? Int else {
            Log.info("telegram sendMessage failed")
            return false
        }

        let deadline = Date().addingTimeInterval(TimeInterval(cfg.remoteTimeoutSec))
        let chatId = cfg.telegramChatId
        Thread.detachNewThread {
            var offset: Int64 = 0
            while Date() < deadline, waiter.decision == nil {
                guard let r = tg.api("getUpdates",
                                     ["timeout": 20, "offset": offset,
                                      "allowed_updates": ["callback_query"]],
                                     timeout: 30),
                      let updates = r["result"] as? [[String: Any]] else { continue }
                for u in updates {
                    if let id = u["update_id"] as? Int64 { offset = max(offset, id + 1) }
                    guard let cq = u["callback_query"] as? [String: Any],
                          let data = cq["data"] as? String,
                          let from = cq["from"] as? [String: Any],
                          let fromId = from["id"] as? Int64,
                          let cqId = cq["id"] as? String else { continue }
                    _ = tg.api("answerCallbackQuery", ["callback_query_id": cqId])
                    guard fromId == chatId else { continue }  // only the configured user
                    if data == "a:\(nonce)" { waiter.resolve(true) }
                    else if data == "d:\(nonce)" { waiter.resolve(false) }
                }
            }
        }

        let ok = waiter.wait(until: deadline) ?? false
        _ = tg.api("editMessageText", ["chat_id": chatId, "message_id": msgId,
                                       "text": text + "\n\n" + (ok ? "✅ approved" : "❌ denied / expired")])
        return ok
    }
}
