import Foundation
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

/// Remote approval over Telegram only: the daemon long-polls getUpdates for the
/// inline-button callback, so everything is outbound HTTPS — no inbound listener,
/// no tailnet/VPN required.
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
        let tg = Telegram(token: cfg.telegramToken)
        let host = ProcessInfo.processInfo.hostName
        let text = """
        🔐 passkey approval
        \(req.operation): \(req.rpId)
        user: \(req.userName)
        from: \(host)
        """
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
                                     timeout: 30) else { continue }
                guard r["ok"] as? Bool == true else {
                    Log.info("getUpdates error: \(r["description"] as? String ?? "\(r)")")
                    Thread.sleep(forTimeInterval: 2)  // error responses return fast; don't hammer
                    continue
                }
                guard let updates = r["result"] as? [[String: Any]] else { continue }
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
