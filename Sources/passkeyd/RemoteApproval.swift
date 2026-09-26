import CryptoKit
import Foundation
import Security

final class Telegram {
    let token: String

    init(token: String) { self.token = token }

    // One polling owner per bot on this machine, shared by setup and approvals.
    // Keep the token out of filenames, and fail busy rather than queue prompts.
    func acquirePollingLock(dir: URL = Config.dir) throws -> FileLock {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let key = SHA256.hash(data: Data(token.utf8)).map { String(format: "%02x", $0) }.joined()
        return try FileLock(url: dir.appendingPathComponent("telegram-\(key).lock"), nonBlocking: true)
    }

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
        let status = nonceBytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        guard status == errSecSuccess else { return false }
        let nonce = nonceBytes.map { String(format: "%02x", $0) }.joined()

        let tg = Telegram(token: cfg.telegramToken)
        let pollingLock: FileLock
        do { pollingLock = try tg.acquirePollingLock() } catch {
            Log.info("Telegram polling busy or unavailable; denying request")
            return false
        }
        defer { pollingLock.unlock() }
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
        // Poll synchronously while holding the lease: a timed-out worker must
        // never outlive its request and consume the next request's callbacks.
        var offset: Int64 = 0
        var decision: Bool?
        while Date() < deadline, decision == nil {
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { break }
            guard let r = tg.api("getUpdates",
                                ["timeout": min(20, max(1, Int(remaining))), "offset": offset,
                                 "allowed_updates": ["callback_query"]],
                                timeout: min(30, remaining)) else { continue }
            guard Date() < deadline else { break }
            guard r["ok"] as? Bool == true else {
                Log.info("getUpdates failed")
                Thread.sleep(forTimeInterval: min(2, max(0, deadline.timeIntervalSinceNow)))
                continue
            }
            guard let updates = r["result"] as? [[String: Any]] else { continue }
            for u in updates {
                if let id = u["update_id"] as? Int64 { offset = max(offset, id + 1) }
                guard Date() < deadline,
                      let cq = u["callback_query"] as? [String: Any],
                      let data = cq["data"] as? String,
                      let from = cq["from"] as? [String: Any],
                      from["id"] as? Int64 == chatId,
                      let message = cq["message"] as? [String: Any],
                      message["message_id"] as? Int == msgId,
                      let chat = message["chat"] as? [String: Any],
                      chat["id"] as? Int64 == chatId,
                      let cqId = cq["id"] as? String,
                      data == "a:\(nonce)" || data == "d:\(nonce)" else { continue }
                decision = data == "a:\(nonce)"
                _ = tg.api("answerCallbackQuery", ["callback_query_id": cqId])
                break // one-shot; later updates cannot change the decision
            }
        }
        let ok = decision ?? false
        _ = tg.api("editMessageText", ["chat_id": chatId, "message_id": msgId,
                                       "text": text + "\n\n" + (ok ? "✅ approved" : "❌ denied / expired")])
        return ok
    }
}
