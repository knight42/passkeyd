import Foundation
import Security

/// A local, short-lived capability proving which private Telegram chat the
/// operator intends to enroll. Unsolicited or previously queued messages cannot
/// establish the approval identity, even when they arrive first.
final class TelegramPairing {
    let command: String
    let deadline: Date
    private let issuedAt: Int64
    private var consumed = false

    init(now: Date = Date(), timeout: TimeInterval = 120) throws {
        var bytes = Data(count: 16)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw fail("could not generate pairing challenge") }
        command = "/pair " + bytes.map { String(format: "%02x", $0) }.joined()
        issuedAt = Int64(now.timeIntervalSince1970)
        deadline = now.addingTimeInterval(timeout)
    }

    func accept(_ update: [String: Any], now: Date = Date()) -> Int64? {
        guard !consumed, now < deadline,
              let message = update["message"] as? [String: Any],
              message["text"] as? String == command,
              let sentAt = message["date"] as? Int64, sentAt >= issuedAt,
              let chat = message["chat"] as? [String: Any],
              chat["type"] as? String == "private",
              let chatId = chat["id"] as? Int64, chatId > 0,
              let sender = message["from"] as? [String: Any],
              sender["id"] as? Int64 == chatId,
              sender["is_bot"] as? Bool == false else { return nil }
        consumed = true
        return chatId
    }
}
