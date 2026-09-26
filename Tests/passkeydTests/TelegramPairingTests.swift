import XCTest
@testable import passkeyd

final class TelegramPairingTests: XCTestCase {
    private let start = Date(timeIntervalSince1970: 1_800_000_000)

    private func update(_ command: String, type: String = "private", chatId: Int64 = 777,
                        senderId: Int64 = 777, bot: Bool = false,
                        date: Int64 = 1_800_000_000) -> [String: Any] {
        ["update_id": Int64(1), "message": ["text": command, "date": date,
          "chat": ["id": chatId, "type": type], "from": ["id": senderId, "is_bot": bot]]]
    }

    func testQueuedStrangerDoesNotPreventOwnerPairing() throws {
        let p = try TelegramPairing(now: start)
        XCTAssertNil(p.accept(update("hello", chatId: 666, senderId: 666), now: start))
        XCTAssertNil(p.accept(update("/pair wrong", chatId: 666, senderId: 666), now: start))
        XCTAssertEqual(p.accept(update(p.command), now: start), 777)
        XCTAssertNil(p.accept(update(p.command), now: start), "pairing is one-shot")
    }

    func testRejectsPublicChatsBotsAndMismatchedIdentity() throws {
        let p = try TelegramPairing(now: start)
        for u in [update(p.command, type: "group"), update(p.command, type: "supergroup"),
                  update(p.command, bot: true), update(p.command, senderId: 666),
                  update(p.command, chatId: -1, senderId: -1)] {
            XCTAssertNil(p.accept(u, now: start))
        }
        XCTAssertEqual(p.accept(update(p.command), now: start), 777)
    }

    func testOnlyFreshMessagesWithinDeadlineAreAccepted() throws {
        let p = try TelegramPairing(now: start)
        XCTAssertNil(p.accept(update(p.command, date: 1_799_999_999), now: start))
        XCTAssertNil(p.accept(update(p.command), now: p.deadline))
        XCTAssertNil(p.accept(update(p.command), now: p.deadline.addingTimeInterval(1)))
    }

    func testOldSetupChallengeAndNonMessageUpdatesCannotPair() throws {
        let old = try TelegramPairing(now: start)
        let p = try TelegramPairing(now: start)
        XCTAssertNil(p.accept(update(old.command), now: start))
        XCTAssertNil(p.accept(["edited_message": update(p.command)["message"]!], now: start))
        XCTAssertNil(p.accept(["callback_query": ["data": p.command]], now: start))
        XCTAssertNil(p.accept(["message": ["text": p.command]], now: start))
        XCTAssertEqual(p.accept(update(p.command), now: start.addingTimeInterval(119)), 777)
    }
}
