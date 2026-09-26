import XCTest
@testable import passkeyd

final class RateLimitTests: XCTestCase {
    func testConcurrentReservationsAndOriginIsolation() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let resultLock = NSLock()
        var allowed = 0
        DispatchQueue.concurrentPerform(iterations: 50) { _ in
            if RateLimit(dir: dir).allow(origin: "https://a.okta.com", maxPerHour: 1) {
                resultLock.lock(); allowed += 1; resultLock.unlock()
            }
        }
        XCTAssertEqual(allowed, 1)
        XCTAssertTrue(RateLimit(dir: dir).allow(origin: "https://b.okta.com", maxPerHour: 1))
    }

    func testExpiryAndPersistenceFailures() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let rate = RateLimit(dir: dir)
        let now = Date()
        XCTAssertTrue(rate.allow(origin: "https://github.com", maxPerHour: 1, now: now))
        XCTAssertFalse(rate.allow(origin: "https://github.com", maxPerHour: 1, now: now))
        XCTAssertTrue(rate.allow(origin: "https://github.com", maxPerHour: 1, now: now.addingTimeInterval(3600)))
        let url = dir.appendingPathComponent("approvals-by-origin.json")
        try Data("corrupt".utf8).write(to: url)
        XCTAssertFalse(rate.allow(origin: "https://github.com", maxPerHour: 1))
        try FileManager.default.removeItem(at: url)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        XCTAssertFalse(rate.allow(origin: "https://github.com", maxPerHour: 1))
    }

    func testTelegramPollingLeaseIsSharedAndReleased() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let first = try Telegram(token: "fake-bot-A").acquirePollingLock(dir: dir)
        XCTAssertThrowsError(try Telegram(token: "fake-bot-A").acquirePollingLock(dir: dir))
        let other = try Telegram(token: "fake-bot-B").acquirePollingLock(dir: dir)
        other.unlock()
        first.unlock()
        let retry = try Telegram(token: "fake-bot-A").acquirePollingLock(dir: dir)
        retry.unlock()
    }
}
