import XCTest

@testable import passkeyd

final class StoreTests: XCTestCase {
    func testAddFindRemovePersist() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("passkeyd-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = try Store(dir: dir)
        try store.add(.init(id: "abc", rpId: "webauthn.io", userName: "zack",
                            userHandle: "aGFuZGxl", backend: "software", createdAt: Date()))

        XCTAssertEqual(store.find(rpId: "webauthn.io", allow: []).count, 1)
        XCTAssertEqual(store.find(rpId: "webauthn.io", allow: ["abc"]).count, 1)
        XCTAssertEqual(store.find(rpId: "webauthn.io", allow: ["other"]).count, 0)
        XCTAssertEqual(store.find(rpId: "okta.com", allow: []).count, 0)

        let reloaded = try Store(dir: dir)
        XCTAssertEqual(reloaded.credentials.count, 1)
        XCTAssertEqual(reloaded.credentials[0].userName, "zack")

        try reloaded.remove(id: "abc")
        XCTAssertTrue(try Store(dir: dir).credentials.isEmpty)
    }
}
