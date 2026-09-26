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

        XCTAssertEqual(try store.find(rpId: "webauthn.io", allow: []).count, 1)
        XCTAssertEqual(try store.find(rpId: "webauthn.io", allow: ["abc"]).count, 1)
        XCTAssertEqual(try store.find(rpId: "webauthn.io", allow: ["other"]).count, 0)
        XCTAssertEqual(try store.find(rpId: "okta.com", allow: []).count, 0)

        let reloaded = try Store(dir: dir)
        XCTAssertEqual(try reloaded.all().count, 1)
        XCTAssertEqual(try reloaded.all()[0].userName, "zack")

        try reloaded.remove(id: "abc")
        XCTAssertTrue(try Store(dir: dir).all().isEmpty)
    }
}

extension StoreTests {
    private func credential(_ id: String, rp: String = "github.com") -> Credential {
        .init(id: id, rpId: rp, userName: "test", userHandle: "YQ", backend: "software", createdAt: Date())
    }

    func testOverlappingStoresPreserveAddsAndDoNotResurrectDeletes() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let a = try Store(dir: dir), b = try Store(dir: dir)
        try a.add(credential("A"))
        try b.add(credential("B"))
        XCTAssertEqual(Set(try a.all().map(\.id)), ["A", "B"])
        try a.remove(id: "A")
        try b.add(credential("C"))
        XCTAssertEqual(Set(try a.all().map(\.id)), ["B", "C"])
    }

    func testExclusionIsScopedToRPAndDoesNotInsertOnFailure() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try Store(dir: dir)
        try store.add(credential("github"))
        try store.add(credential("other", rp: "webauthn.io"), excluding: ["github"])
        XCTAssertThrowsError(try store.add(credential("duplicate"), excluding: ["github"]))
        XCTAssertEqual(try store.all().count, 2)
    }

    func testCorruptOrUnreadableStateIsNeverReplacedWithEmptyStore() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try Store(dir: dir)
        let url = dir.appendingPathComponent("credentials.json")
        try Data("corrupt".utf8).write(to: url)
        XCTAssertThrowsError(try store.add(credential("A")))
        XCTAssertEqual(try String(contentsOf: url), "corrupt")
        try FileManager.default.removeItem(at: url)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        XCTAssertThrowsError(try store.add(credential("A")))
    }
}
