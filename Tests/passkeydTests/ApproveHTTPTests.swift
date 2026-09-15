import XCTest

@testable import passkeyd

final class ApproveHTTPTests: XCTestCase {
    private func fetch(_ url: String) -> Int {
        let sem = DispatchSemaphore(value: 0)
        var code = 0
        URLSession.shared.dataTask(with: URL(string: url)!) { _, resp, _ in
            code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            sem.signal()
        }.resume()
        sem.wait()
        return code
    }

    func testApproveOverLoopback() {
        let waiter = Waiter()
        let http = ApproveHTTP(port: 18378, nonce: "deadbeef", waiter: waiter)
        http.start()
        defer { http.stop() }
        Thread.sleep(forTimeInterval: 0.3)

        XCTAssertEqual(fetch("http://127.0.0.1:18378/a/wrongnonce"), 404)
        XCTAssertNil(waiter.decision)

        XCTAssertEqual(fetch("http://127.0.0.1:18378/a/deadbeef"), 200)
        XCTAssertEqual(waiter.wait(until: Date().addingTimeInterval(2)), true)
    }

    func testDenyOverLoopback() {
        let waiter = Waiter()
        let http = ApproveHTTP(port: 18379, nonce: "cafe", waiter: waiter)
        http.start()
        defer { http.stop() }
        Thread.sleep(forTimeInterval: 0.3)

        XCTAssertEqual(fetch("http://127.0.0.1:18379/d/cafe"), 200)
        XCTAssertEqual(waiter.wait(until: Date().addingTimeInterval(2)), false)
    }
}
