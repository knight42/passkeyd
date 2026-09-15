import XCTest

@testable import passkeyd

final class NetTests: XCTestCase {
    func testTailscaleIPv4InCGNATRange() throws {
        guard let ip = Net.tailscaleIPv4() else {
            throw XCTSkip("no tailscale interface on this machine")
        }
        let parts = ip.split(separator: ".").compactMap { Int($0) }
        XCTAssertEqual(parts.count, 4, ip)
        XCTAssertEqual(parts[0], 100, ip)
        XCTAssertTrue((64...127).contains(parts[1]), ip)
        print("detected tailscale ip: \(ip)")
    }
}
