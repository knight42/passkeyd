import Darwin
import Foundation

enum Net {
    /// This machine's Tailscale IPv4: the first interface address inside the
    /// Tailscale CGNAT range 100.64.0.0/10.
    static func tailscaleIPv4() -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return nil }
        defer { freeifaddrs(ifaddr) }
        var ptr = ifaddr
        while let p = ptr {
            defer { ptr = p.pointee.ifa_next }
            guard let sa = p.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else { continue }
            var addr = sockaddr_in()
            memcpy(&addr, sa, MemoryLayout<sockaddr_in>.size)
            let ip = UInt32(bigEndian: addr.sin_addr.s_addr)
            let a = UInt8(ip >> 24)
            let b = UInt8((ip >> 16) & 0xff)
            guard a == 100, (64...127).contains(b) else { continue }
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            var sin = addr.sin_addr
            inet_ntop(AF_INET, &sin, &buf, socklen_t(INET_ADDRSTRLEN))
            return String(cString: buf)
        }
        return nil
    }
}
