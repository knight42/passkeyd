import Foundation

/// Minimal canonical CBOR encoder — only the shapes WebAuthn responses need.
enum CBOR {
    static func head(major: UInt8, value: UInt64) -> Data {
        var d = Data()
        let m = major << 5
        switch value {
        case 0..<24:
            d.append(m | UInt8(value))
        case 24...UInt64(UInt8.max):
            d.append(m | 24)
            d.append(UInt8(value))
        case ...UInt64(UInt16.max):
            d.append(m | 25)
            d.append(contentsOf: withUnsafeBytes(of: UInt16(value).bigEndian, Array.init))
        case ...UInt64(UInt32.max):
            d.append(m | 26)
            d.append(contentsOf: withUnsafeBytes(of: UInt32(value).bigEndian, Array.init))
        default:
            d.append(m | 27)
            d.append(contentsOf: withUnsafeBytes(of: value.bigEndian, Array.init))
        }
        return d
    }

    static func int(_ v: Int) -> Data {
        v >= 0 ? head(major: 0, value: UInt64(v)) : head(major: 1, value: UInt64(-1 - v))
    }

    static func bytes(_ d: Data) -> Data { head(major: 2, value: UInt64(d.count)) + d }

    static func text(_ s: String) -> Data {
        let u = Data(s.utf8)
        return head(major: 3, value: UInt64(u.count)) + u
    }

    /// Map from pre-encoded (key, value) pairs, emitted in the order given.
    /// Callers are responsible for canonical key order.
    static func map(_ pairs: [(Data, Data)]) -> Data {
        pairs.reduce(head(major: 5, value: UInt64(pairs.count))) { $0 + $1.0 + $1.1 }
    }
}
