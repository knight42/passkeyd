import CryptoKit
import Foundation

enum AuthData {
    static let flagUP: UInt8 = 0x01
    static let flagUV: UInt8 = 0x04
    static let flagAT: UInt8 = 0x40

    static func rpIdHash(_ rpId: String) -> Data { Data(SHA256.hash(data: Data(rpId.utf8))) }

    /// COSE_Key (EC2, ES256) in CTAP2 canonical order: 1, 3, -1, -2, -3.
    static func coseKey(x: Data, y: Data) -> Data {
        CBOR.map([
            (CBOR.int(1), CBOR.int(2)),   // kty: EC2
            (CBOR.int(3), CBOR.int(-7)),  // alg: ES256
            (CBOR.int(-1), CBOR.int(1)),  // crv: P-256
            (CBOR.int(-2), CBOR.bytes(x)),
            (CBOR.int(-3), CBOR.bytes(y)),
        ])
    }

    static func assertion(rpId: String) -> Data {
        var d = rpIdHash(rpId)
        d.append(flagUP | flagUV)
        d.append(contentsOf: [0, 0, 0, 0])  // signCount 0, like Apple's synced passkeys
        return d
    }

    static func attested(rpId: String, credentialId: Data, x: Data, y: Data) -> Data {
        var d = rpIdHash(rpId)
        d.append(flagUP | flagUV | flagAT)
        d.append(contentsOf: [0, 0, 0, 0])
        d.append(Data(count: 16))  // zero AAGUID
        d.append(contentsOf: [UInt8(credentialId.count >> 8), UInt8(credentialId.count & 0xff)])
        d.append(credentialId)
        d.append(coseKey(x: x, y: y))
        return d
    }

    /// attestationObject with fmt "none" (canonical key order: fmt < attStmt < authData).
    static func attestationObject(authData: Data) -> Data {
        CBOR.map([
            (CBOR.text("fmt"), CBOR.text("none")),
            (CBOR.text("attStmt"), CBOR.map([])),
            (CBOR.text("authData"), CBOR.bytes(authData)),
        ])
    }
}
