import CryptoKit
import XCTest

@testable import passkeyd

final class AuthDataTests: XCTestCase {
    func testCBOREncodings() {
        let cases: [String: (got: Data, want: Data)] = [
            "uint 0": (CBOR.int(0), Data([0x00])),
            "uint 23": (CBOR.int(23), Data([0x17])),
            "uint 24": (CBOR.int(24), Data([0x18, 24])),
            "uint 256": (CBOR.int(256), Data([0x19, 0x01, 0x00])),
            "neg -7": (CBOR.int(-7), Data([0x26])),
            "text fmt": (CBOR.text("fmt"), Data([0x63, 0x66, 0x6D, 0x74])),
            "empty map": (CBOR.map([]), Data([0xA0])),
            "bytes": (CBOR.bytes(Data([0xAB])), Data([0x41, 0xAB])),
        ]
        for (name, c) in cases {
            XCTAssertEqual(c.got, c.want, name)
        }
    }

    func testAssertionAuthData() {
        let d = AuthData.assertion(rpId: "webauthn.io")
        XCTAssertEqual(d.count, 37)
        XCTAssertEqual(d.prefix(32), Data(SHA256.hash(data: Data("webauthn.io".utf8))))
        XCTAssertEqual(d[32], 0x05)  // UP|UV
        XCTAssertEqual(d.suffix(4), Data([0, 0, 0, 0]))
    }

    func testAttestedAuthDataLayout() {
        let x = Data(repeating: 1, count: 32)
        let y = Data(repeating: 2, count: 32)
        let credId = Data(repeating: 9, count: 32)
        let d = AuthData.attested(rpId: "example.com", credentialId: credId, x: x, y: y)
        XCTAssertEqual(d[32], 0x45)  // UP|UV|AT
        XCTAssertEqual(Data(d[37..<53]), Data(count: 16))  // zero AAGUID
        XCTAssertEqual(Data(d[53..<55]), Data([0, 32]))  // credId length
        XCTAssertEqual(Data(d[55..<87]), credId)
        XCTAssertEqual(d[87], 0xA5)  // COSE key: 5-entry map
    }

    func testAttestationObjectShape() {
        let obj = AuthData.attestationObject(authData: Data([0xAA]))
        var want = Data([0xA3])
        want += CBOR.text("fmt") + CBOR.text("none")
        want += CBOR.text("attStmt") + Data([0xA0])
        want += CBOR.text("authData") + CBOR.bytes(Data([0xAA]))
        XCTAssertEqual(obj, want)
    }

    func testSignatureRoundTrip() throws {
        let priv = P256.Signing.PrivateKey()
        let key = SoftwareKey(priv: priv)
        let authData = AuthData.assertion(rpId: "webauthn.io")
        let hash = Data(SHA256.hash(data: Data("clientData".utf8)))
        let der = try key.signDER(authData + hash)
        let sig = try P256.Signing.ECDSASignature(derRepresentation: der)
        XCTAssertTrue(priv.publicKey.isValidSignature(sig, for: authData + hash))
    }
}
