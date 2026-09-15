import CryptoKit
import Foundation
import Security

struct PasskeydError: Error, CustomStringConvertible { let description: String }
func fail(_ msg: String) -> PasskeydError { PasskeydError(description: msg) }

protocol SigningKey {
    var x: Data { get }
    var y: Data { get }
    var spkiDER: Data { get }
    func signDER(_ message: Data) throws -> Data
}

protocol KeyBackend {
    var name: String { get }
    func generate(tag: String) throws -> SigningKey
    func load(tag: String) throws -> SigningKey
    func destroy(tag: String)
}

// MARK: - Secure Enclave

struct SEKey: SigningKey {
    let key: SecKey

    private var pubX963: Data {
        guard let pub = SecKeyCopyPublicKey(key),
              let d = SecKeyCopyExternalRepresentation(pub, nil) as Data?
        else { return Data() }
        return d
    }

    var x: Data { pubX963.subdata(in: 1..<33) }
    var y: Data { pubX963.subdata(in: 33..<65) }
    var spkiDER: Data {
        (try? P256.Signing.PublicKey(x963Representation: pubX963).derRepresentation) ?? Data()
    }

    func signDER(_ message: Data) throws -> Data {
        var err: Unmanaged<CFError>?
        // Message variant: hashes the raw authData‖clientDataHash with SHA-256 internally.
        guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                              message as CFData, &err) as Data? else {
            throw fail("SE sign failed: \(err?.takeRetainedValue().localizedDescription ?? "?")")
        }
        return sig
    }
}

final class SecureEnclaveBackend: KeyBackend {
    let name = "secure-enclave"

    private func tagData(_ tag: String) -> Data { Data("passkeyd.se.\(tag)".utf8) }

    func generate(tag: String) throws -> SigningKey {
        var acErr: Unmanaged<CFError>?
        // privateKeyUsage only — a userPresence/biometry ACL would force a local
        // Touch ID prompt and deadlock the remote-approval path.
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &acErr)
        else {
            throw fail("access control: \(acErr?.takeRetainedValue().localizedDescription ?? "?")")
        }
        let attrs: [String: Any] = [
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave as String,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom as String,
            kSecAttrKeySizeInBits as String: 256,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData(tag),
                kSecAttrAccessControl as String: ac,
            ] as [String: Any],
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
            throw fail("SE keygen failed: \(err?.takeRetainedValue().localizedDescription ?? "?")")
        }
        return SEKey(key: key)
    }

    func load(tag: String) throws -> SigningKey {
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData(tag),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom as String,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
        ]
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        guard st == errSecSuccess, let ref = out else { throw fail("SE key \(tag) not found (\(st))") }
        return SEKey(key: ref as! SecKey)
    }

    func destroy(tag: String) {
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData(tag),
            kSecUseDataProtectionKeychain as String: true,
        ]
        SecItemDelete(q as CFDictionary)
    }

    /// Probe the full generate-persist path: SE keygen works from any process, but
    /// persisting into the data-protection keychain requires a properly signed binary.
    static func available() -> Bool {
        let be = SecureEnclaveBackend()
        guard (try? be.generate(tag: "probe")) != nil else { return false }
        be.destroy(tag: "probe")
        return true
    }
}

// MARK: - Software fallback (P-256 in the login keychain)

struct SoftwareKey: SigningKey {
    let priv: P256.Signing.PrivateKey

    var x: Data { priv.publicKey.x963Representation.subdata(in: 1..<33) }
    var y: Data { priv.publicKey.x963Representation.subdata(in: 33..<65) }
    var spkiDER: Data { priv.publicKey.derRepresentation }

    func signDER(_ message: Data) throws -> Data {
        // CryptoKit hashes `message` with SHA-256 internally, matching the SE path.
        try priv.signature(for: message).derRepresentation
    }
}

final class SoftwareBackend: KeyBackend {
    let name = "software"
    private let service = "passkeyd credential key"

    func generate(tag: String) throws -> SigningKey {
        let priv = P256.Signing.PrivateKey()
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
            kSecValueData as String: priv.rawRepresentation,
        ]
        let st = SecItemAdd(add as CFDictionary, nil)
        guard st == errSecSuccess else { throw fail("keychain add failed (\(st))") }
        return SoftwareKey(priv: priv)
    }

    func load(tag: String) throws -> SigningKey {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
            kSecReturnData as String: true,
        ]
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        guard st == errSecSuccess, let d = out as? Data else {
            throw fail("software key \(tag) not found (\(st))")
        }
        return SoftwareKey(priv: try P256.Signing.PrivateKey(rawRepresentation: d))
    }

    func destroy(tag: String) {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
        ]
        SecItemDelete(q as CFDictionary)
    }
}

func probeBackend(log: (String) -> Void) -> KeyBackend {
    if SecureEnclaveBackend.available() { return SecureEnclaveBackend() }
    log("secure enclave unavailable (unsigned binary, or no SE); using software keys in the login keychain")
    return SoftwareBackend()
}
