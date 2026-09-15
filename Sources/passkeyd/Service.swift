import Foundation
import Security

final class Service {
    let cfg: Config
    let store: Store
    let backend: KeyBackend
    let approver: Approver

    init() throws {
        cfg = Config.load()
        try FileManager.default.createDirectory(at: Config.dir, withIntermediateDirectories: true)
        store = try Store(dir: Config.dir)
        backend = probeBackend { Log.info($0) }
        approver = Approver(cfg: cfg, dir: Config.dir)
    }

    func backendFor(_ name: String) -> KeyBackend {
        name == "secure-enclave" ? SecureEnclaveBackend() : SoftwareBackend()
    }

    func handle(_ req: [String: Any]) -> [String: Any] {
        let op = req["op"] as? String ?? ""
        do {
            switch op {
            case "has": return try has(req)
            case "get": return try get(req)
            case "create": return try create(req)
            default: return ["ok": false, "error": "unknown op \(op)"]
            }
        } catch {
            return ["ok": false, "error": "\(error)"]
        }
    }

    private func rpParams(_ req: [String: Any]) throws -> (rpId: String, origin: String) {
        guard let rpId = req["rpId"] as? String, let origin = req["origin"] as? String else {
            throw fail("missing rpId/origin")
        }
        guard RpId.validate(rpId: rpId, origin: origin, allowedRps: cfg.allowedRps) else {
            throw fail("rpId \(rpId) rejected for origin \(origin)")
        }
        return (rpId, origin)
    }

    private func has(_ req: [String: Any]) throws -> [String: Any] {
        let (rpId, _) = try rpParams(req)
        let allow = req["allow"] as? [String] ?? []
        let found = !store.find(rpId: rpId, allow: allow).isEmpty
        Log.info("has rp=\(rpId) allow=\(allow.map { $0.prefix(8) }) -> \(found)")
        return ["ok": true, "has": found]
    }

    private func get(_ req: [String: Any]) throws -> [String: Any] {
        let (rpId, origin) = try rpParams(req)
        guard let hashB64 = req["clientDataHash"] as? String,
              let hash = B64URL.decode(hashB64) else {
            throw fail("missing clientDataHash")
        }
        let allow = req["allow"] as? [String] ?? []
        guard let cred = store.find(rpId: rpId, allow: allow).first else {
            throw fail("no credential for \(rpId)")
        }
        Log.info("get rp=\(rpId) origin=\(origin) cred=\(cred.id.prefix(8))…")
        guard approver.approve(.init(rpId: rpId, userName: cred.userName, operation: "sign in")) else {
            throw fail("not approved")
        }
        let key = try backendFor(cred.backend).load(tag: cred.id)
        let authData = AuthData.assertion(rpId: rpId)
        let sig = try key.signDER(authData + hash)
        return [
            "ok": true,
            "id": cred.id,
            "authenticatorData": B64URL.encode(authData),
            "signature": B64URL.encode(sig),
            "userHandle": cred.userHandle,
        ]
    }

    private func create(_ req: [String: Any]) throws -> [String: Any] {
        let (rpId, origin) = try rpParams(req)
        guard let user = req["user"] as? [String: Any],
              let userName = user["name"] as? String,
              let userHandle = user["id"] as? String else {
            throw fail("missing user")
        }
        let algs = req["algs"] as? [Int] ?? [-7]
        guard algs.contains(-7) else { throw fail("RP does not accept ES256") }
        let excludeIds = req["excludeIds"] as? [String] ?? []
        if store.credentials.contains(where: { excludeIds.contains($0.id) }) {
            throw fail("already registered here (excludeCredentials)")
        }
        Log.info("create rp=\(rpId) origin=\(origin) user=\(userName)")
        guard approver.approve(.init(rpId: rpId, userName: userName, operation: "register")) else {
            throw fail("not approved")
        }
        var idBytes = Data(count: 32)
        _ = idBytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let id = B64URL.encode(idBytes)
        let key = try backend.generate(tag: id)
        let authData = AuthData.attested(rpId: rpId, credentialId: idBytes, x: key.x, y: key.y)
        try store.add(.init(id: id, rpId: rpId, userName: userName, userHandle: userHandle,
                            backend: backend.name, createdAt: Date()))
        return [
            "ok": true,
            "id": id,
            "attestationObject": B64URL.encode(AuthData.attestationObject(authData: authData)),
            "authenticatorData": B64URL.encode(authData),
            "publicKey": B64URL.encode(key.spkiDER),
            "publicKeyAlgorithm": -7,
        ]
    }
}
