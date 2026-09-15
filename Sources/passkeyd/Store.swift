import Foundation

struct Credential: Codable {
    let id: String  // base64url credential id (32 random bytes)
    let rpId: String
    let userName: String
    let userHandle: String  // base64url
    let backend: String
    let createdAt: Date
}

final class Store {
    private let url: URL
    private(set) var credentials: [Credential]

    init(dir: URL) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        url = dir.appendingPathComponent("credentials.json")
        if let d = try? Data(contentsOf: url) {
            let dec = JSONDecoder()
            dec.dateDecodingStrategy = .iso8601
            credentials = try dec.decode([Credential].self, from: d)
        } else {
            credentials = []
        }
    }

    func add(_ c: Credential) throws {
        credentials.append(c)
        try save()
    }

    func remove(id: String) throws {
        credentials.removeAll { $0.id == id }
        try save()
    }

    func find(rpId: String, allow: [String]) -> [Credential] {
        credentials.filter { $0.rpId == rpId && (allow.isEmpty || allow.contains($0.id)) }
    }

    private func save() throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        try enc.encode(credentials).write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
