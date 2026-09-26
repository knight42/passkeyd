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
    private let lockURL: URL

    init(dir: URL) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        url = dir.appendingPathComponent("credentials.json")
        lockURL = dir.appendingPathComponent("credentials.lock")
        _ = try all()
    }

    private func read() throws -> [Credential] {
        guard let data = try PrivateFile.readIfPresent(url) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode([Credential].self, from: data)
    }

    func all() throws -> [Credential] {
        let lock = try FileLock(url: lockURL)
        defer { lock.unlock() }
        return try read()
    }

    // Exclusion and insertion are one transaction, after Service obtains approval.
    func add(_ c: Credential, excluding: [String] = []) throws {
        let lock = try FileLock(url: lockURL)
        defer { lock.unlock() }
        var credentials = try read()
        guard !credentials.contains(where: { $0.rpId == c.rpId && excluding.contains($0.id) }) else {
            throw fail("already registered here (excludeCredentials)")
        }
        credentials.append(c)
        try save(credentials)
    }

    func remove(id: String) throws {
        let lock = try FileLock(url: lockURL)
        defer { lock.unlock() }
        try save(read().filter { $0.id != id })
    }

    func find(rpId: String, allow: [String]) throws -> [Credential] {
        try all().filter { $0.rpId == rpId && (allow.isEmpty || allow.contains($0.id)) }
    }

    private func save(_ credentials: [Credential]) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        try PrivateFile.write(enc.encode(credentials), to: url)
    }
}
