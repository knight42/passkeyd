import Foundation

struct Config: Codable {
    var telegramToken: String = ""
    var telegramChatId: Int64 = 0
    var allowedRps: [String] = ["okta.com", "webauthn.io"]
    /// Host for the fallback approve link. Empty = auto-detect this machine's
    /// tailscale IPv4 at request time.
    var tailnetHost: String = ""
    var approvePort: UInt16 = 8378
    var remoteTimeoutSec: Int = 120
    // Prompt-fatigue backstop, not a security boundary (every prompt still
    // needs an explicit approve). One RP sign-in can burn several attempts
    // (Okta fires get twice per click and auto-retries on failure), so keep
    // enough headroom for normal interactive use.
    var maxApprovalsPerHour: Int = 30
    var forceRemote: Bool = false

    static var dir: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/passkeyd")
    }
    static var path: URL { dir.appendingPathComponent("config.json") }

    static func load() -> Config {
        guard let d = try? Data(contentsOf: path),
              let c = try? JSONDecoder().decode(Config.self, from: d)
        else { return Config() }
        return c
    }

    func save() throws {
        try FileManager.default.createDirectory(at: Self.dir, withIntermediateDirectories: true)
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try enc.encode(self).write(to: Self.path, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                              ofItemAtPath: Self.path.path)
    }
}
