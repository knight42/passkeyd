import Foundation

enum RpId {
    /// The WebAuthn client-side check we take over from the browser: the RP ID must
    /// be a registrable suffix of (or equal to) the caller's origin host, the origin
    /// must be secure, and the RP ID must be on the configured allowlist.
    /// This is the anti-phishing boundary — keep it strict.
    static func validate(rpId: String, origin: String, allowedRps: [String]) -> Bool {
        guard let u = URL(string: origin), let host = u.host?.lowercased() else { return false }
        let rp = rpId.lowercased()
        guard u.scheme == "https" || host == "localhost" else { return false }
        guard !rp.isEmpty, rp.contains(".") || rp == "localhost" else { return false }
        guard host == rp || host.hasSuffix("." + rp) else { return false }
        return allowedRps.contains { rp == $0 || rp.hasSuffix("." + $0) }
    }
}
