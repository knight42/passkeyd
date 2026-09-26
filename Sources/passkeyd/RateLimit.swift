import Foundation

final class RateLimit {
    private let url: URL
    private let lockURL: URL

    init(dir: URL) {
        // The old unscoped approvals.json must not lock unrelated origins out.
        url = dir.appendingPathComponent("approvals-by-origin.json")
        lockURL = dir.appendingPathComponent("approvals.lock")
    }

    func allow(origin: String, maxPerHour: Int, now: Date = Date()) -> Bool {
        do {
            let lock = try FileLock(url: lockURL)
            defer { lock.unlock() }
            var origins: [String: [Double]] = [:]
            if let data = try PrivateFile.readIfPresent(url) {
                origins = try JSONDecoder().decode([String: [Double]].self, from: data)
            }
            let cutoff = now.timeIntervalSince1970 - 3600
            origins = origins.mapValues { $0.filter { $0 > cutoff } }.filter { !$0.value.isEmpty }
            var stamps = origins[origin] ?? []
            guard stamps.count < maxPerHour else { return false }
            stamps.append(now.timeIntervalSince1970)
            origins[origin] = stamps
            try PrivateFile.write(JSONEncoder().encode(origins), to: url)
            return true
        } catch {
            // Corruption or failed persistence must not reset the quota.
            Log.info("approval quota unavailable; denying request")
            return false
        }
    }
}
