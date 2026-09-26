import CoreGraphics
import Foundation
import LocalAuthentication

struct ApprovalRequest {
    let rpId: String
    let origin: String
    let userName: String
    let operation: String  // "sign in" / "register" / "test"
}

enum Session {
    static func screenLockedOrAway() -> Bool {
        guard let d = CGSessionCopyCurrentDictionary() as? [String: Any] else { return true }
        if (d["CGSSessionScreenIsLocked"] as? Bool) == true { return true }
        if (d["kCGSSessionOnConsoleKey"] as? Bool) == false { return true }
        return false
    }
}

enum LocalOutcome {
    case approved
    case denied       // the user explicitly cancelled — do not escalate
    case unavailable  // prompt couldn't run or was interrupted — try remote
}

enum LocalApproval {
    static func touchID(_ req: ApprovalRequest) -> LocalOutcome {
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
            Log.info("LAContext unavailable: \(err?.localizedDescription ?? "?")")
            return .unavailable
        }
        let sem = DispatchSemaphore(value: 0)
        var result = LocalOutcome.denied
        ctx.evaluatePolicy(.deviceOwnerAuthentication,
                           localizedReason: "\(req.operation) at \(req.rpId) as \(req.userName)") { success, error in
            if success {
                result = .approved
            } else if (error as? LAError)?.code != .userCancel {
                result = .unavailable
            }
            sem.signal()
        }
        // The lock-vs-local decision was made at request time; if the screen
        // locks while the prompt is up (agent kicked off the login, the user
        // locked and walked away), the prompt is invisible and would hang
        // until the browser times out. Watch for that and cancel — the
        // .appCancel error lands in the .unavailable branch above, and the
        // caller escalates to remote approval.
        while sem.wait(timeout: .now() + 2) == .timedOut {
            if Session.screenLockedOrAway() {
                Log.info("screen locked while Touch ID pending")
                ctx.invalidate()
            }
        }
        return result
    }
}

final class Approver {
    let cfg: Config
    private let rate: RateLimit

    init(cfg: Config, dir: URL) {
        self.cfg = cfg
        rate = RateLimit(dir: dir)
    }

    func approve(_ req: ApprovalRequest) -> Bool {
        #if DEBUG
        // e2e escape hatch; compiled out of release builds.
        if ProcessInfo.processInfo.environment["PASSKEYD_SKIP_APPROVAL"] == "1" {
            Log.info("DEBUG: approval skipped via PASSKEYD_SKIP_APPROVAL")
            return true
        }
        #endif
        guard rate.allow(origin: req.origin, maxPerHour: cfg.maxApprovalsPerHour) else {
            Log.info("rate limit exceeded, denying \(req.rpId)")
            return false
        }
        if !cfg.forceRemote && !Session.screenLockedOrAway() {
            Log.info("local approval (touch id) for \(req.rpId)")
            switch LocalApproval.touchID(req) {
            case .approved:
                Log.info("approved locally")
                return true
            case .denied:
                Log.info("denied locally")
                return false
            case .unavailable:
                Log.info("local approval unavailable, falling back to remote")
            }
        }
        Log.info("remote approval for \(req.rpId)")
        let ok = RemoteApproval(cfg: cfg).request(req)
        Log.info(ok ? "approved remotely" : "remote approval denied/expired")
        return ok
    }
}
