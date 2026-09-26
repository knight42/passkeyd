import Darwin
import Foundation

/// Lock a stable sidecar inode, never the data file replaced by atomic writes.
/// Separate native-host processes (and separate Store instances) share the lock.
final class FileLock {
    private var fd: Int32 = -1

    init(url: URL, nonBlocking: Bool = false) throws {
        fd = open(url.path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw fail("cannot open state lock") }
        let operation = LOCK_EX | (nonBlocking ? LOCK_NB : 0)
        while flock(fd, operation) != 0 {
            if errno == EINTR { continue }
            close(fd)
            fd = -1
            throw fail(nonBlocking ? "resource busy; retry later" : "cannot acquire state lock")
        }
    }

    func unlock() {
        if fd >= 0 { close(fd); fd = -1 }
    }
    deinit { unlock() }
}

enum PrivateFile {
    /// Create with 0600 before writing any bytes, then atomically replace.
    static func write(_ data: Data, to url: URL) throws {
        var template = Array((url.path + ".XXXXXX").utf8CString)
        let fd = mkstemp(&template)
        guard fd >= 0 else { throw fail("cannot create private state file") }
        let temporary = String(cString: template)
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer {
            try? file.close()
            unlink(temporary)
        }
        try file.write(contentsOf: data)
        guard rename(temporary, url.path) == 0 else { throw fail("cannot replace state file") }
    }

    static func readIfPresent(_ url: URL) throws -> Data? {
        do { return try Data(contentsOf: url) }
        catch let error as NSError where error.domain == NSCocoaErrorDomain && error.code == NSFileReadNoSuchFileError {
            return nil
        }
    }
}
