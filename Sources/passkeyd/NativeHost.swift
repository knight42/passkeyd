import Foundation

/// Chrome native messaging host loop: 4-byte little-endian length + JSON, both ways.
enum NativeHost {
    static func run(service: Service) -> Never {
        let stdin = FileHandle.standardInput
        let stdout = FileHandle.standardOutput
        let writeLock = NSLock()

        func write(_ obj: [String: Any]) {
            guard let body = try? JSONSerialization.data(withJSONObject: obj) else { return }
            var len = UInt32(body.count).littleEndian
            writeLock.lock()
            defer { writeLock.unlock() }
            stdout.write(Data(bytes: &len, count: 4) + body)
        }

        // Chrome kills idle MV3 service workers after ~30 s; periodic pings keep the
        // port — and therefore a pending approval round-trip — alive.
        Thread.detachNewThread {
            while true {
                Thread.sleep(forTimeInterval: 15)
                write(["type": "ping"])
            }
        }

        func readExactly(_ n: Int) -> Data? {
            var buf = Data()
            while buf.count < n {
                guard let chunk = try? stdin.read(upToCount: n - buf.count), !chunk.isEmpty else {
                    return nil
                }
                buf += chunk
            }
            return buf
        }

        while true {
            guard let lenData = readExactly(4) else { exit(0) }  // port closed
            let len = UInt32(littleEndian: lenData.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) })
            guard len > 0, len < 1_000_000,
                  let body = readExactly(Int(len)),
                  var msg = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] else {
                exit(1)
            }
            // "reqId" is the caller's correlation id; "id" stays the credential id.
            let reqId = msg.removeValue(forKey: "reqId")
            var resp = service.handle(msg)
            if let reqId { resp["reqId"] = reqId }
            write(resp)
        }
    }
}
