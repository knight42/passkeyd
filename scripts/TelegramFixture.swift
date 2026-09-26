// Test-only transport installed by e2e_telegram.py's executable bootstrap.
// Production URLRequest construction and response decoding stay unchanged.
import Foundation

final class TelegramFixture: URLProtocol {
    private var forwardedTask: URLSessionDataTask?
    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host == "api.telegram.org"
    }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        var forwarded = request
        let endpoint = ProcessInfo.processInfo.environment["PASSKEYD_TEST_ENDPOINT"]!
        forwarded.url = URL(string: endpoint + request.url!.path)!
        // URLSession may expose the POST body as a stream to URLProtocol.
        if forwarded.httpBody == nil, let stream = request.httpBodyStream {
            stream.open()
            defer { stream.close() }
            var body = Data()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let count = stream.read(&buffer, maxLength: buffer.count)
                if count <= 0 { break }
                body.append(contentsOf: buffer.prefix(count))
            }
            forwarded.httpBodyStream = nil
            forwarded.httpBody = body
        }
        forwardedTask = URLSession(configuration: .ephemeral).dataTask(with: forwarded) { data, response, error in
            if let error {
                self.client?.urlProtocol(self, didFailWithError: error)
                return
            }
            self.client?.urlProtocol(self, didReceive: response!, cacheStoragePolicy: .notAllowed)
            self.client?.urlProtocol(self, didLoad: data ?? Data())
            self.client?.urlProtocolDidFinishLoading(self)
        }
        forwardedTask?.resume()
    }
    override func stopLoading() { forwardedTask?.cancel() }
}
