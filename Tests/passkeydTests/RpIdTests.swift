import XCTest

@testable import passkeyd

final class RpIdTests: XCTestCase {
    func testValidate() {
        let allowed = ["okta.com", "google.com", "webauthn.io", "localhost"]
        let cases: [String: (rpId: String, origin: String, want: Bool)] = [
            "exact host": ("webauthn.io", "https://webauthn.io", true),
            "org subdomain": ("example.okta.com", "https://example.okta.com", true),
            "parent rp for subdomain origin": ("okta.com", "https://example.okta.com", true),
            "google account origin": ("google.com", "https://accounts.google.com", true),
            "google subdomain rp": ("accounts.google.com", "https://accounts.google.com", true),
            "google lookalike rejected": ("google.com", "https://evil-google.com", false),
            "google nested under attacker rejected": ("google.com", "https://accounts.google.com.evil.com", false),
            "google sibling origin rejected": ("accounts.google.com", "https://myaccount.google.com", false),
            "localhost http": ("localhost", "http://localhost:8399", true),
            "plain http rejected": ("webauthn.io", "http://webauthn.io", false),
            "hyphen suffix trick": ("okta.com", "https://evil-okta.com", false),
            "unlisted rp": ("evil.com", "https://evil.com", false),
            "rp not suffix of origin": ("webauthn.io", "https://okta.com", false),
            "empty rp": ("", "https://webauthn.io", false),
            "tld rp": ("com", "https://okta.com", false),
        ]
        for (name, c) in cases {
            XCTAssertEqual(RpId.validate(rpId: c.rpId, origin: c.origin, allowedRps: allowed),
                           c.want, name)
        }
    }
}
