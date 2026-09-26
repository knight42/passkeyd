#!/usr/bin/env python3
"""Exercise actual disk transactions from separate OS processes, with no keys."""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def check(ok, message):
    if not ok:
        raise RuntimeError(message)


def main():
    with tempfile.TemporaryDirectory(prefix='passkeyd-state-e2e-') as tmp:
        work = Path(tmp)
        driver = work / 'main.swift'
        driver.write_text('''import Foundation
let dir = URL(fileURLWithPath: CommandLine.arguments[2])
switch CommandLine.arguments[1] {
case "add":
    let store = try Store(dir: dir)
    let id = CommandLine.arguments[3]
    try store.add(.init(id: id, rpId: "github.com", userName: "test", userHandle: "YQ", backend: "software", createdAt: Date()))
case "reserve":
    print(RateLimit(dir: dir).allow(origin: CommandLine.arguments[3], maxPerHour: 1) ? "allowed" : "denied")
default: fatalError("unknown fixture command")
}
''')
        support = work / 'Support.swift'
        support.write_text('''import Foundation
struct FixtureError: Error { let message: String }
func fail(_ message: String) -> FixtureError { FixtureError(message: message) }
enum Log { static func info(_ message: String) {} }
''')
        binary = work / 'state-fixture'
        subprocess.run(['swiftc', *[str(ROOT / 'Sources/passkeyd' / name) for name in
                        ['FileLock.swift', 'Store.swift', 'RateLimit.swift']],
                        str(support), str(driver), '-o', str(binary)], check=True)
        state = work / 'state'
        state.mkdir()
        def call(op, value):
            return subprocess.check_output([str(binary), op, str(state), str(value)], text=True).strip()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(lambda i: call('add', i), range(64)))
            results = list(pool.map(lambda i: call('reserve', 'https://a.okta.com'), range(64)))
        credentials = json.loads((state / 'credentials.json').read_text())
        check({c['id'] for c in credentials} == {str(i) for i in range(64)}, 'concurrent credential loss')
        check(results.count('allowed') == 1, f'quota admitted {results.count("allowed")} instead of 1')
        check(call('reserve', 'https://b.okta.com') == 'allowed', 'origin quota was not isolated')
        for name in ['credentials.json', 'approvals-by-origin.json']:
            check((state / name).stat().st_mode & 0o777 == 0o600, f'permissions: {name}')
        print('STATE E2E PASS (64 concurrent writers preserved; 1/64 quota reservations admitted; origins isolated)')


if __name__ == '__main__':
    main()
