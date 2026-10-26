// WorkerGrant + the worker-grant event against dstack-compat/test_grant.py's vector.
import CryptoKit
import XCTest

@testable import marAttest

final class WorkerGrantTests: XCTestCase {
    func vector() throws -> [String: Any] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("Fixtures/worker-grant-vector.json")
        return try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    }

    /// A seal the app opened differently from grant.py would hand the guest a wrong root and every GetKey would fail.
    func testOpensTheCoordinatorSeal() throws {
        let v = try vector()
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: try guestHex(v["app_key"] as! String))
        let g = try WorkerGrant(sealed: v["sealed"] as! [String: Any], key: key)
        XCTAssertEqual(g.rootKey, try guestHex(v["root_key"] as! String))
        XCTAssertEqual(g.digest, try guestHex(v["grant_sha256"] as! String))
        XCTAssertEqual(grantRequestClientData(manifestSha256: Data(repeating: 0x22, count: 32), run: Data(repeating: 0x33, count: 32),
                                              sealPub: key.publicKey.x963Representation, taskId: "t"),
                       try guestHex(v["request_client_data"] as! String))
        var tampered = v["sealed"] as! [String: Any]
        tampered["grant"] = (tampered["grant"] as! String) + " "
        XCTAssertThrowsError(try WorkerGrant(sealed: tampered, key: key))
    }

    /// The grant op: the app logs the digest once, before seal; the guest cannot log its own.
    func testGrantEventRules() throws {
        var log = GuestEventLog(runnerCanaryKey: Data(repeating: 7, count: 64))
        let d = Data(repeating: 9, count: 32)
        XCTAssertThrowsError(try log.event(GuestEventLog.workerGrantEvent, d))
        _ = try log.grant(d)
        XCTAssertThrowsError(try log.grant(d))
        _ = try log.seal()
        XCTAssertEqual(log.events.map(\.name), [GuestEventLog.runnerCanaryEvent, GuestEventLog.workerGrantEvent, "system-ready"])
        XCTAssertEqual(log.events[1].payload, d)
        var late = GuestEventLog()
        _ = try late.seal()
        XCTAssertThrowsError(try late.grant(d))
    }
}
