// GuestEventLog + guestAttestClientData against the vector dstack-compat/test_guest_attest.py
// also checks: seal rules, heads and the exact 255 client-data bytes.
import XCTest

@testable import marAttest

final class GuestAttestTests: XCTestCase {
    func testSharedVector() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("Fixtures/guest-attest-vector.json")
        let v = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        let hello = v["hello"] as! [String: String]
        func h(_ s: Any?) throws -> Data { try guestHex(s as! String) }
        var log = GuestEventLog()
        for step in v["ops"] as! [[String: Any]] {
            let f = step["frame"] as! [String: Any]
            let run: () throws -> Data = {
                switch f["op"] as! String {
                case "event": return try log.event(f["name"] as! String, try h(f["payload"]))
                case "seal": return try log.seal()
                default:
                    return try guestAttestClientData(
                        osImageHash: try h(hello["os_image_hash"]), manifestSha256: try h(hello["manifest_sha256"]),
                        run: try h(hello["run"]), head: try log.attest(),
                        caller: try h(f["caller"]), reportData: try h(f["report_data"]))
                }
            }
            if step["error"] != nil {
                XCTAssertThrowsError(try run(), "\(f)")
            } else {
                XCTAssertEqual(try run(), try h(step["head"] ?? step["client_data"]), "\(f)")
            }
        }
    }
}
