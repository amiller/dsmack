// GuestCtl.swift — the app end of the dsmack-ctl virtio console port while the
// guest runs. Frames are uint32_be(len) || JSON, at most 4 KiB, one request at
// a time; the guest agent (dstack-compat/agent.py) is the only peer and speaks
// first: the guest kernel drops port input that arrives before the port is
// opened. The app answers hello, and event/seal/attest under GuestEventLog's seal rule.
// A refusal is an {"error"} reply; a malformed frame or a failed assertion ends
// the handler with that error, which fails the run.

#if canImport(Darwin)
import CryptoKit
import Darwin
import DeviceCheck
import Foundation
import marAttest

let guestCtlMaxFrame = 4096

func serveGuestCtl(fd: Int32, keyId: String, osImageHash: Data, manifestSha256: Data, run: Data) async throws {
    guard let keyIdBytes = Data(base64Encoded: keyId) else { throw Fail("keyId is not base64") }
    var log = GuestEventLog()
    func field(_ m: [String: Any], _ k: String) throws -> String {
        guard let s = m[k] as? String else { throw GuestAttestRefusal("missing string field \(k)") }
        return s
    }
    while let m = try readGuestFrame(fd) {
        var reply: [String: Any]
        do {
            switch m["op"] as? String {
            case "hello": reply = ["os_image_hash": hex(osImageHash), "manifest_sha256": hex(manifestSha256), "run": hex(run)]
            case "event": reply = ["head": hex(try log.event(try field(m, "name"), try guestHex(try field(m, "payload"))))]
            case "seal": reply = ["head": hex(try log.seal())]
            case "attest":
                let caller = try guestHex(try field(m, "caller"))
                let reportData = try guestHex(try field(m, "report_data"))
                let clientData = try guestAttestClientData(osImageHash: osImageHash, manifestSha256: manifestSha256,
                                                           run: run, head: try log.attest(),
                                                           caller: caller, reportData: reportData)
                let assertion = try await DCAppAttestService.shared.generateAssertion(
                    keyId, clientDataHash: Data(SHA256.hash(data: clientData)))
                reply = ["key_id": hex(keyIdBytes), "assertion": hex(assertion),
                         "events": log.events.map { ["name": $0.name, "payload": hex($0.payload)] }]
            default: throw GuestAttestRefusal("unknown op")
            }
        } catch let r as GuestAttestRefusal {
            reply = ["error": r.description]
        }
        try writeGuestFrame(fd, reply)
    }
}

/// nil on a clean EOF between frames (the port closed or was shut down).
func readGuestFrame(_ fd: Int32) throws -> [String: Any]? {
    func exact(_ n: Int) throws -> Data? {
        var buf = [UInt8](repeating: 0, count: n)
        var got = 0
        while got < n {
            let r = buf.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress! + got, n - got) }
            if r < 0 && errno == EINTR { continue }
            guard r >= 0 else { throw Fail("dsmack-ctl read failed (errno \(errno))") }
            if r == 0 && got == 0 { return nil }
            guard r > 0 else { throw Fail("dsmack-ctl closed mid-frame") }
            got += r
        }
        return Data(buf)
    }
    guard let h = try exact(4) else { return nil }
    let n = h.reduce(0) { $0 << 8 | Int($1) }
    guard n <= guestCtlMaxFrame else { throw Fail("dsmack-ctl frame of \(n) bytes exceeds \(guestCtlMaxFrame)") }
    guard let body = try exact(n), let m = try JSONSerialization.jsonObject(with: body) as? [String: Any] else {
        throw Fail("dsmack-ctl frame is not a JSON object")
    }
    return m
}

func writeGuestFrame(_ fd: Int32, _ o: [String: Any]) throws {
    let body = try JSONSerialization.data(withJSONObject: o)
    let d = Data([24, 16, 8, 0].map { UInt8(truncatingIfNeeded: body.count >> $0) }) + body
    var off = 0
    while off < d.count {
        let w = d.withUnsafeBytes { Darwin.write(fd, $0.baseAddress! + off, d.count - off) }
        if w < 0 && errno == EINTR { continue }
        guard w > 0 else { throw Fail("dsmack-ctl write failed (errno \(errno))") }
        off += w
    }
}
#endif
