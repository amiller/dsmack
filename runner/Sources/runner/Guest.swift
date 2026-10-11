import CryptoKit
import DeviceCheck
import Foundation

struct Enrollment { let keyId: String, attestation: Data, clientData: Data }

// The guest's own endpoints on http://runner.local: /attest and /key. Spec: notes/abalone-node-interface.md.
// With --attest the App Attest key is re-enrolled every --reenroll-seconds (default 6 h): Apple's attestation leaf is
// valid about 48 h and verifiers cap enrollment age, so /attest always serves the newest enrollment. Enrollment
// evidence stays in RAM; the runner writes no keyId or attestation to disk.
final class Guest: @unchecked Sendable {
    let app: String, composeHash: String, receiptPub: String, appKey: SymmetricKey
    let lock = NSLock()
    var enrollment: Enrollment?, devClientData: Data  // enrollment nil = --no-attest
    var tail = Task<Void, Never> {}

    init(app: String, composeHash: String, receiptPub: String, appKey: SymmetricKey, boot: Enrollment?, bootClientData: Data) {
        (self.app, self.composeHash, self.receiptPub, self.appKey, enrollment, devClientData) = (app, composeHash, receiptPub, appKey, boot, bootClientData)
    }

    func handle(_ method: String, _ path: String, _ body: Data) async throws -> Data {
        guard method == "POST" else { throw Refusal(status: 405, reason: "runner.local accepts only POST here") }
        let req = try? JSONSerialization.jsonObject(with: body) as? [String: Any]
        switch path {
        case "/attest":
            guard let data = req?["data"] as? String else { throw Refusal(status: 400, reason: "/attest body must be {\"data\": <string>}") }
            return try canonical(try await attest(data))
        case "/key":
            guard let p = req?["path"] as? String else { throw Refusal(status: 400, reason: "/key body must be {\"path\": <string>}") }
            let k = HKDF<SHA256>.deriveKey(inputKeyMaterial: appKey, salt: Data(), info: Data("mac-compose-get-key/1|\(p)".utf8), outputByteCount: 32)
            return try canonical(["key": k.withUnsafeBytes { hex($0) }])
        default: throw Refusal(status: 404, reason: "no runner.local endpoint \(path)")
        }
    }

    func attest(_ data: String) async throws -> [String: Any] {
        try await evidence(try canonical(["compose_hash": composeHash, "data": data, "domain": "mac-compose-assert/1"]))
    }

    // An assertion over sha256(assertClientData) under the current enrollment. A task boot passes its own clientData
    // (domain mac-compose-task-boot/1), which /attest cannot produce: /attest always wraps the data in mac-compose-assert/1.
    func evidence(_ assertClientData: Data) async throws -> [String: Any] {
        guard lock.withLock({ enrollment }) != nil else {
            return ["type": "dev", "bootClientData": devClientData.base64EncodedString(), "assertClientData": assertClientData.base64EncodedString()]
        }
        let hash = Data(SHA256.hash(data: assertClientData))
        // Read the enrollment inside the queue so a re-enrollment cannot swap keys between assertion and reply.
        let (e, assertion) = try await serialized { [self] in
            let e = lock.withLock { enrollment! }
            return (e, try await DCAppAttestService.shared.generateAssertion(e.keyId, clientDataHash: hash))
        }
        return ["type": "macrunner", "attestation": e.attestation.base64EncodedString(), "keyId": e.keyId,
                "bootClientData": e.clientData.base64EncodedString(), "assertion": assertion.base64EncodedString(),
                "assertClientData": assertClientData.base64EncodedString()]
    }

    // A fresh App Attest key over {app, attested, compose_hash, domain "mac-compose-enroll/1", enrolled_at, nonce, receipt_pub}.
    // No KMS round trip: the enrollment binds the same compose_hash and the boot's receipt_pub.
    func reenroll(every seconds: Int) async throws {
        while true {
            try await Task.sleep(for: .seconds(seconds))
            let e = try await serialized { [self] in
                // Carries the boot's KMS nonce so a re-enrolled /attest still identifies this boot (peer.lock takeover).
                let nonce = try JSONSerialization.jsonObject(with: devClientData) as! [String: Any]
                let cd = try canonical(["app": app, "attested": true, "compose_hash": composeHash, "domain": "mac-compose-enroll/1",
                                        "enrolled_at": Int(Date().timeIntervalSince1970), "nonce": nonce["nonce"]!, "receipt_pub": receiptPub])
                let svc = DCAppAttestService.shared, keyId = try await svc.generateKey()
                return Enrollment(keyId: keyId, attestation: try await svc.attestKey(keyId, clientDataHash: Data(SHA256.hash(data: cd))), clientData: cd)
            }
            lock.withLock { enrollment = e }
            log("re-enrolled App Attest key \(e.keyId.prefix(12))...")
        }
    }

    // One App Attest call at a time, in arrival order.
    func serialized<T: Sendable>(_ f: @escaping @Sendable () async throws -> T) async throws -> T {
        let t: Task<T, Error> = lock.withLock {
            let prev = tail
            let t = Task { await prev.value; return try await f() }
            tail = Task { _ = try? await t.value }
            return t
        }
        return try await t.value
    }
}

// Canonical JSON: UTF-8, keys sorted, no whitespace, "/" unescaped (JSONSerialization .sortedKeys .withoutEscapingSlashes).
func canonical(_ o: Any) throws -> Data { try JSONSerialization.data(withJSONObject: o, options: [.sortedKeys, .withoutEscapingSlashes]) }

// sha256 of a certificate's DER SubjectPublicKeyInfo (the "spki_sha256" ACI keysets attest).
func spkiSHA256(_ cert: Data) -> String {
    let d = [UInt8](cert)
    func tlv(_ i: Int) -> (start: Int, end: Int) {
        var len = Int(d[i + 1]), head = 2
        if len & 0x80 != 0 { let n = len & 0x7f; len = d[i + 2 ..< i + 2 + n].reduce(0) { $0 << 8 | Int($1) }; head += n }
        return (i + head, i + head + len)
    }
    var i = tlv(tlv(0).start).start  // Certificate → tbsCertificate contents
    if d[i] == 0xa0 { i = tlv(i).end }  // [0] version
    for _ in 0 ..< 5 { i = tlv(i).end }  // serial, signature, issuer, validity, subject
    return sha256hex(Data(d[i ..< tlv(i).end]))
}

struct Quote { let sha256: String; let spki: Set<String>; let report: Data; let onchain: Any? }

// Runs verify/provider_quote.mjs after checking its bytes against the compiled-in hash. CDHash covers the runner and
// that hash; it does not cover node or node_modules (see README, "Provider quotes").
struct QuoteHelper {
    let node: URL, script: URL, out: URL

    func check() throws {
        let h = sha256hex(try Data(contentsOf: script))
        guard h == providerQuoteHelperSHA256 else { throw Fail("quote helper \(script.path) sha256 \(h) != compiled-in \(providerQuoteHelperSHA256)") }
    }

    // nearai: the API key goes to the helper on stdin (NEAR's report endpoint needs it).
    func run(_ pq: ProviderQuote, host: String, key: String) async throws -> Quote {
        try check()
        let p = Process(), so = Pipe(), se = Pipe()
        p.executableURL = node
        p.arguments = [script.path, String(decoding: try JSONEncoder().encode(pq), as: UTF8.self), host, anchorsDER.joined(separator: ",")]
        let si = Pipe()
        p.standardInput = si
        p.currentDirectoryURL = script.deletingLastPathComponent()
        (p.standardOutput, p.standardError) = (so, se)
        let (o, e, status): (Data, Data, Int32) = try await withCheckedThrowingContinuation { c in
            DispatchQueue.global().async {
                do {
                    try p.run()
                    try si.fileHandleForWriting.write(contentsOf: Data((pq.kind == "nearai" ? key : "").utf8))
                    try si.fileHandleForWriting.close()
                    let o = so.fileHandleForReading.readDataToEndOfFile(), e = se.fileHandleForReading.readDataToEndOfFile()
                    p.waitUntilExit()
                    c.resume(returning: (o, e, p.terminationStatus))
                } catch { c.resume(throwing: error) }
            }
        }
        guard status == 0 else { throw Fail(String(decoding: e, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) }
        let r = try object(o, "quote helper output")
        guard let report = (r["report_b64"] as? String).flatMap({ Data(base64Encoded: $0) }), let spki = r["tls_spki_sha256"] as? [String] else {
            throw Fail("quote helper output lacks report_b64/tls_spki_sha256")
        }
        let sha = sha256hex(report)
        try o.write(to: out.appendingPathComponent("provider-quote-\(sha.prefix(16)).json"))
        log("provider quote verified: \(pq.kind) \(pq.attestation_url) for \(host), report sha256 \(sha)\(r["onchain"].map { ", onchain \($0)" } ?? "")")
        return Quote(sha256: sha, spki: Set(spki), report: report, onchain: r["onchain"])
    }
}
