import Containerization
import CryptoKit
import Darwin
import Foundation

// dsmack-sdk v1, runner side (planning: dsmack-sdk design §1-3; node side node/shared/SDK.swift; Python stand-in
// runner/kms/sdk_runner.py). The runner holds one admitted connection to its node's loopback sdkPort: it asks for a
// challenge, sends get_key with runner_evidence (an App Attest assertion over "dsmack-sdk-runner/1|0x<challenge>|0x<sha256
// of the canonical request>") and opens the app root sealed to its one-time eph_pub. It then serves the guest JSON lines
// on /var/run/dsmack.sock: get_key (leaf derivation and chain link 2 here), evidence and info (from the node). That socket
// exists only inside the VM: the guest agent relays it to a vsock port this process listens on; no host path exists.

func unhex(_ s: String) throws -> Data {
    let h = Array((s.hasPrefix("0x") ? String(s.dropFirst(2)) : s).utf8)
    guard h.count % 2 == 0 else { throw Fail("odd-length hex") }
    return try Data(stride(from: 0, to: h.count, by: 2).map { i in
        guard let b = UInt8(String(decoding: h[i ..< i + 2], as: UTF8.self), radix: 16) else { throw Fail("not hex: \(s.prefix(20))") }
        return b
    })
}

enum SDKv1 {
    static let tags = ["ed25519", "secp256k1", "p256", "raw"]
    static let p256N = [UInt8](try! unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"))
    static let k1N = [UInt8](try! unhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"))

    static func word(_ n: UInt64) -> Data { Data(count: 24) + withUnsafeBytes(of: n.bigEndian) { Data($0) } }
    static func lp(_ d: Data) -> Data { withUnsafeBytes(of: UInt32(d.count).bigEndian) { Data($0) } + d }
    static func hkdf(_ key: SymmetricKey, _ info: Data) -> Data {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: Data(), info: info, outputByteCount: 32).withUnsafeBytes { Data($0) }
    }
    // x mod n for 2^255 < n < 2^256 (one subtraction), refused if zero.
    static func reduce(_ x: Data, _ n: [UInt8]) throws -> Data {
        var b = [UInt8](x), borrow = 0
        if !b.lexicographicallyPrecedes(n) {
            for i in (0 ..< 32).reversed() { let d = Int(b[i]) - Int(n[i]) - borrow; b[i] = UInt8(d & 0xff); borrow = d < 0 ? 1 : 0 }
        }
        guard b.contains(where: { $0 != 0 }) else { throw Fail("derived scalar is zero") }
        return Data(b)
    }
    static func appSigner(_ root: SymmetricKey) throws -> P256.Signing.PrivateKey {
        try P256.Signing.PrivateKey(rawRepresentation: reduce(hkdf(root, Data("dsmack-sdk/v1/app-pub".utf8)), p256N))
    }
    static func tag(_ purpose: String) throws -> String {
        let p = purpose.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        guard p.count == 2, tags.contains(String(p[0])) else { throw Fail("purpose must start with one of ed25519:, secp256k1:, p256:, raw:") }
        return String(p[0])
    }
    static func leaf(_ root: SymmetricKey, _ path: String, _ purpose: String) -> Data {
        hkdf(root, Data("dsmack-sdk/v1/key".utf8) + lp(Data(path.utf8)) + lp(Data(purpose.utf8)))
    }
    // The key handed to the guest and its public key: Ed25519 seed as is, secp256k1/p256 scalars reduced mod n; raw has none.
    static func material(_ tag: String, _ leaf: Data) throws -> (key: Data, pub: Data?) {
        switch tag {
        case "ed25519": return (leaf, try Curve25519.Signing.PrivateKey(rawRepresentation: leaf).publicKey.rawRepresentation)
        case "p256": let k = try reduce(leaf, p256N); return (k, try P256.Signing.PrivateKey(rawRepresentation: k).publicKey.x963Representation)
        case "secp256k1": let k = try reduce(leaf, k1N); return (k, K1.publicKey(k))
        default: return (leaf, nil)
        }
    }
    static func keyStatement(_ path: String, _ purpose: String, _ pub: Data) -> Data {
        Data("dsmack-sdk/key/1".utf8) + lp(Data(path.utf8)) + lp(Data(purpose.utf8)) + lp(pub)
    }
    static func appStatement(_ r: [String: Any], appId: Data, composeHash: Data, appPub: Data) throws -> Data {
        guard let chain = r["chain_id"] as? UInt64, let registry = r["registry"] as? String, let scope = r["scope"] as? String,
              let epoch = r["key_epoch"] as? UInt64, let block = r["block"] as? UInt64, let m = r["M"] as? String else { throw Fail("node release fields") }
        let address = try unhex(registry)
        guard address.count == 20 else { throw Fail("registry address width") }
        let context: [Data] = [word(chain), Data(count: 12), address, try unhex(scope), word(epoch), appId]
        let rest: [Data] = [composeHash, word(block), try unhex(m), appPub]
        return ([Data("dsmack-sdk/app/1".utf8)] + context + rest).reduce(Data(), +)
    }
}

// secp256k1 public keys for the secp256k1: tag (CryptoKit has none): affine double-and-add over four 64-bit limbs,
// little-endian. Not constant time; the scalar is handed to the guest in the same reply.
enum K1 {
    typealias U = [UInt64]
    static let p: U = [0xFFFF_FFFE_FFFF_FC2F, ~0, ~0, ~0], c: UInt64 = 0x1_0000_03D1  // p = 2^256 - c
    static let g = (x: u(try! unhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
                    y: u(try! unhex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")))

    static func u(_ d: Data) -> U { let b = [UInt8](d); return (0 ..< 4).map { i in b[(24 - 8 * i) ..< (32 - 8 * i)].reduce(0) { $0 << 8 | UInt64($1) } } }
    static func bytes(_ a: U) -> Data { Data((0 ..< 4).reversed().flatMap { i in withUnsafeBytes(of: a[i].bigEndian) { Array($0) } }) }
    static func ge(_ a: U, _ b: U) -> Bool { for i in (0 ..< 4).reversed() where a[i] != b[i] { return a[i] > b[i] }; return true }
    static func addRaw(_ a: U, _ b: U) -> (U, Bool) {
        var r = a, carry = false
        for i in 0 ..< 4 { let (s1, o1) = a[i].addingReportingOverflow(b[i]); let (s2, o2) = s1.addingReportingOverflow(carry ? 1 : 0); r[i] = s2; carry = o1 || o2 }
        return (r, carry)
    }
    static func subRaw(_ a: U, _ b: U) -> U {
        var r = a, borrow = false
        for i in 0 ..< 4 { let (d1, o1) = a[i].subtractingReportingOverflow(b[i]); let (d2, o2) = d1.subtractingReportingOverflow(borrow ? 1 : 0); r[i] = d2; borrow = o1 || o2 }
        return r
    }
    static func add(_ a: U, _ b: U) -> U { let (r, carry) = addRaw(a, b); return carry || ge(r, p) ? subRaw(r, p) : r }
    static func sub(_ a: U, _ b: U) -> U { ge(a, b) ? subRaw(a, b) : addRaw(subRaw(a, b), p).0 }
    static func mul(_ a: U, _ b: U) -> U {
        var t = [UInt64](repeating: 0, count: 8)
        for i in 0 ..< 4 {
            var carry: UInt64 = 0
            for j in 0 ..< 4 {
                let (hi, lo) = a[i].multipliedFullWidth(by: b[j])
                let (s1, o1) = lo.addingReportingOverflow(t[i + j]), (s2, o2) = s1.addingReportingOverflow(carry)
                t[i + j] = s2; carry = hi &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0)
            }
            t[i + 4] = carry
        }
        // t = H·2^256 + L ≡ H·c + L (mod p), folded until it fits in 256 bits.
        var r = Array(t[0 ..< 4]), top: U = Array(t[4 ..< 8])
        while top.contains(where: { $0 != 0 }) {
            var hc = [UInt64](repeating: 0, count: 5), carry: UInt64 = 0
            for i in 0 ..< 4 { let (hi, lo) = top[i].multipliedFullWidth(by: c); let (s, o) = lo.addingReportingOverflow(carry); hc[i] = s; carry = hi &+ (o ? 1 : 0) }
            hc[4] = carry
            let (s, o) = addRaw(r, Array(hc[0 ..< 4]))
            r = s; top = [hc[4] &+ (o ? 1 : 0), 0, 0, 0]
        }
        return ge(r, p) ? subRaw(r, p) : r
    }
    static func inv(_ a: U) -> U {
        let e = subRaw(p, [2, 0, 0, 0])
        var r: U = [1, 0, 0, 0], b = a
        for i in 0 ..< 256 { if (e[i / 64] >> UInt64(i % 64)) & 1 == 1 { r = mul(r, b) }; b = mul(b, b) }
        return r
    }
    typealias Point = (x: U, y: U)?
    static func dbl(_ q: Point) -> Point {
        guard let q, q.y != [0, 0, 0, 0] else { return nil }
        let x2 = mul(q.x, q.x), l = mul(add(add(x2, x2), x2), inv(add(q.y, q.y)))
        let x = sub(mul(l, l), add(q.x, q.x))
        return (x, sub(mul(l, sub(q.x, x)), q.y))
    }
    static func plus(_ a: Point, _ b: Point) -> Point {
        guard let a else { return b }
        guard let b else { return a }
        if a.x == b.x { return a.y == b.y ? dbl(a) : nil }
        let l = mul(sub(b.y, a.y), inv(sub(b.x, a.x))), x = sub(sub(mul(l, l), a.x), b.x)
        return (x, sub(mul(l, sub(a.x, x)), a.y))
    }
    // Uncompressed 04 ‖ X ‖ Y for a scalar already reduced mod n and non-zero.
    static func publicKey(_ k: Data) -> Data {
        let s = u(k)
        var r: Point = nil
        for i in (0 ..< 256).reversed() {
            r = dbl(r)
            if (s[i / 64] >> UInt64(i % 64)) & 1 == 1 { r = plus(r, g) }
        }
        return Data([4]) + bytes(r!.x) + bytes(r!.y)
    }
}

// One JSON-lines connection to the node's loopback sdkPort, serialized.
final class NodeLink: @unchecked Sendable {
    let fd: Int32, lock = NSLock()
    var buffer = Data()

    init(_ address: String) throws {
        let parts = address.split(separator: ":")
        guard parts.count == 2, parts[0] == "127.0.0.1", let port = UInt16(parts[1]) else { throw Fail("--sdk-node must be 127.0.0.1:<port>") }
        fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Fail("socket: \(String(cString: strerror(errno)))") }
        var a = sockaddr_in()
        a.sin_family = sa_family_t(AF_INET); a.sin_port = port.bigEndian; a.sin_addr.s_addr = inet_addr("127.0.0.1")
        let ok = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0 } }
        guard ok else { throw Fail("node sdkPort \(address): \(String(cString: strerror(errno)))") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(4))
    }

    func call(_ q: [String: Any]) throws -> [String: Any] {
        try lock.withLock {
            let line = try canonical(q) + Data([10])
            guard line.withUnsafeBytes({ write(fd, $0.baseAddress, $0.count) }) == line.count else { throw Fail("node sdkPort write failed") }
            var chunk = [UInt8](repeating: 0, count: 4096)
            while buffer.firstIndex(of: 10) == nil {
                let n = read(fd, &chunk, chunk.count)
                guard n > 0 else { throw Fail("node sdkPort connection closed") }
                buffer.append(contentsOf: chunk[0 ..< n])
            }
            let i = buffer.firstIndex(of: 10)!
            let reply = try object(Data(buffer[..<i]), "node sdk reply")
            buffer = Data(buffer[(i + 1)...])
            if let e = reply["error"] { throw Fail("node: \(e)") }
            return reply
        }
    }
}

// The app as this runner serves it: its admitted node connection, released roots by epoch, and the guest ops.
final class SDKApp: @unchecked Sendable {
    let node: NodeLink, guest: Guest, appId: String, composeHash: String, cdhash: String
    let lock = NSLock()
    var roots: [UInt64: (root: SymmetricKey, signer: P256.Signing.PrivateKey, statement: [String: Any])] = [:]
    var epoch: UInt64 = 0

    init(node: NodeLink, guest: Guest, appId: String, composeHash: String, cdhash: String) {
        (self.node, self.guest, self.appId, self.composeHash, self.cdhash) = (node, guest, appId, composeHash, cdhash)
    }

    func request(_ op: String, _ fields: [String: Any] = [:]) -> [String: Any] {
        ["v": 1, "op": op, "app_id": appId, "compose_hash": composeHash].merging(fields) { $1 }
    }

    // The boot release: the connection's first key op, carrying this runner's App Attest evidence for `challenge`.
    func boot(challenge: String, eph: P256.KeyAgreement.PrivateKey) async throws {
        var q = request("get_key", ["eph_pub": hex(eph.publicKey.x963Representation)])
        let data = "dsmack-sdk-runner/1|0x\(hex(try unhex(challenge)))|0x\(sha256hex(try canonical(q)))"
        q["runner_evidence"] = try await guest.attest(data)
        epoch = try open(try node.call(q), eph)
    }

    // Opens a get_key reply: the root sealed to eph, its statement naming this app and compose and signed by G.
    func open(_ r: [String: Any], _ eph: P256.KeyAgreement.PrivateKey) throws -> UInt64 {
        guard let s = r["statement"] as? String, let epk = r["epk"] as? String, let sealed = r["sealed"] as? String, let appPub = r["app_pub"] as? String,
              let g = r["group_public"] as? String, let gs = r["group_signature"] as? String, let e = r["key_epoch"] as? UInt64 else { throw Fail("node get_key reply fields") }
        let statement = try unhex(s)
        let aead = try eph.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: try unhex(epk)))
            .hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data("dsmack-sdk/v1/release".utf8), outputByteCount: 32)
        let root = SymmetricKey(data: try AES.GCM.open(AES.GCM.SealedBox(combined: try unhex(sealed)), using: aead, authenticating: Data(SHA256.hash(data: statement))))
        let signer = try SDKv1.appSigner(root), pub = signer.publicKey.x963Representation
        guard pub == (try unhex(appPub)) else { throw Fail("app_pub is not the released root's") }
        guard statement == (try SDKv1.appStatement(r, appId: try unhex(appId), composeHash: try unhex(composeHash), appPub: pub)) else {
            throw Fail("statement does not name this app and compose")
        }
        guard try P256.Signing.PublicKey(x963Representation: try unhex(g)).isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: try unhex(gs)), for: statement) else {
            throw Fail("statement is not signed by the group key")
        }
        lock.withLock { roots[e] = (root, signer, ["signer": g, "message": s, "signature": gs]) }
        return e
    }

    func getKey(_ q: [String: Any]) throws -> [String: Any] {
        guard let path = q["path"] as? String, let purpose = q["purpose"] as? String else { throw Fail("get_key needs path and purpose") }
        var e = epoch
        if let x = q["epoch"] { guard let n = x as? UInt64 else { throw Fail("epoch") }; e = n }
        if lock.withLock({ roots[e] }) == nil {
            let eph = P256.KeyAgreement.PrivateKey()
            _ = try open(try node.call(request("get_key", ["eph_pub": hex(eph.publicKey.x963Representation), "epoch": e])), eph)
        }
        let r = lock.withLock { roots[e]! }
        let (key, pub) = try SDKv1.material(try SDKv1.tag(purpose), SDKv1.leaf(r.root, path, purpose))
        guard let pub else { return ["key": hex(key)] }
        let link = SDKv1.keyStatement(path, purpose, pub)
        return ["key": hex(key), "public_key": hex(pub), "key_epoch": e,
                "chain": [r.statement, ["signer": hex(r.signer.publicKey.x963Representation), "message": hex(link), "signature": hex(try r.signer.signature(for: link).rawRepresentation)]]]
    }

    func evidence(_ q: [String: Any]) async throws -> [String: Any] {
        guard let d = q["report_data"] as? String else { throw Fail("evidence needs report_data") }
        let data = try unhex(d)
        guard data.count <= 64 else { throw Fail("report_data is at most 64 bytes") }
        let r = try node.call(request("evidence", ["report_data": hex(data)]))
        let assertion = try await guest.evidence(try canonical(["compose_hash": composeHash, "data": hex(data), "domain": "dsmack-sdk-assert/1"]))
        return ["statement": ["signer": r["group_public"]!, "message": r["statement"]!, "signature": r["group_signature"]!],
                "report": ["signer": r["app_pub"]!, "message": hex(Data("dsmack-sdk/evidence/1".utf8) + data), "signature": r["app_signature"]!],
                "assertion": assertion, "node": r.filter { ["member", "checked_tx", "key_epoch", "M", "block"].contains($0.key) }]
    }

    func info() throws -> [String: Any] {
        let r = try node.call(request("info"))
        return r.filter { ["app_id", "compose_hash", "scope", "key_epoch", "chain_id", "registry", "block", "group_public", "member", "M", "sdk"].contains($0.key) }
            .merging(["cdhash": cdhash]) { $1 }
    }

    func reply(_ line: Data) async -> Data {
        var out: [String: Any]
        do {
            let q = try object(line, "request")
            guard q["v"] as? Int == 1, let op = q["op"] as? String, ["get_key", "evidence", "info"].contains(op) else { throw Fail("unknown_version_or_op") }
            out = op == "get_key" ? try getKey(q) : op == "info" ? try info() : try await evidence(q)
        } catch { out = ["error": "\(error)"] }
        out["v"] = 1
        return (try! canonical(out)) + Data([10])
    }

    // One thread per guest connection; each arrives as a vsock stream from the guest agent's relay of /var/run/dsmack.sock.
    func serve(_ listener: VsockListener) {
        Task.detached { [self] in
            for await h in listener { Thread.detachNewThread { [self] in connection(h.fileDescriptor) } }
        }
    }

    func connection(_ c: Int32) {
        defer { close(c) }
        var one: Int32 = 1
        setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(4))
        var buffer = Data(), chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            if let i = buffer.firstIndex(of: 10) {
                let line = Data(buffer[..<i])
                buffer = Data(buffer[(i + 1)...])
                let out = blocking { [self] in await reply(line) }
                guard out.withUnsafeBytes({ write(c, $0.baseAddress, $0.count) }) == out.count else { return }
                continue
            }
            guard buffer.count < 65536 else { return }
            let n = read(c, &chunk, chunk.count)
            guard n > 0 else { return }
            buffer.append(contentsOf: chunk[0 ..< n])
        }
    }
}

// Runs async work from a plain thread (the guest socket's), waiting for it.
func blocking<T>(_ f: @escaping @Sendable () async -> T) -> T {
    let done = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var result: T?
    Task { result = await f(); done.signal() }
    done.wait()
    return result!
}
