// Host-side control-session driver for the joined control profile
// (astra-gate R3): the ACTUAL adapter the hvf-control mode runs — not the
// Python HostDriver stand-in. Wire contract = channel/protocol.py +
// channel/terminal_auth.py (dsmx-1.1 / dsmx-terminal-v1):
//
//   * every received frame's header AND payload CRC-32 are verified before the
//     frame is counted or retained (the old ControlRetainer checked neither);
//   * RESULT_TERMINAL is authenticated HERE over the bytes this process
//     actually collected: HMAC-SHA256 with the SESSION_START key, run identity
//     (run_id + nonce = replay refusal), task commitment, stdout/stderr/trace
//     stream commitments rebuilt from the collected OUTPUT_CHUNK/TRACE_CHUNK
//     bytes, artifact rows well-formed, provider counters equal to the host's
//     own accounting, and byte-canonical encoding (exactly one byte string per
//     statement);
//   * retention is aggregate-capped (frames AND bytes) and output/trace
//     collection is per-stream capped, so a hostile guest cannot grow host
//     memory through individually legal frames;
//   * the socket is configured non-blocking explicitly and every send/recv is
//     deadline-bounded through poll(), so a peer that stops reading (without
//     EOF) can stall a write or a drain only until the session deadline.
//
// The external verifier remains the admission authority; this adapter is the
// internal check SPRINT.md §8 requires ("Root terminal HMAC is checked
// internally") and it gates what hvf-control may report as a completed session.
import Foundation

// MARK: - HMAC-SHA256 (RFC 2104 over the local SHA256)

public enum HMACSHA256 {
    public static func authenticate(key: Data, message: Data) -> [UInt8] {
        var k = [UInt8](key)
        if k.count > 64 { k = SHA256.digest(Data(k)) }
        k.append(contentsOf: repeatElement(0, count: 64 - k.count))
        let ipad = Data(k.map { $0 ^ 0x36 })
        let opad = Data(k.map { $0 ^ 0x5c })
        let inner = SHA256.digest(ipad + message)
        return SHA256.digest(opad + Data(inner))
    }

    public static func hexDigest(key: Data, message: Data) -> String {
        authenticate(key: key, message: message).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Python-compatible JSON for terminal verification

/// The terminal record's authenticator is HMAC over the record's canonical
/// JSON — bytes produced by Python `json.dumps(sort_keys=True,
/// separators=(",",":"), ensure_ascii=True)`. Verification re-encodes the
/// parsed record with byte-identical rules (floats in Python repr form) and
/// additionally requires the re-encoding to equal the received bytes, so
/// there is exactly one byte string per statement (terminal_auth.verify).
public enum PyJSON {
    public struct ParseError: Error, CustomStringConvertible { public let description: String }

    /// Strict parse: duplicate object keys, non-finite constants and trailing
    /// bytes are refused (mirrors terminal_auth._strict_loads). Ints stay
    /// Int, anything with `.`/`e` becomes Double (Python json semantics).
    public static func parse(_ payload: Data) throws -> Any {
        var p = Parser(bytes: [UInt8](payload))
        let v = try p.value()
        p.skipWS()
        guard p.at == p.bytes.count else { throw ParseError(description: "trailing bytes after JSON value") }
        return v
    }

    public static func canonical(_ value: Any) throws -> Data {
        Data(encode(value).utf8)
    }

    // ---- encoding (json.dumps sort_keys, separators=(",",":"), ensure_ascii) ----

    static func encode(_ value: Any) -> String {
        switch value {
        case let s as String: return quote(s)
        case let b as Bool: return b ? "true" : "false"   // before numeric: Bool bridges to NSNumber
        case let i as Int: return String(i)
        case let d as Double: return pyRepr(d)
        case let n as NSNumber:
            if isIntegral(n) { return String(n.intValue) }
            return pyRepr(n.doubleValue)
        case let a as [Any]: return "[" + a.map(encode).joined(separator: ",") + "]"
        case let o as [String: Any]:
            let keys = o.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
            return "{" + keys.map { quote($0) + ":" + encode(o[$0]!) }.joined(separator: ",") + "}"
        case is NSNull: return "null"
        default: return "null"
        }
    }

    static func isIntegral(_ n: NSNumber) -> Bool {
        switch String(cString: n.objCType) {
        case "q", "i", "l", "B", "c", "s", "h", "I", "L", "C", "S", "H": return true
        default: return false
        }
    }

    static func quote(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0c}": out += "\\f"
            default:
                if scalar.value < 0x20 || scalar.value > 0x7e {
                    if scalar.value > 0xffff {
                        let v = scalar.value - 0x10000
                        out += String(format: "\\u%04x\\u%04x", 0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff))
                    } else {
                        out += String(format: "\\u%04x", scalar.value)
                    }
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }

    /// Python repr(float) semantics: shortest round-trip digits; positional
    /// notation when -4 <= floor(log10(|x|)) < 16, otherwise `d.ddde±XX` with
    /// a two-digit exponent. Swift's own description switches to exponent
    /// notation at different thresholds, so the shortest digits are taken
    /// from it and re-formatted under Python's rules. `FloatRepr` cases are
    /// golden-tested against real Python output.
    public static func pyRepr(_ d: Double) -> String {
        if d == 0 { return d.sign == .minus ? "-0.0" : "0.0" }
        guard d.isFinite else { return "nan" }   // never canonical; upstream parse refuses these
        let s = d.description   // shortest round-trip digits (Swift's Double description)
        var neg = false
        var body = s
        if body.hasPrefix("-") { neg = true; body.removeFirst() }
        var digits = ""
        var e: Int
        if let eIdx = body.firstIndex(where: { $0 == "e" || $0 == "E" }) {
            let mant = body[body.startIndex..<eIdx]
            e = Int(body[body.index(after: eIdx)...]) ?? 0
            for c in mant where c.isNumber { digits.append(c) }
        } else {
            let intLen = body.firstIndex(of: ".").map { body.distance(from: body.startIndex, to: $0) } ?? body.count
            for c in body where c.isNumber { digits.append(c) }
            e = intLen - 1   // value = d.ddd × 10^e
        }
        // strip redundant zeros of the shortest-digit mantissa (defensive:
        // Swift's description is already shortest)
        while digits.count > 1 && digits.hasSuffix("0") { digits.removeLast() }
        while digits.count > 1 && digits.first == "0" { digits.removeFirst(); e -= 1 }
        let sign = neg ? "-" : ""
        if e >= 16 || e < -4 {
            let mantissa = digits.count == 1 ? digits
                : String(digits.first.map { $0 } ?? "0") + "." + String(digits.dropFirst())
            let absE = abs(e)
            return sign + mantissa + "e" + (e >= 0 ? "+" : "-") + (absE < 10 ? "0" : "") + String(absE)
        }
        if e < 0 {
            return sign + "0." + String(repeating: "0", count: -e - 1) + digits
        }
        if e >= digits.count - 1 {
            return sign + digits + String(repeating: "0", count: e - (digits.count - 1)) + ".0"
        }
        let idx = digits.index(digits.startIndex, offsetBy: e + 1)
        return sign + digits[..<idx] + "." + digits[idx...]
    }

    // ---- strict parsing ----

    struct Parser {
        let bytes: [UInt8]
        var at = 0
        init(bytes: [UInt8]) { self.bytes = bytes }

        mutating func skipWS() {
            while at < bytes.count && (bytes[at] == 0x20 || bytes[at] == 0x09 || bytes[at] == 0x0a || bytes[at] == 0x0d) { at += 1 }
        }
        mutating func expect(_ c: UInt8) throws {
            guard at < bytes.count, bytes[at] == c else {
                throw ParseError(description: "expected '\(Character(UnicodeScalar(c)))' at \(at)")
            }
            at += 1
        }
        mutating func value() throws -> Any {
            skipWS()
            guard at < bytes.count else { throw ParseError(description: "empty JSON") }
            switch bytes[at] {
            case UInt8(ascii: "{"): return try object()
            case UInt8(ascii: "["): return try array()
            case UInt8(ascii: "\""): return try string()
            case UInt8(ascii: "t"): try literal("true"); return true
            case UInt8(ascii: "f"): try literal("false"); return false
            case UInt8(ascii: "n"): try literal("null"); return NSNull()
            default: return try number()
            }
        }
        mutating func literal(_ word: String) throws {
            for c in word.utf8 {
                guard at < bytes.count, bytes[at] == c else { throw ParseError(description: "bad literal") }
                at += 1
            }
        }
        mutating func object() throws -> [String: Any] {
            try expect(UInt8(ascii: "{"))
            var out = [String: Any]()
            skipWS()
            if at < bytes.count, bytes[at] == UInt8(ascii: "}") { at += 1; return out }
            while true {
                skipWS()
                let key = try string()
                skipWS()
                try expect(UInt8(ascii: ":"))
                let v = try value()
                if out[key] != nil { throw ParseError(description: "duplicate object key") }
                out[key] = v
                skipWS()
                guard at < bytes.count else { throw ParseError(description: "unterminated object") }
                if bytes[at] == UInt8(ascii: ",") { at += 1; continue }
                try expect(UInt8(ascii: "}"))
                return out
            }
        }
        mutating func array() throws -> [Any] {
            try expect(UInt8(ascii: "["))
            var out = [Any]()
            skipWS()
            if at < bytes.count, bytes[at] == UInt8(ascii: "]") { at += 1; return out }
            while true {
                out.append(try value())
                skipWS()
                guard at < bytes.count else { throw ParseError(description: "unterminated array") }
                if bytes[at] == UInt8(ascii: ",") { at += 1; continue }
                try expect(UInt8(ascii: "]"))
                return out
            }
        }
        mutating func string() throws -> String {
            try expect(UInt8(ascii: "\""))
            var out = [UInt8]()
            while true {
                guard at < bytes.count else { throw ParseError(description: "unterminated string") }
                let b = bytes[at]; at += 1
                if b == UInt8(ascii: "\"") {
                    guard let s = String(bytes: out, encoding: .utf8) else {
                        throw ParseError(description: "invalid UTF-8 in string")
                    }
                    return s
                }
                if b == UInt8(ascii: "\\") {
                    guard at < bytes.count else { throw ParseError(description: "dangling escape") }
                    let e = bytes[at]; at += 1
                    switch e {
                    case UInt8(ascii: "\""): out.append(UInt8(ascii: "\""))
                    case UInt8(ascii: "\\"): out.append(UInt8(ascii: "\\"))
                    case UInt8(ascii: "/"): out.append(UInt8(ascii: "/"))
                    case UInt8(ascii: "b"): out.append(0x08)
                    case UInt8(ascii: "f"): out.append(0x0c)
                    case UInt8(ascii: "n"): out.append(0x0a)
                    case UInt8(ascii: "r"): out.append(0x0d)
                    case UInt8(ascii: "t"): out.append(0x09)
                    case UInt8(ascii: "u"):
                        let scalar = try unicodeEscape()
                        appendUTF8(scalar, to: &out)
                    default: throw ParseError(description: "bad escape")
                    }
                    continue
                }
                if b < 0x20 { throw ParseError(description: "raw control byte in string") }
                out.append(b)
            }
        }
        /// One \uXXXX; a high surrogate must be followed by its low pair.
        mutating func unicodeEscape() throws -> UInt32 {
            let hi = try hex4()
            if hi >= 0xd800 && hi < 0xdc00 {
                guard at + 1 < bytes.count, bytes[at] == UInt8(ascii: "\\"), bytes[at + 1] == UInt8(ascii: "u") else {
                    throw ParseError(description: "lone high surrogate")
                }
                at += 2
                let lo = try hex4()
                guard lo >= 0xdc00 && lo < 0xe000 else { throw ParseError(description: "bad low surrogate") }
                return 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
            }
            if hi >= 0xdc00 && hi < 0xe000 { throw ParseError(description: "lone low surrogate") }
            return hi
        }
        mutating func hex4() throws -> UInt32 {
            var v: UInt32 = 0
            for _ in 0..<4 {
                guard at < bytes.count else { throw ParseError(description: "short \\u") }
                let h = bytes[at]; at += 1
                switch h {
                case 0x30...0x39: v = v << 4 | UInt32(h - 0x30)
                case 0x61...0x66: v = v << 4 | UInt32(h - 0x61 + 10)
                case 0x41...0x46: v = v << 4 | UInt32(h - 0x41 + 10)
                default: throw ParseError(description: "bad \\u hex")
                }
            }
            return v
        }
        func appendUTF8(_ scalar: UInt32, to out: inout [UInt8]) {
            guard let u = UnicodeScalar(scalar) else { return }
            for byte in String(u).utf8 { out.append(byte) }
        }
        mutating func number() throws -> Any {
            let start = at
            if at < bytes.count, bytes[at] == UInt8(ascii: "-") { at += 1 }
            var digits = 0
            var isFloat = false
            while at < bytes.count {
                let b = bytes[at]
                if b >= 0x30 && b <= 0x39 { digits += 1; at += 1; continue }
                if b == UInt8(ascii: ".") || b == UInt8(ascii: "e") || b == UInt8(ascii: "E")
                    || b == UInt8(ascii: "+") {
                    isFloat = true; at += 1; continue
                }
                if b == UInt8(ascii: "-") {
                    // a minus after the first character is an exponent sign
                    if at > start && (bytes[at - 1] == UInt8(ascii: "e") || bytes[at - 1] == UInt8(ascii: "E")) {
                        isFloat = true; at += 1; continue
                    }
                    break
                }
                break
            }
            guard digits > 0 else { throw ParseError(description: "malformed number") }
            guard let text = String(bytes: bytes[start..<at], encoding: .utf8) else {
                throw ParseError(description: "malformed number bytes")
            }
            if !isFloat, let i = Int(text) { return i }
            guard let d = Double(text), d.isFinite else { throw ParseError(description: "non-finite or malformed number") }
            return d
        }
    }
}

// MARK: - Terminal record authentication (dsmx-terminal-v1)

public struct TerminalRecord {
    public let fields: [String: Any]
    public let status: String
    public let exitStatus: Int
    public let authenticatorHex: String
    public let artifacts: [[Any]]
    public let provider: [String: Any]
}

public enum TerminalRejection: Error, CustomStringConvertible {
    case missingTerminal
    case malformed(String)
    public var description: String {
        switch self {
        case .missingTerminal: return "terminal: no terminal record seen"
        case .malformed(let m): return "terminal rejected: \(m)"
        }
    }
}

public enum TerminalAuth {
    public static let schema = "dsmx-terminal-v1"
    public static let recordFields: Set<String> = [
        "schema", "run_id", "nonce", "task_sha256", "status", "exit_status",
        "started", "finished", "output", "trace", "artifacts", "provider",
        "authenticator",
    ]

    public static func streamCommitment(_ data: Data) -> [String: Any] {
        ["sha256": SHA256.hex(data), "bytes": data.count, "truncated": false]
    }

    static func isLowercaseHex64(_ s: String) -> Bool {
        s.count == 64 && s.allSatisfy { ($0 >= "0" && $0 <= "9") || ($0 >= "a" && $0 <= "f") }
    }

    /// Full host-side verification over the bytes THIS process collected —
    /// mirrors channel/terminal_auth.py::verify field for field.
    public static func verify(payload: Data, hmacKey: Data, runId: String, nonce: String,
                              taskSHA256: String, collectedStdout: Data, collectedStderr: Data,
                              collectedTrace: Data,
                              expectedProvider: [String: Int]) throws -> TerminalRecord {
        let obj: Any
        do { obj = try PyJSON.parse(payload) }
        catch { throw TerminalRejection.malformed("unparseable: \(error)") }
        guard let record = obj as? [String: Any] else {
            throw TerminalRejection.malformed("record is not an object")
        }
        guard Set(record.keys) == recordFields else {
            throw TerminalRejection.malformed("field set \(record.keys.sorted()) != expected")
        }
        guard record["schema"] as? String == schema else {
            throw TerminalRejection.malformed("schema mismatch")
        }
        // exactly one byte string per statement: canonical re-encode == payload
        let canonical: Data
        do { canonical = try PyJSON.canonical(record) }
        catch { throw TerminalRejection.malformed("re-encode failed: \(error)") }
        guard canonical == payload else { throw TerminalRejection.malformed("record is not canonical") }
        guard record["run_id"] as? String == runId else {
            throw TerminalRejection.malformed("run_id mismatch (replay or tampering)")
        }
        guard record["nonce"] as? String == nonce else {
            throw TerminalRejection.malformed("nonce mismatch (replay from another session)")
        }
        guard record["task_sha256"] as? String == taskSHA256 else {
            throw TerminalRejection.malformed("task commitment mismatch (task tampering)")
        }
        let status = record["status"] as? String ?? ""
        guard status == "completed" || status == "failed" else {
            throw TerminalRejection.malformed("status not allowed")
        }
        guard let output = record["output"] as? [String: Any], output.count == 2,
              output["stdout"] != nil, output["stderr"] != nil else {
            throw TerminalRejection.malformed("output commitments malformed")
        }
        let expectedOutput: [String: Any] = [
            "stdout": streamCommitment(collectedStdout),
            "stderr": streamCommitment(collectedStderr),
        ]
        guard pyEqual(output, expectedOutput) else {
            throw TerminalRejection.malformed("output commitments do not match collected bytes")
        }
        guard let trace = record["trace"] as? [String: Any] else {
            throw TerminalRejection.malformed("trace commitment malformed")
        }
        guard pyEqual(trace, streamCommitment(collectedTrace)) else {
            throw TerminalRejection.malformed("trace commitment does not match collected trace")
        }
        guard let artifacts = record["artifacts"] as? [Any] else {
            throw TerminalRejection.malformed("artifact list malformed")
        }
        for row in artifacts {
            guard let row = row as? [Any], row.count == 3,
                  row[0] is String, row[1] is String, row[2] is Int else {
                throw TerminalRejection.malformed("artifact entry malformed")
            }
            guard isLowercaseHex64(row[1] as! String) else {
                throw TerminalRejection.malformed("artifact \(row[0]) sha256 malformed")
            }
        }
        guard let provider = record["provider"] as? [String: Any],
              ["streams", "requests", "bytes_up", "bytes_down"].allSatisfy({ provider[$0] != nil }) else {
            throw TerminalRejection.malformed("provider block malformed")
        }
        for (k, v) in expectedProvider {
            guard (provider[k] as? Int) == v else {
                throw TerminalRejection.malformed("provider \(k) mismatch (\(String(describing: provider[k])) != \(v))")
            }
        }
        // the authenticator: HMAC over the canonical record WITHOUT the field
        var base = record
        let claimed = base.removeValue(forKey: "authenticator") as? String ?? ""
        guard let baseBytes = try? PyJSON.canonical(base) else {
            throw TerminalRejection.malformed("base re-encode failed")
        }
        let mac = HMACSHA256.hexDigest(key: hmacKey, message: baseBytes)
        guard mac == claimed else {
            throw TerminalRejection.malformed("authenticator invalid (forged or corrupted)")
        }
        return TerminalRecord(fields: record, status: status,
                              exitStatus: record["exit_status"] as? Int ?? -1,
                              authenticatorHex: claimed,
                              artifacts: artifacts.compactMap { $0 as? [Any] },
                              provider: provider)
    }

    /// Structural equality with Python dict semantics: Bool never equals a
    /// number ("truncated": false is not 0), ints and floats compare by value
    /// (0 == 0.0), containers recurse.
    static func pyEqual(_ a: Any, _ b: Any) -> Bool {
        switch (a, b) {
        case (let x as Bool, let y as Bool): return x == y
        case (is Bool, _): return false
        case (_, is Bool): return false
        case (let x as Int, let y as Int): return x == y
        case (let x as Int, let y as Double): return Double(x) == y
        case (let x as Double, let y as Int): return x == Double(y)
        case (let x as Double, let y as Double): return x == y
        case (let x as String, let y as String): return x == y
        case (is NSNull, is NSNull): return true
        case (let x as [Any], let y as [Any]):
            return x.count == y.count && zip(x, y).map(pyEqual).allSatisfy { $0 }
        case (let x as [String: Any], let y as [String: Any]):
            return x.count == y.count && x.allSatisfy { y[$0.key] != nil && pyEqual($0.value, y[$0.key]!) }
        default: return false
        }
    }
}

// MARK: - Aggregate-capped, CRC-checked retention + collection

/// Streaming host-side sink for the guest->host stream (replaces the
/// boundary-only ControlRetainer): every frame is CRC-verified, retention and
/// collection are aggregate-capped, and the collected stdout/stderr/trace
/// bytes feed TerminalAuth.verify. SESSION_START never appears (host->guest).
public final class ControlSessionRetainer {
    public struct Limits {
        public var maxRecord: Int = DSMX.defaultMaxRecord
        public var maxFrames: Int = 4096                 // aggregate retained frames
        public var maxRetainedBytes: Int = 64 << 20      // aggregate retained bytes
        public var maxOutputBytesPerStream: Int = 16 << 20
        public var maxTraceBytes: Int = 4 << 20
        public init() {}
    }

    public private(set) var retained = Data()
    public private(set) var frames = 0
    public private(set) var terminalFrames = 0
    public private(set) var postTerminalBytes = 0
    public private(set) var stdout = Data()
    public private(set) var stderr = Data()
    public private(set) var trace = Data()
    public private(set) var terminalPayload: Data?
    public private(set) var limits: Limits
    private var pending = Data()
    private var closed = false

    public init(limits: Limits = Limits()) { self.limits = limits }

    public var bytes: Int { retained.count }

    public func feed(_ chunk: Data) throws {
        guard !closed else { throw DSMXError("feed after close") }
        pending.append(chunk)
        while !pending.isEmpty {
            if terminalFrames > 0 {
                postTerminalBytes += pending.count
                retained.append(pending)
                pending.removeAll()
                throw DSMXError("\(postTerminalBytes) byte(s) after terminal record")
            }
            guard pending.count >= DSMX.headerLength else { return }
            guard pending.prefix(4) == DSMX.magic else { throw DSMXError("bad frame magic") }
            let version = pending.be16(at: pending.startIndex + 4)
            guard version == 1 else { throw DSMXError("unsupported version \(version)") }
            guard let kind = DSMXKind(rawValue: pending.be16(at: pending.startIndex + 6)) else {
                throw DSMXError("unknown kind")
            }
            guard kind.isGuestToHost else { throw DSMXError("host-to-guest kind \(kind.rawValue) in guest stream") }
            // header CRC BEFORE the claimed length is trusted (fail closed from
            // the header alone, like the channel codec)
            let headerPrefix = pending.prefix(12)
            let foundHCRC = pending.be32(at: pending.startIndex + 12)
            guard foundHCRC == CRC32.checksum(headerPrefix) else { throw DSMXError("header crc mismatch") }
            let length = Int(pending.be32(at: pending.startIndex + 8))
            guard length <= limits.maxRecord else { throw DSMXError("claimed \(length) exceeds max \(limits.maxRecord)") }
            let total = DSMX.headerLength + length + DSMX.trailerLength
            guard pending.count >= total else { return }
            let payload = pending.subdata(in: pending.index(pending.startIndex, offsetBy: DSMX.headerLength)
                ..< pending.index(pending.startIndex, offsetBy: DSMX.headerLength + length))
            let foundPCRC = pending.be32(at: pending.index(pending.startIndex, offsetBy: DSMX.headerLength + length))
            guard foundPCRC == CRC32.checksum(payload) else { throw DSMXError("payload crc mismatch") }
            // aggregate retention caps BEFORE the frame is kept
            guard frames + 1 <= limits.maxFrames else {
                throw DSMXError("aggregate frame cap \(limits.maxFrames) exceeded")
            }
            guard retained.count + total <= limits.maxRetainedBytes else {
                throw DSMXError("aggregate retention cap \(limits.maxRetainedBytes) exceeded")
            }
            try collect(kind: kind, payload: payload)
            if kind == .resultTerminal {
                terminalFrames += 1
                terminalPayload = payload
            }
            frames += 1
            retained.append(pending.prefix(total))
            pending.removeFirst(total)
        }
    }

    /// OUTPUT_CHUNK payload = [selector] + data (0 stdout, 1 stderr);
    /// TRACE_CHUNK payload = data. Per-stream caps bound host memory.
    func collect(kind: DSMXKind, payload: Data) throws {
        switch kind {
        case .traceChunk:
            guard trace.count + payload.count <= limits.maxTraceBytes else {
                throw DSMXError("trace cap \(limits.maxTraceBytes) exceeded")
            }
            trace.append(payload)
        case .outputChunk:
            guard let first = payload.first else { throw DSMXError("empty output chunk") }
            let data = payload.dropFirst()
            if first == 0 {
                guard stdout.count + data.count <= limits.maxOutputBytesPerStream else {
                    throw DSMXError("stdout cap \(limits.maxOutputBytesPerStream) exceeded")
                }
                stdout.append(data)
            } else if first == 1 {
                guard stderr.count + data.count <= limits.maxOutputBytesPerStream else {
                    throw DSMXError("stderr cap \(limits.maxOutputBytesPerStream) exceeded")
                }
                stderr.append(data)
            } else {
                throw DSMXError("unknown output stream selector \(first)")
            }
        default:
            break
        }
    }

    /// Close the channel: EOF without exactly one CRC-valid terminal is a
    /// truncated session, never a success.
    public func close() throws {
        guard pending.isEmpty else { throw DSMXError("eof with \(pending.count) frame bytes pending (truncated)") }
        guard terminalFrames == 1 else { throw DSMXError("stream closed with \(terminalFrames) terminal record(s)") }
        closed = true
    }

    /// Authenticate the terminal over the bytes actually collected. The
    /// session may only be reported complete after this returns.
    public func verifyTerminal(hmacKey: Data, runId: String, nonce: String,
                               taskSHA256: String,
                               expectedProvider: [String: Int] = [:]) throws -> TerminalRecord {
        guard let payload = terminalPayload else { throw TerminalRejection.missingTerminal }
        return try TerminalAuth.verify(payload: payload, hmacKey: hmacKey, runId: runId,
                                       nonce: nonce, taskSHA256: taskSHA256,
                                       collectedStdout: stdout, collectedStderr: stderr,
                                       collectedTrace: trace, expectedProvider: expectedProvider)
    }
}

// MARK: - Explicitly non-blocking, deadline-bounded channel I/O

public enum ControlIO {
    public struct Timeout: Error, CustomStringConvertible { public let description: String }
    public struct IOFailure: Error, CustomStringConvertible { public let description: String }

    public enum RecvResult {
        case data(Data)
        case wouldBlock
        case eof
    }

    /// Configure the descriptor non-blocking EXPLICITLY (astra-gate R3: the
    /// old path described the socket as nonblocking but never configured it).
    public static func makeNonblocking(fd: Int32) throws {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0 else { throw IOFailure(description: "F_GETFL: \(String(cString: strerror(errno)))") }
        guard fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw IOFailure(description: "F_SETFL O_NONBLOCK: \(String(cString: strerror(errno)))")
        }
    }

    /// Deadline-bounded send of the whole buffer; throws Timeout when no
    /// further progress is possible before the deadline (a peer that stops
    /// reading without EOF can stall the write only until the deadline).
    public static func sendAll(fd: Int32, _ data: Data, deadline: ContinuousClock.Instant) throws {
        var sent = 0
        let buf = [UInt8](data)
        while sent < buf.count {
            let now = ContinuousClock.now
            guard now < deadline else {
                throw Timeout(description: "control send deadline exceeded after \(sent)/\(buf.count) bytes")
            }
            let remaining = deadline - now
            let ms = Int32(max(1, min(1_000, Int(remaining / .milliseconds(1)))))
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&pfd, 1, ms)
            if ready < 0 {
                if errno == EINTR { continue }
                throw IOFailure(description: "poll: \(String(cString: strerror(errno)))")
            }
            if ready == 0 { continue }
            let n = buf[sent...].withUnsafeBytes { raw -> Int in
                Darwin.send(fd, raw.baseAddress, raw.count, 0)
            }
            if n > 0 { sent += n; continue }
            if n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) { continue }
            throw IOFailure(description: "send: \(String(cString: strerror(errno)))")
        }
    }

    /// One deadline-bounded receive. `.eof` only after a checked poll reported
    /// readable and recv(2) returned 0.
    public static func recv(fd: Int32, maxBytes: Int = 65536,
                            deadline: ContinuousClock.Instant) throws -> RecvResult {
        let now = ContinuousClock.now
        guard now < deadline else { throw Timeout(description: "control recv deadline exceeded") }
        let remaining = deadline - now
        let ms = Int32(max(1, min(1_000, Int(remaining / .milliseconds(1)))))
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let ready = poll(&pfd, 1, ms)
        if ready < 0 {
            if errno == EINTR { return .wouldBlock }
            throw IOFailure(description: "poll: \(String(cString: strerror(errno)))")
        }
        if ready == 0 { return .wouldBlock }
        var buf = Data(count: maxBytes)
        let n = buf.withUnsafeMutableBytes { raw -> Int in
            Darwin.recv(fd, raw.baseAddress, maxBytes, 0)
        }
        if n > 0 { return .data(buf.prefix(n)) }
        if n == 0 { return .eof }
        if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { return .wouldBlock }
        throw IOFailure(description: "recv: \(String(cString: strerror(errno)))")
    }
}

// MARK: - Host endpoint ownership (astra-gate R4)

/// Owns the HOST end of the control socketpair with an explicit close on every
/// path (the guest end moves into the archive, which owns it from the call on
/// — including refusals). close() is idempotent; deinit closes any remainder,
/// so the descriptor can never leak past the object's lifetime.
public final class ControlHostEndpoint {
    public let fileDescriptor: Int32
    private var closed = false

    public init(fd: Int32) {
        fileDescriptor = fd
        _ = fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC)
    }

    public func close() {
        guard !closed else { return }
        closed = true
        repeat {} while Darwin.close(fileDescriptor) != 0 && errno == EINTR
    }

    deinit {
        if !closed { repeat {} while Darwin.close(fileDescriptor) != 0 && errno == EINTR }
    }
}
