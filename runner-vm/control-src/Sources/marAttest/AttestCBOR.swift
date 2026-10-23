// Strict bounded CBOR decoding for App Attest evidence, mirroring the
// verifier's trusted core (verifier/attest_core.py::CBOR) rule for rule:
//
//   - definite lengths only; no tags, no floats, no indefinite containers
//     (major 7 beyond false/true/null is refused);
//   - hard size cap 100_000 bytes, container size cap 100, depth cap 12;
//   - duplicate map keys are refused; map keys must be int/str/bytes;
//   - trailing bytes after the top-level item are refused.
//
// Byte-level fidelity to that decoder is what makes "verified locally" mean
// "the verifier will parse the same structure": the cross-check tests feed
// this decoder objects produced by the verifier's own attest_rig encoder.
import Foundation

public enum AttestCBORError: Error, Equatable, CustomStringConvertible {
    case invalidSize(Int)
    case truncated
    case unsupportedType(major: Int, info: Int)
    case depth
    case lengthTooBig(Int)
    case invalidUTF8
    case containerSize(Int)
    case invalidMapKey
    case duplicateKey
    case trailingBytes(Int)

    public var description: String {
        switch self {
        case .invalidSize(let n): return "attest_cbor: invalid size \(n)"
        case .truncated: return "attest_cbor: truncated"
        case .unsupportedType(let m, let i): return "attest_cbor: unsupported type major=\(m) info=\(i)"
        case .depth: return "attest_cbor: depth exceeded"
        case .lengthTooBig(let n): return "attest_cbor: length \(n) over cap"
        case .invalidUTF8: return "attest_cbor: invalid utf-8 string"
        case .containerSize(let n): return "attest_cbor: container size \(n) over cap"
        case .invalidMapKey: return "attest_cbor: map key must be int/str/bytes"
        case .duplicateKey: return "attest_cbor: duplicate map key"
        case .trailingBytes(let n): return "attest_cbor: \(n) trailing byte(s)"
        }
    }
}

/// Decoded CBOR value: the exact subset the trusted core supports.
public enum AttestCBORValue: Equatable {
    case unsigned(UInt64)
    case negative(Int64)          // -1 - n
    case bytes(Data)
    case text(String)
    case array([AttestCBORValue])
    case map([AttestCBORMapKey: AttestCBORValue])
    case boolean(Bool)
    case null

    public var asData: Data? { if case .bytes(let d) = self { return d }; return nil }
    public var asString: String? { if case .text(let s) = self { return s }; return nil }
    public var asInt: Int? {
        switch self {
        case .unsigned(let u): return Int(exactly: u)
        case .negative(let n): return Int(exactly: n)
        default: return nil
        }
    }
    public var asMap: [AttestCBORMapKey: AttestCBORValue]? {
        if case .map(let m) = self { return m }; return nil
    }
    public var asArray: [AttestCBORValue]? { if case .array(let a) = self { return a }; return nil }
}

/// Map keys compare exactly like Python's (int/str/bytes never collide).
public enum AttestCBORMapKey: Hashable {
    case int(Int64)
    case str(String)
    case bytes(Data)
}

struct AttestCBORReader {
    let data: Data
    var pos: Int = 0
    static let maxSize = 100_000
    static let maxContainer = 100

    init(_ data: Data) throws {
        guard data.count <= AttestCBORReader.maxSize else { throw AttestCBORError.invalidSize(data.count) }
        self.data = data
    }

    mutating func take(_ n: Int) throws -> Data {
        guard n >= 0, pos + n <= data.count else { throw AttestCBORError.truncated }
        let out = data.subdata(in: pos..<(pos + n))
        pos += n
        return out
    }

    mutating func read(depth: Int = 0) throws -> AttestCBORValue {
        guard depth < 12 else { throw AttestCBORError.depth }
        let head = try take(1)[0]
        let major = Int(head >> 5), info = Int(head & 31)
        if major == 7 {
            switch info {
            case 20: return .boolean(false)
            case 21: return .boolean(true)
            case 22: return .null
            default: throw AttestCBORError.unsupportedType(major: major, info: info)
            }
        }
        guard major <= 5, info <= 27 else { throw AttestCBORError.unsupportedType(major: major, info: info) }
        let n: UInt64
        if info < 24 { n = UInt64(info) }
        else {
            let width = 1 << (info - 24)
            let raw = try take(width)
            n = raw.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        }
        switch major {
        case 0:
            return .unsigned(n)      // Python ints are unbounded; asInt bounds later use
        case 1:
            guard n <= UInt64(Int64.max) else { throw AttestCBORError.lengthTooBig(Int(n)) }
            return .negative(-1 - Int64(n))
        case 2:
            guard n <= UInt64(AttestCBORReader.maxSize) else { throw AttestCBORError.lengthTooBig(Int(n)) }
            return .bytes(try take(Int(n)))
        case 3:
            guard n <= UInt64(AttestCBORReader.maxSize) else { throw AttestCBORError.lengthTooBig(Int(n)) }
            let raw = try take(Int(n))
            guard let s = String(data: raw, encoding: .utf8) else { throw AttestCBORError.invalidUTF8 }
            return .text(s)
        default:
            guard n <= UInt64(AttestCBORReader.maxContainer) else {
                throw AttestCBORError.containerSize(Int(n))
            }
            if major == 4 {
                var items: [AttestCBORValue] = []
                for _ in 0..<Int(n) { items.append(try read(depth: depth + 1)) }
                return .array(items)
            }
            var map: [AttestCBORMapKey: AttestCBORValue] = [:]
            for _ in 0..<Int(n) {
                let key = try read(depth: depth + 1)
                let mapKey: AttestCBORMapKey
                switch key {
                case .unsigned(let u): guard let i = Int64(exactly: u) else { throw AttestCBORError.invalidMapKey }
                                       mapKey = .int(i)
                case .negative(let i): mapKey = .int(i)
                case .text(let s): mapKey = .str(s)
                case .bytes(let b): mapKey = .bytes(b)
                default: throw AttestCBORError.invalidMapKey
                }
                guard map[mapKey] == nil else { throw AttestCBORError.duplicateKey }
                map[mapKey] = try read(depth: depth + 1)
            }
            return .map(map)
        }
    }

    func end() throws {
        guard pos == data.count else { throw AttestCBORError.trailingBytes(data.count - pos) }
    }
}

public enum AttestCBOR {
    /// Decode one CBOR item; refuse anything after it (like attest_core.decode).
    public static func decode(_ data: Data) throws -> AttestCBORValue {
        var reader = try AttestCBORReader(data)
        let value = try reader.read()
        try reader.end()
        return value
    }
}
