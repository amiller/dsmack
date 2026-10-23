// dsmx-1.1 frame codec for the host side of the joined control channel.
// Wire-compatible with the channel lane's codec (../backend-join/channel/
// protocol.py, read-only reference): MAGIC "DSMX", version u16 BE = 1,
// kind u16 BE, payload_len u32 BE, header CRC-32 (ISO-HDLC), payload, payload
// CRC-32 BE. The golden vectors in tests/golden/control-profile.json were
// PRODUCED with that real codec and asserted against this implementation's
// rules, so the bytes the app relays and retains are exactly what the
// verifier's decoder will read back.
//
// Division of authority (deliberate): the app ENCODES host->guest frames
// (SESSION_START / TASK_INPUT / PROVIDER_RESPONSE) and SCANS boundaries of the
// guest->host stream so retention can stop at RESULT_TERMINAL and count
// frames/bytes. CRC verification, duplicate-terminal, route allowlists and the
// HMAC terminal stay with the guest codec and the external verifier: a
// fail-closed host scanner needs only magic/version/kind/length.
import Foundation

public enum DSMXKind: UInt16 {
    case taskInput = 1          // host->guest, pre-committed task descriptor
    case providerRequest = 2    // guest->host, opaque routed stream data
    case resultTerminal = 3     // guest->host, at most one, always last
    case traceChunk = 4         // guest->host, bounded trace append
    case outputChunk = 5        // guest->host, bounded workload output append
    case haltNotice = 6         // guest->host, advisory; never workload success
    case providerResponse = 7   // host->guest, opaque routed stream data
    case sessionStart = 8       // host->guest, exactly once, first on channel
    case sessionAbort = 9       // guest->host, fatal guest-side failure

    public var isGuestToHost: Bool {
        switch self {
        case .providerRequest, .resultTerminal, .traceChunk, .outputChunk, .haltNotice, .sessionAbort:
            return true
        case .taskInput, .providerResponse, .sessionStart:
            return false
        }
    }
}

public struct DSMXError: Error, CustomStringConvertible {
    public let description: String
    public init(_ reason: String) { description = "dsmx: \(reason)" }
}

public enum DSMX {
    public static let headerLength = 16
    public static let trailerLength = 4
    public static let defaultMaxRecord = 1 << 20
    static let magic = Data("DSMX".utf8)

    /// Encode one host->guest frame. Only host-direction kinds are encodable
    /// here; payload above the record cap is refused before any byte is sent.
    public static func encodeHostFrame(kind: DSMXKind, payload: Data,
                                       maxRecord: Int = defaultMaxRecord) throws -> Data {
        guard !kind.isGuestToHost else { throw DSMXError("host may not encode guest->guest kind \(kind.rawValue)") }
        guard payload.count <= maxRecord else { throw DSMXError("payload \(payload.count) exceeds max \(maxRecord)") }
        var header = Data(magic)
        header.appendBE(UInt16(1))
        header.appendBE(kind.rawValue)
        header.appendBE(UInt32(payload.count))
        var frame = header
        frame.appendBE(CRC32.checksum(header))
        frame.append(payload)
        frame.appendBE(CRC32.checksum(payload))
        return frame
    }

    /// Scan a complete guest->host byte stream: frame boundaries, direction and
    /// size rules, terminal-once-and-last. Returns the counts the lifecycle
    /// `channel_closed` stage must report. CRC authenticity is the external
    /// verifier's authority, never skipped by it and never claimed here.
    public static func scanGuestStream(_ data: Data, maxRecord: Int = defaultMaxRecord) throws
        -> (frames: Int, bytes: Int, terminalFrames: Int, postTerminalBytes: Int) {
        var off = data.startIndex, frames = 0, terminals = 0, post = 0
        while off < data.endIndex {
            let remaining = data.distance(from: off, to: data.endIndex)
            if terminals > 0 { post += remaining; break }   // any byte after the terminal is a violation
            guard remaining >= headerLength else { throw DSMXError("truncated header at \(remaining) bytes") }
            guard data[off..<data.index(off, offsetBy: 4)] == magic else { throw DSMXError("bad frame magic") }
            let version = data.be16(at: data.index(off, offsetBy: 4))
            guard version == 1 else { throw DSMXError("unsupported version \(version)") }
            guard let kind = DSMXKind(rawValue: data.be16(at: data.index(off, offsetBy: 6))) else {
                throw DSMXError("unknown kind")
            }
            guard kind.isGuestToHost else { throw DSMXError("host-to-guest kind \(kind.rawValue) in guest stream") }
            let length = Int(data.be32(at: data.index(off, offsetBy: 8)))
            guard length <= maxRecord else { throw DSMXError("claimed \(length) exceeds max \(maxRecord)") }
            let total = headerLength + length + trailerLength
            guard remaining >= total else { throw DSMXError("truncated frame body") }
            if kind == .resultTerminal { terminals += 1 }
            frames += 1
            off = data.index(off, offsetBy: total)
        }
        return (frames, data.count, terminals, post)
    }

    /// The RESULT_TERMINAL payload bytes (the signed dsmx-terminal-v1 record).
    /// The control statement's transcript.terminal_sha256 commits to exactly
    /// these bytes. Throws on any stream that would not scan clean with
    /// exactly one terminal.
    public static func terminalPayload(of data: Data, maxRecord: Int = defaultMaxRecord) throws -> Data {
        var off = data.startIndex, terminals = 0
        var payload = Data()
        while off < data.endIndex {
            let remaining = data.distance(from: off, to: data.endIndex)
            guard remaining >= headerLength else { throw DSMXError("truncated header") }
            guard data[off..<data.index(off, offsetBy: 4)] == magic else { throw DSMXError("bad frame magic") }
            guard data.be16(at: data.index(off, offsetBy: 4)) == 1 else { throw DSMXError("unsupported version") }
            guard let kind = DSMXKind(rawValue: data.be16(at: data.index(off, offsetBy: 6))) else {
                throw DSMXError("unknown kind")
            }
            guard kind.isGuestToHost else { throw DSMXError("host-to-guest kind in guest stream") }
            let length = Int(data.be32(at: data.index(off, offsetBy: 8)))
            guard length <= maxRecord else { throw DSMXError("claimed \(length) exceeds max") }
            let total = headerLength + length + trailerLength
            guard remaining >= total else { throw DSMXError("truncated frame body") }
            if kind == .resultTerminal { terminals += 1; payload = data.subdata(in: data.index(off, offsetBy: headerLength)..<data.index(off, offsetBy: headerLength + length)) }
            off = data.index(off, offsetBy: total)
        }
        guard terminals == 1 else { throw DSMXError("\(terminals) terminal record(s)") }
        return payload
    }
}

/// Live retention sink for the guest->host stream: the relay feeds received
/// bytes; the retained bytes are written verbatim to control.rec once the
/// channel closes. SESSION_START never appears here (it is host->guest and
/// secret-bearing); retention stops at the terminal and any later byte fails
/// the run closed.
public final class ControlRetainer {
    public private(set) var retained = Data()
    public private(set) var frames = 0
    public private(set) var terminalFrames = 0
    public private(set) var postTerminalBytes = 0
    private var pending = Data()
    private let maxRecord: Int
    private var closed = false

    public init(maxRecord: Int = DSMX.defaultMaxRecord) { self.maxRecord = maxRecord }

    public var bytes: Int { retained.count }

    public func feed(_ chunk: Data) throws {
        guard !closed else { throw DSMXError("feed after close") }
        pending.append(chunk)
        while !pending.isEmpty {
            if terminalFrames > 0 {
                postTerminalBytes += pending.count
                retained.append(pending); pending.removeAll()
                throw DSMXError("\(postTerminalBytes) byte(s) after terminal record")
            }
            guard pending.count >= DSMX.headerLength else { return }
            guard pending.prefix(4) == DSMX.magic else { throw DSMXError("bad frame magic") }
            guard pending.be16(at: pending.startIndex + 4) == 1 else { throw DSMXError("unsupported version") }
            guard let kind = DSMXKind(rawValue: pending.be16(at: pending.startIndex + 6)) else {
                throw DSMXError("unknown kind")
            }
            guard kind.isGuestToHost else { throw DSMXError("host-to-guest kind in guest stream") }
            let length = Int(pending.be32(at: pending.startIndex + 8))
            guard length <= maxRecord else { throw DSMXError("claimed \(length) exceeds max \(maxRecord)") }
            let total = DSMX.headerLength + length + DSMX.trailerLength
            guard pending.count >= total else { return }
            if kind == .resultTerminal { terminalFrames += 1 }
            frames += 1
            retained.append(pending.prefix(total))
            pending.removeFirst(total)
        }
    }

    /// Close the channel: a stream that ended without exactly one terminal
    /// record is missing its terminal, never a success (clean EOF without
    /// RESULT_TERMINAL is reported as missing).
    public func close() throws {
        guard pending.isEmpty else { throw DSMXError("eof with \(pending.count) frame bytes pending (truncated)") }
        guard terminalFrames == 1 else {
            throw DSMXError("stream closed with \(terminalFrames) terminal record(s)")
        }
        closed = true
    }
}

extension Data {
    func be16(at i: Int) -> UInt16 { UInt16(self[i]) << 8 | UInt16(self[i + 1]) }
    func be32(at i: Int) -> UInt32 {
        UInt32(self[i]) << 24 | UInt32(self[i + 1]) << 16 | UInt32(self[i + 2]) << 8 | UInt32(self[i + 3])
    }
    mutating func appendBE(_ v: UInt16) { append(UInt8(v >> 8)); append(UInt8(v & 0xff)) }
    mutating func appendBE(_ v: UInt32) {
        append(UInt8((v >> 24) & 0xff)); append(UInt8((v >> 16) & 0xff))
        append(UInt8((v >> 8) & 0xff)); append(UInt8(v & 0xff))
    }
}
