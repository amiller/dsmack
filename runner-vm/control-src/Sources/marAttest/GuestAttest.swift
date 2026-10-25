// Guest Attest, the pure half: the event log the app keeps for the guest (the
// RTMR3 counterpart), its seal rule, and the fixed 255-byte client data an
// Attest assertion signs. Reference: dstack-compat/guest_attest.py; shared
// vector: Tests/marAttestTests/Fixtures/guest-attest-vector.json.
import CryptoKit
import Foundation

public let guestAttestDomain = "dsmack.appattest.guest-attest/1"

public struct GuestAttestRefusal: Error, CustomStringConvertible {
    public let description: String
    public init(_ s: String) { description = s }
}

/// domain || os_image_hash || manifest_sha256 || run || event_head || caller || report_data
public func guestAttestClientData(osImageHash: Data, manifestSha256: Data, run: Data, head: Data,
                                  caller: Data, reportData: Data) throws -> Data {
    let fields = [osImageHash, manifestSha256, run, head, caller, reportData]
    guard fields.map(\.count) == [32, 32, 32, 32, 32, 64] else {
        throw GuestAttestRefusal("client data fields must be 5 x 32 bytes and 64 bytes of report_data")
    }
    return fields.reduce(Data(guestAttestDomain.utf8), +)
}

/// Before seal: events and one seal. After seal (which appends system-ready): attest only.
public struct GuestEventLog {
    public static let maxEvents = 16
    public static let maxAttests = 64
    public private(set) var events: [(name: String, payload: Data)] = []
    public private(set) var head = Data(count: 32)
    public private(set) var sealed = false
    private var attests = 0

    /// The app's own event: the runner canary public key, kept off the guest's event path.
    public static let runnerCanaryEvent = "canary-runner-key"

    public init() {}

    public init(runnerCanaryKey: Data) {
        append(Self.runnerCanaryEvent, runnerCanaryKey)
    }

    public mutating func event(_ name: String, _ payload: Data) throws -> Data {
        guard !sealed else { throw GuestAttestRefusal("event refused after seal") }
        guard name != Self.runnerCanaryEvent else { throw GuestAttestRefusal("\(name) is the app's event") }
        guard events.count < Self.maxEvents else { throw GuestAttestRefusal("more than \(Self.maxEvents) events") }
        append(name, payload)
        return head
    }

    public mutating func seal() throws -> Data {
        guard !sealed else { throw GuestAttestRefusal("seal refused after seal") }
        sealed = true
        append("system-ready", Data())
        return head
    }

    /// Admits one attest; returns the head its client data commits to.
    public mutating func attest() throws -> Data {
        guard sealed else { throw GuestAttestRefusal("attest refused before seal") }
        guard attests < Self.maxAttests else { throw GuestAttestRefusal("more than \(Self.maxAttests) attests") }
        attests += 1
        return head
    }

    private mutating func append(_ name: String, _ payload: Data) {
        events.append((name, payload))
        let digest = Data(SHA256.hash(data: lp(Data(name.utf8)) + lp(payload)))
        head = Data(SHA256.hash(data: head + digest))
    }
}

private func lp(_ d: Data) -> Data {
    Data([24, 16, 8, 0].map { UInt8(truncatingIfNeeded: d.count >> $0) }) + d
}

/// Hex from the guest; refuses anything else.
public func guestHex(_ s: String) throws -> Data {
    func nibble(_ c: UInt8) throws -> UInt8 {
        switch c {
        case 48...57: return c - 48
        case 97...102: return c - 87
        case 65...70: return c - 55
        default: throw GuestAttestRefusal("invalid hex")
        }
    }
    let u = Array(s.utf8)
    guard u.count % 2 == 0 else { throw GuestAttestRefusal("odd-length hex") }
    return Data(try stride(from: 0, to: u.count, by: 2).map { try nibble(u[$0]) << 4 | nibble(u[$0 + 1]) })
}
