// Host network probe, the pure half: address classes, the CGNAT verdict and the report bytes.
// The app measures (mar HostNetprobeIO.swift) and asserts the report as a guest Attest whose
// caller is hostNetprobeCaller, which the guest cannot use. Reference: resip research/netprobe/netprobe.py.
import CryptoKit
import Foundation

public let hostNetprobeSchema = "dsmack.host-netprobe/1"
public let hostNetprobeCaller = Data(SHA256.hash(data: Data(hostNetprobeSchema.utf8)))

public struct Hop: Equatable {
    public let src: String?
    public let kind: String
    public let rttUs: Int?
    public init(src: String?, kind: String, rttUs: Int?) { self.src = src; self.kind = kind; self.rttUs = rttUs }
}

func ipv4(_ a: String) -> [UInt8]? {
    let p = a.split(separator: ".", omittingEmptySubsequences: false).compactMap { UInt8($0) }
    return p.count == 4 ? p : nil
}

/// silent, cgnat (100.64.0.0/10), private (RFC 1918), public, or other (loopback, link-local, multicast, reserved).
public func addressClass(_ a: String?) -> String {
    guard let a else { return "silent" }
    guard let b = ipv4(a) else { return "other" }
    if b[0] == 100 && b[1] & 0xc0 == 64 { return "cgnat" }
    if b[0] == 10 || b[0] == 172 && b[1] & 0xf0 == 16 || b[0] == 192 && b[1] == 168 { return "private" }
    if b[0] == 0 || b[0] == 127 || b[0] >= 224 || b[0] == 169 && b[1] == 254 || b[0] == 192 && b[1] == 0 && b[2] == 0
        || b[0] == 198 && b[1] & 0xfe == 18 { return "other" }
    return "public"
}

/// behind_cgnat (nil = unknown) and the rule that decided it.
/// path: hops toward an anycast target up to the first public hop. selfHops: hops toward the echo-seen address.
/// wans: router WAN addresses from NAT-PMP and UPnP, nil where the router gave none.
public func cgnatVerdict(iface: String, path: [Hop], selfHops: [Hop], publicAddr: String, wans: [String?]) -> (Bool?, String) {
    if ["utun", "ipsec", "ppp", "tun", "tap"].contains(where: iface.hasPrefix) { return (nil, "default_route_is_tunnel") }
    if path.prefix(while: { addressClass($0.src) != "public" }).contains(where: { addressClass($0.src) == "cgnat" }) {
        return (true, "cgnat_hop_before_first_public_hop")
    }
    for case let a? in wans {
        if addressClass(a) == "cgnat" { return (true, "gateway_wan_in_cgnat_range") }
        if a == publicAddr { return (false, "gateway_wan_equals_echo_address") }
    }
    guard let last = selfHops.last, last.kind == "reached", last.src == publicAddr else { return (nil, "own_public_address_not_reached") }
    if selfHops.dropLast().contains(where: { !["private", "silent"].contains(addressClass($0.src)) }) {
        return (true, "own_public_address_beyond_non_private_hop")
    }
    // The access link (cable, DSL, fiber, radio) is the first hop slower than 3x the LAN gateway.
    guard let lan = path.first?.rttUs, let step = path.firstIndex(where: { ($0.rttUs ?? 0) > 3 * max(lan, 1000) }) else {
        return (nil, "no_access_link_latency_step")
    }
    return selfHops.count <= step ? (false, "own_public_address_inside_access_link") : (true, "own_public_address_beyond_access_link")
}

/// The report bytes the assertion binds: classes, kinds, integer RTTs and sha256(salt || address); never an address.
public func hostNetprobeReport(at: Int, iface: String, gateway: String, path: [Hop], selfHops: [Hop], echoServices: Int,
                               publicAddr: String, salt: Data, natpmp: String, upnp: String, wans: [String?]) throws -> Data {
    guard let pub = ipv4(publicAddr), salt.count == 32 else { throw GuestAttestRefusal("netprobe: bad public address or salt") }
    let (behind, reason) = cgnatVerdict(iface: iface, path: path, selfHops: selfHops, publicAddr: publicAddr, wans: wans)
    func hop(_ h: Hop) -> [String: Any] {
        ["class": addressClass(h.src), "kind": h.kind, "rtt_us": h.rttUs.map { $0 as Any } ?? NSNull()]
    }
    let report: [String: Any] = [
        "schema": hostNetprobeSchema, "at": at,
        "route": ["iface": String(iface.prefix { !$0.isNumber }), "gateway": addressClass(gateway)],
        "path": path.map(hop), "self": selfHops.map(hop),
        "echo": ["services": echoServices, "class": addressClass(publicAddr),
                 "commitment": SHA256.hash(data: salt + Data(pub)).map { String(format: "%02x", $0) }.joined()],
        "natpmp": natpmp, "upnp": upnp,
        "behind_cgnat": behind.map { $0 as Any } ?? NSNull(), "reason": reason,
    ]
    return try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys, .withoutEscapingSlashes])
}
