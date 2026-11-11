// HostNetprobeIO.swift — the measuring half of the host network probe (verdict and report: marAttest
// HostNetprobe.swift). Unprivileged: ICMP over SOCK_DGRAM as /sbin/ping does, NAT-PMP and SSDP over UDP,
// three HTTPS echo services. Read-only toward the routers: no mappings are requested.

#if canImport(Darwin)
import CryptoKit
import Darwin
import Foundation
import marAttest

let netprobeEcho = ["https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"]
let netprobeTarget = "1.1.1.1"

func inAddr(_ a: String) throws -> in_addr {
    var x = in_addr()
    guard inet_pton(AF_INET, a, &x) == 1 else { throw Fail("netprobe: \(a) is not IPv4") }
    return x
}

func sockaddrIn(_ a: String, _ port: UInt16) throws -> sockaddr_in {
    var s = sockaddr_in()
    s.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); s.sin_family = sa_family_t(AF_INET)
    s.sin_port = port.bigEndian; s.sin_addr = try inAddr(a)
    return s
}

/// A UDP or ICMP datagram exchange: send once, then hand each reply to `take` until it returns
/// non-nil or `wait` seconds pass.
func exchange<T>(proto: Int32, ttl: Int32? = nil, to: String, port: UInt16 = 0, _ pkt: Data, wait: Double,
                 _ take: (Data, String, Int) -> T?) throws -> T? {
    let fd = socket(AF_INET, SOCK_DGRAM, proto)
    guard fd >= 0 else { throw Fail("netprobe: socket errno \(errno)") }
    defer { close(fd) }
    if var t = ttl { guard setsockopt(fd, IPPROTO_IP, IP_TTL, &t, 4) == 0 else { throw Fail("netprobe: IP_TTL errno \(errno)") } }
    var dst = try sockaddrIn(to, port)
    let start = ContinuousClock.now
    let sent = pkt.withUnsafeBytes { b in withUnsafePointer(to: &dst) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, b.baseAddress, pkt.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } }
    guard sent == pkt.count else { throw Fail("netprobe: sendto \(to) errno \(errno)") }
    var buf = [UInt8](repeating: 0, count: 4096)
    while true {
        let left = wait - Double((ContinuousClock.now - start) / .microseconds(1)) / 1e6
        if left <= 0 { return nil }
        var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&p, 1, Int32(left * 1000) + 1) >= 0 else { throw Fail("netprobe: poll errno \(errno)") }
        if p.revents & Int16(POLLIN) == 0 { continue }
        var from = sockaddr_in(), len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let n = withUnsafeMutablePointer(to: &from) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, buf.count, 0, $0, &len) } }
        guard n >= 0 else { throw Fail("netprobe: recvfrom errno \(errno)") }
        let us = Int((ContinuousClock.now - start) / .microseconds(1))
        if let r = take(Data(buf[0..<n]), String(cString: inet_ntoa(from.sin_addr)), us) { return r }
    }
}

/// One ICMP echo at `ttl`: (responder, ttl | unreach | reached, rtt µs), or nil if nothing matched within 1 s.
func icmpProbe(_ dst: String, ttl: Int32, seq: UInt16) throws -> Hop? {
    var id = Data(count: 12); id.withUnsafeMutableBytes { arc4random_buf($0.baseAddress, 12) }
    id.replaceSubrange(2..<4, with: [UInt8(seq >> 8), UInt8(seq & 0xff)])
    var sum = 0x0800 + stride(from: 0, to: 12, by: 2).reduce(0) { $0 + Int(id[$1]) << 8 + Int(id[$1 + 1]) }
    sum = (sum >> 16) + (sum & 0xffff); sum = ~(sum + (sum >> 16)) & 0xffff
    let pkt = Data([8, 0, UInt8(sum >> 8), UInt8(sum & 0xff)]) + id
    return try exchange(proto: IPPROTO_ICMP, ttl: ttl, to: dst, pkt, wait: 1) { d, src, us in
        let d = d.count > 20 ? d.dropFirst(Int(d[d.startIndex] & 0xf) * 4) : Data()
        guard d.count >= 16 else { return nil }
        let b = d.startIndex
        if d[b] == 0, d.dropFirst(4) == id { return Hop(src: src, kind: "reached", rttUs: us) }
        guard d[b] == 3 || d[b] == 11, d.count > 28 else { return nil }
        let inner = d.dropFirst(8 + Int(d[b + 8] & 0xf) * 4)
        return inner.count >= 8 && inner.dropFirst(4).prefix(4) == id.prefix(4)
            ? Hop(src: src, kind: d[b] == 11 ? "ttl" : "unreach", rttUs: us) : nil
    }
}

/// Up to 8 hops, three tries each (median RTT); stops when reached, unreachable, or (stopPublic) at the first public hop.
func netTrace(_ dst: String, stopPublic: Bool) throws -> [Hop] {
    var hops: [Hop] = []
    for ttl in 1...8 {
        let got = try (0..<3).compactMap { try icmpProbe(dst, ttl: Int32(ttl), seq: UInt16(ttl * 16 + $0)) }
        let rtts = got.compactMap(\.rttUs).sorted()
        let hop = got.first.map { Hop(src: $0.src, kind: $0.kind, rttUs: rtts[rtts.count / 2]) } ?? Hop(src: nil, kind: "silent", rttUs: nil)
        hops.append(hop)
        if hop.kind != "ttl" && hop.kind != "silent" || stopPublic && addressClass(hop.src) == "public" { break }
    }
    return hops
}

func natpmpWan(_ gw: String) throws -> (String, String?) {
    try exchange(proto: IPPROTO_UDP, to: gw, port: 5351, Data([0, 0]), wait: 3) { d, src, _ -> (String, String?)? in
        guard src == gw, d.count >= 12, d[1] == 128 else { return nil }
        let code = Int(d[2]) << 8 | Int(d[3])
        if code != 0 { return ("result_\(code)", nil) }
        let a = d[8..<12].map(String.init).joined(separator: ".")
        return (addressClass(a), a)
    } ?? ("no_answer", nil)
}

func httpText(_ r: URLRequest) async throws -> String {
    let (body, resp) = try await URLSession.shared.data(for: r)
    guard (resp as? HTTPURLResponse)?.statusCode == 200 else { throw Fail("netprobe: \(r.url!) answered \(resp)") }
    return String(decoding: body, as: UTF8.self)
}

func firstMatch(_ re: String, _ s: String) -> [String]? {
    let rx = try! NSRegularExpression(pattern: re, options: [.caseInsensitive, .dotMatchesLineSeparators])
    return rx.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)).map { m in
        (1..<m.numberOfRanges).map { String(s[Range(m.range(at: $0), in: s)!]) }
    }
}

func upnpWan() async throws -> (String, String?) {
    let st = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
    let search = Data("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: \(st)\r\n\r\n".utf8)
    var locs = Set<String>()
    _ = try exchange(proto: IPPROTO_UDP, to: "239.255.255.250", port: 1900, search, wait: 3) { d, _, _ -> Bool? in
        if let l = firstMatch(#"location:\s*(\S+)"#, String(decoding: d, as: UTF8.self)) { locs.insert(l[0]) }
        return nil
    }
    if locs.isEmpty { return ("no_igd", nil) }
    for loc in locs.sorted() {
        let desc = try await httpText(URLRequest(url: URL(string: loc)!, timeoutInterval: 5))
        guard let svc = firstMatch(#"<serviceType>(urn:schemas-upnp-org:service:WAN(?:IP|PPP)Connection:\d)</serviceType>.*?<controlURL>([^<]+)</controlURL>"#, desc)
        else { continue }
        var r = URLRequest(url: URL(string: svc[1], relativeTo: URL(string: loc)!)!, timeoutInterval: 5)
        r.httpMethod = "POST"
        r.setValue("text/xml; charset=\"utf-8\"", forHTTPHeaderField: "Content-Type")
        r.setValue("\"\(svc[0])#GetExternalIPAddress\"", forHTTPHeaderField: "SOAPAction")
        r.httpBody = Data(#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetExternalIPAddress xmlns:u="\#(svc[0])"/></s:Body></s:Envelope>"#.utf8)
        if let a = firstMatch(#"<NewExternalIPAddress>([^<]+)<"#, try await httpText(r))?[0] { return (addressClass(a), a) }
    }
    return ("empty", nil)
}

func defaultRoute() throws -> (gateway: String, iface: String) {
    let p = Process(), pipe = Pipe()
    p.executableURL = URL(fileURLWithPath: "/sbin/route"); p.arguments = ["-n", "get", "default"]; p.standardOutput = pipe
    try p.run(); p.waitUntilExit()
    let s = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    guard p.terminationStatus == 0, let g = firstMatch(#"gateway: (\S+)"#, s), let i = firstMatch(#"interface: (\S+)"#, s)
    else { throw Fail("netprobe: no IPv4 default route") }
    return (g[0], i[0])
}

/// Measures and returns (report bytes, salt). The salt opens the report's commitment to the public address.
func hostNetprobe() async throws -> (Data, Data) {
    let route = try defaultRoute()
    var seen: [String] = []
    for u in netprobeEcho {
        seen.append(try await httpText(URLRequest(url: URL(string: u)!, timeoutInterval: 8)).trimmingCharacters(in: .whitespacesAndNewlines))
    }
    guard Set(seen).count == 1 else { throw Fail("netprobe: echo services disagree") }
    let path = try netTrace(netprobeTarget, stopPublic: true), selfHops = try netTrace(seen[0], stopPublic: false)
    let pmp = try natpmpWan(route.gateway), up = try await upnpWan()
    var salt = Data(count: 32); salt.withUnsafeMutableBytes { arc4random_buf($0.baseAddress, 32) }
    let report = try hostNetprobeReport(at: Int(Date().timeIntervalSince1970), iface: route.iface, gateway: route.gateway,
                                        path: path, selfHops: selfHops, echoServices: netprobeEcho.count, publicAddr: seen[0],
                                        salt: salt, natpmp: pmp.0, upnp: up.0, wans: [pmp.1, up.1])
    return (report, salt)
}
#endif
