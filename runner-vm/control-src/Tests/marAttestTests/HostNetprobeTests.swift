import XCTest

@testable import marAttest

final class HostNetprobeTests: XCTestCase {
    func h(_ src: String?, _ kind: String, _ us: Int?) -> Hop { Hop(src: src, kind: kind, rttUs: us) }

    /// A double-NAT home whose ISP numbers its first router in 10/8 (measured on the Mini, 2026-11-04,
    /// addresses replaced) is not CGNAT: the own public address answers at LAN latency. The rule
    /// "private hop past the home gateway means CGNAT" would have said true.
    func testDoubleNatHomeWithPrivateIspHop() {
        let path = [h("192.168.0.1", "ttl", 3761), h("10.0.0.1", "ttl", 5042), h("10.20.30.40", "ttl", 16135), h("203.0.113.9", "ttl", 20887)]
        let selfHops = [h("192.168.0.1", "ttl", 4316), h("198.51.100.7", "reached", 5012)]
        XCTAssertEqual(cgnatVerdict(iface: "en1", path: path, selfHops: selfHops, publicAddr: "198.51.100.7", wans: [nil, nil]).1,
                       "own_public_address_inside_access_link")
        XCTAssertEqual(cgnatVerdict(iface: "en1", path: path, selfHops: selfHops, publicAddr: "198.51.100.7", wans: [nil, nil]).0, false)
        // The same home with the public address held by a carrier NAT past the access link.
        let carrier = [h("192.168.0.1", "ttl", 4000), h("10.0.0.1", "ttl", 5000), h("10.20.30.40", "ttl", 16000), h("198.51.100.7", "reached", 17000)]
        XCTAssertEqual(cgnatVerdict(iface: "en1", path: path, selfHops: carrier, publicAddr: "198.51.100.7", wans: [nil, nil]).0, true)
        let shared = [h("192.168.0.1", "ttl", 4000), h("100.72.0.1", "ttl", 15000), h("203.0.113.9", "ttl", 20000)]
        XCTAssertEqual(cgnatVerdict(iface: "en1", path: shared, selfHops: selfHops, publicAddr: "198.51.100.7", wans: [nil]).1,
                       "cgnat_hop_before_first_public_hop")
        XCTAssertNil(cgnatVerdict(iface: "utun4", path: path, selfHops: selfHops, publicAddr: "198.51.100.7", wans: []).0)
    }

    func testReportCarriesNoAddress() throws {
        let path = [h("192.168.0.1", "ttl", 3761), h(nil, "silent", nil), h("203.0.113.9", "ttl", 20887)]
        let r = try hostNetprobeReport(at: 1, iface: "en1", gateway: "192.168.0.1", path: path,
                                       selfHops: [h("198.51.100.7", "reached", 900)], echoServices: 3, publicAddr: "198.51.100.7",
                                       salt: Data(count: 32), natpmp: "result_3", upnp: "empty", wans: [nil, nil])
        let s = String(decoding: r, as: UTF8.self)
        for a in ["192.168", "203.0", "198.51"] { XCTAssertFalse(s.contains(a)) }
        XCTAssertTrue(s.contains(#""behind_cgnat":false"#), s)
    }
}
