import Foundation

// Read-only check of the runner's GroupCheck against its compiled release network (sepolia.base.org caps eth_getLogs at
// 200 blocks; GroupCheck bisects keyEpochs instead). Takes the registry's current epoch E >= 2: a release for E is
// accepted; for E-1 only as an explicit previous epoch, with G read at E-1's last block, which must be the block before
// the KeyEpochStarted(scope, E) log; E-1 with the current G and E-2 are refused.
// usage (mini): xcrun swiftc runner/Sources/runner/GroupCheck.swift runner/test/GroupCheckSepolia.swift -o OUT && OUT
struct Fail: Error, CustomStringConvertible { let description: String; init(_ d: String) { description = d } }
func hex(_ d: some Sequence<UInt8>) -> String { d.map { String(format: "%02x", $0) }.joined() }
func unhex(_ s: String) throws -> Data {
    let h = Array((s.hasPrefix("0x") ? String(s.dropFirst(2)) : s).utf8)
    guard h.count % 2 == 0 else { throw Fail("odd-length hex") }
    return try Data(stride(from: 0, to: h.count, by: 2).map { i in
        guard let b = UInt8(String(decoding: h[i ..< i + 2], as: UTF8.self), radix: 16) else { throw Fail("not hex") }
        return b
    })
}

@main struct GroupCheckSepolia {
    static func main() throws {
        let c = GroupCheck(rpc: URL(string: RunnerNetwork.rpc)!, chainId: RunnerNetwork.chainId, registry: RunnerNetwork.registry, appRegistry: RunnerNetwork.appRegistry)
        let scope = Data(count: 32), latest = try c.quantity(try c.call("eth_blockNumber", [])), now = try c.epoch(scope, at: latest)
        guard now >= 2 else { throw Fail("registry epoch \(now) < 2") }
        func g(_ at: UInt64) throws -> Data { Data([4]) + (try c.read(GroupCheck.sharedKeys, scope, at: at)).prefix(64) }
        func release(_ e: UInt64) -> [String: Any] {
            ["chain_id": c.chainId, "registry": c.registry, "app_registry": c.appRegistry, "scope": hex(scope), "key_epoch": e, "block": latest]
        }
        func refused(_ f: () throws -> Void, _ expect: String) throws {
            do { try f(); throw Fail("accepted: \(expect)") } catch let e as Fail where e.description.contains(expect) { print("refused: \(e)") }
        }
        try c.verify(release(now), group: try g(latest), previous: false)
        let end = try c.epochEnd(scope, now - 1, before: latest)
        let started = try c.call("eth_getLogs", [["address": c.registry, "topics": ["0x143519224fe404fde2f926e45a8cd8de4da43c648680d13caadff828449c7ad0", "0x" + hex(scope)],
                                                  "fromBlock": "0x" + String(end + 1, radix: 16), "toBlock": "0x" + String(end + 1, radix: 16)]]) as! [[String: Any]]
        guard started.count == 1, try unhex(started[0]["data"] as! String).last == UInt8(now) else { throw Fail("no KeyEpochStarted(scope, \(now)) at block \(end + 1)") }
        let prev = try g(end)
        try c.verify(release(now - 1), group: prev, previous: true)
        try refused({ try c.verify(release(now - 1), group: prev, previous: false) }, "is not the current key epoch")
        try refused({ try c.verify(release(now - 1), group: try g(latest), previous: true) }, "group key is not sharedKeys")
        if now >= 3 { try refused({ try c.verify(release(now - 2), group: prev, previous: true) }, "is not the current key epoch") }
        var other = release(now); other["app_registry"] = "0x" + String(repeating: "11", count: 20)
        try refused({ try c.verify(other, group: try g(latest), previous: false) }, "release names chain")
        print("GroupCheckSepolia: pass, epoch \(now) at \(latest), epoch \(now - 1) ended at block \(end), G \(hex(prev).prefix(18))...")
    }
}
