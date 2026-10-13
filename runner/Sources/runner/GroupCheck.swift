import Foundation

// The network the runner checks its node's releases against, compiled in so M_runner covers it, as ReleaseNetwork
// (node/mac/NetworkConfig.swift) pins the node's: RPC, chain id, the group-key registry and the AppRegistry. Only an
// SDK_TEST_NETWORK build (build_mac.py --runner --sdk-test-network) takes them from the command line.
enum RunnerNetwork {
    static let rpc = "https://sepolia.base.org", chainId: UInt64 = 84532
    static let registry = "0xd4B33C83576a6049d29c6B849ec73491e52781a0", appRegistry = "0xa4d26deDf4d086216a0E2cFbc7bdA49918f5C5c3"
}

// A release must name this network, and its G (group_public) must be the registry's committed sharedKeys(scope) for the
// statement's key epoch, which must be the registry's current epoch, or the one directly before it when the runner
// asked for that epoch explicitly (get_key(epoch=prev) during a rotation). G is read at the statement's block if the
// epoch was current there, else at the epoch's last block, found by galloping back and bisecting keyEpochs(scope) over
// block numbers (eth_call at past blocks; no eth_getLogs, which sepolia.base.org caps at 200 blocks).
// Same check: sdk/python/dsmack_sdk/verify.py group_on_chain.
struct GroupCheck {
    static let keyEpochs = "0xd71779d9", sharedKeys = "0xd5b7abaf"
    let rpc: URL, chainId: UInt64, registry: String, appRegistry: String

    // At most 20 calls a second: sepolia.base.org answers {"code":-32007,"message":"25/second request limit reached"}
    // beyond 25, and a previous-epoch check bisects with a few dozen calls.
    func call(_ method: String, _ params: [Any]) throws -> Any {
        Thread.sleep(forTimeInterval: 0.05)
        var req = URLRequest(url: rpc)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "content-type")
        req.httpBody = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": 1, "method": method, "params": params])
        let done = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var reply: (Data?, Error?)
        URLSession.shared.dataTask(with: req) { d, _, e in reply = (d, e); done.signal() }.resume()
        done.wait()
        guard let d = reply.0 else { throw Fail("RPC \(method): \(reply.1.map { "\($0)" } ?? "no reply")") }
        let text = String(decoding: d.prefix(300), as: UTF8.self)
        guard let r = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { throw Fail("RPC \(method): reply is not a JSON object: \(text)") }
        if let e = r["error"] { throw Fail("RPC \(method) error \(e)") }
        guard let v = r["result"] else { throw Fail("RPC \(method): no result: \(text)") }
        return v
    }
    func quantity(_ s: Any?) throws -> UInt64 {
        guard let s = s as? String, s.hasPrefix("0x"), let n = UInt64(s.dropFirst(2), radix: 16) else { throw Fail("RPC quantity \(s ?? "nil")") }
        return n
    }
    func read(_ selector: String, _ scope: Data, at block: UInt64?) throws -> Data {
        let tag = block.map { "0x" + String($0, radix: 16) } ?? "latest"
        guard let s = try call("eth_call", [["to": registry, "data": selector + hex(scope)], tag]) as? String else { throw Fail("eth_call result") }
        return try unhex(s)
    }
    // keyEpochs(scope) at a block (nil: latest); an empty result means no registry code yet there, so no epoch started.
    func epoch(_ scope: Data, at block: UInt64?) throws -> UInt64 {
        let w = try read(Self.keyEpochs, scope, at: block)
        if w.isEmpty { return 0 }
        guard w.count == 32, w.prefix(24).allSatisfy({ $0 == 0 }) else { throw Fail("keyEpochs is not a small ABI word") }
        return w.suffix(8).reduce(0) { $0 << 8 | UInt64($1) }
    }
    // The last block of `e`, which had ended by `block`.
    func epochEnd(_ scope: Data, _ e: UInt64, before block: UInt64) throws -> UInt64 {
        guard try epoch(scope, at: block) > e else { throw Fail("key epoch \(e) had not ended at block \(block)") }
        var hi = block, step: UInt64 = 1, lo = block - 1  // epoch(hi) > e throughout
        while lo > 0, try epoch(scope, at: lo) > e { hi = lo; step *= 2; lo = hi > step ? hi - step : 0 }
        while hi - lo > 1 { let mid = (lo + hi) / 2; if try epoch(scope, at: mid) > e { hi = mid } else { lo = mid } }
        return lo
    }
    func verify(_ r: [String: Any], group: Data, previous: Bool) throws {
        guard let chain = r["chain_id"] as? UInt64, let reg = r["registry"] as? String, let apps = r["app_registry"] as? String, let s = r["scope"] as? String,
              let e = r["key_epoch"] as? UInt64, let block = r["block"] as? UInt64 else { throw Fail("node release fields") }
        guard chain == chainId, reg.lowercased() == registry.lowercased(), apps.lowercased() == appRegistry.lowercased(), try quantity(try call("eth_chainId", [])) == chainId else {
            throw Fail("release names chain \(chain), registry \(reg), AppRegistry \(apps), not this runner's \(chainId), \(registry), \(appRegistry)")
        }
        let scope = try unhex(s), now = try epoch(scope, at: nil)
        guard e == now || (previous && e + 1 == now) else { throw Fail("key epoch \(e) is not the current key epoch \(now)\(previous ? " or the one before it" : "")") }
        let at = try epoch(scope, at: block) == e ? block : try epochEnd(scope, e, before: block)
        let k = try read(Self.sharedKeys, scope, at: at)
        guard try epoch(scope, at: at) == e, k.count == 128, k[127] == 1, Data([4]) + k.prefix(64) == group else {
            throw Fail("group key is not sharedKeys(scope) for key epoch \(e) at block \(at)")
        }
    }
}
