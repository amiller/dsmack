import Foundation

struct NativeUpdateError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
    init(_ message: String) { self.message = message }
}

/// updates.json, published with each node-vX.Y.Z release. A hint only: the updater checks the
/// download against it, then asks MeasurementRegistry, which alone decides what installs.
struct NodeUpdateFeed {
    static let repository = "amiller/dsmack"
    static let latest = URL(string:"https://github.com/\(repository)/releases/latest/download/updates.json")!
    let version: String, tag: String, url: URL, sha256: String, M: Data, notes: String, raw: Data

    init(data: Data) throws {
        guard data.count<=65536, let d=try? JSONSerialization.jsonObject(with:data) as? [String:Any],
              Set(d.keys)==["version","tag","url","sha256","M","notes"],
              let version=d["version"] as? String, version.range(of:"^[0-9]{1,4}\\.[0-9]{1,4}\\.[0-9]{1,4}$",options:.regularExpression) != nil,
              let tag=d["tag"] as? String, tag=="node-v"+version,
              let link=d["url"] as? String, let url=URL(string:link),
              url.lastPathComponent.range(of:"^[A-Za-z0-9._-]+\\.zip$",options:.regularExpression) != nil,
              link=="https://github.com/\(Self.repository)/releases/download/\(tag)/"+url.lastPathComponent,
              let sha=d["sha256"] as? String, sha.range(of:"^[0-9a-f]{64}$",options:.regularExpression) != nil,
              let m=d["M"] as? String, m.range(of:"^0x[0-9a-f]{64}$",options:.regularExpression) != nil,
              let notes=d["notes"] as? String, notes.count<=4000 else {throw NativeUpdateError("updates.json is malformed.")}
        self.version=version;self.tag=tag;self.url=url;self.sha256=sha;self.M=try unhex(m);self.notes=notes;self.raw=data
    }
    func newer(than installed: String) -> Bool {version.compare(installed,options:.numeric) == .orderedDescending}
}

/// MeasurementRegistry.isAdmitted on the network compiled into this build.
struct MeasurementAdmission {
    static let margin: UInt64 = 43_200  // one day of Base blocks
    let chain: Chain

    static func configured() throws -> MeasurementAdmission {
        guard let s=ReleaseNetwork.settings, let rpc=(s["rpc"] as? String).flatMap(URL.init(string:)),
              let registry=s["measurementRegistry"] as? String, let id=(s["chainId"] as? NSNumber)?.uint64Value
        else {throw NativeUpdateError("This build has no measurement registry configured, so it installs no updates.")}
        return MeasurementAdmission(chain:Chain(rpcURL:rpc,registry:registry,chainId:id))
    }

    /// The block at which m was admitted, if it stays admitted for `margin` more blocks.
    func check(_ m: Data) throws -> UInt64 {
        let id: UInt64, block: UInt64, now: UInt64, later: UInt64
        do {
            id=try quantity(chain.rpc("eth_chainId",[]))
            block=try quantity(chain.rpc("eth_blockNumber",[]))
            now=try smallWord(chain.call("isAdmitted(bytes32,uint256)",m+word(block)))
            later=try smallWord(chain.call("isAdmitted(bytes32,uint256)",m+word(block+Self.margin)))
        } catch {throw NativeUpdateError("Cannot read the measurement registry \(chain.registry) via \(chain.rpcURL.host ?? "RPC"): \(error). Nothing was installed.")}
        guard id==chain.chainId else {throw NativeUpdateError("The RPC serves chain \(id), not \(chain.chainId). Nothing was installed.")}
        guard now==1 else {throw NativeUpdateError("Build not admitted: measurement \(hex(m)) has no open window in the registry at block \(block).")}
        guard later==1 else {throw NativeUpdateError("Build admitted at block \(block) but its window closes within \(Self.margin) blocks; not installing.")}
        return block
    }
}
