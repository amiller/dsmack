import Foundation
import CoreFoundation

// Release-owner recommendations are fetched only from the pinned public repository.
// This is not a chain admission oracle: the GUI names that trust boundary explicitly.
struct NativeUpdateError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
    init(_ message: String) { self.message = message }
}
struct NativeUpdateRecommendation {
    static let repository = "amiller/dsmack"
    static let discovery = URL(string:"https://api.github.com/repos/amiller/dsmack/releases/tags/native-recommended")!
    let tag: String
    let version: String
    let build: Int
    let archive: URL
    let sha256: String
    let bytes: Int
    let expires: Date
    let network: [String:String]
    let previousBuilds: [Int]
    let rollbackBuilds: [Int]
    let evidence: URL
    static let networkKeys = ["chainId", "registry", "category", "protocolVersion", "relay", "rpc", "peer", "badges", "accountFactory"]

    static func network(_ settings: [String:Any]) throws -> [String:String] {
        var result=[String:String]()
        for key in networkKeys {
            guard let value=settings[key] else {throw NativeUpdateError("This build has no complete update network profile.")}
            if let text=value as? String {result[key]=text}
            else if let number=value as? NSNumber {result[key]=number.stringValue}
            else {throw NativeUpdateError("Unsupported network profile.")}
        }
        return result
    }
    static func exactKeys(_ object:[String:Any], _ keys:[String]) throws {
        guard Set(object.keys)==Set(keys) else {throw NativeUpdateError("Unsupported release recommendation format.")}
    }
    static func integer(_ value:Any?) -> Int? {
        guard let n=value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), n.doubleValue.rounded()==n.doubleValue,
              n.doubleValue>=0, n.doubleValue<=2147483647 else {return nil}
        return n.intValue
    }
    init(data:Data,currentBuild:Int,highestBuild:Int,network expected:[String:String],now:Date=Date()) throws {
        guard data.count<=65536, let d=try JSONSerialization.jsonObject(with:data) as? [String:Any] else {throw NativeUpdateError("Release recommendation is too large or malformed.")}
        try Self.exactKeys(d,["format","tag","version","build","archive","sha256","bytes","expires","network","previousBuilds","rollbackBuilds","qualification","evidence"])
        guard Self.integer(d["format"])==1,
              let tag=d["tag"] as? String, tag.range(of:"^native-v[0-9][A-Za-z0-9._-]{0,63}$",options:.regularExpression) != nil,
              let version=d["version"] as? String, version.range(of:"^[0-9][A-Za-z0-9._-]{0,63}$",options:.regularExpression) != nil,
              let build=Self.integer(d["build"]),build>currentBuild,build>=highestBuild,
              let bytes=Self.integer(d["bytes"]),bytes>0,bytes<=250_000_000,
              let digest=d["sha256"] as? String,digest.range(of:"^[0-9a-f]{64}$",options:.regularExpression) != nil,
              let archiveString=d["archive"] as? String,let archive=URL(string:archiveString),
              archive.scheme=="https",archive.host=="github.com",archive.user==nil,archive.password==nil,archive.query==nil,archive.fragment==nil,
              archive.path.hasPrefix("/\(Self.repository)/releases/download/\(tag)/"),archive.lastPathComponent.range(of:"^[A-Za-z0-9._-]+\\.zip$",options:.regularExpression) != nil,
              archive.pathComponents.count==7,
              let expiry=d["expires"] as? String,let expires=ISO8601DateFormatter().date(from:expiry),expires>now,expires.timeIntervalSince(now)<=7*86400,
              let network=d["network"] as? [String:String],network==expected,
              d["qualification"] as? String=="release-owner-qualified",
              let previous=d["previousBuilds"] as? [Any],let rollback=d["rollbackBuilds"] as? [Any],previous.count<=32,rollback.count<=32,
              previous.allSatisfy({Self.integer($0) != nil}),rollback.allSatisfy({Self.integer($0) != nil}),
              let evidenceString=d["evidence"] as? String,let evidence=URL(string:evidenceString),evidence.scheme=="https",evidence.host=="github.com",evidence.user==nil,evidence.password==nil,evidence.query==nil,evidence.fragment==nil,
              evidence.path.hasPrefix("/\(Self.repository)/") else {throw NativeUpdateError("The recommendation is expired, incompatible, a downgrade, or not qualified by the release owner.")}
        let previousBuilds=previous.compactMap(Self.integer),rollbackBuilds=rollback.compactMap(Self.integer)
        guard Set(previousBuilds).count==previousBuilds.count,Set(rollbackBuilds).count==rollbackBuilds.count,previousBuilds.contains(currentBuild) else {throw NativeUpdateError("This release does not support updating your current build.")}
        self.tag=tag;self.version=version;self.build=build;self.archive=archive;self.sha256=digest;self.bytes=bytes;self.expires=expires;self.network=network;self.previousBuilds=previousBuilds;self.rollbackBuilds=rollbackBuilds;self.evidence=evidence
    }
}
