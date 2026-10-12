import Foundation
import CryptoKit
import Security

/// Signed-app test of the seed Enclave seal. `unit` uses a random tag and deletes its key.
/// `open <config>` and `delete <config>` act on a seed's real seal, for cross-binary probes.
@main struct SeedSealTests {
    static func emit(_ fields:[String:Any]) {
        print(String(decoding:try! JSONSerialization.data(withJSONObject:fields,options:[.sortedKeys]),as:UTF8.self))
    }
    static func node(_ path:String) throws -> Node {
        let url=URL(fileURLWithPath:path)
        guard let d=try JSONSerialization.jsonObject(with:Data(contentsOf:url)) as? [String:Any] else {throw DemoError.invalid("config JSON")}
        return Node(try Config(d,path:url),log:{_,_ in})
    }
    static func main() throws {
        let args=CommandLine.arguments
        if args.count==3 && args[1]=="open" {
            let n=try node(args[2])
            do {let opened=try SeedSeal.read(n.cfg.sealPath!,tag:n.sealTag);emit(["opened":true,"epoch":opened.epoch,"groupPublic":hex(opened.key.publicKey.x963Representation)])}
            catch {emit(["opened":false,"error":"\(error)"]);exit(2)}
            return
        }
        if args.count==3 && args[1]=="delete" {
            let status=SecItemDelete(SeedSeal.query(try node(args[2]).sealTag) as CFDictionary)
            emit(["deleted":status==errSecSuccess,"status":status]);return
        }
        try need(args.count==2 && args[1]=="unit","usage: SeedSealTests unit | open <config> | delete <config>")
        var bytes=[UInt8](repeating:0,count:16)
        try need(SecRandomCopyBytes(kSecRandomDefault,bytes.count,&bytes)==errSecSuccess,"random tag")
        let tag=Data("dev.dsmack.seed-seal.test:".utf8)+Data(bytes),other=tag+Data([1])
        defer {SecItemDelete(SeedSeal.query(tag) as CFDictionary);SecItemDelete(SeedSeal.query(other) as CFDictionary)}
        let dir=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true)
        defer {try? FileManager.default.removeItem(at:dir)}
        var checks=0
        func check(_ ok:Bool,_ label:String) throws {try need(ok,label);checks+=1}
        func rejects(_ label:String,_ op:() throws -> Void) throws {
            do {try op()} catch {checks+=1;return}
            throw DemoError.invalid("accepted: "+label)
        }
        let key=P256.Signing.PrivateKey(),path=dir.appendingPathComponent("seed.sealed-key")
        try rejects("open without Enclave key") {_=try SeedSeal.read(path,tag:tag)}
        try SeedSeal.write(path,tag:tag,epoch:7,key:key)
        let opened=try SeedSeal.read(path,tag:tag)
        try check(opened.epoch==7 && opened.key.rawRepresentation==key.rawRepresentation,"round trip")
        let mode=try FileManager.default.attributesOfItem(atPath:path.path)[.posixPermissions] as? Int
        try check(mode==0o600,"seal file mode")
        let sealed=try Data(contentsOf:path)
        try check(sealed.range(of:key.rawRepresentation)==nil,"plaintext key absent from file")
        var tampered=sealed;tampered[tampered.count-1]^=1;try tampered.write(to:path)
        try rejects("tampered seal") {_=try SeedSeal.read(path,tag:tag)}
        try sealed.prefix(sealed.count-20).write(to:path)
        try rejects("truncated seal") {_=try SeedSeal.read(path,tag:tag)}
        try sealed.write(to:path)
        _=try SeedSeal.enclaveKey(other)
        try rejects("seal opened by another Enclave key") {_=try SeedSeal.read(path,tag:other)}
        try SeedSeal.write(path,tag:tag,epoch:8,key:key)
        try check(try SeedSeal.read(path,tag:tag).epoch==8,"reseal replaces epoch")
        // Key attributes the policy rests on.
        var q=SeedSeal.query(tag);q[kSecReturnAttributes as String]=true
        var item:CFTypeRef?;try check(SecItemCopyMatching(q as CFDictionary,&item)==errSecSuccess,"attributes")
        let attributes=item as! [String:Any]
        try check(attributes[kSecAttrTokenID as String] as? String==kSecAttrTokenIDSecureEnclave as String,"Secure Enclave token")
        var export:Unmanaged<CFError>?
        try check(SecKeyCopyExternalRepresentation(try SeedSeal.find(tag)!,&export)==nil,"private key not exportable")
        // Config rules.
        let base:[String:Any]=["rpc":"http://127.0.0.1:1","registry":"0x1111111111111111111111111111111111111111","chainId":31337,
                               "category":hex(zero32),"relay":"http://127.0.0.1:1","name":"seal-test"]
        let cfgPath=URL(fileURLWithPath:"/x/seed-a.json")
        try check(try Config(base,path:cfgPath).sealPath==nil,"non-sealer never seals")
        try check(try Config(base.merging(["sealer":true]){$1},path:cfgPath).sealPath?.path=="/x/seed-a.sealed-key","seal beside config")
        try rejects("sealer without config path") {_=try Config(base.merging(["sealer":true]){$1})}
        try check(try Config(base.merging(["peer":"a"]){$1}).peers==["a"],"single peer")
        try check(try Config(base.merging(["peer":["a","b"]]){$1}).peers==["a","b"],"peer list")
        try check(try Config(base.merging(["peer":""]){$1}).peers==[],"empty peer")
        try rejects("peer of wrong type") {_=try Config(base.merging(["peer":7]){$1})}
        emit(["checks":checks,"accessGroup":attributes[kSecAttrAccessGroup as String] ?? NSNull(),
              "accessControl":attributes[kSecAttrAccessControl as String].map{"\($0)"} ?? NSNull(),"result":"pass"])
    }
}
