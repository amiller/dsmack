import Foundation
import CryptoKit

// dsmack-sdk node side: app_root vectors, allow check, statement, epochs and the loopback JSON-line server.
// Fixed group scalars, no RPC, Keychain or App Attest. Compile with every node/shared source.
@main struct SDKVectors {
    static func main() throws {
        var passed=0
        func check(_ ok:Bool,_ label:String) throws {try need(ok,label);passed+=1;print("PASS "+label)}
        func refused(_ r:[String:Any],_ expected:String,_ label:String) throws {
            try check((r["error"] as? String)?.contains(expected)==true && r["v"] as? Int==1,"\(label) refused: \(r["error"] ?? "accepted")")
        }
        let chainId:UInt64=84532,registry="0xd4b33c83576a6049d29c6b849ec73491e52781a0",scope=zero32
        let b=Data(repeating:0,count:31)
        let g1=try P256.Signing.PrivateKey(rawRepresentation:b+[0x11]),g2=try P256.Signing.PrivateKey(rawRepresentation:b+[0x22])
        let sponsor=try P256.Signing.PrivateKey(rawRepresentation:b+[0x33]),stranger=try P256.Signing.PrivateKey(rawRepresentation:b+[0x44])
        let appX=Data(repeating:0xa1,count:32),appY=Data(repeating:0xa2,count:32)
        let c1=Data(repeating:0xc1,count:32),c1b=Data(repeating:0xc2,count:32),c3=Data(repeating:0xc3,count:32)
        let m=Data(repeating:0x4d,count:32)

        let rootX2=try SDK.appRoot(g2,chainId:chainId,registry:registry,scope:scope,keyEpoch:2,appId:appX).withUnsafeBytes{Data($0)}
        print("vector app_root(g2, epoch 2, app X) \(hex(rootX2))")
        try check(hex(rootX2)==vectorX2,"pinned app_root vector")

        func node(_ name:String) throws -> Node {
            try Node(Config(["rpc":"http://127.0.0.1:1","registry":registry,"chainId":Int(chainId),"category":hex(zero32),"relay":"http://127.0.0.1:1",
                             "name":name,"protocolVersion":2,"sdkPort":1]),log:{_,_ in})
        }
        let a=try node("a"),bNode=try node("b")
        a.hold(scope,g1,epoch:1);a.hold(scope,g2,epoch:2);bNode.hold(scope,g2,epoch:2)
        try check(a.previous[scope]?.epoch==1 && a.cfg.sdkPort==1,"bump keeps the previous epoch's key")
        func service(_ n:Node) -> SDKService {
            var s=n.sdkService(sponsor:sponsor.publicKey,measurement:m);s.block={1234};return s
        }
        let sa=service(a),sb=service(bNode)
        func allow(_ app:Data,_ compose:Data,until:Int=4_000_000_000,by key:P256.Signing.PrivateKey?=nil) throws -> [String:Any] {
            let message=try SDK.allowMessage(chainId:chainId,registry:registry,appId:app,composeHash:compose,scope:scope,until:UInt64(until))
            return ["scope":hex(scope),"until":until,"signature":hex(try (key ?? sponsor).signature(for:message).rawRepresentation)]
        }
        func call(_ s:SDKService,_ q:[String:Any]) throws -> [String:Any] {
            let line=s.reply(try JSONSerialization.data(withJSONObject:q))
            try need(line.last==10 && line.dropLast().firstIndex(of:10)==nil,"one JSON line per reply")
            return try JSONSerialization.jsonObject(with:line) as! [String:Any]
        }
        func getKey(_ s:SDKService,_ app:Data,_ compose:Data,allow record:[String:Any]?=nil,epoch:Int?=nil) throws -> (reply:[String:Any],root:Data?) {
            let eph=P256.KeyAgreement.PrivateKey()
            var q:[String:Any]=["v":1,"op":"get_key","app_id":hex(app),"compose_hash":hex(compose),"allow":try record ?? allow(app,compose),
                                "eph_pub":hex(eph.publicKey.x963Representation)]
            if let epoch {q["epoch"]=epoch}
            let r=try call(s,q)
            guard let epk=r["epk"] as? String,let sealed=r["sealed"] as? String,let st=r["statement"] as? String else {return (r,nil)}
            let k=try eph.sharedSecretFromKeyAgreement(with:P256.KeyAgreement.PublicKey(x963Representation:unhex(epk)))
                .hkdfDerivedSymmetricKey(using:SHA256.self,salt:Data(),sharedInfo:Data("dsmack-sdk/v1/release".utf8),outputByteCount:32)
            return (r,try AES.GCM.open(AES.GCM.SealedBox(combined:unhex(sealed)),using:k,authenticating:Data(SHA256.hash(data:unhex(st)))))
        }

        let ax=try getKey(sa,appX,c1),bx=try getKey(sb,appX,c1)
        try check(ax.root != nil && ax.root==bx.root && ax.root==rootX2,"two nodes with the same group key derive the same app_root")
        try check(ax.reply["app_pub"] as? String==bx.reply["app_pub"] as? String && ax.reply["key_epoch"] as? Int==2,"same app_pub on both nodes, current epoch 2")
        let ay=try getKey(sa,appY,c1)
        try check(ay.root != nil && ay.root != ax.root && ay.reply["app_pub"] as? String != ax.reply["app_pub"] as? String,"different app_id, different app_root")
        let ax2=try getKey(sa,appX,c1b)
        try check(ax2.root==ax.root && ax2.reply["app_pub"] as? String==ax.reply["app_pub"] as? String && ax2.reply["statement"] as? String != ax.reply["statement"] as? String,
                  "different compose_hash under the same app_id: same key, statement names the compose")
        try refused(try getKey(sa,appX,c3,allow:try allow(appX,c1)).reply,"compose not allowed under app_id","unlisted compose")
        try refused(try getKey(sa,appY,c1,allow:try allow(appX,c1)).reply,"compose not allowed under app_id","record for another app")
        try refused(try getKey(sa,appX,c1,allow:try allow(appX,c1,by:stranger)).reply,"compose not allowed under app_id","record signed by a non-sponsor key")
        try refused(try getKey(sa,appX,c1,allow:try allow(appX,c1,until:1000)).reply,"allow record expired","expired record")

        let a1=try getKey(sa,appX,c1,epoch:1)
        let rootX1=try SDK.appRoot(g1,chainId:chainId,registry:registry,scope:scope,keyEpoch:1,appId:appX).withUnsafeBytes{Data($0)}
        try check(a1.root==rootX1 && a1.root != ax.root && a1.reply["key_epoch"] as? Int==1,"get_key(epoch=prev) after a bump returns the old epoch's root")
        try refused(try getKey(sa,appX,c1,epoch:3).reply,"key epoch 3 not held","future epoch")
        try refused(try getKey(sa,appX,c1,epoch:0).reply,"key epoch 0 not held","older than previous epoch")
        try refused(try getKey(sb,appX,c1,epoch:1).reply,"key epoch 1 not held","epoch this node never held")

        for (name,r) in [("epoch 2",ax.reply),("epoch 1",a1.reply)] {
            let st=try unhex(r["statement"] as! String),sig=try P256.Signing.ECDSASignature(rawRepresentation:unhex(r["group_signature"] as! String))
            let e=UInt64(r["key_epoch"] as! Int),g=e==2 ? g2:g1
            let rebuilt=try SDK.statement(chainId:chainId,registry:registry,scope:scope,keyEpoch:e,appId:appX,composeHash:c1,block:1234,measurement:m,appPub:unhex(r["app_pub"] as! String))
            try check(st==rebuilt && r["group_public"] as? String==hex(g.publicKey.x963Representation),"\(name) statement encodes (app_id, app_pub, compose_hash, block, epoch, M)")
            try check(g.publicKey.isValidSignature(sig,for:st),"\(name) statement verifies against the group public key")
            try check(!(e==2 ? g1:g2).publicKey.isValidSignature(sig,for:st) && !g.publicKey.isValidSignature(sig,for:st+[0]),"\(name) statement fails under the other key or altered")
        }

        let evidenceQuery:[String:Any]=["v":1,"op":"evidence","app_id":hex(appX),"compose_hash":hex(c1),"allow":try allow(appX,c1),"report_data":hex(Data(repeating:7,count:32))]
        try refused(try call(sa,evidenceQuery),"no check-in yet","evidence before any check-in")
        a.keyLock.withLock{a.checkIn=(word(42),"0x"+String(repeating:"ab",count:32))}
        let ev=try call(sa,evidenceQuery)
        let appPub=try P256.Signing.PublicKey(x963Representation:unhex(ev["app_pub"] as! String))
        try check(appPub.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation:unhex(ev["app_signature"] as! String)),for:Data("dsmack-sdk/evidence/1".utf8)+Data(repeating:7,count:32))
                  && ev["member"] as? String==hex(word(42)) && ev["M"] as? String==hex(m) && ev["checked_tx"] as? String=="0x"+String(repeating:"ab",count:32),"evidence: app_pub signs report_data, with member, M and check-in")
        var long=evidenceQuery;long["report_data"]=hex(Data(repeating:7,count:65))
        try refused(try call(sa,long),"report_data is at most 64 bytes","65-byte report_data")
        var info=evidenceQuery;info["op"]="info";info["report_data"]=nil
        let i=try call(sa,info)
        try check(i["sdk"] as? String=="dsmack-sdk/v1" && i["chain_id"] as? Int==Int(chainId) && i["registry"] as? String==registry && i["key_epoch"] as? Int==2 && i["sealed"]==nil,"info names app, scope, epoch, chain, member and M")
        var bad=info;bad["op"]="sign";try refused(try call(sa,bad),"unknown op","op sign (slice 2)")
        bad=info;bad["v"]=2;try refused(try call(sa,bad),"unsupported v","v 2")
        try refused(try JSONSerialization.jsonObject(with:sa.reply(Data("not json".utf8))) as! [String:Any],"JSON text did not start","malformed line")

        a.retire(scope)
        try refused(try getKey(sa,appX,c1).reply,"no group key held","current request after the key is retired")
        try check(try getKey(sa,appX,c1,epoch:2).root==rootX2,"retired epoch stays available as previous")

        try check(try SDK.reduceP256(Data(repeating:0xff,count:32))==unhex("0x00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaae"),"p256 reduction subtracts n once")
        do {_=try SDK.reduceP256(Data(SDK.p256Order));throw DemoError.invalid("zero scalar accepted")} catch DemoError.invalid(let e) {try check(e=="derived scalar is zero","zero scalar refused")}

        let port=try SDK.listen(port:0,sb.reply)
        let fd=socket(AF_INET,SOCK_STREAM,0)
        var addr=sockaddr_in();addr.sin_family=sa_family_t(AF_INET);addr.sin_port=port.bigEndian;addr.sin_addr.s_addr=inet_addr("127.0.0.1")
        try need(withUnsafePointer(to:&addr){$0.withMemoryRebound(to:sockaddr.self,capacity:1){connect(fd,$0,socklen_t(MemoryLayout<sockaddr_in>.size))}}==0,"connect")
        var getQ=info;getQ["op"]="get_key";getQ["eph_pub"]=hex(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        let out=try JSONSerialization.data(withJSONObject:info)+[10]+JSONSerialization.data(withJSONObject:getQ)+[10]
        _=out.withUnsafeBytes{write(fd,$0.baseAddress,$0.count)}
        var got=Data(),chunk=[UInt8](repeating:0,count:4096)
        while got.filter({$0==10}).count<2 {let n=read(fd,&chunk,chunk.count);try need(n>0,"server closed");got.append(contentsOf:chunk[0..<n])}
        close(fd)
        let lines=got.split(separator:10).map{try! JSONSerialization.jsonObject(with:Data($0)) as! [String:Any]}
        try check(lines.count==2 && lines[0]["error"] != nil && lines[1]["sealed"] != nil && lines[1]["app_pub"] as? String==ax.reply["app_pub"] as? String,
                  "loopback server: two requests on one connection, one reply line each (info refused on b: no check-in)")
        print("SDKVectors passed: \(passed) checks")
    }
    /// Cross-checked with an independent Python HKDF-SHA256 over the same salt and info.
    static let vectorX2="0xff7581dad655737c4a35ef4192a3f5897bfdf54ea7c70570b8c185a4230fab59"
}
