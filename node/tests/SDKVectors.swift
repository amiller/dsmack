import Foundation
import CryptoKit

// dsmack-sdk node side: app_root vectors, AppRegistry allow check, runner admission, statement, epochs and the loopback
// server. Fixed group scalars, no RPC or Keychain: the AppRegistry read is an in-memory table at a chosen block. Compile with every node/shared source.
// Three builds: -D SDK_TEST_TRUST (runner measurements from config); release mode with node/shared/SDKRunners.swift naming
// the fixture runner's M_runner (`--sdk-runners-file`, see .github/workflows/mac-build.yml); release mode with the empty committed list,
// which only checks that the SDK refuses to start.
// usage: SDKVectors node/tests/sdk_runner_fixture.json  (test-only synthetic App Attest evidence, never Apple's, over real
// CodeDirectories from contracts/fixtures/resign; node/tests/sdk_runner_fixture.py)
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
        let appRegistry="0x9a676e781a523b5d0c0e43731313a708cb607508",admin=Data(repeating:0xad,count:20)
        let fx=try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[1]))) as! [String:Any]
        try need(fx["synthetic_only"] as? Bool==true,"fixture must be synthetic")
        let now=UInt64(fx["now"] as! Int),anchor=Data(base64Encoded:fx["synthetic_root"] as! String)!,runner=try bytes32(fx["runner_m"] as! String),modifiedM=fx["modified_m"] as! String
        let enrollments=fx["enrollments"] as! [String:[String:Any]]
        let appX=Data(repeating:0xa1,count:32),appY=Data(repeating:0xa2,count:32),appS=Data(repeating:0xa5,count:32),appZ=Data(repeating:0xa9,count:32)
        // c1 and c1b are the composes the synthetic runner enrollments "good" and "wrong_compose" attest.
        let c1=try bytes32(fx["compose_sha256"] as! String),c1b=zero32,c3=Data(repeating:0xc3,count:32)
        let m=Data(repeating:0x4d,count:32)

        let rootX2=try SDK.appRoot(g2,chainId:chainId,registry:registry,scope:scope,keyEpoch:2,appId:appX).withUnsafeBytes{Data($0)}
        print("vector app_root(g2, epoch 2, app X) \(hex(rootX2))")
        try check(hex(rootX2)==vectorX2,"pinned app_root vector")
        try check(hex(try SDK.appSigner(SymmetricKey(data:rootX2)).publicKey.x963Representation)==vectorAppPubX2,"pinned app_pub vector")

        #if SDK_TEST_TRUST
        let trust:[String:Any]=["sdkRunners":[hex(runner)],"sdkTestAnchor":fx["synthetic_root"]!]
        #else
        let trust:[String:Any]=[:]
        #endif
        func node(_ name:String) throws -> Node {
            try Node(Config(["rpc":"http://127.0.0.1:1","registry":registry,"chainId":Int(chainId),"category":hex(zero32),"relay":"http://127.0.0.1:1",
                             "name":name,"protocolVersion":2,"sdkPort":1,"appRegistry":appRegistry].merging(trust){$1}),log:{_,_ in})
        }
        let base:[String:Any]=["rpc":"http://127.0.0.1:1","registry":registry,"chainId":1,"category":hex(zero32),"relay":"http://127.0.0.1:1","name":"x"]
        func configRefused(_ extra:[String:Any],_ expected:String,_ label:String) throws {
            do {_=try Config(base.merging(extra){$1});throw DemoError.invalid("accepted")}
            catch DemoError.invalid(let e) {try check(e==expected,label)}
        }
        #if SDK_TEST_TRUST
        try configRefused(["sdkPort":1,"appRegistry":appRegistry,"sdkTestAnchor":trust["sdkTestAnchor"]!],"sdkPort and a non-empty sdkRunners list go together","test build: sdkPort without config runner CDHashes refused")
        #else
        try configRefused(["sdkPort":1,"appRegistry":appRegistry,"sdkRunners":[hex(runner)]],"sdkRunners is compiled into the node (inside M); a config list needs an SDK_TEST_TRUST build",
                          "release build: config-only sdkRunners refused")
        try configRefused(["sdkRunners":[hex(runner)]],"sdkRunners is compiled into the node (inside M); a config list needs an SDK_TEST_TRUST build",
                          "release build: config sdkRunners refused without sdkPort too")
        if compiledSDKRunnerMeasurements.isEmpty {
            try configRefused(["sdkPort":1,"appRegistry":appRegistry],"sdkPort needs a runner measurement compiled into the node (build_mac.py --sdk-runner)",
                              "release build with no compiled runner: sdkPort refused")
            print("SDKVectors passed: \(passed) checks (no compiled runner: SDK refusals only)")
            return
        }
        #endif
        try configRefused(["sdkPort":1].merging(trust){$1},"sdkPort and appRegistry go together","sdkPort without an AppRegistry address refused: no SDK without the on-chain table")
        let a=try node("a"),bNode=try node("b")
        #if !SDK_TEST_TRUST
        try check(a.cfg.sdkRunners==[runner],"release build: runner measurements are the compiled-in list")
        #endif
        a.hold(scope,g1,epoch:1);a.hold(scope,g2,epoch:2);bNode.hold(scope,g2,epoch:2)
        try check(a.previous[scope]?.epoch==1 && a.cfg.sdkPort==1,"bump keeps the previous epoch's key")
        // The AppRegistry table: apps(appId) {admin, scope} and composes(appId, composeHash) {from, until}, read at `block`.
        var apps=[appX:scope,appY:scope,appS:Data(repeating:1,count:32)]
        let open:(UInt64,UInt64)=(0,UInt64.max)
        var windows=[appX+c1:open,appY+c1:open,appX+c1b:open,appS+c1:open]
        func service(_ n:Node,runners:[Data]?=nil,at:UInt64?=nil,block:UInt64=1234) -> SDKService {
            var s=n.sdkService(appRegistry:appRegistry,measurement:m,runners:runners ?? n.cfg.sdkRunners,anchor:anchor);s.now={at ?? now}
            s.appTable={app,compose in let w=windows[app+compose] ?? (0,0)
                return SDK.Entry(block:block,admin:apps[app]==nil ? Data(repeating:0,count:20):admin,scope:apps[app] ?? zero32,from:w.0,until:w.1)}
            return s
        }
        let sa=service(a),sb=service(bNode)
        func call(_ s:SDKService,_ q:[String:Any],_ session:inout SDKSession) throws -> [String:Any] {
            let line=s.reply(try JSONSerialization.data(withJSONObject:q),&session)
            try need(line.last==10 && line.dropLast().firstIndex(of:10)==nil,"one JSON line per reply")
            return try JSONSerialization.jsonObject(with:line) as! [String:Any]
        }
        func canonical(_ o:[String:Any]) throws -> Data {try JSONSerialization.data(withJSONObject:o,options:[.sortedKeys,.withoutEscapingSlashes])}
        func cborBytes(_ d:Data) -> Data {d.count<24 ? Data([0x40+UInt8(d.count)])+d : d.count<256 ? Data([0x58,UInt8(d.count)])+d : Data([0x59,UInt8(d.count>>8),UInt8(d.count&0xff)])+d}
        // What the runner would send: its /attest object over "dsmack-sdk-runner/1|challenge|sha256(request)".
        func runnerEvidence(_ name:String,_ challenge:Data,_ request:[String:Any],code:String?=nil) throws -> [String:Any] {
            let e=enrollments[name]!,leaf=try P256.Signing.PrivateKey(rawRepresentation:unhex(e["leaf_scalar_synthetic"] as! String))
            let boot=try JSONSerialization.jsonObject(with:Data(base64Encoded:e["boot_client_data"] as! String)!) as! [String:Any]
            let client=try canonical(["compose_hash":boot["compose_hash"]!,"domain":"mac-compose-assert/1",
                                      "data":SDK.runnerDomain+"|"+hex(challenge)+"|"+hex(Data(SHA256.hash(data:try canonical(request))))])
            let auth=try unhex(e["assert_prefix"] as! String)+[0,0,0,1]+unhex(e["assert_ext"] as! String)
            let sig=try leaf.signature(for:sha(auth+sha(client))).derRepresentation
            let assertion=Data([0xa2,0x69])+Data("signature".utf8)+cborBytes(sig)+[0x71]+Data("authenticatorData".utf8)+cborBytes(auth)
            return ["type":"macrunner","keyId":e["key_id"]!,"attestation":e["attestation"]!,"bootClientData":e["boot_client_data"]!,
                    "assertion":assertion.base64EncodedString(),"assertClientData":client.base64EncodedString(),
                    "code":(fx["code"] as! [String:Any])[code ?? e["code"] as! String]!]
        }
        // runner: nil sends no evidence; otherwise ask this connection for a challenge and attach that enrollment's evidence.
        func send(_ s:SDKService,_ session:inout SDKSession,_ q:[String:Any],runner name:String?=nil,code:String?=nil,alter:((inout [String:Any])->Void)?=nil) throws -> [String:Any] {
            var full=q
            if let name {
                let challenge=try unhex(try call(s,["v":1,"op":"challenge"],&session)["challenge"] as! String)
                full["runner_evidence"]=try runnerEvidence(name,challenge,q,code:code)
                alter?(&full)
            }
            return try call(s,full,&session)
        }
        var sxA=SDKSession(),sxB=SDKSession(),szA=SDKSession()
        func getKey(_ s:SDKService,_ session:inout SDKSession,_ app:Data,_ compose:Data,epoch:Int?=nil,runner name:String?=nil) throws -> (reply:[String:Any],root:Data?) {
            let eph=P256.KeyAgreement.PrivateKey()
            var q:[String:Any]=["v":1,"op":"get_key","app_id":hex(app),"compose_hash":hex(compose),"eph_pub":hex(eph.publicKey.x963Representation)]
            if let epoch {q["epoch"]=epoch}
            let r=try send(s,&session,q,runner:name)
            guard let epk=r["epk"] as? String,let sealed=r["sealed"] as? String,let st=r["statement"] as? String else {return (r,nil)}
            let k=try eph.sharedSecretFromKeyAgreement(with:P256.KeyAgreement.PublicKey(x963Representation:unhex(epk)))
                .hkdfDerivedSymmetricKey(using:SHA256.self,salt:Data(),sharedInfo:Data("dsmack-sdk/v1/release".utf8),outputByteCount:32)
            return (r,try AES.GCM.open(AES.GCM.SealedBox(combined:unhex(sealed)),using:k,authenticating:Data(SHA256.hash(data:unhex(st)))))
        }

        var plain=SDKSession()
        try refused(try getKey(sa,&plain,appX,c1).reply,"runner evidence required","plain local client for an allowed compose, get_key")
        let plainQuery:[String:Any]=["v":1,"app_id":hex(appX),"compose_hash":hex(c1),"report_data":"0x07"]
        for op in ["evidence","info"] {var q=plainQuery;q["op"]=op;try refused(try call(sa,q,&plain),"runner evidence required","plain local client, \(op)")}
        _=try call(sa,["v":1,"op":"challenge"],&plain)
        try refused(try getKey(sa,&plain,appX,c1).reply,"runner evidence required","plain client holding a challenge but no evidence")
        var fresh=SDKSession(),q=plainQuery;q["op"]="info";q["runner_evidence"]=try runnerEvidence("good",Data(repeating:9,count:32),plainQuery)
        try refused(try call(sa,q,&fresh),"needs a challenge on this connection","evidence without a challenge issued to this connection")
        var s1=SDKSession();q=plainQuery;q["op"]="info"
        try refused(try send(sa,&s1,q,runner:"modified"),"runner measurement 0x\(modifiedM) not admitted","modified runner (another M_runner) refused")
        try refused(try send(service(a,runners:[try bytes32(modifiedM)]),&s1,q,runner:"good"),"not admitted","runner whose M_runner is not in the admitted set refused")
        try refused(try send(sa,&s1,q,runner:"good",code:"resigned"),"runner CodeDirectory is not the attested CDHash",
                    "CodeDirectory that is not the attested one (same M, another CDHash) refused")
        var sTeam=SDKSession()
        let team=try getKey(sa,&sTeam,appX,c1,runner:"other_team")
        try check(team.root==rootX2 && sTeam.compose==c1 && (enrollments["other_team"]!["cdhash"] as! String) != (enrollments["good"]!["cdhash"] as! String),
                  "another team's signing of the admitted runner (own App ID and CDHash, same M_runner) admitted, same app_root: \(team.reply["error"] ?? "ok")")
        try refused(try send(sa,&s1,q,runner:"stale"),"not this compose or is stale","enrollment older than 12 h")
        try refused(try send(sa,&s1,q,runner:"wrong_compose"),"not this compose or is stale","runner booted another compose")
        try refused(try send(sa,&s1,q,runner:"good"){$0["epoch"]=2},"not over this challenge and request","request altered after the runner signed it")
        try refused(try call(sa,q,&s1),"runner evidence required","challenge used once, then plain again")
        _=try call(sa,["v":1,"op":"challenge"],&s1)
        var late=q;late["runner_evidence"]=try runnerEvidence("good",s1.challenge!.value,q)
        try refused(try call(service(a,at:now+61),late,&s1),"challenge expired","challenge older than 60 s")
        try check(s1.compose==nil && plain.compose==nil,"no refused connection is admitted")

        let ax=try getKey(sa,&sxA,appX,c1,runner:"good"),bx=try getKey(sb,&sxB,appX,c1,runner:"good")
        try check(sxA.compose==c1,"runner admitted for its compose on this connection")
        try check(ax.root != nil && ax.root==bx.root && ax.root==rootX2,"two nodes with the same group key derive the same app_root")
        try check(ax.reply["app_pub"] as? String==bx.reply["app_pub"] as? String && ax.reply["key_epoch"] as? Int==2,"same app_pub on both nodes, current epoch 2")
        let ay=try getKey(sa,&sxA,appY,c1)
        try check(ay.root != nil && ay.root != ax.root && ay.reply["app_pub"] as? String != ax.reply["app_pub"] as? String,"different app_id, different app_root")
        try refused(try getKey(sa,&sxA,appX,c1b).reply,"connection admitted for another compose","admitted connection asks for another compose")
        let ax2=try getKey(sa,&szA,appX,c1b,runner:"wrong_compose")
        try check(ax2.root==ax.root && ax2.reply["app_pub"] as? String==ax.reply["app_pub"] as? String && ax2.reply["statement"] as? String != ax.reply["statement"] as? String,
                  "different compose_hash under the same app_id: same key, statement names the compose")
        try check(ax.reply["block"] as? Int==1234 && ax.reply["app_registry"] as? String==appRegistry,"statement names the block the AppRegistry was read at")
        var fresh3=SDKSession()
        try refused(try getKey(sa,&fresh3,appX,c3,runner:"good").reply,"compose not allowed under app_id at block 1234","unlisted compose, before runner admission")
        try check(fresh3.compose==nil,"unlisted compose admits no connection")
        try refused(try getKey(sa,&sxA,appX,c3).reply,"compose not allowed under app_id","unlisted compose on an admitted connection")
        try refused(try getKey(sa,&sxA,appZ,c1).reply,"app_id not in AppRegistry at block 1234","app not created")
        windows[appX+c1]=(0,1234)
        try refused(try getKey(sa,&sxA,appX,c1).reply,"compose window closed at block 1234, read at 1234","window closed at the read block, on an admitted connection")
        let early=try getKey(service(a,block:1233),&sxA,appX,c1)
        try check(early.root==rootX2 && early.reply["block"] as? Int==1233,"same window read at an earlier block, before it closed, is honoured and named")
        windows[appX+c1]=(1235,UInt64.max)
        try refused(try getKey(sa,&sxA,appX,c1).reply,"compose window opens at block 1235","window not yet open")
        windows[appX+c1]=nil
        try refused(try getKey(sa,&sxA,appX,c1).reply,"compose not allowed under app_id","revoked compose")
        windows[appX+c1]=open
        apps[appX]=nil
        try refused(try getKey(sa,&sxA,appX,c1).reply,"app_id not in AppRegistry","window left behind for an app the table no longer lists")
        apps[appX]=scope
        try refused(try getKey(sa,&sxA,appS,c1).reply,"no group key held for scope 0x0101","scope comes from the table: an app in a scope this node lacks")

        let a1=try getKey(sa,&sxA,appX,c1,epoch:1)
        let rootX1=try SDK.appRoot(g1,chainId:chainId,registry:registry,scope:scope,keyEpoch:1,appId:appX).withUnsafeBytes{Data($0)}
        try check(a1.root==rootX1 && a1.root != ax.root && a1.reply["key_epoch"] as? Int==1,"get_key(epoch=prev) after a bump returns the old epoch's root")
        try refused(try getKey(sa,&sxA,appX,c1,epoch:3).reply,"key epoch 3 not held","future epoch")
        try refused(try getKey(sa,&sxA,appX,c1,epoch:0).reply,"key epoch 0 not held","older than previous epoch")
        try refused(try getKey(sb,&sxB,appX,c1,epoch:1).reply,"key epoch 1 not held","epoch this node never held")

        for (name,r) in [("epoch 2",ax.reply),("epoch 1",a1.reply)] {
            let st=try unhex(r["statement"] as! String),sig=try P256.Signing.ECDSASignature(rawRepresentation:unhex(r["group_signature"] as! String))
            let e=UInt64(r["key_epoch"] as! Int),g=e==2 ? g2:g1
            let rebuilt=try SDK.statement(chainId:chainId,registry:registry,scope:scope,keyEpoch:e,appId:appX,composeHash:c1,block:1234,measurement:m,appPub:unhex(r["app_pub"] as! String))
            try check(st==rebuilt && r["group_public"] as? String==hex(g.publicKey.x963Representation),"\(name) statement encodes (app_id, app_pub, compose_hash, block, epoch, M)")
            try check(g.publicKey.isValidSignature(sig,for:st),"\(name) statement verifies against the group public key")
            try check(!(e==2 ? g1:g2).publicKey.isValidSignature(sig,for:st) && !g.publicKey.isValidSignature(sig,for:st+[0]),"\(name) statement fails under the other key or altered")
        }

        let evidenceQuery:[String:Any]=["v":1,"op":"evidence","app_id":hex(appX),"compose_hash":hex(c1),"report_data":hex(Data(repeating:7,count:32))]
        try refused(try call(sa,evidenceQuery,&sxA),"no check-in yet","evidence before any check-in")
        a.keyLock.withLock{a.checkIn=(word(42),"0x"+String(repeating:"ab",count:32))}
        let ev=try call(sa,evidenceQuery,&sxA)
        let appPub=try P256.Signing.PublicKey(x963Representation:unhex(ev["app_pub"] as! String))
        try check(appPub.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation:unhex(ev["app_signature"] as! String)),for:Data("dsmack-sdk/evidence/1".utf8)+Data(repeating:7,count:32))
                  && ev["member"] as? String==hex(word(42)) && ev["M"] as? String==hex(m) && ev["checked_tx"] as? String=="0x"+String(repeating:"ab",count:32),"evidence: app_pub signs report_data, with member, M and check-in")
        var long=evidenceQuery;long["report_data"]=hex(Data(repeating:7,count:65))
        try refused(try call(sa,long,&sxA),"report_data is at most 64 bytes","65-byte report_data")
        var info=evidenceQuery;info["op"]="info";info["report_data"]=nil
        let i=try call(sa,info,&sxA)
        try check(i["sdk"] as? String=="dsmack-sdk/v1" && i["chain_id"] as? Int==Int(chainId) && i["registry"] as? String==registry && i["key_epoch"] as? Int==2 && i["sealed"]==nil,"info names app, scope, epoch, chain, member and M")
        var bad=info;bad["op"]="sign";try refused(try call(sa,bad,&sxA),"unknown op","op sign (slice 2)")
        bad=info;bad["v"]=2;try refused(try call(sa,bad,&sxA),"unsupported v","v 2")
        try refused(try JSONSerialization.jsonObject(with:sa.reply(Data("not json".utf8),&sxA)) as! [String:Any],"JSON text did not start","malformed line")

        a.retire(scope)
        try refused(try getKey(sa,&sxA,appX,c1).reply,"no group key held","current request after the key is retired")
        try check(try getKey(sa,&sxA,appX,c1,epoch:2).root==rootX2,"retired epoch stays available as previous")
        a.hold(scope,g1,epoch:3)
        try check(try getKey(sa,&sxA,appX,c1,epoch:2).root==rootX2 && getKey(sa,&sxA,appX,c1).reply["key_epoch"] as? Int==3,"re-acquired epoch 3 after retiring 2: serves 3 and previous 2")
        try refused(try getKey(sa,&sxA,appX,c1,epoch:1).reply,"key epoch 1 not held","second bump drops epoch 1: previous epoch only")
        a.retire(scope);a.hold(scope,g2,epoch:5)
        try refused(try getKey(sa,&sxA,appX,c1,epoch:3).reply,"key epoch 3 not held","skipped epoch: 3 is not the epoch before 5, so it is not kept")
        try check(try SDK.reduceP256(Data(repeating:0xff,count:32))==unhex("0x00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaae"),"p256 reduction subtracts n once")
        do {_=try SDK.reduceP256(Data(SDK.p256Order));throw DemoError.invalid("zero scalar accepted")} catch DemoError.invalid(let e) {try check(e=="derived scalar is zero","zero scalar refused")}

        let port=try SDK.listen(port:0,sb.reply)
        func connectLoopback() throws -> Int32 {
            let fd=socket(AF_INET,SOCK_STREAM,0)
            var addr=sockaddr_in();addr.sin_family=sa_family_t(AF_INET);addr.sin_port=port.bigEndian;addr.sin_addr.s_addr=inet_addr("127.0.0.1")
            try need(withUnsafePointer(to:&addr){$0.withMemoryRebound(to:sockaddr.self,capacity:1){connect(fd,$0,socklen_t(MemoryLayout<sockaddr_in>.size))}}==0,"connect")
            return fd
        }
        func exchange(_ fd:Int32,_ q:[String:Any]) throws -> [String:Any] {
            let out=try JSONSerialization.data(withJSONObject:q)+[10]
            _=out.withUnsafeBytes{write(fd,$0.baseAddress,$0.count)}
            var got=Data(),byte=[UInt8](repeating:0,count:1)
            while got.last != 10 {try need(read(fd,&byte,1)==1,"server closed");got.append(byte[0])}
            return try JSONSerialization.jsonObject(with:got) as! [String:Any]
        }
        var getQ=info;getQ["op"]="get_key";getQ["eph_pub"]=hex(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        let plainFD=try connectLoopback()
        let plainReplies=[try exchange(plainFD,getQ),try exchange(plainFD,info)]
        close(plainFD)
        try check(plainReplies.allSatisfy{($0["error"] as? String)?.contains("runner evidence required")==true && $0["sealed"]==nil && $0["app_pub"]==nil},
                  "loopback server: plain local client for an allowed compose gets nothing")
        let fd=try connectLoopback()
        let challenge=try unhex(try exchange(fd,["v":1,"op":"challenge"])["challenge"] as! String)
        var admitted=getQ;admitted["runner_evidence"]=try runnerEvidence("good",challenge,getQ)
        let lines=[try exchange(fd,admitted),try exchange(fd,getQ)]
        close(fd)
        try check(lines.allSatisfy{$0["sealed"] != nil && $0["app_pub"] as? String==ax.reply["app_pub"] as? String},
                  "loopback server: challenge, admitted get_key, then get_key on the admitted connection")
        print("SDKVectors passed: \(passed) checks")
    }
    /// The same vectors are pinned in sdk/test_sdk.py test_vectors_match_swift (Python dsmack_sdk).
    static let vectorX2="0xff7581dad655737c4a35ef4192a3f5897bfdf54ea7c70570b8c185a4230fab59"
    static let vectorAppPubX2="0x0499a9357634ed27c08281b0b7eae22d69f20bfdf4df82b4a56e20ba8d6ce4914becc54035cd9c3112e69b314bdf9d5f7f0692877e1efbc3a38c565ef9ddd237fb"
}
