import Foundation
import CryptoKit
import Darwin

/// dsmack-sdk v1, node side (planning dsmack-sdk-design §2-3): per-app roots derived from the group key G,
/// served to the runner as JSON lines. The "dsmack-sdk/..." strings are frozen: changing one changes every app key.
enum SDK {
    static let runnerDomain="dsmack-sdk-runner/1",challengeSeconds:UInt64=60,maxEnrollmentAge:Int64=12*3600
    static let p256Order=[UInt8](try! unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"))

    static func appRoot(_ group: P256.Signing.PrivateKey,chainId: UInt64,registry: String,scope: Data,keyEpoch: UInt64,appId: Data) throws -> SymmetricKey {
        try need(scope.count==32 && appId.count==32,"scope and app_id are 32 bytes")
        return HKDF<SHA256>.deriveKey(inputKeyMaterial:SymmetricKey(data:group.rawRepresentation),
            salt:word(chainId)+(try addressWord(registry))+scope+word(keyEpoch)+appId,info:Data("dsmack-sdk/v1/app".utf8),outputByteCount:32)
    }
    /// The app's P-256 key (app_pub): HKDF(app_root, info "dsmack-sdk/v1/app-pub") reduced mod n.
    static func appSigner(_ root: SymmetricKey) throws -> P256.Signing.PrivateKey {
        let raw=HKDF<SHA256>.deriveKey(inputKeyMaterial:root,info:Data("dsmack-sdk/v1/app-pub".utf8),outputByteCount:32).withUnsafeBytes{Data($0)}
        return try P256.Signing.PrivateKey(rawRepresentation:reduceP256(raw))
    }
    static func reduceP256(_ x: Data) throws -> Data {
        try need(x.count==32,"scalar width")
        var b=[UInt8](x),borrow=0
        if !b.lexicographicallyPrecedes(p256Order) { // x < 2^256 < 2n: one subtraction
            for i in (0..<32).reversed() {let d=Int(b[i])-Int(p256Order[i])-borrow;b[i]=UInt8(d & 0xff);borrow=d<0 ? 1:0}
        }
        try need(b.contains{$0 != 0},"derived scalar is zero")
        return Data(b)
    }
    /// G signs this per release: chain link 1 of get_key and the core of evidence.
    static func statement(chainId: UInt64,registry: String,scope: Data,keyEpoch: UInt64,appId: Data,composeHash: Data,
                          block: UInt64,measurement: Data,appPub: Data) throws -> Data {
        try need([scope,appId,composeHash,measurement].allSatisfy{$0.count==32} && appPub.count==65,"statement field widths")
        return Data("dsmack-sdk/app/1".utf8)+word(chainId)+(try addressWord(registry))+scope+word(keyEpoch)+appId+composeHash+word(block)+measurement+appPub
    }
    /// AppRegistry's apps(appId) and composes(appId, composeHash), both read at `block`.
    struct Entry {let block:UInt64,admin:Data,scope:Data,from:UInt64,until:UInt64}
    /// AppRegistry.isAllowed at the entry's block, with the reason when not; returns the app's scope.
    static func allowedScope(_ e: Entry) throws -> Data {
        try need(e.admin != Data(repeating:0,count:20),"app_id not in AppRegistry at block \(e.block)")
        try need(e.until != 0,"compose not allowed under app_id at block \(e.block)")
        try need(e.from<=e.block,"compose window opens at block \(e.from), read at \(e.block)")
        try need(e.block<e.until,"compose window closed at block \(e.until), read at \(e.block)")
        return e.scope
    }

    /// JSON lines on 127.0.0.1 (the loopback channel the runner already uses for its KMS; no socket file).
    /// Returns the bound port; port 0 picks one.
    static func listen(port: UInt16,_ reply: @escaping (Data,inout SDKSession)->Data) throws -> UInt16 {
        let fd=socket(AF_INET,SOCK_STREAM,0);try need(fd>=0,"sdk socket")
        var one:Int32=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,socklen_t(4))
        var a=sockaddr_in();a.sin_family=sa_family_t(AF_INET);a.sin_port=port.bigEndian;a.sin_addr.s_addr=inet_addr("127.0.0.1")
        var size=socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound=withUnsafeMutablePointer(to:&a){$0.withMemoryRebound(to:sockaddr.self,capacity:1){bind(fd,$0,size)==0 && Darwin.listen(fd,16)==0 && getsockname(fd,$0,&size)==0}}
        guard bound else {let e=String(cString:strerror(errno));close(fd);throw DemoError.invalid("sdk listen 127.0.0.1:\(port): \(e)")}
        Thread.detachNewThread {
            while true {
                let c=accept(fd,nil,nil)
                if c>=0 {Thread.detachNewThread {serve(c,reply)}}
            }
        }
        return UInt16(bigEndian:a.sin_port)
    }
    static func serve(_ c: Int32,_ reply: (Data,inout SDKSession)->Data) {
        defer {close(c)}
        var session=SDKSession()
        var one:Int32=1;setsockopt(c,SOL_SOCKET,SO_NOSIGPIPE,&one,socklen_t(4))
        var buffer=Data(),chunk=[UInt8](repeating:0,count:4096)
        while true {
            if let newline=buffer.firstIndex(of:10) {
                let out=reply(Data(buffer[..<newline]),&session);buffer=Data(buffer[(newline+1)...])
                guard out.withUnsafeBytes({write(c,$0.baseAddress,$0.count)})==out.count else {return}
                continue
            }
            guard buffer.count<65536 else {return}
            let n=read(c,&chunk,chunk.count);guard n>0 else {return}
            buffer.append(contentsOf:chunk[0..<n])
        }
    }
}

/// One connection's runner admission: the challenge it was issued and, once admitted, the runner's compose_hash.
struct SDKSession {var challenge:(value:Data,issued:UInt64)?;var compose:Data?}

/// challenge, get_key, evidence and info. Each key op names the runner's app_id and compose_hash; the node reads
/// AppRegistry at the current block for the app's scope and the compose's window, and the G-signed statement names that
/// block. get_key returns the app root sealed to eph_pub, never leaf keys.
/// Runner admission (the RunnerGate pattern of the native authority): the first key op on a connection carries
/// runner_evidence, the runner's /attest object, whose assertion covers
/// {"compose_hash","data":"dsmack-sdk-runner/1|<challenge>|<sha256 of the request without runner_evidence, JSON
/// sorted keys, no spaces>","domain":"mac-compose-assert/1"} for the challenge this connection was issued at most 60 s
/// before. Enrollment and assertion must name a CDHash in `runners` and the request's compose_hash; the connection then
/// serves only that compose. Without it every key op is refused.
struct SDKService {
    let chainId: UInt64,registry: String,appRegistry: String,measurement: Data
    let runners: [Data],anchor: Data
    let checkIn: () throws -> (member:Data,tx:String)
    let group: (Data,UInt64?) throws -> (epoch:UInt64,key:P256.Signing.PrivateKey)
    /// AppRegistry entry for (app_id, compose_hash) at one block.
    var appTable: (Data,Data) throws -> SDK.Entry
    var now: () -> UInt64={UInt64(Date().timeIntervalSince1970)}

    func reply(_ line: Data,_ session: inout SDKSession) -> Data {
        var out:[String:Any]
        do {out=try handle(line,&session)} catch {out=["error":"\(error)"]}
        out["v"]=1
        return (try! JSONSerialization.data(withJSONObject:out,options:[.sortedKeys]))+Data([10])
    }
    func handle(_ line: Data,_ session: inout SDKSession) throws -> [String:Any] {
        guard let q=try JSONSerialization.jsonObject(with:line) as? [String:Any] else {throw DemoError.invalid("request is not a JSON object")}
        try need(q["v"] as? Int==1,"unsupported v")
        if q["op"] as? String=="challenge" {
            let c=SymmetricKey(size:.bits256).withUnsafeBytes{Data($0)};session.challenge=(c,now());return ["challenge":hex(c)]
        }
        guard let op=q["op"] as? String,let a=q["app_id"] as? String,let c=q["compose_hash"] as? String
        else {throw DemoError.invalid("request needs op, app_id and compose_hash")}
        let appId=try bytes32(a),composeHash=try bytes32(c)
        var epoch:UInt64?
        if let e=q["epoch"] {guard let n=e as? Int,n>=0 else {throw DemoError.invalid("epoch")};epoch=UInt64(n)}
        guard ["get_key","evidence","info"].contains(op) else {throw DemoError.invalid("unknown op")}
        let entry=try appTable(appId,composeHash),scope=try SDK.allowedScope(entry)
        if session.compose==nil {try admit(q,composeHash,&session)}
        try need(session.compose==composeHash,"connection admitted for another compose")
        let r=try release(appId,composeHash,scope,entry.block,epoch)
        switch op {
        case "get_key":
            guard let e=q["eph_pub"] as? String else {throw DemoError.invalid("get_key needs eph_pub")}
            let ephemeral=P256.KeyAgreement.PrivateKey()
            let key=try ephemeral.sharedSecretFromKeyAgreement(with:P256.KeyAgreement.PublicKey(x963Representation:unhex(e)))
                .hkdfDerivedSymmetricKey(using:SHA256.self,salt:Data(),sharedInfo:Data("dsmack-sdk/v1/release".utf8),outputByteCount:32)
            let sealed=try AES.GCM.seal(r.root.withUnsafeBytes{Data($0)},using:key,authenticating:Data(SHA256.hash(data:r.statement))).combined!
            return r.fields.merging(["epk":hex(ephemeral.publicKey.x963Representation),"sealed":hex(sealed)]){$1}
        case "evidence":
            guard let d=q["report_data"] as? String else {throw DemoError.invalid("evidence needs report_data")}
            let data=try unhex(d);try need(data.count<=64,"report_data is at most 64 bytes")
            let id=try checkIn()
            let signature=try r.signer.signature(for:Data("dsmack-sdk/evidence/1".utf8)+data)
            return r.fields.merging(["report_data":hex(data),"app_signature":hex(signature.rawRepresentation),"member":hex(id.member),"checked_tx":id.tx]){$1}
        default:
            return r.fields.merging(["member":hex(try checkIn().member),"sdk":"dsmack-sdk/v1"]){$1}
        }
    }
    func admit(_ q: [String:Any],_ composeHash: Data,_ session: inout SDKSession) throws {
        guard let e=q["runner_evidence"] as? [String:Any] else {throw DemoError.invalid("runner evidence required")}
        guard let issued=session.challenge else {throw DemoError.invalid("runner evidence needs a challenge on this connection")}
        session.challenge=nil
        let at=now(),compose=String(hex(composeHash).dropFirst(2))
        try need(at<=issued.issued+SDK.challengeSeconds,"challenge expired")
        guard Set(e.keys)==["type","keyId","attestation","bootClientData","assertion","assertClientData"],e["type"] as? String=="macrunner",
              let keyID=e["keyId"] as? String,let attestation=e["attestation"] as? String,let boot=e["bootClientData"] as? String,
              let assertion=e["assertion"] as? String,let asserted=e["assertClientData"] as? String else {throw DemoError.invalid("runner evidence fields")}
        var request=q;request["runner_evidence"]=nil
        let requestHash=Data(SHA256.hash(data:try JSONSerialization.data(withJSONObject:request,options:[.sortedKeys,.withoutEscapingSlashes])))
        do {
            let bootData=try unb64(boot),assertedData=try unb64(asserted)
            let enrolled=try verifyAttestation(try unb64(attestation),keyID:keyID,challenge:bootData,cdhashes:runners,at:Date(timeIntervalSince1970:TimeInterval(at)),anchor:anchor)
            guard let b=try JSONSerialization.jsonObject(with:bootData) as? [String:Any],["mac-compose-boot/1","mac-compose-enroll/1"].contains(b["domain"] as? String),
                  (b["attested"] as? NSNumber).map({CFGetTypeID($0)==CFBooleanGetTypeID() && $0.boolValue})==true,
                  b["compose_hash"] as? String==compose,let enrolledAt=b["enrolled_at"] as? Int,
                  (-60...SDK.maxEnrollmentAge).contains(Int64(at)-Int64(enrolledAt)) else {throw DemoError.invalid("runner enrollment is not this compose or is stale")}
            let a=try verifyAssertion(try unb64(assertion),clientData:assertedData,publicKey:enrolled.publicKey,previousCounter:0,cdhashes:runners)
            guard a.cdhash != nil,a.cdhash==enrolled.cdhash,let body=try JSONSerialization.jsonObject(with:assertedData) as? [String:Any],
                  Set(body.keys)==["compose_hash","data","domain"],body["domain"] as? String=="mac-compose-assert/1",body["compose_hash"] as? String==compose,
                  body["data"] as? String==SDK.runnerDomain+"|"+hex(issued.value)+"|"+hex(requestHash) else {throw DemoError.invalid("runner assertion is not over this challenge and request")}
        } catch let reject as AppAttestReject {throw DemoError.invalid("runner evidence: \(reject.reason)")}
        session.compose=composeHash
    }
    func release(_ appId: Data,_ composeHash: Data,_ scope: Data,_ b: UInt64,_ epoch: UInt64?) throws
        -> (root:SymmetricKey,signer:P256.Signing.PrivateKey,statement:Data,fields:[String:Any]) {
        let g=try group(scope,epoch)
        let root=try SDK.appRoot(g.key,chainId:chainId,registry:registry,scope:scope,keyEpoch:g.epoch,appId:appId)
        let signer=try SDK.appSigner(root),pub=signer.publicKey.x963Representation
        let statement=try SDK.statement(chainId:chainId,registry:registry,scope:scope,keyEpoch:g.epoch,appId:appId,composeHash:composeHash,block:b,measurement:measurement,appPub:pub)
        let signature=try g.key.signature(for:statement)
        return (root,signer,statement,["app_id":hex(appId),"compose_hash":hex(composeHash),"scope":hex(scope),"key_epoch":g.epoch,"chain_id":chainId,
            "registry":registry,"app_registry":appRegistry,"block":b,"M":hex(measurement),"app_pub":hex(pub),"statement":hex(statement),
            "group_signature":hex(signature.rawRepresentation),"group_public":hex(g.key.publicKey.x963Representation)])
    }
}

extension Chain {
    /// AppRegistry apps(appId) {admin, scope} and composes(appId, composeHash) {from, until}, both at `block`.
    func appEntry(_ appRegistry: String,_ appId: Data,_ composeHash: Data,at block: UInt64) throws -> SDK.Entry {
        let app=try call("apps(bytes32)",appId,to:appRegistry,at:block),window=try call("composes(bytes32,bytes32)",appId+composeHash,to:appRegistry,at:block)
        try need(app.count==64 && app.prefix(12)==Data(repeating:0,count:12) && window.count==64,"AppRegistry encoding")
        return SDK.Entry(block:block,admin:app.subdata(in:12..<32),scope:app.suffix(32),from:try smallWord(window.prefix(32)),until:try smallWord(window.suffix(32)))
    }
}

extension Node {
    func sdkService(appRegistry: String,measurement: Data,runners: [Data],anchor: Data=AppAttestProfile.rootDER) -> SDKService {
        SDKService(chainId:cfg.chainId,registry:cfg.registry,appRegistry:appRegistry,measurement:measurement,runners:runners,anchor:anchor,
                   checkIn:{[unowned self] in guard let c=lastCheckIn() else {throw DemoError.invalid("no check-in yet")};return c},
                   group:{[unowned self] in try groupKey($0,epoch:$1)},
                   appTable:{[chain] in try chain.appEntry(appRegistry,$0,$1,at:try quantity(chain.rpc("eth_blockNumber",[])))})
    }
    /// Serves the SDK once per process when the config sets sdkPort.
    func startSDK() throws {
        guard let port=cfg.sdkPort,sdkBound==nil else {return}
        guard let appRegistry=cfg.appRegistry else {throw DemoError.invalid("the SDK needs appRegistry in config")}
        guard let m=try ownMeasurement()?.value else {throw DemoError.invalid("the SDK needs this build's measurement")}
        #if SDK_TEST_TRUST
        let service=sdkService(appRegistry:appRegistry,measurement:m,runners:cfg.sdkRunners,anchor:cfg.sdkTestAnchor)
        log("sdk test trust",["anchorSHA256":hex(sha(cfg.sdkTestAnchor))])
        #else
        let service=sdkService(appRegistry:appRegistry,measurement:m,runners:cfg.sdkRunners)
        #endif
        sdkBound=try SDK.listen(port:port,service.reply)
        log("sdk listening",["address":"127.0.0.1:\(sdkBound!)","appRegistry":appRegistry,"runners":cfg.sdkRunners.map(hex)])
    }
}
