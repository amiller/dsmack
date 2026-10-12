import Foundation
import CryptoKit
import Darwin

/// dsmack-sdk v1, node side (planning dsmack-sdk-design §2-3): per-app roots derived from the group key G,
/// served to the runner as JSON lines. The "dsmack-sdk/..." strings are frozen: changing one changes every app key.
enum SDK {
    /// P-256 (x9.63) key that signs interim allow records. Compiled in, so it is part of M; nil serves nothing.
    /// TODO(AppRegistry): replace with composes(appId, composeHash) windows read on chain at the statement's block.
    static let sponsor: Data? = nil
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
    /// The interim allow check: the sponsor signs (app_id, compose_hash, scope, until) for this chain and registry.
    static func allowMessage(chainId: UInt64,registry: String,appId: Data,composeHash: Data,scope: Data,until: UInt64) throws -> Data {
        Data("dsmack-sdk/allow/1".utf8)+word(chainId)+(try addressWord(registry))+appId+composeHash+scope+word(until)
    }

    /// JSON lines on 127.0.0.1 (the loopback channel the runner already uses for its KMS; no socket file).
    /// Returns the bound port; port 0 picks one.
    static func listen(port: UInt16,_ reply: @escaping (Data)->Data) throws -> UInt16 {
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
    static func serve(_ c: Int32,_ reply: (Data)->Data) {
        defer {close(c)}
        var one:Int32=1;setsockopt(c,SOL_SOCKET,SO_NOSIGPIPE,&one,socklen_t(4))
        var buffer=Data(),chunk=[UInt8](repeating:0,count:4096)
        while true {
            if let newline=buffer.firstIndex(of:10) {
                let out=reply(Data(buffer[..<newline]));buffer=Data(buffer[(newline+1)...])
                guard out.withUnsafeBytes({write(c,$0.baseAddress,$0.count)})==out.count else {return}
                continue
            }
            guard buffer.count<65536 else {return}
            let n=read(c,&chunk,chunk.count);guard n>0 else {return}
            buffer.append(contentsOf:chunk[0..<n])
        }
    }
}

/// get_key, evidence and info. Each request names the runner's app_id and compose_hash and carries the
/// sponsor's allow record {scope, until, signature}; get_key returns the app root sealed to eph_pub, never leaf keys.
/// TODO(runner admission): the design's boot check (runner App Attest over dsmack-sdk-boot/1, CDHash admitted)
/// is not here yet, so any local process that can reach the port and present an allow record gets that app's root.
struct SDKService {
    let chainId: UInt64,registry: String,sponsor: P256.Signing.PublicKey,measurement: Data
    let checkIn: () throws -> (member:Data,tx:String)
    let group: (Data,UInt64?) throws -> (epoch:UInt64,key:P256.Signing.PrivateKey)
    var block: () throws -> UInt64
    var now: () -> UInt64={UInt64(Date().timeIntervalSince1970)}

    func reply(_ line: Data) -> Data {
        var out:[String:Any]
        do {out=try handle(line)} catch {out=["error":"\(error)"]}
        out["v"]=1
        return (try! JSONSerialization.data(withJSONObject:out,options:[.sortedKeys]))+Data([10])
    }
    func handle(_ line: Data) throws -> [String:Any] {
        guard let q=try JSONSerialization.jsonObject(with:line) as? [String:Any] else {throw DemoError.invalid("request is not a JSON object")}
        try need(q["v"] as? Int==1,"unsupported v")
        guard let op=q["op"] as? String,let a=q["app_id"] as? String,let c=q["compose_hash"] as? String,let allow=q["allow"] as? [String:Any]
        else {throw DemoError.invalid("request needs op, app_id, compose_hash and allow")}
        let appId=try bytes32(a),composeHash=try bytes32(c)
        var epoch:UInt64?
        if let e=q["epoch"] {guard let n=e as? Int,n>=0 else {throw DemoError.invalid("epoch")};epoch=UInt64(n)}
        guard ["get_key","evidence","info"].contains(op) else {throw DemoError.invalid("unknown op")}
        let r=try release(appId,composeHash,try allowed(appId,composeHash,allow),epoch)
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
    func allowed(_ appId: Data,_ composeHash: Data,_ d: [String:Any]) throws -> Data {
        guard let s=d["scope"] as? String,let u=d["until"] as? Int,u>=0,let g=d["signature"] as? String else {throw DemoError.invalid("allow needs scope, until and signature")}
        let scope=try bytes32(s)
        let message=try SDK.allowMessage(chainId:chainId,registry:registry,appId:appId,composeHash:composeHash,scope:scope,until:UInt64(u))
        try need(sponsor.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation:unhex(g)),for:message),"compose not allowed under app_id")
        try need(now()<UInt64(u),"allow record expired")
        return scope
    }
    func release(_ appId: Data,_ composeHash: Data,_ scope: Data,_ epoch: UInt64?) throws
        -> (root:SymmetricKey,signer:P256.Signing.PrivateKey,statement:Data,fields:[String:Any]) {
        let g=try group(scope,epoch)
        let root=try SDK.appRoot(g.key,chainId:chainId,registry:registry,scope:scope,keyEpoch:g.epoch,appId:appId)
        let signer=try SDK.appSigner(root),pub=signer.publicKey.x963Representation,b=try block()
        let statement=try SDK.statement(chainId:chainId,registry:registry,scope:scope,keyEpoch:g.epoch,appId:appId,composeHash:composeHash,block:b,measurement:measurement,appPub:pub)
        let signature=try g.key.signature(for:statement)
        return (root,signer,statement,["app_id":hex(appId),"compose_hash":hex(composeHash),"scope":hex(scope),"key_epoch":g.epoch,"chain_id":chainId,
            "registry":registry,"block":b,"M":hex(measurement),"app_pub":hex(pub),"statement":hex(statement),
            "group_signature":hex(signature.rawRepresentation),"group_public":hex(g.key.publicKey.x963Representation)])
    }
}

extension Node {
    func sdkService(sponsor: P256.Signing.PublicKey,measurement: Data) -> SDKService {
        SDKService(chainId:cfg.chainId,registry:cfg.registry,sponsor:sponsor,measurement:measurement,
                   checkIn:{[unowned self] in guard let c=lastCheckIn() else {throw DemoError.invalid("no check-in yet")};return c},
                   group:{[unowned self] in try groupKey($0,epoch:$1)},block:{[chain] in try quantity(chain.rpc("eth_blockNumber",[]))})
    }
    /// Serves the SDK once per process when the config sets sdkPort.
    func startSDK() throws {
        guard let port=cfg.sdkPort,sdkBound==nil else {return}
        guard let key=SDK.sponsor else {throw DemoError.invalid("sdkPort is set but this build has no compiled-in SDK sponsor key")}
        guard let m=try ownMeasurement()?.value else {throw DemoError.invalid("the SDK needs this build's measurement")}
        let service=sdkService(sponsor:try P256.Signing.PublicKey(x963Representation:key),measurement:m)
        sdkBound=try SDK.listen(port:port,service.reply)
        log("sdk listening",["address":"127.0.0.1:\(sdkBound!)"])
    }
}
