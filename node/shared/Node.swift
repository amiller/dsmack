import Foundation
import DeviceCheck
import CryptoKit
import Darwin
import Security

let zero32=Data(repeating:0,count:32)
#if MODIFIED
let variant="modified" // negative control: differs in measured code, must never be admitted
#else
let variant="honest"
#endif

struct Config {
    let rpc: URL; let registry: String; let chainId: UInt64; let category: Data; let relay: URL; let name: String
    let badges: String?; let accountFactory: String?
    let peers: [String]; let helloDelay: Double; let protocolVersion: Int; let persistentIdentity: Bool
    let publicDirectory: Bool; let label: String
    /// Loopback port for the dsmack-sdk JSON-line server (SDK.swift); nil serves nothing.
    let sdkPort: UInt16?
    /// Runner CDHashes (full SHA-256) admitted to the SDK port; required, non-empty, with sdkPort.
    let sdkRunners: [Data]
    /// Set only for owner-flagged seeds (`sealer: true`): the sealed group key beside the config file.
    let sealPath: URL?
    init(_ d: [String:Any],path: URL?=nil) throws {
        guard let rpc=d["rpc"] as? String,let registry=d["registry"] as? String,let chainId=d["chainId"] as? Int,let category=d["category"] as? String,
              let relay=d["relay"] as? String,let name=d["name"] as? String,let r=URL(string:rpc),let l=URL(string:relay) else {throw DemoError.invalid("config fields")}
        self.rpc=r;self.registry=registry;self.chainId=UInt64(chainId);self.category=try bytes32(category);self.relay=l;self.name=name
        switch d["peer"] {
        case nil: peers=[]
        case let one as String: peers=one.isEmpty ? []:[one]
        case let list as [String]: peers=list
        default: throw DemoError.invalid("peer must be a name or a list of names")
        }
        let sealer=d["sealer"] as? Bool ?? false
        try need(!sealer || path != nil,"sealer needs a config file path")
        sealPath=sealer ? path!.deletingPathExtension().appendingPathExtension("sealed-key"):nil
        helloDelay=d["helloDelay"] as? Double ?? 0
        protocolVersion=d["protocolVersion"] as? Int ?? 1
        try need(protocolVersion==1 || protocolVersion==2,"unsupported protocol version")
        persistentIdentity=d["persistentIdentity"] as? Bool ?? false
        // A public Mac node lists itself in the relay directory unless "publicDirectory": false.
        #if os(macOS)
        publicDirectory=d["publicDirectory"] as? Bool ?? true
        #else
        publicDirectory=d["publicDirectory"] as? Bool ?? false
        #endif
        label=d["label"] as? String ?? ""
        if let p=d["sdkPort"] {guard let n=p as? Int,(1...65535).contains(n) else {throw DemoError.invalid("sdkPort must be 1-65535")};sdkPort=UInt16(n)} else {sdkPort=nil}
        sdkRunners=try (d["sdkRunners"] as? [String] ?? []).map(bytes32)
        try need((sdkPort==nil)==sdkRunners.isEmpty && (d["sdkRunners"]==nil || d["sdkRunners"] is [String]),"sdkPort and a non-empty sdkRunners list go together")
        try need(label.range(of:"^[A-Za-z0-9 ._-]{0,32}$",options:.regularExpression) != nil,"label: up to 32 of A-Z a-z 0-9 space . _ -")
        badges=d["badges"] as? String;accountFactory=d["accountFactory"] as? String
        try need((badges == nil)==(accountFactory == nil),"incomplete badge configuration")
        if let badges,let accountFactory {_=try addressWord(badges);_=try addressWord(accountFactory)}
        #if GUI
        // A host-controlled developer config must never redirect the trusted RPC
        // or admission policy of a measured release build.
        if let fixed=ReleaseNetwork.settings {
            try need(rpc==fixed["rpc"] as? String && registry.lowercased()==(fixed["registry"] as? String)?.lowercased()
                && chainId==fixed["chainId"] as? Int && category.lowercased()==(fixed["category"] as? String)?.lowercased()
                && relay==fixed["relay"] as? String && protocolVersion==fixed["protocolVersion"] as? Int
                && badges?.lowercased()==(fixed["badges"] as? String)?.lowercased()
                && accountFactory?.lowercased()==(fixed["accountFactory"] as? String)?.lowercased()
                && d["sdkRunners"] as? [String]==fixed["sdkRunners"] as? [String],"release network override rejected")
        }
        #endif
    }
}

/// One network node: App Attest key enrolled on chain, fresh check-in per action,
/// peer messages through an untrusted relay mailbox, group key held in RAM only.
final class Node {
    let cfg: Config; let chain: Chain; let log: (String,[String:Any]) -> Void
    let service=DCAppAttestService.shared
    let session=P256.KeyAgreement.PrivateKey()
    var sessionPublic: Data {session.publicKey.x963Representation}
    var keyID=""; var owner=""; var me=Data(); var held=[Data:P256.Signing.PrivateKey](); var heldEpoch=[Data:UInt64](); var nonces=[String:Data](); var heartbeats=[String:Date]()
    var badgeParticipation=false;var badgeComplete=false;var nextBadgeAttempt=Date.distantPast
    let directoryState=NativeDirectoryState()
    var nextDirectoryAttempt=Date.distantPast
    var directoryReceipt: String?
    /// Guards group-key writes and the last check-in, which the SDK server thread reads.
    let keyLock=NSLock()
    /// The previous epoch's group key per scope, kept in RAM until the next bump or exit (SDK get_key(epoch=prev)).
    var previous=[Data:(epoch:UInt64,key:P256.Signing.PrivateKey)]()
    var checkIn:(member:Data,tx:String)?
    var sdkBound:UInt16?
    func lastCheckIn() -> (member:Data,tx:String)? {keyLock.withLock{checkIn}}
    func hold(_ scope: Data,_ key: P256.Signing.PrivateKey,epoch: UInt64) {
        keyLock.withLock {
            if let old=held[scope],let e=heldEpoch[scope],e != epoch {previous[scope]=(e,old)}
            held[scope]=key;heldEpoch[scope]=epoch
        }
    }
    func retire(_ scope: Data) {
        keyLock.withLock {
            if let old=held.removeValue(forKey:scope),let e=heldEpoch.removeValue(forKey:scope) {previous[scope]=(e,old)}
        }
    }
    /// The held key for `epoch` (nil: the current one), or the previous epoch's key.
    func groupKey(_ scope: Data,epoch: UInt64?) throws -> (epoch:UInt64,key:P256.Signing.PrivateKey) {
        try keyLock.withLock {
            if let key=held[scope],let e=heldEpoch[scope],epoch==nil || epoch==e {return (e,key)}
            if let old=previous[scope],let epoch,epoch==old.epoch {return old}
            throw DemoError.invalid(epoch.map{"key epoch \($0) not held for scope \(hex(scope))"} ?? "no group key held for scope \(hex(scope))")
        }
    }
    private var measured: (fields:[String:Any],value:Data)?
    /// This executable's measurement inputs and M (open-admission design §2); nil where unsupported (iOS).
    func ownMeasurement() throws -> (fields:[String:Any],value:Data)? {
        #if os(macOS)
        if measured == nil {
            do {let x=try CodeMeasurement.ofSelf();measured=(x.enrollFields,try x.value())}
            catch {throw DemoError.invalid("cannot measure this executable; enrollment and directory listing need its code measurement: \(error)")}
        }
        #endif
        return measured
    }
    private let operationLock=NSLock()
    private var operations=[(Node)->Void]()
    func enqueueOperation(_ operation:@escaping (Node)->Void) {
        operationLock.lock();operations.append(operation);operationLock.unlock()
    }
    func runOperations() {
        operationLock.lock();let pending=operations;operations.removeAll();operationLock.unlock()
        for operation in pending {operation(self)}
    }
    private var identityLock: Int32 = -1
    deinit {if identityLock >= 0 {close(identityLock)}}
    func lockIdentity() throws {
        guard cfg.persistentIdentity && identityLock < 0 else {return}
        let path=try statePath().appendingPathExtension("lock").path
        let fd=Darwin.open(path,O_CREAT | O_RDWR,0o600)
        try need(fd >= 0,"cannot open identity lock")
        if flock(fd,LOCK_EX | LOCK_NB) != 0 {close(fd);throw DemoError.invalid("identity already running")}
        identityLock=fd
    }
    struct EnrollmentState: Codable {var keyID: String;var attestation: String?;var clientData: String?}
    func statePath() throws -> URL {
        let root=try FileManager.default.url(for:.applicationSupportDirectory,in:.userDomainMask,appropriateFor:nil,create:true)
            .appendingPathComponent("AttestNode",isDirectory:true)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
        let domain="\(cfg.chainId):\(cfg.registry.lowercased()):\(hex(cfg.category)):\(cfg.name)"
        return root.appendingPathComponent(hex(keccak(Data(domain.utf8)))+".json")
    }
    func saveState(_ state: EnrollmentState) throws {
        if cfg.persistentIdentity {
            let path=try statePath();try JSONEncoder().encode(state).write(to:path,options:.atomic)
            try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:path.path)
        }
    }
    init(_ cfg: Config,log: @escaping (String,[String:Any]) -> Void) {
        self.cfg=cfg;chain=Chain(rpcURL:cfg.rpc,registry:cfg.registry,chainId:cfg.chainId);self.log=log
        directoryState.setEnabled(cfg.publicDirectory)
    }
    func relay(_ path: String,_ body: [String:Any]?=nil) throws -> [String:Any] {
        guard let r=try http(cfg.relay.appendingPathComponent(path),body) as? [String:Any] else {throw DemoError.invalid("relay response")}
        return r
    }
    private var nativeAttestation = NativeAttestation()
    private func native<T>(_ stage:String,operation:(@escaping (T?,Error?)->Void)->Void) throws -> T {
        log("apple operation started",["stage":stage])
        do {
            let result:T = try nativeAttestation.call(stage:stage,operation:operation)
            log("apple operation succeeded",["stage":stage]);return result
        } catch {
            log("apple operation failed",["stage":stage,"errorChain":NativeAttestation.errorChain(error)])
            throw error
        }
    }
    func appAttest(enroll: Bool,_ context: Data) throws -> Data {
        // Enrollment hashes clientData; assertions already receive its digest.
        try native(enroll ? "attestKey" : "generateAssertion") {done in
            if enroll {service.attestKey(keyID,clientDataHash:Data(SHA256.hash(data:context)),completionHandler:done)}
            else {service.generateAssertion(keyID,clientDataHash:context,completionHandler:done)}
        }
    }
    func start() throws {
        try lockIdentity()
        log("connecting",[:])
        try need(try quantity(chain.rpc("eth_chainId",[]))==cfg.chainId,"wrong chain")
        guard let o=try relay("info")["owner"] as? String else {throw DemoError.invalid("relay owner")};owner=o
        log("start",["variant":variant,"rpc":cfg.rpc.absoluteString,"registry":cfg.registry,"owner":owner,"appAttestSupported":service.isSupported])
        try need(service.isSupported,"App Attest unsupported")
        log("attesting",[:])
        var state: EnrollmentState?
        if cfg.persistentIdentity {
            let path=try statePath()
            if FileManager.default.fileExists(atPath:path.path) {
                state=try JSONDecoder().decode(EnrollmentState.self,from:Data(contentsOf:path))
                guard let kid=Data(base64Encoded:state!.keyID),kid.count==32 else {throw DemoError.invalid("stored key ID")}
                let existing=try chain.enrollment(kid,category:cfg.category)
                if existing.enrolled && existing.expires>UInt64(Date().timeIntervalSince1970) {
                    keyID=state!.keyID;me=keccak(cfg.category+kid)
                    log("identity resumed",["member":hex(me),"expires":existing.expires]);return
                }
                if existing.enrolled {
                    log("identity expired",["previousMember":hex(keccak(cfg.category+kid)),"message":"A new attestation identity is required by the current verifier policy"])
                    state=nil
                }
            }
        }
        let measurement=try ownMeasurement()
        if state==nil {
            keyID = try native("generateKey") {done in service.generateKey(completionHandler:done)}
            state=EnrollmentState(keyID:keyID);try saveState(state!)
        } else {keyID=state!.keyID}
        guard let kid=Data(base64Encoded:keyID),kid.count==32 else {throw DemoError.invalid("key id")}
        me=keccak(cfg.category+kid)
        var context: Data;var attestation: Data
        if let cached=state!.attestation,let originalContext=state!.clientData {
            guard let value=Data(base64Encoded:cached) else {throw DemoError.invalid("stored enrollment")}
            attestation=value;context=try unhex(originalContext)
            log("resuming enrollment",[:])
        } else {
            if let savedContext=state!.clientData {context=try unhex(savedContext)}
            else {
                context=try keccak(Data("TEE_INTEROP_ENROLL_V1".utf8)+addressWord(cfg.registry)+addressWord(owner)+sessionPublic)
                // Persist before calling Apple so a service-unavailable retry
                // uses the same key and clientDataHash, even after a restart.
                state!.clientData=hex(context);try saveState(state!)
            }
            attestation=try appAttest(enroll:true,context)
            state!.attestation=attestation.base64EncodedString();state!.clientData=hex(context)
            try saveState(state!)
        }
        let r=try relay("enroll",Node.enrollBody(category:cfg.category,attestation:attestation,clientData:context,measurement:measurement?.fields ?? [:]))
        log("enrolled",["keyId":hex(kid),"member":hex(me),"tx":r["tx"] ?? "","sessionPublic":hex(sessionPublic)])
    }
    static func enrollBody(category:Data,attestation:Data,clientData:Data,measurement:[String:Any]) -> [String:Any] {
        ["category":hex(category),"attestation":attestation.base64EncodedString(),"clientData":hex(clientData)].merging(measurement){$1}
    }
    /// action: 0 join, 2 bootstrap, 3 receipt. The relay is gas sponsor and Request.owner.
    func execute(_ action: UInt64,scope: Data=zero32,group: P256.Signing.PrivateKey?=nil,envelope: Data=zero32) throws -> String {
        try executeDetailed(action,scope:scope,group:group,envelope:envelope).0
    }
    func executeDetailed(_ action: UInt64,scope: Data=zero32,group: P256.Signing.PrivateKey?=nil,envelope: Data=zero32) throws -> (String,Request) {
        let nonce=try smallWord(chain.call("nonces(address)",addressWord(owner)))
        let point=group?.publicKey.x963Representation ?? Data(repeating:0,count:65)
        let request=Request(action:action,category:cfg.category,owner:owner,session:keccak(sessionPublic),nonce:nonce,deadline:try chain.requestDeadline(),
                            scope:action<2 ? zero32:scope,x:point.subdata(in:1..<33),y:point.subdata(in:33..<65),envelope:envelope)
        let epoch=action<2 ? 0:try chain.keyEpoch(scope,protocolVersion:cfg.protocolVersion)
        let context=try request.context(registry:cfg.registry,chainId:cfg.chainId,protocolVersion:cfg.protocolVersion,keyEpoch:epoch)
        let assertion=try appAttest(enroll:false,context)
        let signature=try group.map{hex(try $0.signature(for:RawDigest(data:context)).rawRepresentation)} ?? "0x"
        guard let tx=try relay("execute",["request":request.json,"context":hex(context),"assertion":assertion.base64EncodedString(),
                                          "keyId":keyID,"groupSignature":signature])["tx"] as? String else {throw DemoError.invalid("relay tx")}
        if action==3 && scope==zero32 {directoryReceipt=tx}
        let member=me;keyLock.withLock{checkIn=(member,tx)}
        log("executed",["action":action,"scope":hex(scope),"keyEpoch":epoch,"tx":tx]);return (tx,request)
    }
    func join() throws -> String {try execute(0)}
    func bootstrap(_ scope: Data) throws {
        let epoch=try chain.keyEpoch(scope,protocolVersion:cfg.protocolVersion)
        let key=P256.Signing.PrivateKey();_=try execute(2,scope:scope,group:key);hold(scope,key,epoch:epoch)
    }
    func aad(_ scope: Data,_ recipient: Data,_ recipientPublic: Data) throws -> Data {
        try Data("TEE_INTEROP_PARCEL_V1".utf8)+word(cfg.chainId)+addressWord(cfg.registry)+scope+recipient+recipientPublic
    }
    func transport(_ peerPublic: Data,_ associated: Data) throws -> SymmetricKey {
        try session.sharedSecretFromKeyAgreement(with:P256.KeyAgreement.PublicKey(x963Representation:peerPublic))
            .hkdfDerivedSymmetricKey(using:SHA256.self,salt:Data(SHA256.hash(data:associated)),sharedInfo:Data("TEE_INTEROP_PARCEL_V1".utf8),outputByteCount:32)
    }
    /// Seal the held group key to a peer whose fresh on-chain check-in binds recipientPublic; commit the release on chain.
    func export(_ scope: Data,recipientPublic pub: Data,recipientTx: String) throws -> (Data,String) {
        try need(pub.count==65,"recipient public key")
        let peer=try chain.checkedPeer(recipientTx);try need(peer.session==keccak(pub),"recipient key binding")
        try chain.eligible(peer.member,peer.category,scope)
        guard let key=held[scope] else {throw DemoError.invalid("no local key")}
        try need(heldEpoch[scope]==(try chain.keyEpoch(scope,protocolVersion:cfg.protocolVersion)),"key epoch changed")
        try need(try chain.groupPublic(scope)==key.publicKey.x963Representation,"local key not committed")
        let associated=try aad(scope,peer.member,pub)
        guard let sealed=try AES.GCM.seal(key.rawRepresentation,using:transport(pub,associated),authenticating:associated).combined else {throw DemoError.invalid("AEAD result")}
        let parcel=sessionPublic+pub+peer.member+scope+sealed
        return (parcel,try execute(3,scope:scope,group:key,envelope:keccak(parcel)))
    }
    func importParcel(_ parcel: Data,senderTx: String) throws -> Data {
        try need(parcel.count==254,"parcel size")
        let scope=parcel.subdata(in:162..<194)
        try need(parcel.subdata(in:65..<130)==sessionPublic && parcel.subdata(in:130..<162)==me,"parcel recipient")
        try chain.eligible(me,cfg.category,scope);try chain.validateRelease(senderTx,parcel,scope)
        let associated=try aad(scope,me,sessionPublic)
        let raw=try AES.GCM.open(AES.GCM.SealedBox(combined:parcel.suffix(60)),using:transport(parcel.prefix(65),associated),authenticating:associated)
        let key=try P256.Signing.PrivateKey(rawRepresentation:raw)
        try need(try chain.groupPublic(scope)==key.publicKey.x963Representation,"imported key commitment")
        let epoch=try chain.keyEpoch(scope,protocolVersion:cfg.protocolVersion)
        let receipt=try execute(3,scope:scope,group:key,envelope:keccak(parcel))
        hold(scope,key,epoch:epoch)
        log("key verified",["scope":hex(scope),"keyEpoch":heldEpoch[scope] ?? 0,
            "groupPublic":hex(key.publicKey.x963Representation),"senderReceipt":senderTx,"receipt":receipt])
        return scope
    }
    func send(_ to: String,_ message: [String:Any]) throws {
        var m=message;m["from"]=cfg.name;_=try relay("send/\(to)",m);log("sent",["to":to,"type":m["type"] ?? ""])
    }
    func receive(timeout: Double) throws -> [String:Any] {
        let end=Date().addingTimeInterval(timeout)
        while Date()<end {
            if let m=try relay("recv/\(cfg.name)")["message"] as? [String:Any] {log("received",["type":m["type"] ?? "","from":m["from"] ?? ""]);return m}
            Thread.sleep(forTimeInterval:0.5)
        }
        throw DemoError.invalid("receive timeout")
    }
    /// Holds the overall group key and hands it to admitted peers until a STOP message.
    func listen() throws {
        try start()
        if !(try chain.committed(zero32)) {try bootstrap(zero32)}
        try need(held[zero32] != nil,"overall key committed by another process; this node cannot export it")
        try serve(allowTestStop:true)
    }
    /// Operator seed with bounded retries; never silently rotate a committed key.
    func maintainSeed() {
        var delay:Double=2,wakeable=true
        while true {
            do {
                try start()
                #if os(macOS)
                try startSDK()
                #endif
                let epoch=try chain.keyEpoch(zero32,protocolVersion:cfg.protocolVersion)
                if heldEpoch[zero32] != epoch {retire(zero32)}
                let committed=try chain.committed(zero32)
                if !committed {try bootstrap(zero32)}
                else if held[zero32] == nil,let path=cfg.sealPath {try unseal(path,epoch:epoch)}
                if held[zero32] == nil {
                    try need(!cfg.peers.isEmpty,"seed recovery requires a live peer, a sealed key or explicit new key epoch")
                    try connect(startIdentity:false)
                }
                if let path=cfg.sealPath,!committed || sealedFrom != epoch {try seal(path,epoch:epoch)}
                log("seed ready",["keyEpoch":epoch]);delay=2;wakeable=true;try serve()
            } catch {
                log("seed retrying",["error":String(describing:error),"retryAfterSeconds":delay])
                // Relay senders are unauthenticated: one heartbeat may cut a failure streak's backoff short, not every wait.
                if awaitHolder(delay,wakeable:wakeable) {wakeable=false};delay=min(delay*2,60)
            }
        }
    }
    private var sealedFrom: UInt64?
    func seal(_ path: URL,epoch: UInt64) throws {
        guard let key=held[zero32] else {throw DemoError.invalid("no key to seal")}
        try SeedSeal.write(path,tag:sealTag,epoch:epoch,key:key)
        sealedFrom=epoch;log("sealed key written",["keyEpoch":epoch,"path":path.path])
    }
    /// Reopens the sealed key only for the current epoch and committed key: no peer, no transaction.
    func unseal(_ path: URL,epoch: UInt64) throws {
        guard FileManager.default.fileExists(atPath:path.path) else {log("no sealed key",["path":path.path]);return}
        let opened=try SeedSeal.read(path,tag:sealTag)
        let group=try chain.groupPublic(zero32)
        guard opened.epoch==epoch && opened.key.publicKey.x963Representation==group else {
            log("sealed key stale",["sealedEpoch":opened.epoch,"keyEpoch":epoch]);return
        }
        hold(zero32,opened.key,epoch:epoch);sealedFrom=epoch
        log("sealed key loaded",["keyEpoch":epoch,"groupPublic":hex(group)])
    }
    var sealTag: Data {Data("dev.dsmack.seed-seal.v1:\(cfg.chainId):\(cfg.registry.lowercased()):\(cfg.name)".utf8)}
    /// Backoff that listens: a peer heartbeat announcing a held key at this epoch ends the wait early,
    /// and HELLOs get an immediate ERROR so requesters move to their next peer.
    @discardableResult func awaitHolder(_ seconds: Double,wakeable: Bool=true) -> Bool {
        let end=Date().addingTimeInterval(seconds)
        do {
            let epoch=try chain.keyEpoch(zero32,protocolVersion:cfg.protocolVersion)
            while Date()<end {
                guard let m=try relay("recv/\(cfg.name)")["message"] as? [String:Any],let from=m["from"] as? String else {Thread.sleep(forTimeInterval:0.5);continue}
                if m["type"] as? String=="HELLO" {try send(from,["type":"ERROR","reason":"seed holds no key"])}
                if m["type"] as? String=="HEARTBEAT" && cfg.peers.contains(from) {
                    heartbeats[from]=Date()
                    if wakeable && m["holds"] as? Bool==true && (m["keyEpoch"] as? NSNumber)?.uint64Value==epoch {log("peer holds key",["peer":from]);return true}
                }
            }
        } catch {
            log("seed backoff unreachable",["error":String(describing:error)])
            Thread.sleep(forTimeInterval:max(0,end.timeIntervalSinceNow))
        }
        return false
    }
    /// Production participants ignore unauthenticated test STOP messages.
    func serve(allowTestStop: Bool=false) throws {
        var checkedAt=Date.distantPast
        while true {
            if Date().timeIntervalSince(checkedAt)>30 {
                try need(heldEpoch[zero32]==(try chain.keyEpoch(zero32,protocolVersion:cfg.protocolVersion)),"key epoch changed")
                guard let kid=Data(base64Encoded:keyID) else {throw DemoError.invalid("key ID")}
                let identity=try chain.enrollment(kid,category:cfg.category)
                try need(identity.enrolled && identity.expires>UInt64(Date().timeIntervalSince1970),"identity renewal required")
                checkedAt=Date();log("network reachable",[:])
                // Advisory: a relay policy refusing HEARTBEAT must not stop key service.
                for peer in cfg.peers {
                    do {try send(peer,["type":"HEARTBEAT","keyEpoch":heldEpoch[zero32] ?? 0,"holds":held[zero32] != nil])}
                    catch {log("heartbeat refused",["peer":peer,"error":"\(error)"])}
                }
            }
            runOperations()
            attemptParticipantBadge()
            attemptDirectoryCheckIn()
            var message: [String:Any]
            do {message=try receive(timeout:15)}
            catch DemoError.invalid(let reason) where reason=="receive timeout" {continue}
            guard let type=message["type"] as? String,let from=message["from"] as? String else {log("ignored malformed message",[:]);continue}
            let m=message
            do {
                switch type {
                case "HELLO":
                    guard let pub=m["sessionPublic"] as? String,let tx=m["joinTx"] as? String,let nonce=m["nonce"] as? String else {throw DemoError.invalid("HELLO fields")}
                    let (parcel,receipt)=try export(zero32,recipientPublic:unhex(pub),recipientTx:tx)
                    nonces[from]=try unhex(nonce)
                    try send(from,["type":"PARCEL","parcel":hex(parcel),"receiptTx":receipt])
                case "PROOF":
                    guard let nonce=nonces.removeValue(forKey:from),let sig=m["signature"] as? String else {throw DemoError.invalid("unexpected PROOF")}
                    let group=try P256.Signing.PublicKey(x963Representation:chain.groupPublic(zero32))
                    try need(group.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation:unhex(sig)),for:nonce),"PROOF signature")
                    log("peer holds group key",["peer":from])
                case "STOP":
                    try need(allowTestStop,"test control disabled");log("stop",[:]);return
                case "HEARTBEAT": heartbeats[from]=Date()
                case "ERROR", "PARCEL": log("ignored stale message",["type":type])
                default: throw DemoError.invalid("message type")
                }
            } catch {
                log("refused",["peer":from,"type":type,"error":"\(error)"])
                if type=="HELLO" {try send(from,["type":"ERROR","reason":"\(error)"])}
            }
        }
    }
    /// Asks each peer in turn, most recently heard first, for the overall group key.
    func connect(startIdentity: Bool=true) throws {
        if startIdentity {try start()}
        log("getting key",[:])
        if cfg.peers.isEmpty {return try acquire(from:"")}
        var failures=[String]()
        for peer in cfg.peers.sorted(by:{(heartbeats[$0] ?? .distantPast)>(heartbeats[$1] ?? .distantPast)}) {
            do {return try acquire(from:peer)}
            catch {failures.append("\(peer): \(error)");log("peer failed",["peer":peer,"error":"\(error)"])}
        }
        throw DemoError.invalid("no peer delivered the key: "+failures.joined(separator:"; "))
    }
    /// Joins, asks `peer` for the overall group key, imports it, proves possession.
    func acquire(from peer: String) throws {
        let joinTx=try join()
        Thread.sleep(forTimeInterval:cfg.helloDelay)
        let nonce=Data(SHA256.hash(data:Data(UUID().uuidString.utf8)))
        if !peer.isEmpty {try send(peer,["type":"HELLO","member":hex(me),"joinTx":joinTx,"sessionPublic":hex(sessionPublic),"nonce":hex(nonce)])}
        let until=Date().addingTimeInterval(60)
        var reply: [String:Any]?
        while Date()<until {
            let message=try receive(timeout:max(1,until.timeIntervalSinceNow))
            // Other peers may ask us for keys while we are still acquiring ours.
            // Those requests must not consume the expected faucet reply.
            guard message["from"] as? String == peer else {log("ignored while acquiring",[:]);continue}
            if message["type"] as? String == "ERROR" {throw DemoError.invalid("faucet: \(message["reason"] ?? "unavailable")")}
            guard message["type"] as? String == "PARCEL" else {continue}
            reply=message;break
        }
        guard let m=reply,let parcel=m["parcel"] as? String,let tx=m["receiptTx"] as? String else {throw DemoError.invalid("faucet receipt timeout")}
        let scope=try importParcel(unhex(parcel),senderTx:tx)
        log("imported group key",["scope":hex(scope),"groupPublic":hex(try chain.groupPublic(scope))])
        guard let key=held[scope] else {throw DemoError.invalid("no key")}
        try send(peer,["type":"PROOF","signature":hex(try key.signature(for:nonce).rawRepresentation)])
    }
    /// Keep the admitted participant alive, serving authenticated peers after receipt.
    /// A missing seed never silently replaces the committed shared key.
    func participate() throws {
        try start()
        #if os(macOS)
        try startSDK()
        #endif
        let epoch=try chain.keyEpoch(zero32,protocolVersion:cfg.protocolVersion)
        if heldEpoch[zero32] != epoch {retire(zero32)}
        if held[zero32] == nil {try connect(startIdentity:false)} else {_=try join()}
        badgeParticipation=true
        log("participating",["member":hex(me),"keyEpoch":epoch])
        attemptParticipantBadge()
        try serve()
    }

}

/// ECIES (cofactor, variable IV, X9.63 SHA-256, AES-GCM) seal of `epoch ‖ groupPublic ‖ key` to a permanent
/// Secure Enclave P-256 key: data protection Keychain, this app's default access group,
/// AfterFirstUnlockThisDeviceOnly with privateKeyUsage. No exportable key blob is ever written.
enum SeedSeal {
    static let algorithm=SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    static func query(_ tag: Data) -> [String:Any] {
        [kSecClass as String:kSecClassKey,kSecAttrApplicationTag as String:tag,kSecAttrTokenID as String:kSecAttrTokenIDSecureEnclave,
         kSecUseDataProtectionKeychain as String:true]
    }
    static func find(_ tag: Data) throws -> SecKey? {
        var q=query(tag);q[kSecReturnRef as String]=true
        var item:CFTypeRef?;let status=SecItemCopyMatching(q as CFDictionary,&item)
        if status==errSecItemNotFound {return nil}
        try need(status==errSecSuccess,"seal key Keychain lookup failed (\(status))")
        return (item as! SecKey)
    }
    static func enclaveKey(_ tag: Data) throws -> SecKey {
        if let key=try find(tag) {return key}
        var error:Unmanaged<CFError>?
        guard let access=SecAccessControlCreateWithFlags(nil,kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,.privateKeyUsage,&error) else {throw error!.takeRetainedValue()}
        let attributes:[String:Any]=[kSecAttrKeyType as String:kSecAttrKeyTypeECSECPrimeRandom,kSecAttrKeySizeInBits as String:256,
            kSecAttrTokenID as String:kSecAttrTokenIDSecureEnclave,kSecUseDataProtectionKeychain as String:true,
            kSecPrivateKeyAttrs as String:[kSecAttrIsPermanent as String:true,kSecAttrApplicationTag as String:tag,kSecAttrAccessControl as String:access]]
        guard let key=SecKeyCreateRandomKey(attributes as CFDictionary,&error) else {throw error!.takeRetainedValue()}
        return key
    }
    static func write(_ path: URL,tag: Data,epoch: UInt64,key: P256.Signing.PrivateKey) throws {
        guard let pub=SecKeyCopyPublicKey(try enclaveKey(tag)) else {throw DemoError.invalid("seal public key")}
        var error:Unmanaged<CFError>?
        let plain=word(epoch).suffix(8)+key.publicKey.x963Representation+key.rawRepresentation
        guard let sealed=SecKeyCreateEncryptedData(pub,algorithm,plain as CFData,&error) else {throw error!.takeRetainedValue()}
        try (sealed as Data).write(to:path,options:.atomic)
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:path.path)
    }
    static func read(_ path: URL,tag: Data) throws -> (epoch: UInt64,key: P256.Signing.PrivateKey) {
        guard let private_=try find(tag) else {throw DemoError.invalid("sealed key present but its Enclave key is missing")}
        var error:Unmanaged<CFError>?
        guard let plain=SecKeyCreateDecryptedData(private_,algorithm,try Data(contentsOf:path) as CFData,&error) as Data? else {throw error!.takeRetainedValue()}
        try need(plain.count==105,"sealed key size")
        let key=try P256.Signing.PrivateKey(rawRepresentation:plain.suffix(32))
        try need(key.publicKey.x963Representation==plain.subdata(in:8..<73),"sealed key commitment")
        return (plain.prefix(8).reduce(UInt64(0)){($0<<8)|UInt64($1)},key)
    }
}
