import Foundation
import DeviceCheck
import CryptoKit

let args=CommandLine.arguments
guard args.count==3 else {exit(64)}
let out=URL(fileURLWithPath:args[1],isDirectory:true)
let owner=args[2]
try FileManager.default.createDirectory(at:out,withIntermediateDirectories:true)
func save(_ name:String,_ data:Data) throws {try data.write(to:out.appendingPathComponent(name),options:.atomic)}
func json(_ name:String,_ value:[String:Any]) throws {try save(name,JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]))}
func die(_ reason:String)->Never {try? json("fatal.json",["reason":reason]);exit(1)}
let service=DCAppAttestService.shared
let session=P256.KeyAgreement.PrivateKey()
let sessionPublic=session.publicKey.x963Representation
let sessionHash=keccak(sessionPublic)
var held=[String:P256.Signing.PrivateKey]()
var outgoing=[String:Data]() // ciphertext only; never a raw signing key
var keyID=""
func attestCall(_ mode:String,_ context:Data) throws -> Data {
    let semaphore=DispatchSemaphore(value:0);var result:Data?;var failure:Error?
    let callback:(Data?,Error?)->Void={data,error in result=data;failure=error;semaphore.signal()}
    if mode=="enroll" {service.attestKey(keyID,clientDataHash:Data(SHA256.hash(data:context)),completionHandler:callback)}
    else {service.generateAssertion(keyID,clientDataHash:Data(SHA256.hash(data:context)),completionHandler:callback)}
    try need(semaphore.wait(timeout:.now()+90) == .success,"App Attest timeout")
    if let error=failure {throw error};guard let data=result else {throw DemoError.invalid("missing App Attest response")};return data
}
func memberID(_ category:Data) throws -> Data {
    guard let kid=Data(base64Encoded:keyID),kid.count==32 else {throw DemoError.invalid("key id")}
    return keccak(category+kid)
}
func aad(_ scope:Data,_ recipient:Data,_ recipientPublic:Data) throws -> Data {
    return try Data("TEE_INTEROP_PARCEL_V1".utf8)+word(84532)+addressWord(demoRegistry)+scope+recipient+recipientPublic
}
func operation(_ input:[String:Any],_ index:Int) throws -> [String:Any] {
    guard let action=input["action"] as? String,let categoryHex=input["category"] as? String else {throw DemoError.invalid("operation fields")}
    let category=try bytes32(categoryHex);let me=try memberID(category)
    let scope=try bytes32(input["scope"] as? String ?? hex(Data(repeating:0,count:32)))
    var envelope=Data(repeating:0,count:32);var group:P256.Signing.PrivateKey?;var number:UInt64=0
    if action=="export" {
        guard let pubHex=input["recipientPublic"] as? String,let tx=input["recipientTransaction"] as? String else {throw DemoError.invalid("recipient fields")}
        let pub=try unhex(pubHex);try need(pub.count==65,"recipient public key")
        let peer=try checkedPeer(tx);try need(peer.session==keccak(pub),"recipient key binding");try eligible(peer.member,peer.category,scope)
        try eligible(me,category,scope)
        guard let key=held[hex(scope)] else {throw DemoError.invalid("no local key")}
        try need(try groupPublic(scope)==key.publicKey.x963Representation,"local key not committed")
        let associated=try aad(scope,peer.member,pub)
        let shared=try session.sharedSecretFromKeyAgreement(with:P256.KeyAgreement.PublicKey(x963Representation:pub))
        let transport=shared.hkdfDerivedSymmetricKey(using:SHA256.self,salt:Data(SHA256.hash(data:associated)),sharedInfo:Data("TEE_INTEROP_PARCEL_V1".utf8),outputByteCount:32)
        let sealed=try AES.GCM.seal(key.rawRepresentation,using:transport,authenticating:associated)
        guard let combined=sealed.combined else {throw DemoError.invalid("AEAD result")}
        let parcel=sessionPublic+pub+peer.member+scope+combined
        envelope=keccak(parcel);outgoing[hex(envelope)]=parcel
        // Publish only ciphertext; the recipient must also check the on-chain
        // donor Receipt transaction produced from this exact context.
        try save("parcel-\(index).bin",parcel);group=key;number=3
    }else if action=="import" {
        guard let raw=input["parcel"] as? String,let tx=input["senderTransaction"] as? String else {throw DemoError.invalid("parcel fields")}
        let parcel=try unhex(raw);try need(parcel.count==254,"parcel size")
        try need(parcel.subdata(in:65..<130)==sessionPublic && parcel.subdata(in:130..<162)==me && parcel.subdata(in:162..<194)==scope,"parcel recipient/scope")
        try eligible(me,category,scope);try validateRelease(tx,parcel,scope)
        let associated=try aad(scope,me,sessionPublic)
        let shared=try session.sharedSecretFromKeyAgreement(with:P256.KeyAgreement.PublicKey(x963Representation:parcel.prefix(65)))
        let transport=shared.hkdfDerivedSymmetricKey(using:SHA256.self,salt:Data(SHA256.hash(data:associated)),sharedInfo:Data("TEE_INTEROP_PARCEL_V1".utf8),outputByteCount:32)
        let rawKey=try AES.GCM.open(AES.GCM.SealedBox(combined:parcel.suffix(60)),using:transport,authenticating:associated)
        let key=try P256.Signing.PrivateKey(rawRepresentation:rawKey)
        try need(try groupPublic(scope)==key.publicKey.x963Representation,"imported key commitment")
        held[hex(scope)]=key;group=key;number=3;envelope=keccak(parcel)
    }else if action=="bootstrap" {
        try need(scope==category || scope==Data(repeating:0,count:32),"bootstrap scope")
        let current=try call("sharedKeys(bytes32)",scope);try need(current.count==128 && smallWord(current.suffix(32))==0,"already bootstrapped")
        let key=P256.Signing.PrivateKey();held[hex(scope)]=key;group=key;number=2
    }else if action=="join" {number=0}
    else if action=="claim" {number=1}
    else {throw DemoError.invalid("unsupported action")}
    let nonce=try smallWord(call("nonces(address)",addressWord(owner)))
    let now=UInt64(Date().timeIntervalSince1970)
    let point=group?.publicKey.x963Representation ?? Data(repeating:0,count:65)
    let request=Request(action:number,category:category,owner:owner,session:sessionHash,nonce:nonce,deadline:now+55,scope:number<2 ? Data(repeating:0,count:32):scope,x:point.subdata(in:1..<33),y:point.subdata(in:33..<65),envelope:envelope)
    let context=try request.context(registry:demoRegistry)
    #if MODIFIED
    // Negative control differs in measured code; it must never be admitted.
    let marker="modified"
    #else
    let marker="honest"
    #endif
    let assertion=try attestCall("assert",context)
    var result:[String:Any]=["request":request.json,"context":hex(context),"assertion":assertion.base64EncodedString(),"keyId":keyID,"memberId":hex(me),"sessionPublic":hex(sessionPublic),"variant":marker]
    if let key=group {result["groupSignature"]=hex(try key.signature(for:RawDigest(data:context)).rawRepresentation)}else{result["groupSignature"]="0x"}
    if let parcel=outgoing[hex(envelope)] {result["parcel"]=hex(parcel)}
    return result
}
do {
    _=try addressWord(owner);try need(service.isSupported,"App Attest unsupported")
    try need(try quantity(rpc("eth_chainId",[]))==84532,"wrong chain")
    let semaphore=DispatchSemaphore(value:0);var failure:Error?
    service.generateKey {key,error in keyID=key ?? "";failure=error;semaphore.signal()}
    try need(semaphore.wait(timeout:.now()+60) == .success,"key generation timeout")
    if let e=failure {throw e};try need(!keyID.isEmpty,"missing key id")
    let enrollment=try keccak(Data("TEE_INTEROP_ENROLL_V1".utf8)+addressWord(demoRegistry)+addressWord(owner)+sessionPublic)
    try save("attestation.cbor",attestCall("enroll",enrollment));try save("enrollment.context",enrollment)
    try json("ready.json",["keyId":keyID,"sessionPublic":hex(sessionPublic),"registry":demoRegistry,"owner":owner,"pid":ProcessInfo.processInfo.processIdentifier,"chainStateTrust":"HTTPS sepolia.base.org; no light client"])
    for index in 1...100 {
        let path=out.appendingPathComponent("request-\(index).json")
        while !FileManager.default.fileExists(atPath:path.path) {
            if FileManager.default.fileExists(atPath:out.appendingPathComponent("stop").path){exit(0)}
            Thread.sleep(forTimeInterval:0.1)
        }
        do {
            let raw=try Data(contentsOf:path);try need(raw.count<=32768,"request size")
            guard let input=try JSONSerialization.jsonObject(with:raw) as? [String:Any] else {throw DemoError.invalid("request JSON")}
            try json("response-\(index).json",operation(input,index))
        }catch {try json("response-\(index).json",["error":String(describing:error)])}
    }
}catch {die(String(describing:error))}
