import Foundation
import CryptoKit

/// Exercises the production transport derivation and parcel guards without
/// enrollment, Keychain writes, RPC calls or persisted secret material.
@main struct ParcelCryptoTests {
    static func main() throws {
        let config:[String:Any]=["rpc":"http://127.0.0.1:1","registry":"0x1111111111111111111111111111111111111111","chainId":31337,"category":hex(zero32),"relay":"http://127.0.0.1:1","name":"parcel-crypto-test"]
        let sender=Node(try Config(config),log:{_,_ in})
        var verificationEvents=0
        let receiver=Node(try Config(config),log:{event,_ in if event=="key verified" {verificationEvents += 1}})
        receiver.me=word(42)
        let other=Node(try Config(config),log:{_,_ in})
        let scope=word(7),secret=P256.Signing.PrivateKey().rawRepresentation
        let associated=try sender.aad(scope,receiver.me,receiver.sessionPublic)
        let senderKey=try sender.transport(receiver.sessionPublic,associated)
        let receiverKey=try receiver.transport(sender.sessionPublic,associated)
        let sealed=try AES.GCM.seal(secret,using:senderKey,authenticating:associated).combined!
        try need(try AES.GCM.open(AES.GCM.SealedBox(combined:sealed),using:receiverKey,authenticating:associated)==secret,"valid production transport failed")
        var passed=1
        func rejects(_ name:String,expected:String?=nil,_ operation:()throws->Void) throws {
            var rejected=false
            do {try operation()} catch {
                if let expected {
                    guard case DemoError.invalid(let reason)=error,reason==expected else {throw error}
                }
                rejected=true
            }
            try need(rejected,"negative case accepted: "+name)
            passed += 1;print("PASS "+name)
        }
        var corrupted=sealed;corrupted[20] ^= 1
        try rejects("tampered ciphertext") {_=try AES.GCM.open(AES.GCM.SealedBox(combined:corrupted),using:receiverKey,authenticating:associated)}
        var badTag=sealed;badTag[badTag.count-1] ^= 1
        try rejects("tampered authentication tag") {_=try AES.GCM.open(AES.GCM.SealedBox(combined:badTag),using:receiverKey,authenticating:associated)}
        let wrongScope=try receiver.aad(word(8),receiver.me,receiver.sessionPublic)
        try rejects("wrong scope") {_=try AES.GCM.open(AES.GCM.SealedBox(combined:sealed),using:receiver.transport(sender.sessionPublic,wrongScope),authenticating:wrongScope)}
        let wrongRecipient=try receiver.aad(scope,word(43),receiver.sessionPublic)
        try rejects("wrong recipient identity") {_=try AES.GCM.open(AES.GCM.SealedBox(combined:sealed),using:receiver.transport(sender.sessionPublic,wrongRecipient),authenticating:wrongRecipient)}
        try rejects("wrong receiver ECDH key") {_=try AES.GCM.open(AES.GCM.SealedBox(combined:sealed),using:other.transport(sender.sessionPublic,associated),authenticating:associated)}
        var otherConfig=config;otherConfig["chainId"]=31338
        let foreign=Node(try Config(otherConfig),log:{_,_ in})
        let wrongChain=try foreign.aad(scope,receiver.me,receiver.sessionPublic)
        try rejects("wrong chain binding") {_=try AES.GCM.open(AES.GCM.SealedBox(combined:sealed),using:receiver.transport(sender.sessionPublic,wrongChain),authenticating:wrongChain)}
        otherConfig=config;otherConfig["registry"]="0x2222222222222222222222222222222222222222"
        let otherRegistry=Node(try Config(otherConfig),log:{_,_ in})
        let wrongRegistry=try otherRegistry.aad(scope,receiver.me,receiver.sessionPublic)
        try rejects("wrong registry binding") {_=try AES.GCM.open(AES.GCM.SealedBox(combined:sealed),using:receiver.transport(sender.sessionPublic,wrongRegistry),authenticating:wrongRegistry)}
        let foreignParcel=sender.sessionPublic+other.sessionPublic+receiver.me+scope+sealed
        try rejects("production import rejects foreign recipient before RPC",expected:"parcel recipient") {_=try receiver.importParcel(foreignParcel,senderTx:"unused")}
        try rejects("production import rejects truncated parcel before RPC",expected:"parcel size") {_=try receiver.importParcel(foreignParcel.dropLast(),senderTx:"unused")}
        try need(receiver.held.isEmpty && receiver.heldEpoch.isEmpty && verificationEvents==0,"negative import mutated held key or emitted verified receipt")
        print("PASS no held key or verified receipt from rejected imports")
        print("Parcel crypto checks passed: \(passed+1). Scope: transport authentication plus production pre-RPC import guards; not full-chain receipt validation.")
    }
}
