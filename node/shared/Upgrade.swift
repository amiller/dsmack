import Foundation
import CryptoKit

struct UpgradeInvitation: Codable {
    let version:Int
    let chainId:UInt64
    let badges:String
    let factory:String
    let account:String
    let participantToken:UInt64
    let bundleId:String
}
struct UpgradeRequest: Codable {
    let invitation:UpgradeInvitation
    let newPoint:Data
    let generation:UInt64
    let deadline:UInt64
    let newSignature:Data
    let newKeyId:Data
    let receiptRequest:Request
    let receiptTransaction:String
}

extension Node {
    func builderBundleId(_ account:String) -> String {"dev.attestnode.builder.a"+account.lowercased()}
    func badgePolicy() throws -> (badges:String,factory:String) {
        guard let badges=cfg.badges,let factory=cfg.accountFactory else {throw DemoError.invalid("NFT upgrades are not enabled on this network")}
        try need(try chain.call("badges()",to:factory)==addressWord(badges),"account factory policy")
        return (badges,factory)
    }
    func personalKey() throws -> PersonalAccountKey {
        try PersonalAccountKey.loadOrCreate(chainId:cfg.chainId,factory:badgePolicy().factory)
    }
    func defaultPersonalAccount(_ key:PersonalAccountKey) throws -> String {
        let value=try chain.call("accountAddress(uint256,uint256)",Data(key.publicPoint.dropFirst()),to:badgePolicy().factory)
        try need(value.count==32 && value.prefix(12)==Data(repeating:0,count:12),"personal account address")
        return hex(value.suffix(20))
    }
    func checkInvitation(_ invitation:UpgradeInvitation) throws {
        let policy=try badgePolicy()
        try need(invitation.version==2 && invitation.chainId==cfg.chainId
            && invitation.badges.lowercased()==policy.badges.lowercased()
            && invitation.factory.lowercased()==policy.factory.lowercased(),"upgrade belongs to another network")
        try need(invitation.bundleId==builderBundleId(invitation.account),"Save a fresh invitation with this account’s builder bundle identifier")
        try need(invitation.participantToken>0,"missing participant NFT")
        try need(try smallWord(chain.call("isAccount(address)",addressWord(invitation.account),to:policy.factory))==1,"unknown personal account")
        try need(try chain.call("badges()",to:invitation.account)==addressWord(policy.badges),"personal account policy")
        try need(try chain.call("ownerOf(uint256)",word(invitation.participantToken),to:policy.badges)==addressWord(invitation.account),"participant NFT ownership")
        let badge=try chain.call("badges(uint256)",word(invitation.participantToken),to:policy.badges)
        try need(badge.count==128 && smallWord(badge.subdata(in:64..<96))==1,"upgrade parent is not Level 1")
    }
    func linkPath(_ key:PersonalAccountKey) throws -> URL {
        let root=try statePath().deletingLastPathComponent()
        // Public metadata is isolated by this signed app's actual personal key.
        // It cannot grant control; every load still checks on-chain ownership.
        let id=try keccak(word(cfg.chainId)+addressWord(badgePolicy().factory)+key.publicPoint)
        return root.appendingPathComponent("upgrade-"+hex(id)+".json")
    }
    func linkedAccount(_ key:PersonalAccountKey) throws -> UpgradeInvitation? {
        let path=try linkPath(key)
        guard FileManager.default.fileExists(atPath:path.path) else {return nil}
        let data=try Data(contentsOf:path);try need(data.count<=4096,"upgrade metadata size")
        let invitation=try JSONDecoder().decode(UpgradeInvitation.self,from:data)
        try checkInvitation(invitation)
        return invitation
    }
    func saveLink(_ invitation:UpgradeInvitation,key:PersonalAccountKey) throws {
        try checkInvitation(invitation)
        let path=try linkPath(key)
        try JSONEncoder().encode(invitation).write(to:path,options:.atomic)
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:path.path)
    }
    func exportUpgradeInvitation() throws -> UpgradeInvitation {
        let policy=try badgePolicy(),key=try personalKey()
        let account=try linkedAccount(key)?.account ?? defaultPersonalAccount(key)
        try checkControl(account,key:key)
        let token=try smallWord(chain.call("participantOf(address)",addressWord(account),to:policy.badges))
        let invitation=UpgradeInvitation(version:2,chainId:cfg.chainId,badges:policy.badges,factory:policy.factory,account:account,participantToken:token,bundleId:builderBundleId(account))
        try checkInvitation(invitation);return invitation
    }
    func checkControl(_ account:String,key:PersonalAccountKey) throws {
        try need(try chain.call("keyX()",to:account)+chain.call("keyY()",to:account)==Data(key.publicPoint.dropFirst()),"This app does not currently control that account. If you already approved the handoff, continue in the new copy.")
    }
    func adapterAddress() throws -> String {
        let result=try chain.call("categories(bytes32)",cfg.category)
        try need(result.count==192,"category encoding")
        return hex(result.subdata(in:12..<32))
    }
    func verifiedTeam(keyId:Data,expectedContext:Data?=nil,maxAge:UInt64=3600,forAccount:String?=nil) throws -> Data {
        try need(keyId.count==32,"upgrade key ID")
        let adapter=try adapterAddress()
        let evidence=try chain.call("assertionEvidence(bytes32)",keyId,to:adapter)
        try need(evidence.count==160 && evidence.prefix(32) != Data(repeating:0,count:32),"missing verified app assertion")
        if let expectedContext {try need(evidence.prefix(32)==expectedContext,"upgrade assertion was superseded; create a fresh request")}
        let checked=try smallWord(evidence.subdata(in:96..<128)),now=UInt64(Date().timeIntervalSince1970)
        try need(checked<=now+5 && now<checked+maxAge,"upgrade assertion expired; create a fresh request")
        let cds=try chain.call("cds()",to:adapter);try need(cds.count==32,"code registry encoding")
        let registry=hex(cds.suffix(20)),cd=Data(evidence.subdata(in:32..<64))
        let rp=try chain.call("rpIdHash(bytes32)",cd,to:registry)
        try need(rp==evidence.subdata(in:64..<96) && rp != Data(repeating:0,count:32),"upgrade build is no longer admitted")
        let team=try chain.call("teamIdHash(bytes32)",cd,to:registry)
        try need(team.count==32 && team != Data(repeating:0,count:32),"build has no verified developer team")
        if let account=forAccount {
            let bundle=try chain.call("bundleIdHash(bytes32)",cd,to:registry)
            try need(bundle==Data(SHA256.hash(data:Data(builderBundleId(account).utf8))),"Sign a build with the bundle identifier in your participant invitation")
        }
        return team
    }
    func requireIndependentTeam(_ team:Data) throws {
        try need(try team != chain.call("publisherTeam()",to:badgePolicy().badges),"Run the admitted copy signed with your own Apple Developer team first")
    }
    func prepareUpgrade(_ invitation:UpgradeInvitation) throws -> UpgradeRequest {
        try checkInvitation(invitation)
        guard let group=held[zero32],let kid=Data(base64Encoded:keyID) else {throw DemoError.invalid("Join the network before preparing the upgrade")}
        let key=try personalKey()
        let generation=try smallWord(chain.call("generation()",to:invitation.account))
        let deadline=UInt64(Date().timeIntervalSince1970)+3300
        let digest=try PersonalAccountEncoding.handoffDigest(chainId:cfg.chainId,account:invitation.account,generation:generation,newPoint:key.publicPoint,deadline:deadline)
        let (tx,request)=try executeDetailed(3,group:group,envelope:digest)
        let epoch=try chain.keyEpoch(zero32,protocolVersion:cfg.protocolVersion)
        let context=try request.context(registry:cfg.registry,chainId:cfg.chainId,protocolVersion:cfg.protocolVersion,keyEpoch:epoch)
        try requireIndependentTeam(verifiedTeam(keyId:kid,expectedContext:context,forAccount:invitation.account))
        let signature=try key.handoff(chainId:cfg.chainId,account:invitation.account,generation:generation,newPoint:key.publicPoint,deadline:deadline)
        let result=UpgradeRequest(invitation:invitation,newPoint:key.publicPoint,generation:generation,deadline:deadline,newSignature:signature,newKeyId:kid,receiptRequest:request,receiptTransaction:tx)
        return result
    }
    func trackUpgrade(_ request:UpgradeRequest) throws {
        let key=try personalKey()
        try need(request.newPoint==key.publicPoint,"upgrade request belongs to another app key")
        try saveLink(request.invitation,key:key);badgeComplete=false;nextBadgeAttempt=Date().addingTimeInterval(30)
        log("upgrade awaiting approval",["personalAccount":request.invitation.account,"newKeyFingerprint":hex(keccak(key.publicPoint).prefix(8))])
    }
    /// Validate again immediately before signing; the caller must first obtain
    /// explicit human approval of this account and new-key fingerprint.
    func validateUpgrade(_ request:UpgradeRequest) throws -> Data {
        let invitation=request.invitation
        try checkInvitation(invitation)
        let key=try personalKey();try checkControl(invitation.account,key:key)
        let now=UInt64(Date().timeIntervalSince1970)
        try need(request.deadline>now && request.deadline<=now+3600,"upgrade request expired")
        try need(try smallWord(chain.call("generation()",to:invitation.account))==request.generation,"account control already changed")
        let digest=try PersonalAccountEncoding.handoffDigest(chainId:cfg.chainId,account:invitation.account,generation:request.generation,newPoint:request.newPoint,deadline:request.deadline)
        try need(request.newPoint != key.publicPoint,"new app must have its own control key")
        let publicKey=try P256.Signing.PublicKey(x963Representation:request.newPoint)
        try need(publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation:request.newSignature),for:RawDigest(data:digest)),"new app key signature")
        let receipt=request.receiptRequest
        try need(receipt.action==3 && receipt.category==cfg.category && receipt.scope==zero32 && receipt.envelope==digest,"upgrade receipt binding")
        let epoch=try chain.keyEpoch(zero32,protocolVersion:cfg.protocolVersion)
        let context=try receipt.context(registry:cfg.registry,chainId:cfg.chainId,protocolVersion:cfg.protocolVersion,keyEpoch:epoch)
        let team=try verifiedTeam(keyId:request.newKeyId,expectedContext:context,forAccount:invitation.account)
        try requireIndependentTeam(team)
        return team
    }
    func approveUpgrade(_ request:UpgradeRequest) throws -> String {
        _=try validateUpgrade(request)
        let key=try personalKey(),invitation=request.invitation
        let signature=try key.handoff(chainId:cfg.chainId,account:invitation.account,generation:request.generation,newPoint:request.newPoint,deadline:request.deadline)
        let coords=Data(request.newPoint.dropFirst())
        let response=try relay("account-handoff",["account":invitation.account,"x":hex(coords.prefix(32)),"y":hex(coords.suffix(32)),"deadline":request.deadline,"oldSignature":hex(signature),"newSignature":hex(request.newSignature)])
        try need(try chain.call("keyX()",to:invitation.account)+chain.call("keyY()",to:invitation.account)==coords,"account handoff not confirmed")
        log("upgrade approved",["personalAccount":invitation.account,"transaction":response["tx"] ?? ""])
        return response["tx"] as? String ?? ""
    }
}
