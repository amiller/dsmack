import Foundation
import CryptoKit

/// Read-only integration checks against the existing isolated Mac NFT fixture.
/// Run as a signed app with the original participant's Keychain access group.
@main struct UpgradeValidation {
    static func main() throws {
        let args=CommandLine.arguments
        try need(args.count==3,"usage: upgrade-validation config.json participant-key-id")
        let config=try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:args[1]))) as! [String:Any]
        let node=Node(try Config(config),log:{_,_ in})
        let invitation=try node.exportUpgradeInvitation()
        try need(invitation.chainId==31337,"isolated test chain only")
        let before=try smallWord(node.chain.call("generation()",to:invitation.account))
        func rejects(_ expected:String,_ operation:()throws->Void) throws {
            do {try operation();throw DemoError.invalid("negative test unexpectedly succeeded: "+expected)}
            catch DemoError.invalid(let reason) {try need(reason.contains(expected) && !reason.hasPrefix("negative test"),"wrong rejection: "+reason)}
        }
        let wrongNetwork=UpgradeInvitation(version:2,chainId:84532,badges:invitation.badges,factory:invitation.factory,account:invitation.account,participantToken:invitation.participantToken,bundleId:invitation.bundleId)
        try rejects("another network") {try node.checkInvitation(wrongNetwork)}
        let testKey=try P256.Signing.PrivateKey(rawRepresentation:word(2))
        let point=testKey.publicKey.x963Representation,deadline=UInt64(Date().timeIntervalSince1970)+300
        let digest=try PersonalAccountEncoding.handoffDigest(chainId:31337,account:invitation.account,generation:before,newPoint:point,deadline:deadline)
        let signature=try testKey.signature(for:RawDigest(data:digest)).rawRepresentation
        let kid=try bytes32(args[2])
        let request=Request(action:3,category:node.cfg.category,owner:"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",session:word(1),nonce:987654,deadline:deadline,scope:zero32,x:word(1),y:word(2),envelope:digest)
        let forged=UpgradeRequest(invitation:invitation,newPoint:point,generation:before,deadline:deadline,newSignature:signature,newKeyId:kid,receiptRequest:request,receiptTransaction:"0x"+String(repeating:"00",count:32))
        // A perfectly valid new-key signature must not substitute for an
        // attested, admitted independent app bound to the handoff context.
        try rejects("superseded") {_=try node.validateUpgrade(forged)}
        let team=try node.verifiedTeam(keyId:kid)
        try rejects("own Apple Developer team") {try node.requireIndependentTeam(team)}
        let broken=UpgradeRequest(invitation:invitation,newPoint:point,generation:before,deadline:deadline,newSignature:Data(repeating:0,count:64),newKeyId:kid,receiptRequest:request,receiptTransaction:forged.receiptTransaction)
        try rejects("new app key signature") {_=try node.validateUpgrade(broken)}
        try need(try smallWord(node.chain.call("generation()",to:invitation.account))==before,"negative tests changed account control")
        print("Upgrade invitation export passed; wrong network, unbound assertion, publisher team, and invalid new-key signature rejected; account control unchanged")
        print(String(decoding:try JSONEncoder().encode(invitation),as:UTF8.self))
    }
}
