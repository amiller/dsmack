import Foundation
import CryptoKit

@main struct PersonalAccountVectors {
    static func main() throws {
        // Public test key 1; never saved in the Keychain or used by the app.
        let key=try P256.Signing.PrivateKey(rawRepresentation:word(1))
        let personal=PersonalAccountKey(key:key)
        let account="0x1111111111111111111111111111111111111111"
        let claim=word(777)
        let consent=try PersonalAccountEncoding.consentDigest(chainId:84532,account:account,generation:2,claim:claim)
        let signature=try personal.consent(chainId:84532,account:account,generation:2,claim:claim)
        try need(key.publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation:signature),for:RawDigest(data:consent)),"personal consent signature")
        let next=try P256.Signing.PrivateKey(rawRepresentation:word(2)).publicKey.x963Representation
        let handoff=try PersonalAccountEncoding.handoffDigest(chainId:84532,account:account,generation:2,newPoint:next,deadline:1800000000)
        let handoffSignature=try personal.handoff(chainId:84532,account:account,generation:2,newPoint:next,deadline:1800000000)
        try need(key.publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation:handoffSignature),for:RawDigest(data:handoff)),"personal handoff signature")
        try need(hex(consent)=="0x2df8f1c27b1e058d0efafdd5d5beb887d8c2650c854408996c4d04366d719f32","consent ABI vector")
        try need(hex(handoff)=="0xbcecee4309169ca1d70f98d8cf7d90c2497e0deb3d3552fcb572c54c66b39b52","handoff ABI vector")
        let result:[String:Any] = ["consentDigest":hex(consent),"handoffDigest":hex(handoff),"publicPoint":hex(personal.publicPoint),"signature":hex(signature),"handoffSignature":hex(handoffSignature)]
        print(String(decoding:try JSONSerialization.data(withJSONObject:result,options:[.sortedKeys]),as:UTF8.self))
    }
}
