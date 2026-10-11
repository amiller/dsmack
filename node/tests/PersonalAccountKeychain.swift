import Foundation
import CryptoKit
import Security

@main struct PersonalAccountKeychain {
    static func main() throws {
        // Random, test-only scope: never touches an existing participant key.
        var bytes=[UInt8](repeating:0,count:20)
        try need(SecRandomCopyBytes(kSecRandomDefault,bytes.count,&bytes)==errSecSuccess,"random test scope")
        let factory=hex(Data(bytes)), chainId:UInt64=31337
        let identity=hex(try keccak(word(chainId)+addressWord(factory)))
        let query:[String:Any]=[kSecClass as String:kSecClassGenericPassword,
            kSecAttrService as String:"dev.attestnode.personal-badge-key.v1",
            kSecAttrAccount as String:identity,kSecUseDataProtectionKeychain as String:true,
            kSecAttrSynchronizable as String:false]
        defer {SecItemDelete(query as CFDictionary)}
        let first=try PersonalAccountKey.loadOrCreate(chainId:chainId,factory:factory)
        let second=try PersonalAccountKey.loadOrCreate(chainId:chainId,factory:factory)
        try need(first.publicPoint==second.publicPoint,"Keychain did not preserve personal identity")
        let account="0x1111111111111111111111111111111111111111"
        let digest=try PersonalAccountEncoding.consentDigest(chainId:chainId,account:account,generation:0,claim:word(777))
        let signature=try second.consent(chainId:chainId,account:account,generation:0,claim:word(777))
        let publicKey=try P256.Signing.PublicKey(x963Representation:first.publicPoint)
        try need(publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation:signature),for:RawDigest(data:digest)),"restored key signature")
        try need(SecItemDelete(query as CFDictionary)==errSecSuccess,"temporary test key cleanup")
        print("Personal account Keychain create/reload/sign passed; temporary test entry removed")
    }
}
