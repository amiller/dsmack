import Foundation
import CryptoKit
import Security

/// Personal badge control is deliberately separate from the shared faucet key.
/// The private key is saved only in this signed app's local Keychain access group.
final class PersonalAccountKey {
    private let key: P256.Signing.PrivateKey
    init(key: P256.Signing.PrivateKey) { self.key=key }
    var publicPoint: Data { key.publicKey.x963Representation }

    static func loadOrCreate(chainId: UInt64, factory: String) throws -> PersonalAccountKey {
        let identity=hex(try keccak(word(chainId)+addressWord(factory)))
        let query: [String:Any] = [kSecClass as String:kSecClassGenericPassword,
            kSecAttrService as String:"dev.attestnode.personal-badge-key.v1",
            kSecAttrAccount as String:identity,
            kSecUseDataProtectionKeychain as String:true,
            kSecAttrSynchronizable as String:false]
        func read() throws -> P256.Signing.PrivateKey? {
            var lookup=query;lookup[kSecReturnData as String]=true;lookup[kSecMatchLimit as String]=kSecMatchLimitOne
            var item:CFTypeRef?;let status=SecItemCopyMatching(lookup as CFDictionary,&item)
            if status == errSecItemNotFound {return nil}
            try need(status == errSecSuccess,"Personal account Keychain unavailable (\(status)); existing identity was not replaced")
            guard let data=item as? Data else {throw DemoError.invalid("Personal account Keychain data")}
            return try P256.Signing.PrivateKey(rawRepresentation:data)
        }
        if let key=try read() {return PersonalAccountKey(key:key)}
        let generated=P256.Signing.PrivateKey()
        var item=query;item[kSecValueData as String]=generated.rawRepresentation
        item[kSecAttrAccessible as String]=kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status=SecItemAdd(item as CFDictionary,nil)
        if status == errSecDuplicateItem, let existing=try read() {return PersonalAccountKey(key:existing)}
        try need(status == errSecSuccess,"Could not save personal account Keychain identity (\(status))")
        return PersonalAccountKey(key:generated)
    }
    func consent(chainId: UInt64,account: String,generation: UInt64,claim: Data) throws -> Data {
        let digest=try PersonalAccountEncoding.consentDigest(chainId:chainId,account:account,generation:generation,claim:claim)
        return try key.signature(for:RawDigest(data:digest)).rawRepresentation
    }
    func handoff(chainId: UInt64,account: String,generation: UInt64,newPoint: Data,deadline: UInt64) throws -> Data {
        let digest=try PersonalAccountEncoding.handoffDigest(chainId:chainId,account:account,generation:generation,newPoint:newPoint,deadline:deadline)
        return try key.signature(for:RawDigest(data:digest)).rawRepresentation
    }
}

enum PersonalAccountEncoding {
    static func consentDigest(chainId: UInt64,account: String,generation: UInt64,claim: Data) throws -> Data {
        try need(claim.count==32,"claim digest width")
        let payload=try keccak(Data("ATTEST_PERSONAL_CONSENT_V1".utf8))+word(chainId)+addressWord(account)+word(generation)+claim
        return Data(SHA256.hash(data:payload))
    }
    static func handoffDigest(chainId: UInt64,account: String,generation: UInt64,newPoint: Data,deadline: UInt64) throws -> Data {
        try need(newPoint.count==65 && newPoint.first==4,"personal public key encoding")
        _=try P256.Signing.PublicKey(x963Representation:newPoint)
        let payload=try keccak(Data("ATTEST_PERSONAL_HANDOFF_V1".utf8))+word(chainId)+addressWord(account)+word(generation)+newPoint.dropFirst()+word(deadline)
        return Data(SHA256.hash(data:payload))
    }
}
