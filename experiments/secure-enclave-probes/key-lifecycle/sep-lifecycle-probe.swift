import Foundation
import CryptoKit
import Security

func keychainCount() -> Int {
    var result: CFTypeRef?
    let query: [String: Any] = [kSecClass as String: kSecClassKey,
        kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnAttributes as String: true]
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return 0 }
    guard status == errSecSuccess, let attrs = result as? [[String: Any]] else { return -1 }
    return attrs.count
}
func say(_ key: String, _ value: Any) { print("\(key)=\(value)") }
func derive(_ key: SecureEnclave.P256.KeyAgreement.PrivateKey, _ pub: P256.KeyAgreement.PublicKey) throws -> SymmetricKey {
    try key.sharedSecretFromKeyAgreement(with: pub).hkdfDerivedSymmetricKey(
        using: SHA256.self, salt: Data("synthetic-lifecycle".utf8),
        sharedInfo: Data("receiving-test-v1".utf8), outputByteCount: 32)
}
let mode = CommandLine.arguments[1]
let directory = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
let before = keychainCount()
say("keychain_keys_before", before)
say("pid", ProcessInfo.processInfo.processIdentifier)
do {
    if mode == "capture" || mode == "memory-only" {
        let receiver = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        let sender = P256.KeyAgreement.PrivateKey()
        let secret = try derive(receiver, sender.publicKey)
        let plaintext = Data("ONLY SYNTHETIC LIFECYCLE CANARY".utf8)
        let sealed = try AES.GCM.seal(plaintext, using: secret)
        guard let combined = sealed.combined else { throw NSError(domain: "missing envelope", code: 1) }
        let record: [String: String] = [
            "sender": sender.publicKey.x963Representation.base64EncodedString(),
            "receiver": receiver.publicKey.x963Representation.base64EncodedString(),
            "envelope": combined.base64EncodedString()]
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]).write(to: directory.appendingPathComponent("envelope.json"))
        if mode == "capture" {
            let blob = receiver.dataRepresentation
            let target = directory.appendingPathComponent("wrapped.blob")
            try blob.write(to: target)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
            say("wrapped_blob_bytes", blob.count)
        }
        say("saved_recoverable_capability", mode == "capture")
        say("local_synthetic_decrypt", try AES.GCM.open(sealed, using: secret) == plaintext)
    } else if mode == "restore" {
        let record = try JSONSerialization.jsonObject(with: Data(contentsOf: directory.appendingPathComponent("envelope.json"))) as! [String: String]
        let receiver = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Data(contentsOf: directory.appendingPathComponent("wrapped.blob")))
        let sender = try P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: record["sender"]!)!)
        let secret = try derive(receiver, sender)
        let combined = Data(base64Encoded: record["envelope"]!)!
        let sealed = try AES.GCM.SealedBox(combined: combined)
        say("same_receiving_public_key", receiver.publicKey.x963Representation.base64EncodedString() == record["receiver"]!)
        say("post_exit_synthetic_decrypt", try AES.GCM.open(sealed, using: secret) == Data("ONLY SYNTHETIC LIFECYCLE CANARY".utf8))
        let wrong = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        do { _ = try AES.GCM.open(sealed, using: derive(wrong, sender)); say("wrong_key_rejected", false); exit(2) }
        catch { say("wrong_key_rejected", true) }
        var corrupt = combined
        corrupt[corrupt.count - 1] ^= 1
        do { _ = try AES.GCM.open(AES.GCM.SealedBox(combined: corrupt), using: secret); say("tamper_rejected", false); exit(2) }
        catch { say("tamper_rejected", true) }
    } else { throw NSError(domain: "unknown mode", code: 1) }
    let after = keychainCount()
    say("keychain_keys_after", after)
    say("keychain_count_unchanged", before >= 0 && after == before)
} catch {
    say("probe_failed", String(describing: error))
    exit(1)
}
