import Foundation
import Security
let mode = CommandLine.arguments[1]
let root = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
let tag = Data(("dev.dsmack.synthetic.seckey-delete." + root.lastPathComponent).utf8)
var query: [String: Any] = [kSecClass as String: kSecClassKey,
    kSecAttrApplicationTag as String: tag, kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecUseDataProtectionKeychain as String: true]
func say(_ name: String, _ value: Any) { print("\(name)=\(value)") }
func lookup() -> SecKey? {
    var q = query; q[kSecReturnRef as String] = true
    var item: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &item)
    say("lookup_status", status)
    if status != errSecSuccess { return nil }
    return (item as! SecKey)
}
func operation(_ key: SecKey, _ name: String) -> Bool {
    var error: Unmanaged<CFError>?
    let message = Data("synthetic deletion control".utf8)
    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error) else {
        say(name, false); say(name + "_error", error?.takeRetainedValue().localizedDescription ?? "unknown"); return false
    }
    var pub = SecKeyCopyPublicKey(key)!
    if let captured = try? Data(contentsOf: root.appendingPathComponent("original-public.bin")) {
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits as String: 256]
        pub = SecKeyCreateWithData(captured as CFData, attrs as CFDictionary, &error)!
        let current = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!, &error)! as Data
        say(name + "_matches_original_public", current == captured)
        if current != captured { return false }
    }
    let verified = SecKeyVerifySignature(pub, .ecdsaSignatureMessageX962SHA256, message as CFData, signature, &error)
    let wrongAttrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256, kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]]
    let wrongPrivate = SecKeyCreateRandomKey(wrongAttrs as CFDictionary, &error)!
    let wrongVerified = SecKeyVerifySignature(SecKeyCopyPublicKey(wrongPrivate)!, .ecdsaSignatureMessageX962SHA256, message as CFData, signature, &error)
    say(name + "_wrong_public_rejected", !wrongVerified)
    let tamper = SecKeyVerifySignature(pub, .ecdsaSignatureMessageX962SHA256, Data("wrong message".utf8) as CFData, signature, &error)
    say(name + "_wrong_message_rejected", !tamper)
    say(name, verified); return verified
}
say("pid", ProcessInfo.processInfo.processIdentifier)
do {
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    if mode == "create" || mode == "transient" {
        var error: Unmanaged<CFError>?
        let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error)!
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256, kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: mode == "create",
                kSecAttrApplicationTag as String: tag, kSecAttrAccessControl as String: acl]]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue()
        }
        let pub = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!, &error)! as Data
        try pub.write(to: root.appendingPathComponent("original-public.bin"))
        guard operation(key, "creation_operation_verified") else { exit(2) }
        let exported = SecKeyCopyExternalRepresentation(key, &error)
        say("private_external_export_supported", exported != nil)
        say("attributes_key_names", (SecKeyCopyAttributes(key) as? [String: Any])?.keys.sorted() ?? [])
        if var copied = SecKeyCopyAttributes(key) as? [String: Any] {
            copied.removeValue(forKey: kSecAttrAccessControl as String)
            let encoded = try PropertyListSerialization.data(fromPropertyList: copied, format: .binary, options: 0)
            try encoded.write(to: root.appendingPathComponent("captured-token-attributes.plist"))
            say("captured_token_attributes_bytes", encoded.count)
        }
        var q = query; q[kSecReturnPersistentRef as String] = true
        var ref: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &ref)
        say("persistent_ref_status", status)
        if status == errSecSuccess, let data = ref as? Data {
            try data.write(to: root.appendingPathComponent("persistent-ref.bin"))
            say("persistent_ref_bytes", data.count)
        }
        if mode == "transient" { say("transient_lookup_absent", lookup() == nil) }
    } else if mode == "hold" {
        guard let key = lookup(), operation(key, "predelete_operation_verified") else { exit(2) }
        try Data("ready".utf8).write(to: root.appendingPathComponent("holder-ready"))
        let deadline = Date().addingTimeInterval(45)
        while !FileManager.default.fileExists(atPath: root.appendingPathComponent("delete-done").path) && Date() < deadline { Thread.sleep(forTimeInterval: 0.1) }
        guard FileManager.default.fileExists(atPath: root.appendingPathComponent("delete-done").path) else { exit(3) }
        _ = operation(key, "retained_postdelete_operation_verified")
        say("postdelete_lookup_absent", lookup() == nil)
    } else if mode == "delete" {
        let status = SecItemDelete(query as CFDictionary)
        say("unique_synthetic_delete_status", status)
        guard status == errSecSuccess else { exit(2) }
        try Data("deleted".utf8).write(to: root.appendingPathComponent("delete-done"))
    } else if mode == "tokenrestore" {
        let data = try Data(contentsOf: root.appendingPathComponent("captured-token-attributes.plist"))
        let attrs = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as! [String: Any]
        var error: Unmanaged<CFError>?
        if let key = SecKeyCreateWithData(Data() as CFData, attrs as CFDictionary, &error) {
            say("copied_token_attributes_reconstruct", true)
            _ = operation(key, "copied_token_post_exit_operation_verified")
        } else {
            say("copied_token_attributes_reconstruct", false)
            say("reconstruct_error", error?.takeRetainedValue().localizedDescription ?? "unknown")
        }
    } else if mode == "reopen" {
        say("post_exit_lookup_absent", lookup() == nil)
        let ref = try Data(contentsOf: root.appendingPathComponent("persistent-ref.bin"))
        let q: [String: Any] = [kSecValuePersistentRef as String: ref,
            kSecReturnRef as String: true, kSecUseDataProtectionKeychain as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        say("captured_persistent_ref_reopen_status", status)
        if status == errSecSuccess { _ = operation(item as! SecKey, "persistent_ref_operation_verified") }
    } else { exit(4) }
} catch { say("fatal_error", String(describing: error)); exit(1) }
