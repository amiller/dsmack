import Foundation
import DeviceCheck
import CryptoKit
import Security

// Disposable experiment only. The persistent and volatile paths are different
// compiled executables; volatile builds contain no Keychain storage path.
let args = CommandLine.arguments
guard args.count == 3 else { exit(64) }
let out = URL(fileURLWithPath: args[1], isDirectory: true)
let config = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: args[2]))) as! [String: String]
try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
func save(_ name: String, _ data: Data) throws { try data.write(to: out.appendingPathComponent(name), options: .atomic) }
func json(_ name: String, _ value: [String: Any]) throws {
    try save(name, JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]))
}
func die(_ reason: String) -> Never {
    try? json("error.json", ["reason": reason]); exit(1)
}
func attest(_ fields: [String: String]) throws {
    let clientData = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
    try save("clientData.bin", clientData)
    let service = DCAppAttestService.shared
    guard service.isSupported else { die("App Attest unsupported") }
    let semaphore = DispatchSemaphore(value: 0)
    var keyID = ""
    service.generateKey { key, error in
        guard let key = key, error == nil else { die("generateKey: \(String(describing: error))") }
        keyID = key; semaphore.signal()
    }
    guard semaphore.wait(timeout: .now() + 45) == .success else { die("generateKey timeout") }
    try save("keyId.txt", Data(keyID.utf8))
    service.attestKey(keyID, clientDataHash: Data(SHA256.hash(data: clientData))) { data, error in
        guard let data = data, error == nil else { die("attestKey: \(String(describing: error))") }
        do { try save("attestation.cbor", data) } catch { die("save attestation") }
        semaphore.signal()
    }
    guard semaphore.wait(timeout: .now() + 90) == .success else { die("attestKey timeout") }
    try save("ready.txt", Data("ready".utf8))
}
#if MODIFIED
let variant = "modified"
#else
let variant = "honest"
#endif
try json("runtime.json", ["variant": variant, "pid": ProcessInfo.processInfo.processIdentifier,
    "os": ProcessInfo.processInfo.operatingSystemVersionString])

#if PERSISTENT
let serviceName = "dev.dsmack.custody-experiment.20260916"
guard let account = config["account"], account.hasPrefix("custody-test-") else { die("invalid test account") }
var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: serviceName, kSecAttrAccount as String: account,
    kSecUseDataProtectionKeychain as String: true]
let key: P256.Signing.PrivateKey
if config["mode"] == "store" {
    key = P256.Signing.PrivateKey()
    var add = query
    add[kSecValueData as String] = key.rawRepresentation
    add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else { die("SecItemAdd: \(status)") }
} else if config["mode"] == "read" {
    query[kSecReturnData as String] = true
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let data = result as? Data else { die("SecItemCopyMatching: \(status)") }
    key = try P256.Signing.PrivateKey(rawRepresentation: data)
} else { die("invalid persistent mode") }
let aes = SymmetricKey(data: SHA256.hash(data: key.rawRepresentation))
let plaintext: Data
if config["mode"] == "store" {
    plaintext = Data("synthetic persistent ciphertext custody test".utf8)
    let sealed = try AES.GCM.seal(plaintext, using: aes)
    try save("sealed.bin", sealed.combined!)
} else {
    let ciphertext = try Data(contentsOf: URL(fileURLWithPath: config["ciphertext"]!))
    plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: ciphertext), using: aes)
}
let message = Data(config["nonce"]!.utf8)
try save("signature.der", key.signature(for: message).derRepresentation)
try save("publicKey.bin", key.publicKey.x963Representation)
try json("custody.json", ["keychain_mode": "data_protection", "mode": config["mode"]!,
    "public_key": key.publicKey.x963Representation.base64EncodedString(),
    "plaintext_sha256": Data(SHA256.hash(data: plaintext)).base64EncodedString()])
try attest(["protocol": "custody-persistent/v1", "session": config["session"]!,
    "nonce": config["nonce"]!, "public_key": key.publicKey.x963Representation.base64EncodedString()])
try save("done.txt", Data("complete".utf8))
#else
// This private key and any delivered category key are never serialized.
let ephemeral = P256.KeyAgreement.PrivateKey()
let session = config["session"]!
let fields = ["protocol": "custody-volatile/v1", "session": session,
    "nonce": config["nonce"]!, "ephemeral_public_key": ephemeral.publicKey.x963Representation.base64EncodedString()]
try attest(fields)
var category: P256.Signing.PrivateKey? = nil
for index in 1...2 {
    let parcelURL = out.appendingPathComponent("parcel-\(index).json")
    let stop = out.appendingPathComponent("stop.txt")
    let deadline = Date().addingTimeInterval(180)
    while !FileManager.default.fileExists(atPath: parcelURL.path) && !FileManager.default.fileExists(atPath: stop.path) {
        if Date() > deadline { die("parcel timeout") }
        Thread.sleep(forTimeInterval: 0.1)
    }
    if FileManager.default.fileExists(atPath: stop.path) { break }
    var stage = "parse_parcel"
    do {
        let parcel = try JSONSerialization.jsonObject(with: Data(contentsOf: parcelURL)) as! [String: String]
        stage = "network_signature"
        let authority = try P256.Signing.PublicKey(x963Representation: Data(base64Encoded: networkPublicKeyBase64)!)
        let signed = Data(("custody-parcel/v1." + parcel["sender_public_key"]! + "." + parcel["ciphertext"]! + "." + session).utf8)
        let authorization = try P256.Signing.ECDSASignature(derRepresentation: Data(base64Encoded: parcel["authorization"]!)!)
        guard authority.isValidSignature(authorization, for: signed) else { throw NSError(domain: "parcel_authority", code: 1) }
        stage = "transport_decryption"
        let sender = try P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: parcel["sender_public_key"]!)!)
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: sender)
        let transport = shared.hkdfDerivedSymmetricKey(using: SHA256.self,
            salt: Data(SHA256.hash(data: Data(config["nonce"]!.utf8))),
            sharedInfo: Data("custody-volatile/v1".utf8), outputByteCount: 32)
        let box = try AES.GCM.SealedBox(combined: Data(base64Encoded: parcel["ciphertext"]!)!)
        let raw = try AES.GCM.open(box, using: transport, authenticating: Data(session.utf8))
        stage = "category_key_import"
        category = try P256.Signing.PrivateKey(rawRepresentation: raw)
        stage = "stored_ciphertext_decryption"
        let stored = try Data(contentsOf: URL(fileURLWithPath: config["data_ciphertext"]!))
        let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: stored), using: SymmetricKey(data: SHA256.hash(data: raw)))
        let signature = try category!.signature(for: Data(config["nonce"]!.utf8))
        try json("result-\(index).json", ["accepted": true,
            "public_key": category!.publicKey.x963Representation.base64EncodedString(),
            "signature": signature.derRepresentation.base64EncodedString(),
            "plaintext_sha256": Data(SHA256.hash(data: plaintext)).base64EncodedString()])
    } catch {
        try json("result-\(index).json", ["accepted": false, "reason": "parcel_decryption_failed",
            "stage": stage, "error_domain": (error as NSError).domain, "error_code": (error as NSError).code,
            "category_key_present": category != nil])
    }
}
try save("done.txt", Data("complete".utf8))
#endif
