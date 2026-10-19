import Foundation
import CryptoKit
import Security
import Darwin

enum ProbeError: Error { case invalidArguments, unavailable, unsafeDirectory, existingState, missingState, controlsFailed }
func hex<D: Sequence>(_ bytes: D) -> String where D.Element == UInt8 { bytes.map { String(format: "%02x", $0) }.joined() }
func require(_ condition: Bool) throws { if !condition { throw ProbeError.controlsFailed } }

// The state directory (second argument) is the only state/output destination.
let root = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
let blobURL = root.appendingPathComponent("wrapped-key.bin")
let initialPublicURL = root.appendingPathComponent("initial-public.bin")

func writePrivate(_ data: Data, to url: URL) throws {
    try data.write(to: url, options: [.atomic])
    guard chmod(url.path, 0o600) == 0 else { throw ProbeError.unsafeDirectory }
}

func run() throws {
    guard CommandLine.arguments.count == 3, ["create", "reopen", "sign-input"].contains(CommandLine.arguments[1]) else { throw ProbeError.invalidArguments }
    let phase = CommandLine.arguments[1]
    #if VARIANT_B
    print("callerVariant=B")
    #else
    print("callerVariant=A")
    #endif
    let attrs = try FileManager.default.attributesOfItem(atPath: root.path)
    guard attrs[.type] as? FileAttributeType == .typeDirectory,
          (attrs[.posixPermissions] as? NSNumber)?.intValue == 0o700,
          (attrs[.ownerAccountID] as? NSNumber)?.uint32Value == getuid() else { throw ProbeError.unsafeDirectory }
    guard SecureEnclave.isAvailable else { throw ProbeError.unavailable }
    let key: SecureEnclave.P256.Signing.PrivateKey
    if phase == "create" {
        guard !FileManager.default.fileExists(atPath: blobURL.path),
              !FileManager.default.fileExists(atPath: initialPublicURL.path) else { throw ProbeError.existingState }
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                         [.privateKeyUsage], &accessError) else {
            throw accessError!.takeRetainedValue() as Error
        }
        key = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: access)
        // Opaque device-bound wrapped representation, never printed or exported.
        try writePrivate(key.dataRepresentation, to: blobURL)
        try writePrivate(key.publicKey.x963Representation, to: initialPublicURL)
    } else {
        let blobAttrs = try FileManager.default.attributesOfItem(atPath: blobURL.path)
        guard (blobAttrs[.posixPermissions] as? NSNumber)?.intValue == 0o600 else { throw ProbeError.unsafeDirectory }
        key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(contentsOf: blobURL))
    }
    let point = key.publicKey.x963Representation
    try require(point.count == 65 && point.first == 4)
    try require(point == Data(contentsOf: initialPublicURL))
    let wrongPublic = P256.Signing.PrivateKey().publicKey // Synthetic control only; no scalar serialization.
    if phase == "sign-input" {
        let hash32 = try Data(contentsOf: root.appendingPathComponent("contract-hash32.bin"))
        try require(hash32.count == 32)
        // Intentionally select Data overload. Contract verifies SHA256(input hash32),
        // even when input hash32 is an EIP-191/Keccak digest. This is not EOA signing.
        let signature = try key.signature(for: hash32)
        let actualDigest = SHA256.hash(data: hash32)
        var tamperedInput = hash32
        tamperedInput[0] ^= 1
        let controls: [String: Bool] = [
            "validInputDataOverload": key.publicKey.isValidSignature(signature, for: hash32),
            "validActualDigest": key.publicKey.isValidSignature(signature, for: actualDigest),
            "rejectTamperedInput": !key.publicKey.isValidSignature(signature, for: tamperedInput),
            "rejectWrongKey": !wrongPublic.isValidSignature(signature, for: actualDigest)
        ]
        try require(controls.values.allSatisfy { $0 })
        let result: [String: Any] = [
            "schema": "dsmack-sep-contract-signer-public-v1", "phase": phase,
            "samePersistedPublicKey": true, "secureEnclaveAvailable": true,
            "accessPolicy": "AfterFirstUnlockThisDeviceOnly + privateKeyUsage; no userPresence",
            "signingSemantics": "CryptoKit Data overload on exact32 input; ECDSA P-256 digest = SHA256(inputHash32); not EOA signing",
            "inputHash32": hex(hash32), "actualDigestSHA256": hex(actualDigest),
            "publicKeyX963": hex(point), "qx": hex(point.dropFirst().prefix(32)), "qy": hex(point.suffix(32)),
            "signatureDER": hex(signature.derRepresentation), "signatureRawRS": hex(signature.rawRepresentation),
            "r": hex(signature.rawRepresentation.prefix(32)), "s": hex(signature.rawRepresentation.suffix(32)),
            "controls": controls
        ]
        let json = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
        try writePrivate(json, to: root.appendingPathComponent("public-sign-input.json"))
        print("phase=sign-input vectors=1 controls=pass samePersistedPublicKey=true")
        return
    }
    let fixtures = [
        ("login", "login.example.invalid", """
login.example.invalid wants you to sign in with your Ethereum account:
0x1111111111111111111111111111111111111111

Synthetic SEP signer test only.

URI: https://login.example.invalid/session
Version: 1
Chain ID: 31337
Nonce: SepProbe20261011
Issued At: 2026-10-11T00:00:00Z
Expiration Time: 2099-01-01T00:00:00Z
"""),
        ("bounded-session-fixture", "auction.example.invalid", """
Synthetic session grant fixture v1
Domain: auction.example.invalid
Chain: 31337
Wallet: 0x1111111111111111111111111111111111111111
Session public key: synthetic-session-key-0001
Scope: auction:submit-bid
Maximum synthetic value: 100
Expires: 2026-10-11T00:05:00Z
Nonce: SessionProbe20261011
""")
    ]
    var vectors: [[String: Any]] = []
    for (id, domain, message) in fixtures {
        let bytes = Data(message.utf8)
        let digest = SHA256.hash(data: bytes)
        // Digest overload: ECDSA signs this exact SHA-256 digest, without hashing it again.
        let signature = try key.signature(for: digest)
        let derRoundTrip = try P256.Signing.ECDSASignature(derRepresentation: signature.derRepresentation)
        let changedBytes = Data(message.replacingOccurrences(of: domain, with: "wrong.example.invalid").utf8)
        let changedDigest = SHA256.hash(data: changedBytes)
        var changedSignature = signature.rawRepresentation
        changedSignature[changedSignature.count - 1] ^= 1
        let parsedTamper = try? P256.Signing.ECDSASignature(rawRepresentation: changedSignature)
        let controls: [String: Bool] = [
            "validDigest": key.publicKey.isValidSignature(signature, for: digest),
            "validMessageDataOverload": key.publicKey.isValidSignature(signature, for: bytes),
            "validDERRoundTrip": key.publicKey.isValidSignature(derRoundTrip, for: digest),
            "rejectWrongDomain": !key.publicKey.isValidSignature(signature, for: changedDigest),
            "rejectWrongKey": !wrongPublic.isValidSignature(signature, for: digest),
            "rejectDoubleHash": !key.publicKey.isValidSignature(signature, for: SHA256.hash(data: Data(digest))),
            "rejectSignatureTamper": parsedTamper.map { !key.publicKey.isValidSignature($0, for: digest) } ?? true
        ]
        try require(controls.values.allSatisfy { $0 })
        vectors.append(["id": id, "domain": domain, "messageUTF8": message, "messageHex": hex(bytes),
                        "digestSHA256": hex(digest), "signatureDER": hex(signature.derRepresentation),
                        "signatureRawRS": hex(signature.rawRepresentation),
                        "r": hex(signature.rawRepresentation.prefix(32)), "s": hex(signature.rawRepresentation.suffix(32)),
                        "wrongDomainDigestSHA256": hex(changedDigest), "tamperedSignatureRawRS": hex(changedSignature),
                        "controls": controls])
    }
    let wrongPoint = wrongPublic.x963Representation
    let result: [String: Any] = [
        "schema": "dsmack-sep-signer-public-v1", "phase": phase,
        "secureEnclaveAvailable": true, "samePersistedPublicKey": true,
        "accessPolicy": "AfterFirstUnlockThisDeviceOnly + privateKeyUsage; no userPresence",
        "signingSemantics": "ECDSA P-256 over SHA256(exact UTF8 message bytes); CryptoKit Digest overload; no EIP-191 prefix",
        "publicKeyX963": hex(point), "qx": hex(point.dropFirst().prefix(32)), "qy": hex(point.suffix(32)),
        "wrongPublicQx": hex(wrongPoint.dropFirst().prefix(32)), "wrongPublicQy": hex(wrongPoint.suffix(32)),
        "vectors": vectors
    ]
    let json = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
    try writePrivate(json, to: root.appendingPathComponent("public-\(phase).json"))
    print("phase=\(phase) vectors=\(vectors.count) controls=pass samePersistedPublicKey=true")
}

do { try run() } catch {
    // Deliberately omit error object descriptions which might include sensitive provider state.
    fputs("SEP signer probe failed\n", stderr)
    exit(1)
}
