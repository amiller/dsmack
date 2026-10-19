// Secure Enclave output-exposure contract probe (stock public CryptoKit APIs only).
//
// Corrected probe for secure-enclave-completion-20261010, superseding the
// secure-enclave-contract-20261010 spike after independent review:
//   * any stage error, unmet expectation, unknown mode, directory-creation
//     failure, precondition violation or cleanup failure exits NONZERO;
//   * "full" requires a fresh isolated run directory and refuses to overwrite
//     existing fixture files;
//   * cleanup prints success only after each removal is verified;
//   * the fixed HPKE internal-host-scheduling assertion is removed from
//     measured logs (API-level observation only);
//   * the ML-KEM foreign-ciphertext control compares the wrong-key
//     decapsulation against otherEnc.sharedSecret and proves a ciphertext
//     sealed under otherEnc.sharedSecret fails to open under wrongSecret;
//   * the Secure Enclave side ML-KEM secret is directly consumed via
//     withUnsafeBytes and only its byte COUNT is logged.
//
// Synthetic inputs only. Never prints secret/key byte values: only types,
// byte counts, fingerprints of public material, equality/verification
// outcomes, availability and error descriptions. No keychain access;
// persistence uses disposable task-local files only.
//
// Modes:
//   full    - run every stage, create disposable artifacts/ files (0600);
//             refuses if any fixture file already exists
//   reuse   - reconstruct Secure Enclave keys from persisted wrapped
//             dataRepresentation files and prove the same key was recovered
//   cleanup - remove the disposable artifacts created by "full"

import CryptoKit
import Foundation

// Aggregated failure tracking: the probe exits nonzero if anything failed.
final class ProbeVerifier {
    private(set) var failures: [String] = []
    var failed: Bool { !failures.isEmpty }

    func fail(_ reason: String) {
        failures.append(reason)
        line("probe_failure", reason)
    }
}
let verifier = ProbeVerifier()

func line(_ key: String, _ value: String) {
    print("\(key)=\(value)")
}

/// Log a boolean expectation. Unexpected outcomes record a failure.
func expect(_ key: String, _ ok: Bool, unexpected value: String, expected: String) {
    line(key, ok ? expected : value)
    line(key + "_expectation_passed", ok ? "true" : "false")
    if !ok { verifier.fail("expectation unmet: \(key)") }
}

let message = Data("dsmack-secure-enclave-completion-20261010 synthetic message".utf8)
let salt = Data("synthetic-salt-20261010".utf8)
let info = Data("synthetic-info-20261010".utf8)

let cwd = FileManager.default.currentDirectoryPath
let artDir = cwd + "/artifacts"
let fixtureNames = [
    "se-p256-signing-key.blob", "se-p256-signing-pub-x963.blob",
    "se-p256-ka-key.blob", "host-sim-peer-pub-x963.blob",
    "host-sim-ka-aead-sealed.bin",
    "se-mlkem768-key.blob", "host-sim-mlkem-encapsulated.bin",
    "host-sim-mlkem-aead-sealed.bin",
]
func fixturePath(_ name: String) -> String { artDir + "/" + name }
let signingBlob = fixturePath("se-p256-signing-key.blob")
let signingPub = fixturePath("se-p256-signing-pub-x963.blob")
let kaBlob = fixturePath("se-p256-ka-key.blob")
let kaPeerPub = fixturePath("host-sim-peer-pub-x963.blob")
let kaSealed = fixturePath("host-sim-ka-aead-sealed.bin")
let kemBlob = fixturePath("se-mlkem768-key.blob")
let kemEncapsulated = fixturePath("host-sim-mlkem-encapsulated.bin")
let kemSealed = fixturePath("host-sim-mlkem-aead-sealed.bin")

/// Create the file with restrictive permissions from the start (no 0644 window).
func writeRestricted(_ data: Data, _ path: String) throws {
    let ok = FileManager.default.createFile(
        atPath: path, contents: data,
        attributes: [.posixPermissions: 0o600])
    guard ok else { throw NSError(domain: "se-probe", code: 3,
                                  userInfo: [NSLocalizedDescriptionKey: "createFile failed: \(path)"]) }
}

func readBlob(_ path: String) throws -> Data {
    try Data(contentsOf: URL(fileURLWithPath: path))
}

/// A stage error is recorded and fails the run; execution continues so all
/// stages still report, but the process exit code is nonzero.
func stage(_ name: String, _ body: () throws -> Void) {
    do {
        try body()
    } catch {
        verifier.fail("stage \(name) error: \(type(of: error)): \(error)")
    }
}

// MARK: - Stage 1: SecureEnclave.P256.Signing

func stageP256Signing() {
    stage("se_p256_signing") {
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        line("se_p256_signing_datarep_bytes", String(key.dataRepresentation.count))
        line("se_p256_signing_pub_x963_bytes", String(key.publicKey.x963Representation.count))
        let sig = try key.signature(for: message)
        line("se_p256_signature_der_bytes", String(sig.derRepresentation.count))
        line("se_p256_host_verify_positive",
             key.publicKey.isValidSignature(sig, for: message) ? "true" : "false")
        expect("se_p256_host_verify_positive_check",
               key.publicKey.isValidSignature(sig, for: message),
               unexpected: "false", expected: "true")
        let tampered = Data("tampered synthetic message".utf8)
        expect("se_p256_host_verify_negative_tampered",
               !key.publicKey.isValidSignature(sig, for: tampered),
               unexpected: "false", expected: "true")
        try writeRestricted(key.dataRepresentation, signingBlob)
        try writeRestricted(key.publicKey.x963Representation, signingPub)
        line("se_p256_signing_persisted", "artifacts/se-p256-signing-key.blob+pub (0600, created 0600)")
    }
}

// MARK: - Stage 2: SecureEnclave.P256.KeyAgreement ECDH, software peer = host simulation

func stageP256KeyAgreement() {
    stage("se_p256_ka") {
        let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        line("se_p256_ka_datarep_bytes", String(seKey.dataRepresentation.count))
        // HOST SIMULATION peer: a normal software CryptoKit key in the same
        // process standing in for a second device. One mini cannot prove a
        // two-device enclave-to-enclave exchange.
        let hostSimPeer = P256.KeyAgreement.PrivateKey()
        line("host_sim_peer", "software P256.KeyAgreement.PrivateKey in-process")

        let secretSESide = try seKey.sharedSecretFromKeyAgreement(with: hostSimPeer.publicKey)
        let secretHostSide = try hostSimPeer.sharedSecretFromKeyAgreement(with: seKey.publicKey)
        line("ecdh_secret_type_se_side", String(describing: type(of: secretSESide)))
        // Proof the returned SharedSecret is host-readable memory, without
        // printing the bytes: the withUnsafeBytes body runs on the host CPU.
        line("ecdh_secret_host_readable_bytecount",
             String(secretSESide.withUnsafeBytes { $0.count }))

        let keySE = secretSESide.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
        let keyHost = secretHostSide.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
        expect("ecdh_hkdf_derived_keys_equal", keySE == keyHost,
               unexpected: "false", expected: "true")

        let otherInfo = secretSESide.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: Data("other".utf8), outputByteCount: 32)
        expect("ecdh_hkdf_other_info_differs", otherInfo != keySE,
               unexpected: "false", expected: "true")

        let secondPeer = P256.KeyAgreement.PrivateKey()
        let secondSecret = try hostSimPeer.sharedSecretFromKeyAgreement(with: secondPeer.publicKey)
        let secondKey = secondSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
        expect("ecdh_other_peer_differs", secondKey != keyHost,
               unexpected: "false", expected: "true")

        // Use control: the host-visible derived keys are usable symmetric keys.
        let sealed = try AES.GCM.seal(message, using: keySE)
        guard let combined = sealed.combined else { throw NSError(domain: "se-probe", code: 1) }
        let opened = try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: keyHost)
        expect("ecdh_aead_seal_se_open_host_roundtrip", opened == message,
               unexpected: "false", expected: "true")

        try writeRestricted(seKey.dataRepresentation, kaBlob)
        try writeRestricted(hostSimPeer.publicKey.x963Representation, kaPeerPub)
        try writeRestricted(combined, kaSealed)
        line("se_p256_ka_persisted", "artifacts/se-p256-ka-key.blob + peer pub + sealed (0600)")
    }
}

// MARK: - Stage 3: HPKE with the Secure Enclave key agreement key as recipient

func stageHPKE() {
    stage("se_hpke") {
        let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        var sender = try HPKE.Sender(
            recipientKey: seKey.publicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            info: info)
        var recipient = try HPKE.Recipient(
            privateKey: seKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            info: info,
            encapsulatedKey: sender.encapsulatedKey)
        line("hpke_encapsulated_key_bytes", String(sender.encapsulatedKey.count))
        let ciphertext = try sender.seal(message)
        let plaintext = try recipient.open(ciphertext)
        expect("hpke_se_recipient_open_roundtrip", plaintext == message,
               unexpected: "false", expected: "true")
        // API-level observation only: no HPKE API hands the KEM secret or the
        // schedule secret back to the caller; Recipient.open returns plaintext
        // to the calling host process. WHERE the key schedule executes is an
        // implementation question outside this probe (see README/report), and
        // is deliberately not asserted here.
        line("hpke_kem_secret_returned_by_api", "false (no public HPKE API returns it)")
        line("hpke_plaintext_returned_to_caller", "true (Recipient.open returns Data)")
    }
}

// MARK: - Stage 4/5: SecureEnclave ML-DSA / ML-KEM (gated on macOS 26)

func stageSEMLDSA() {
    stage("se_mldsa65") {
        guard #available(macOS 26.0, *) else {
            line("se_mldsa65_availability", "unavailable-below-macos-26")
            return
        }
        let key = try SecureEnclave.MLDSA65.PrivateKey()
        // NOT persisted: this stage measures sizes/sign/verify only. The three
        // persisted key kinds are P256 signing, P256 key agreement and MLKEM768.
        line("se_mldsa65_datarep_bytes", String(key.dataRepresentation.count))
        line("se_mldsa65_pub_raw_bytes", String(key.publicKey.rawRepresentation.count))
        let sig = try key.signature(for: message)
        line("se_mldsa65_signature_bytes", String(sig.count))
        expect("se_mldsa65_host_verify_positive",
               key.publicKey.isValidSignature(sig, for: message),
               unexpected: "false", expected: "true")
        let tampered = Data("tampered synthetic message".utf8)
        expect("se_mldsa65_host_verify_negative_tampered",
               !key.publicKey.isValidSignature(sig, for: tampered),
               unexpected: "false", expected: "true")
    }
}

func stageSEMLKEM() {
    stage("se_mlkem768") {
        guard #available(macOS 26.0, *) else {
            line("se_mlkem768_availability", "unavailable-below-macos-26")
            return
        }
        let seKey = try SecureEnclave.MLKEM768.PrivateKey.generate()
        line("se_mlkem768_datarep_bytes", String(seKey.dataRepresentation.count))
        line("se_mlkem768_pub_raw_bytes", String(seKey.publicKey.rawRepresentation.count))

        // HOST SIMULATION sender: encapsulation against the Secure Enclave
        // public key runs in software in this process.
        let enc = try seKey.publicKey.encapsulate()
        line("mlkem768_encapsulated_bytes", String(enc.encapsulated.count))
        line("mlkem_sender_secret_type", String(describing: type(of: enc.sharedSecret)))
        line("mlkem_sender_secret_host_readable_bytecount",
             String(enc.sharedSecret.withUnsafeBytes { $0.count }))

        let seSideSecret = try seKey.decapsulate(enc.encapsulated)
        line("se_mlkem_decapsulate_returns", String(describing: type(of: seSideSecret)))
        // Directly consume the Secure Enclave side decapsulation output and log
        // ONLY the byte count, never the bytes.
        line("se_mlkem_se_side_secret_host_readable_bytecount",
             String(seSideSecret.withUnsafeBytes { $0.count }))
        expect("se_mlkem_secret_matches_host_sender", seSideSecret == enc.sharedSecret,
               unexpected: "false", expected: "true")

        // Negative control (corrected): decapsulating another key's ciphertext
        // with this key must NOT reproduce the secret that other key's sender
        // actually derived for that ciphertext (ML-KEM implicit rejection) ...
        let otherKey = try SecureEnclave.MLKEM768.PrivateKey.generate()
        let otherEnc = try otherKey.publicKey.encapsulate()
        let wrongSecret = try seKey.decapsulate(otherEnc.encapsulated)
        expect("se_mlkem_wrongsecret_equals_otherenc_sharedsecret",
               wrongSecret != otherEnc.sharedSecret,
               unexpected: "true", expected: "false")
        expect("se_mlkem_wrongsecret_equals_original_secret",
               wrongSecret != enc.sharedSecret,
               unexpected: "true", expected: "false")
        // ... and a ciphertext actually sealed under otherEnc.sharedSecret must
        // fail to open under wrongSecret (implicit rejection is a usable key
        // only for the correct key/ciphertext pair).
        let otherSealed = try AES.GCM.seal(message, using: otherEnc.sharedSecret)
        guard let otherCombined = otherSealed.combined else {
            throw NSError(domain: "se-probe", code: 4)
        }
        var openedUnderWrong = false
        if (try? AES.GCM.open(AES.GCM.SealedBox(combined: otherCombined), using: wrongSecret)) != nil {
            openedUnderWrong = true
        }
        expect("se_mlkem_otherenc_ciphertext_opens_under_wrongsecret",
               !openedUnderWrong,
               unexpected: "true", expected: "false")

        // Cross-process persistence fixture: seal a synthetic message with the
        // derived key so "reuse" mode can prove the wrapped dataRepresentation
        // reconstructs to the same Secure Enclave key without persisting any
        // secret key material itself.
        let sealed = try AES.GCM.seal(message, using: enc.sharedSecret)
        guard let combined = sealed.combined else { throw NSError(domain: "se-probe", code: 2) }
        try writeRestricted(seKey.dataRepresentation, kemBlob)
        try writeRestricted(enc.encapsulated, kemEncapsulated)
        try writeRestricted(combined, kemSealed)
        line("se_mlkem768_persisted", "artifacts/se-mlkem768-key.blob + encapsulated + sealed (0600)")
    }
}

// MARK: - Stage 6: wrapped-nature negative control

func stageWrappedNature() {
    stage("wrapped_nature") {
        // The SE dataRepresentation is a wrapped blob, not raw host key
        // material: host software key constructors must reject it. (Rejection
        // by a raw-key constructor is consistent with a wrapped blob; the
        // wrapping/encryption property itself is attributed to Apple
        // documentation, not proven here — see README.)
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        var hostAccepted = false
        do {
            _ = try P256.Signing.PrivateKey(rawRepresentation: key.dataRepresentation)
            hostAccepted = true
        } catch {}
        expect("se_p256_blob_accepted_as_host_software_key", !hostAccepted,
               unexpected: "true", expected: "false")
        if #available(macOS 26.0, *) {
            let kem = try SecureEnclave.MLKEM768.PrivateKey.generate()
            var kemAccepted = false
            do {
                _ = try MLKEM768.PrivateKey(
                    seedRepresentation: kem.dataRepresentation, publicKey: kem.publicKey)
                kemAccepted = true
            } catch {}
            expect("se_mlkem_blob_accepted_as_host_seed", !kemAccepted,
                   unexpected: "true", expected: "false")
        }
    }
}

// MARK: - Precondition: fresh isolated run directory for "full"

func requireFreshDirectory() -> Bool {
    let fm = FileManager.default
    var preexisting: [String] = []
    for name in fixtureNames {
        if fm.fileExists(atPath: fixturePath(name)) { preexisting.append(name) }
    }
    var dirOccupied = false
    if fm.fileExists(atPath: artDir) {
        if let contents = try? fm.contentsOfDirectory(atPath: artDir), !contents.isEmpty {
            dirOccupied = true
        }
    }
    if !preexisting.isEmpty || dirOccupied {
        verifier.fail("precondition: run directory not fresh (preexisting: \(preexisting.joined(separator: ",")) occupied=\(dirOccupied))")
        line("precondition_fresh_directory", "false")
        return false
    }
    line("precondition_fresh_directory", "true")
    return true
}

// MARK: - Reuse mode: cross-process reconstruction from wrapped dataRepresentation files

func modeReuse() {
    stage("reuse_p256_signing") {
        let blob = try readBlob(signingBlob)
        let pub = try readBlob(signingPub)
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        expect("reuse_signing_datarep_bytes_same", key.dataRepresentation.count == blob.count,
               unexpected: "false", expected: "true")
        let publicKey = try P256.Signing.PublicKey(x963Representation: pub)
        expect("reuse_signing_pub_matches",
               key.publicKey.x963Representation == publicKey.x963Representation,
               unexpected: "false", expected: "true")
        let sig = try key.signature(for: message)
        expect("reuse_signing_host_verify_positive",
               publicKey.isValidSignature(sig, for: message),
               unexpected: "false", expected: "true")
    }
    stage("reuse_p256_ka") {
        let blob = try readBlob(kaBlob)
        let peerPubData = try readBlob(kaPeerPub)
        let sealedData = try readBlob(kaSealed)
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
        let peerPub = try P256.KeyAgreement.PublicKey(x963Representation: peerPubData)
        let secret = try key.sharedSecretFromKeyAgreement(with: peerPub)
        let derived = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
        let opened = try AES.GCM.open(AES.GCM.SealedBox(combined: sealedData), using: derived)
        expect("reuse_ka_rederived_key_opens_original_ciphertext", opened == message,
               unexpected: "false", expected: "true")
    }
    stage("reuse_se_mlkem768") {
        guard #available(macOS 26.0, *) else {
            line("reuse_se_mlkem768_availability", "unavailable-below-macos-26")
            return
        }
        let blob = try readBlob(kemBlob)
        let encData = try readBlob(kemEncapsulated)
        let sealedData = try readBlob(kemSealed)
        let key = try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: blob)
        let secret = try key.decapsulate(encData)
        let opened = try AES.GCM.open(AES.GCM.SealedBox(combined: sealedData), using: secret)
        expect("reuse_mlkem_rederived_secret_opens_original_ciphertext", opened == message,
               unexpected: "false", expected: "true")
    }
}

// MARK: - Cleanup mode: remove only files this probe created, verifying removal

func modeCleanup() {
    let fm = FileManager.default
    var removed: [String] = []
    for name in fixtureNames {
        let path = fixturePath(name)
        if fm.fileExists(atPath: path) {
            do {
                try fm.removeItem(atPath: path)
            } catch {
                verifier.fail("cleanup: removeItem threw for \(name): \(error)")
                continue
            }
            // Honest cleanup: count it only if it is actually gone.
            if fm.fileExists(atPath: path) {
                verifier.fail("cleanup: \(name) still exists after removal")
            } else {
                removed.append(name)
            }
        }
    }
    line("cleanup_removed", removed.joined(separator: ","))
    // Remove the artifacts directory too when we emptied it; report the outcome.
    if fm.fileExists(atPath: artDir) {
        if let contents = try? fm.contentsOfDirectory(atPath: artDir), contents.isEmpty {
            if (try? fm.removeItem(atPath: artDir)) != nil, !fm.fileExists(atPath: artDir) {
                line("cleanup_artifacts_dir_removed", "true")
            } else {
                verifier.fail("cleanup: artifacts directory could not be removed")
                line("cleanup_artifacts_dir_removed", "false")
            }
        } else {
            line("cleanup_artifacts_dir_removed", "skipped (not empty)")
        }
    }
    line("cleanup_files_expected", String(fixtureNames.count))
    line("cleanup_files_removed_verified", String(removed.count))
    if removed.count != fixtureNames.count && removed.count > 0 {
        // Partial removal: some fixtures existed but could not all be removed.
        verifier.fail("cleanup: removed \(removed.count) of \(fixtureNames.count) expected fixtures")
    }
}

// MARK: - Main

@main
struct SEContractProbe {
    static func main() {
        let args = CommandLine.arguments
        let mode = args.count > 1 ? args[1] : "full"
        let os = ProcessInfo.processInfo.operatingSystemVersion
        line("probe_mode", mode)
        line("os_version", "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)")
        line("secure_enclave_is_available", SecureEnclave.isAvailable ? "true" : "false")
        if !SecureEnclave.isAvailable {
            verifier.fail("precondition: SecureEnclave not available")
        }

        switch mode {
        case "full":
            guard requireFreshDirectory() else { exit(2) }
            do {
                try FileManager.default.createDirectory(
                    atPath: artDir, withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700])
            } catch {
                verifier.fail("artifacts directory creation failed: \(error)")
                line("verdict", "FAIL (\(verifier.failures.count) failure(s))")
                exit(3)
            }
            guard FileManager.default.fileExists(atPath: artDir) else {
                verifier.fail("artifacts directory missing after creation")
                line("verdict", "FAIL (\(verifier.failures.count) failure(s))")
                exit(3)
            }
            stageP256Signing()
            stageP256KeyAgreement()
            stageHPKE()
            stageSEMLDSA()
            stageSEMLKEM()
            stageWrappedNature()
        case "reuse":
            modeReuse()
        case "cleanup":
            modeCleanup()
        default:
            verifier.fail("unknown mode \(mode)")
        }

        if verifier.failed {
            line("verdict", "FAIL (\(verifier.failures.count) failure(s))")
            exit(1)
        }
        line("verdict", "PASS")
    }
}
