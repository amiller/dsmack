// Security.framework SecKey key-exchange/ECIES output-contract probe.
//
// Bounded experiment for secure-enclave-completion-20261010. The prior spike
// enumerated the CryptoKit surface only; independent review left
// Security.framework coverage open. This probe exercises the DOCUMENTED
// PUBLIC SecKey key-agreement APIs and records where their outputs land:
//   * SecKeyCopyKeyExchangeResult (ECDH + KDF)  -> returns CFData bytes
//   * SecKeyCreateEncryptedData / SecKeyCreateDecryptedData (ECIES)
//        -> decrypt returns PLAINTEXT to the caller
//
// Keys are FRESH, TEMPORARY and NONPERSISTENT: created in memory with
// SecKeyCreateRandomKey (no kSecAttrIsPersistent, no keychain add, no real
// or pre-existing items). The pinned Apple Security source
// (SecKeyAdaptors.c SecKeyECDHCopyX963Result / SecKeyECIESCopyDecryptedData,
// revision db15acbe) shows these adaptors run the KDF and AEAD in host
// process memory over host CFData buffers; this probe records the runtime
// API-level outputs that the source predicts. No private SPI is invoked.
//
// Logs only byte counts, booleans, algorithm names and error descriptions.
// Mode: full (single mode).

import Foundation
import Security

final class ProbeVerifier {
    private(set) var failures: [String] = []
    var failed: Bool { !failures.isEmpty }
    func fail(_ reason: String) {
        print("probe_failure=\(reason)")
        failures.append(reason)
    }
}
let verifier = ProbeVerifier()

func line(_ key: String, _ value: String) {
    print("\(key)=\(value)")
}

func expect(_ key: String, _ ok: Bool, unexpected value: String, expected: String) {
    line(key, ok ? expected : value)
    line(key + "_expectation_passed", ok ? "true" : "false")
    if !ok { verifier.fail("expectation unmet: \(key)") }
}

let message = Data("dsmack-seckey-ecies-probe-20261010 synthetic payload".utf8)

/// Fresh in-memory P-256 key pair, never added to any keychain.
func makeNonpersistentKey() throws -> SecKey {
    var error: Unmanaged<CFError>?
    let params: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
    ]
    guard let key = SecKeyCreateRandomKey(params as CFDictionary, &error) else {
        throw error?.takeRetainedValue() ?? NSError(domain: "seckey-probe", code: 1)
    }
    return key
}

@main
struct SecKeyECIESProbe {
    static func main() {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        line("probe_mode", "full")
        line("os_version", "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)")
        line("keys", "fresh temporary NONPERSISTENT SecKeyCreateRandomKey pairs; no keychain use")

        do {
            // Two independent in-memory identities (host-simulated peers).
            let alice = try makeNonpersistentKey()
            let bob = try makeNonpersistentKey()
            guard let alicePub = SecKeyCopyPublicKey(alice),
                  let bobPub = SecKeyCopyPublicKey(bob) else {
                throw NSError(domain: "seckey-probe", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "SecKeyCopyPublicKey failed"])
            }

            // --- SecKeyCopyKeyExchangeResult: documented public ECDH+KDF ---
            var keError: Unmanaged<CFError>?
            let keParams: [CFString: Any] = [
                SecKeyKeyExchangeParameter.requestedSize.rawValue: 32,
                SecKeyKeyExchangeParameter.sharedInfo.rawValue: Data("synthetic-shared-info-20261010".utf8),
            ]
            guard let aliceDerived = SecKeyCopyKeyExchangeResult(
                alice, SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256, bobPub,
                keParams as CFDictionary, &keError) else {
                throw keError?.takeRetainedValue() ?? NSError(domain: "seckey-probe", code: 3)
            }
            guard let bobDerived = SecKeyCopyKeyExchangeResult(
                bob, SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256, alicePub,
                keParams as CFDictionary, &keError) else {
                throw keError?.takeRetainedValue() ?? NSError(domain: "seckey-probe", code: 3)
            }
            line("seckey_keyexchange_returns", "CFData")
            line("seckey_keyexchange_derived_bytes_host_readable_count",
                 String(CFDataGetLength(aliceDerived)))
            let equal = CFEqual(aliceDerived, bobDerived)
            expect("seckey_keyexchange_both_sides_equal", equal,
                   unexpected: "false", expected: "true")
            // The return type IS host bytes: this is a raw pointer into this
            // process's memory, counted above without printing contents.
            _ = CFDataGetBytePtr(aliceDerived)

            // --- ECIES roundtrip: documented public encrypt/decrypt ---
            var encError: Unmanaged<CFError>?
            guard let encrypted = SecKeyCreateEncryptedData(
                bobPub, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                message as CFData, &encError) else {
                throw encError?.takeRetainedValue() ?? NSError(domain: "seckey-probe", code: 4)
            }
            line("seckey_ecies_encrypted_bytes", String(CFDataGetLength(encrypted)))

            var decError: Unmanaged<CFError>?
            guard let decrypted = SecKeyCreateDecryptedData(
                bob, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                encrypted, &decError) else {
                throw decError?.takeRetainedValue() ?? NSError(domain: "seckey-probe", code: 5)
            }
            let plaintext = decrypted as Data
            expect("seckey_ecies_decrypt_roundtrip", plaintext == message,
                   unexpected: "false", expected: "true")
            line("seckey_ecies_decrypt_returns", "CFData plaintext in host process memory")
            line("seckey_ecies_plaintext_host_readable_count", String(plaintext.count))

            // Tamper negative control: modify one ciphertext byte.
            var tampered = encrypted as Data
            if !tampered.isEmpty { tampered[tampered.count - 1] ^= 0xFF }
            var tamperError: Unmanaged<CFError>?
            let tamperOpened = SecKeyCreateDecryptedData(
                bob, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                tampered as CFData, &tamperError)
            expect("seckey_ecies_tampered_decrypt_fails", tamperOpened == nil,
                   unexpected: "false", expected: "true")

            // Wrong-recipient negative control: alice cannot decrypt bob's mail.
            var wrongError: Unmanaged<CFError>?
            let wrongOpened = SecKeyCreateDecryptedData(
                alice, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM,
                encrypted, &wrongError)
            expect("seckey_ecies_wrong_recipient_decrypt_fails", wrongOpened == nil,
                   unexpected: "false", expected: "true")

            // Keys are in-memory only; nothing was persisted anywhere.
            line("seckey_keys_persisted", "false (in-memory SecKeyRef only, released at exit)")
        } catch {
            verifier.fail("stage error: \(error)")
        }

        if verifier.failed {
            line("verdict", "FAIL (\(verifier.failures.count) failure(s))")
            exit(1)
        }
        line("verdict", "PASS")
    }
}
