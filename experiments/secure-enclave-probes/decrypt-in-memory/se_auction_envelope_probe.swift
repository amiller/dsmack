// SAME-DEVICE two-Secure-Enclave-key auction envelope simulation.
//
// Bounded experiment for secure-enclave-completion-20261010. THIS IS A
// SAME-DEVICE SIMULATION ON ONE Mac mini, NOT a two-device hardware
// exchange. Two independently generated SEP-backed P256 key-agreement keys
// (one per role, each generated in a SEPARATE process) derive a
// transcript-bound HKDF key; a synthetic sealed-bid auction envelope
// demonstrates roundtrip, tamper, wrong-peer and wrong-context rejection, and
// an explicitly protocol-level (NOT hardware-enforced) release boundary.
//
// Local transcript names do NOT establish hardware app-code identity or
// binding: no attestation, code identity, freshness or replay validation is
// performed here. Stock public CryptoKit returns the ECDH SharedSecret and
// HKDF SymmetricKey to the HOST process, so the auctioneer host can read
// every bid; the release boundary below is enforced by protocol logic only.
//
// Logs only: types, byte counts, SHA-256 fingerprints of PUBLIC keys, a
// SHA-256 fingerprint of the DERIVED key (one-way; never the key bytes),
// equality outcomes and error descriptions. Synthetic inputs only; no
// keychain; wrapped persistence only in this disposable directory.
//
// Modes (each invocation = one process):
//   gen-bidder         - process A: generate bidder SEP P256 KA key, persist wrapped blob
//   gen-auctioneer     - process B: generate auctioneer SEP P256 KA key, persist wrapped blob
//   exchange-bidder    - process C: bidder side ECDH + transcript-bound HKDF, seal bids
//   exchange-auctioneer- process D: auctioneer side ECDH + HKDF, open + controls + release
//   cleanup            - remove every fixture this probe created (verified)

import CryptoKit
import Foundation

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

func expect(_ key: String, _ ok: Bool, unexpected value: String, expected: String) {
    line(key, ok ? expected : value)
    line(key + "_expectation_passed", ok ? "true" : "false")
    if !ok { verifier.fail("expectation unmet: \(key)") }
}

// Canonical transcript. Synthetic values only.
let domain = "dsmack.secure-enclave-completion-20261010.auction-envelope.v1"
let auctionID = "auction-synthetic-20261010-001"
let context = "bid-submission-v1"
let winningBid = Data("bidder=BIDDER-1;bid_amount_microunits=42000000;salt=b1".utf8)
let losingBid = Data("bidder=BIDDER-2;bid_amount_microunits=17000000;salt=b2".utf8)

let cwd = FileManager.default.currentDirectoryPath
let artDir = cwd + "/artifacts"
let bidderBlob = artDir + "/se-bidder-ka-key.blob"
let bidderPubFile = artDir + "/se-bidder-ka-pub-x963.blob"
let auctioneerBlob = artDir + "/se-auctioneer-ka-key.blob"
let auctioneerPubFile = artDir + "/se-auctioneer-ka-pub-x963.blob"
let winningEnvelopeFile = artDir + "/bid-envelope-winner.bin"
let losingEnvelopeFile = artDir + "/bid-envelope-loser.bin"
let bidderFingerprintFile = artDir + "/bidder-derived-fingerprint.txt"
let allFixtures = [
    "se-bidder-ka-key.blob", "se-bidder-ka-pub-x963.blob",
    "se-auctioneer-ka-key.blob", "se-auctioneer-ka-pub-x963.blob",
    "bid-envelope-winner.bin", "bid-envelope-loser.bin",
    "bidder-derived-fingerprint.txt",
]
func fixturePath(_ name: String) -> String { artDir + "/" + name }

func writeRestricted(_ data: Data, _ path: String) throws {
    let ok = FileManager.default.createFile(
        atPath: path, contents: data,
        attributes: [.posixPermissions: 0o600])
    guard ok else { throw NSError(domain: "se-auction", code: 3,
                                  userInfo: [NSLocalizedDescriptionKey: "createFile failed: \(path)"]) }
}

func readBlob(_ path: String) throws -> Data {
    try Data(contentsOf: URL(fileURLWithPath: path))
}

func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

/// Public-key fingerprint: SHA-256 over the X9.63 public bytes (public data).
func fingerprint(pub: P256.KeyAgreement.PublicKey) -> String {
    sha256Hex(pub.x963Representation)
}

/// Transcript-bound HKDF: canonical protocol domain, auction id, BOTH ordered
/// key identities (role-ordered public-key fingerprints) and context.
func deriveTranscriptKey(secret: SharedSecret, bidderFp: String, auctioneerFp: String,
                         auction: String, ctx: String) -> SymmetricKey {
    let salt = Data("\(domain)|\(auction)".utf8)
    let sharedInfo = Data("bidder=\(bidderFp)||auctioneer=\(auctioneerFp)|\(ctx)".utf8)
    return secret.hkdfDerivedSymmetricKey(
        using: SHA256.self, salt: salt, sharedInfo: sharedInfo, outputByteCount: 32)
}

/// One-way fingerprint of the derived symmetric key (32-byte SHA-256 digest).
func fingerprint(key: SymmetricKey) -> String {
    key.withUnsafeBytes { raw in
        let copy = Data(bytes: raw.baseAddress!, count: raw.count)
        return sha256Hex(copy)
    }
}

func requireArtifactsDirFresh() -> Bool {
    let fm = FileManager.default
    var preexisting: [String] = []
    for name in allFixtures where fm.fileExists(atPath: fixturePath(name)) {
        preexisting.append(name)
    }
    if !preexisting.isEmpty {
        verifier.fail("precondition: run directory not fresh (preexisting: \(preexisting.joined(separator: ",")))")
        line("precondition_fresh_directory", "false")
        return false
    }
    line("precondition_fresh_directory", "true")
    return true
}

func ensureArtifactsDir() -> Bool {
    do {
        try FileManager.default.createDirectory(
            atPath: artDir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
    } catch {
        verifier.fail("artifacts directory creation failed: \(error)")
        return false
    }
    guard FileManager.default.fileExists(atPath: artDir) else {
        verifier.fail("artifacts directory missing after creation")
        return false
    }
    return true
}

// MARK: - Process A/B: independent SEP key generation (one process per role)

func modeGenBidder() {
    guard requireArtifactsDirFresh(), ensureArtifactsDir() else { finish() }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        line("simulation_scope", "SAME-DEVICE simulation (one Mac mini); not a two-device exchange")
        line("bidder_key_backing", "SecureEnclave.P256.KeyAgreement.PrivateKey (SEP-backed)")
        line("bidder_pub_fingerprint", fingerprint(pub: key.publicKey))
        try writeRestricted(key.dataRepresentation, bidderBlob)
        try writeRestricted(key.publicKey.x963Representation, bidderPubFile)
        line("bidder_persisted", "artifacts/se-bidder-ka-key.blob (wrapped dataRepresentation, 0600)")
    } catch {
        verifier.fail("gen-bidder error: \(error)")
    }
}

func modeGenAuctioneer() {
    // Refuse to overwrite this role's own fixtures if generation is retried.
    let fm = FileManager.default
    if fm.fileExists(atPath: auctioneerBlob) || fm.fileExists(atPath: auctioneerPubFile) {
        verifier.fail("precondition: auctioneer fixtures already exist (refusing overwrite)")
        finish()
    }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        line("simulation_scope", "SAME-DEVICE simulation (one Mac mini); not a two-device exchange")
        line("auctioneer_key_backing", "SecureEnclave.P256.KeyAgreement.PrivateKey (SEP-backed)")
        line("auctioneer_pub_fingerprint", fingerprint(pub: key.publicKey))
        try writeRestricted(key.dataRepresentation, auctioneerBlob)
        try writeRestricted(key.publicKey.x963Representation, auctioneerPubFile)
        line("auctioneer_persisted", "artifacts/se-auctioneer-ka-key.blob (wrapped dataRepresentation, 0600)")
    } catch {
        verifier.fail("gen-auctioneer error: \(error)")
    }
}

// MARK: - Process C: bidder side derivation + bid sealing

func modeExchangeBidder() {
    do {
        let bidderKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: readBlob(bidderBlob))
        let auctioneerPub = try P256.KeyAgreement.PublicKey(x963Representation: readBlob(auctioneerPubFile))
        let bidderFp = fingerprint(pub: bidderKey.publicKey)
        let auctioneerFp = fingerprint(pub: auctioneerPub)

        // SEP performs the ECDH private operation; the SharedSecret returns to
        // THIS host process (output-exposure contract), then HKDF runs on host.
        let secret = try bidderKey.sharedSecretFromKeyAgreement(with: auctioneerPub)
        line("bidder_ecdh_secret_type", String(describing: type(of: secret)))
        line("bidder_ecdh_secret_host_readable_bytecount", String(secret.withUnsafeBytes { $0.count }))
        let key = deriveTranscriptKey(secret: secret, bidderFp: bidderFp,
                                      auctioneerFp: auctioneerFp, auction: auctionID, ctx: context)
        let fp = fingerprint(key: key)
        line("bidder_transcript_bound_derived_key_fingerprint_sha256", fp)
        line("bidder_transcript", "domain=\(domain)|auction=\(auctionID)|bidder=\(bidderFp)|auctioneer=\(auctioneerFp)|context=\(context)")

        // Seal the two synthetic bids under the transcript-bound key.
        let winnerSealed = try AES.GCM.seal(winningBid, using: key)
        let loserSealed = try AES.GCM.seal(losingBid, using: key)
        guard let winnerCombined = winnerSealed.combined, let loserCombined = loserSealed.combined else {
            throw NSError(domain: "se-auction", code: 4)
        }
        try writeRestricted(winnerCombined, winningEnvelopeFile)
        try writeRestricted(loserCombined, losingEnvelopeFile)
        try writeRestricted(Data(fp.utf8), bidderFingerprintFile)
        line("bid_envelopes_sealed", "winner+loser (AES-GCM, transcript-bound key)")
    } catch {
        verifier.fail("exchange-bidder error: \(error)")
    }
}

// MARK: - Process D: auctioneer side derivation, controls, release boundary

func modeExchangeAuctioneer() {
    do {
        let auctioneerKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: readBlob(auctioneerBlob))
        let bidderPub = try P256.KeyAgreement.PublicKey(x963Representation: readBlob(bidderPubFile))
        let bidderFp = fingerprint(pub: bidderPub)
        let auctioneerFp = fingerprint(pub: auctioneerKey.publicKey)

        let secret = try auctioneerKey.sharedSecretFromKeyAgreement(with: bidderPub)
        line("auctioneer_ecdh_secret_type", String(describing: type(of: secret)))
        line("auctioneer_ecdh_secret_host_readable_bytecount", String(secret.withUnsafeBytes { $0.count }))
        let key = deriveTranscriptKey(secret: secret, bidderFp: bidderFp,
                                      auctioneerFp: auctioneerFp, auction: auctionID, ctx: context)
        let fp = fingerprint(key: key)
        line("auctioneer_transcript_bound_derived_key_fingerprint_sha256", fp)

        // Matching fingerprints WITHOUT either side ever logging key bytes.
        let bidderFpFromFile = String(data: try readBlob(bidderFingerprintFile), encoding: .utf8) ?? ""
        expect("bidder_auctioneer_derived_key_fingerprints_match",
               bidderFpFromFile == fp, unexpected: "false", expected: "true")

        // Positive: permitted open of both sealed bids by the auctioneer.
        let winnerCombined = try readBlob(winningEnvelopeFile)
        let loserCombined = try readBlob(losingEnvelopeFile)
        let winnerOpened = try AES.GCM.open(AES.GCM.SealedBox(combined: winnerCombined), using: key)
        expect("envelope_roundtrip_winner_opens", winnerOpened == winningBid,
               unexpected: "false", expected: "true")
        let loserOpened = try AES.GCM.open(AES.GCM.SealedBox(combined: loserCombined), using: key)
        expect("envelope_roundtrip_loser_opens", loserOpened == losingBid,
               unexpected: "false", expected: "true")

        // Tamper control: flip one ciphertext byte -> must fail.
        var tampered = winnerCombined
        if !tampered.isEmpty { tampered[tampered.count - 1] ^= 0xFF }
        var tamperOpened = false
        if (try? AES.GCM.open(AES.GCM.SealedBox(combined: tampered), using: key)) != nil {
            tamperOpened = true
        }
        expect("envelope_tampered_open_fails", !tamperOpened,
               unexpected: "false", expected: "true")

        // Wrong-context control: same keys/auction, different context string.
        let wrongCtxKey = deriveTranscriptKey(secret: secret, bidderFp: bidderFp,
                                              auctioneerFp: auctioneerFp,
                                              auction: auctionID, ctx: "wrong-context")
        expect("wrong_context_key_fingerprint_differs", fingerprint(key: wrongCtxKey) != fp, unexpected: "false", expected: "true")
        var wrongCtxOpened = false
        if (try? AES.GCM.open(AES.GCM.SealedBox(combined: winnerCombined), using: wrongCtxKey)) != nil {
            wrongCtxOpened = true
        }
        expect("envelope_wrong_context_open_fails", !wrongCtxOpened,
               unexpected: "false", expected: "true")

        // Wrong-auction control: same keys/context, different auction id.
        let wrongAuctionKey = deriveTranscriptKey(secret: secret, bidderFp: bidderFp,
                                                  auctioneerFp: auctioneerFp,
                                                  auction: "auction-synthetic-20261010-OTHER",
                                                  ctx: context)
        var wrongAuctionOpened = false
        if (try? AES.GCM.open(AES.GCM.SealedBox(combined: winnerCombined), using: wrongAuctionKey)) != nil {
            wrongAuctionOpened = true
        }
        expect("envelope_wrong_auction_open_fails", !wrongAuctionOpened,
               unexpected: "false", expected: "true")

        // Wrong-peer control: an unrelated THIRD freshly generated SEP key in
        // this process pretending to be the bidder. Its transcript-bound key
        // differs and cannot open the envelope sealed for the real bidder.
        let fakeBidderKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        let fakeBidderFp = fingerprint(pub: fakeBidderKey.publicKey)
        let fakeSecret = try auctioneerKey.sharedSecretFromKeyAgreement(with: fakeBidderKey.publicKey)
        let fakeKey = deriveTranscriptKey(secret: fakeSecret, bidderFp: fakeBidderFp,
                                          auctioneerFp: auctioneerFp,
                                          auction: auctionID, ctx: context)
        expect("wrong_peer_key_fingerprint_differs", fingerprint(key: fakeKey) != fp, unexpected: "false", expected: "true")
        var wrongPeerOpened = false
        if (try? AES.GCM.open(AES.GCM.SealedBox(combined: winnerCombined), using: fakeKey)) != nil {
            wrongPeerOpened = true
        }
        expect("envelope_wrong_peer_open_fails", !wrongPeerOpened,
               unexpected: "false", expected: "true")

        // Permitted release boundary (PROTOCOL-LEVEL ONLY): the auctioneer
        // releases winner identity + clearing price, never the losing bid.
        // It computes the clearing price from the opened winning bid.
        guard let winnerText = String(data: winnerOpened, encoding: .utf8),
              let amount = winnerText.split(separator: ";")
                .first(where: { $0.hasPrefix("bid_amount_microunits=") })?
                .split(separator: "=").last
        else {
            throw NSError(domain: "se-auction", code: 5)
        }
        let release = "winner=BIDDER-1;clearing_price_microunits=\(amount)"
        line("release_record", release)
        let loserAmountMarker = "17000000"
        expect("release_record_excludes_losing_bid_amount",
               !release.contains(loserAmountMarker),
               unexpected: "false", expected: "true")
        line("release_boundary_enforcement", "protocol-logic-only (host process holds derived key)")
        line("host_reachability",
             "ecdh_secret+derived_key+all_bid_plaintexts readable by auctioneer host process memory")
        line("hardware_confinement_of_derived_key", "not-available-via-inspected-public-APIs (see contract probe)")
    } catch {
        verifier.fail("exchange-auctioneer error: \(error)")
    }
}

// MARK: - Cleanup (verified)

func modeCleanup() {
    let fm = FileManager.default
    var removed: [String] = []
    for name in allFixtures {
        let path = fixturePath(name)
        if fm.fileExists(atPath: path) {
            do {
                try fm.removeItem(atPath: path)
            } catch {
                verifier.fail("cleanup: removeItem threw for \(name): \(error)")
                continue
            }
            if fm.fileExists(atPath: path) {
                verifier.fail("cleanup: \(name) still exists after removal")
            } else {
                removed.append(name)
            }
        }
    }
    line("cleanup_removed", removed.joined(separator: ","))
    if fm.fileExists(atPath: artDir),
       let contents = try? fm.contentsOfDirectory(atPath: artDir), contents.isEmpty {
        if (try? fm.removeItem(atPath: artDir)) != nil, !fm.fileExists(atPath: artDir) {
            line("cleanup_artifacts_dir_removed", "true")
        } else {
            verifier.fail("cleanup: artifacts directory could not be removed")
        }
    }
    line("cleanup_files_expected", String(allFixtures.count))
    line("cleanup_files_removed_verified", String(removed.count))
    if removed.count != allFixtures.count { verifier.fail("cleanup: missing expected fixtures") }
}

func finish() -> Never {
    if verifier.failed {
        line("verdict", "FAIL (\(verifier.failures.count) failure(s))")
        exit(1)
    }
    line("verdict", "PASS")
    exit(0)
}

// MARK: - Main

@main
struct SEAuctionEnvelopeProbe {
    static func main() {
        let mode = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
        let os = ProcessInfo.processInfo.operatingSystemVersion
        line("probe_mode", mode)
        line("os_version", "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)")
        line("secure_enclave_is_available", SecureEnclave.isAvailable ? "true" : "false")
        if !SecureEnclave.isAvailable {
            verifier.fail("precondition: SecureEnclave not available")
        }

        switch mode {
        case "gen-bidder": modeGenBidder()
        case "gen-auctioneer": modeGenAuctioneer()
        case "exchange-bidder": modeExchangeBidder()
        case "exchange-auctioneer": modeExchangeAuctioneer()
        case "cleanup": modeCleanup()
        default:
            verifier.fail("unknown mode \(mode)")
        }
        finish()
    }
}
