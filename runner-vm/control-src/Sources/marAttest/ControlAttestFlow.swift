// The runtime path for the NEW HVF control profile: observed hvf-control run →
// app-internal HMAC terminal verification → derived checker verdict over the
// exact prompt bytes → HvFControlEmit receipt (dsmack-hvf-control-statement/1,
// guest-sealed terminal record embedded verbatim) → DCAppAttestService-
// equivalent assertion over the EXACT control_statement bytes → offline
// verification → receipt completion + counter advance.
//
// What executes here, in order (every step fail-closed, nothing written until
// the observed facts are verified):
//   0. receipt dir must be EMPTY (the verifier admits exactly the
//      HVF receipt files — anything else is profile_evidence_mismatch);
//   1. OBSERVED OUTCOME FIRST: the retained control stream must scan clean
//      (exactly one terminal frame, nothing after it), the terminal record
//      must HMAC-verify against the host key over THIS run_id/nonce/task and
//      the collected stdout/stderr/guest-trace bytes (the app-internal check —
//      the key is never exported), the sealed artifacts must be exactly the
//      single result.json over the reconstructed document, and the checker
//      verdict must be DERIVED pass from the exact prompt bytes. No assertion
//      happens over an unverified or failed outcome, and there is deliberately
//      NO legacy/VZ statement anywhere on this path.
//   2. COUNTER PREDICTION under the per-key flock (see CounterStore.swift for
//      the circularity resolution): fresh dedicated key → 1, else
//      lastVerifiedCounter + 1; state is never invented.
//   3. HvFControlEmit.writeReceipt — the 10 library files + the exact
//      control-statement bytes over the final lifecycle head.
//   4. Cancellation check, then the injected AssertionProducer (the signed
//      app's 3-line DCAppAttestService adapter; this library never calls
//      DeviceCheck itself) with clientDataHash = sha256(statement bytes).
//   5. OFFLINE VERIFICATION of the returned assertion: ECDSA P-256 by the
//      enrollment-certified key over sha256(sha256(authData ‖ sha256(statement
//      bytes))), and the recovered counter MUST equal the predicted counter
//      (counter_binding, app-side half). On any failure the receipt directory
//      is rolled back to empty — no receipt-like bytes survive — and the store
//      does not advance.
//   6. keyId.txt + assertion.cbor + the staged enroll files complete the
//      exactly-14-file set; the store advances to the VERIFIED counter under
//      the same lock.
//
// Single-shot by design: a counter mismatch ends the run (see CounterStore);
// there is no retry, because re-emitting would append a second lifecycle
// stage sequence and the verifier requires exactly six stages in order.
import Foundation
import marControl

/// Production adapter surface: `(keyId, clientDataHash) -> assertion CBOR`.
/// The signed app implements this with DCAppAttestService.generateAssertion;
/// tests implement it with synthetic P-256 keys. This module contains NO
/// DeviceCheck import and performs NO signing.
public protocol AssertionProducer: Sendable {
    func generateAssertion(keyId: String, clientDataHash: Data) async throws -> Data
}

public enum ControlAttestFlowError: Error, Equatable, CustomStringConvertible {
    case receiptDirNotEmpty([String])
    case receiptDirMissing(String)
    case receiptEnumerationFailed(String)
    case duplicateFactsMismatch(String)
    case controlStreamUnclean(terminalFrames: Int, postTerminalBytes: Int)
    case terminalArtifactMismatch(String)
    case outcomeNotAdmissible(String)
    case stopReasonNotGuestRequested(String)
    case receiptFileSetWrong([String])
    case assertionProducerFailed(String)
    case rollbackFailed(String)

    public var description: String {
        switch self {
        case .receiptDirNotEmpty(let f):
            return "attest_flow: receipt dir not empty: \(f.joined(separator: ", "))"
        case .receiptDirMissing(let p): return "attest_flow: receipt dir missing: \(p)"
        case .receiptEnumerationFailed(let m):
            return "attest_flow: receipt enumeration failed: \(m)"
        case .duplicateFactsMismatch(let m):
            return "attest_flow: duplicate fact disagrees with the authenticated source: \(m)"
        case .controlStreamUnclean(let t, let p):
            return "attest_flow: retained control stream unclean (terminals \(t), post-terminal \(p))"
        case .terminalArtifactMismatch(let m):
            return "attest_flow: sealed artifacts disagree with the reconstructed result: \(m)"
        case .outcomeNotAdmissible(let m):
            return "attest_flow: outcome not admissible: \(m)"
        case .stopReasonNotGuestRequested(let r):
            return "attest_flow: stop reason \(r) is not guest-requested (host halt is not success authority)"
        case .receiptFileSetWrong(let f):
            return "attest_flow: receipt file set wrong (expected exactly \(HvFControlEmit.receiptFiles.count) files): \(f.sorted().joined(separator: ", "))"
        case .assertionProducerFailed(let m):
            return "attest_flow: assertion producer failed: \(m)"
        case .rollbackFailed(let m):
            return "attest_flow: ROLLBACK INCOMPLETE — \(m) (operator must inspect the receipt dir)"
        }
    }
}

/// Enrollment evidence staged once, verified offline before any use.
/// keyId.txt must be the canonical base64 of sha256(leaf certificate public
/// point) — exactly the verifier's key-id rule — and the enrollment's nonce
/// extension must bind the staged client-data bytes to this app identity.
public struct EnrollReceipt {
    public static let enrollDomain = "minimal-attested-run-enroll/1"   // statement.ENROLL_DOMAIN
    public static let maxClientDataBytes = 4096
    public static let maxEnrollmentCborBytes = 100_000                  // attest_core decode cap

    public let keyId: String
    public let appId: String
    public let enrollClientData: Data
    public let enrollmentCbor: Data
    /// X9.63 point of the certified key (assertions must verify under it).
    public let publicPoint: Data

    /// Read the three enroll files once (size-capped) and verify offline.
    /// `rootPem` is optional PUBLIC data: when supplied it must match the
    /// pinned Apple App Attestation Root DER hash (a sanity check only —
    /// full chain anchoring stays with the verifier).
    public static func load(directory: URL, appId: String, environment: String = "development",
                            rootPem: Data? = nil) throws -> EnrollReceipt {
        if let pem = rootPem { try AppAttestVerify.verifyRootPin(rootPem: pem) }
        let keyIdRaw = try readFileOnce(directory.appendingPathComponent("keyId.txt"), cap: 512)
        let clientData = try readFileOnce(directory.appendingPathComponent("enroll-client-data.bin"),
                                          cap: maxClientDataBytes)
        let enrollment = try readFileOnce(directory.appendingPathComponent("enrollment.cbor"),
                                          cap: maxEnrollmentCborBytes)
        guard let keyIdText = String(data: keyIdRaw, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines), !keyIdText.isEmpty
        else { throw AppAttestError.missingField("keyId.txt is not utf-8 text") }

        // The client data must be the canonical enrollment statement shape
        // {domain, challenge: hex} over THIS app's enroll challenge bytes.
        // (The verifier recomputes it from ITS challenge — an app-side check
        // can only catch staging mistakes, and does.)
        if let obj = try? PyJSON.parse(clientData) as? [String: Any],
           Set(obj.keys) == ["domain", "challenge"],
           obj["domain"] as? String == enrollDomain,
           let hex = obj["challenge"] as? String,
           hex.count % 2 == 0, hex.allSatisfy({ $0.isHexDigit && !$0.isUppercase }),
           (try? PyJSON.canonical(obj)) == clientData {
            // shape OK
        } else {
            throw AppAttestError.missingField("enroll client data is not canonical {domain,challenge} JSON")
        }

        let verified = try AppAttestVerify.verifyEnrollment(enrollmentCbor: enrollment,
                                                            keyId: keyIdText, appId: appId,
                                                            enrollClientData: clientData,
                                                            environment: environment)
        return EnrollReceipt(keyId: keyIdText, appId: appId, enrollClientData: clientData,
                             enrollmentCbor: enrollment, publicPoint: verified.publicPoint)
    }

    static func readFileOnce(_ url: URL, cap: Int) throws -> Data {
        guard let handle = FileHandle(forReadingAtPath: url.path) else {
            throw AppAttestError.missingField("cannot read \(url.lastPathComponent)")
        }
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: cap + 1) else {
            throw AppAttestError.missingField("read failed: \(url.lastPathComponent)")
        }
        guard data.count <= cap else {
            throw AppAttestError.missingField("\(url.lastPathComponent) over \(cap) bytes")
        }
        guard !data.isEmpty else {
            throw AppAttestError.missingField("\(url.lastPathComponent) is empty")
        }
        return data
    }
}

/// What the mode observed for this run, beyond the HvFRunFacts. The terminal
/// HMAC key stays host-side; status/exit are NOT taken from here — they are
/// recovered from the VERIFIED terminal record.
public struct ControlAttestRunObservation: Sendable {
    public let runId: String
    public let nonceHex: String
    public let hmacKey: Data
    public let expectedProvider: [String: Int]
    /// Only "guest-requested" proceeds (verifier lifecycle rule; host-halt is
    /// not success authority). Set from the checked teardown observation.
    public let stopReason: String

    public init(runId: String, nonceHex: String, hmacKey: Data,
                expectedProvider: [String: Int], stopReason: String) {
        self.runId = runId; self.nonceHex = nonceHex; self.hmacKey = hmacKey
        self.expectedProvider = expectedProvider; self.stopReason = stopReason
    }
}

public struct ControlAttestOutcome {
    public let receiptDirectory: URL
    public let controlStatement: Data
    public let assertionCbor: Data
    public let verifiedCounter: Int
    public let counterState: AssertionCounterState
    /// The files, verified present and exactly-nothing-else.
    public let files: [String]
}

public enum KeyPolicy {
    /// Reviewed default: this run uses a fresh dedicated App Attest key whose
    /// enrollment was verified and which has never produced an assertion —
    /// its first assertion carries counter 1. If the store nonetheless has
    /// history for the keyId, the prediction is lastVerified + 1 (the key is
    /// not fresh; we never assume 1 over recorded history).
    case freshDedicatedKey
    /// An existing key with recorded history; a missing record is a refusal
    /// (state is never invented for a key that may have prior assertions).
    case existingKey
}

public enum ControlAttestFlow {

    public static var controlFiles: [String] { HvFControlEmit.receiptFiles }

    /// The full evidence-and-assertion path. See the file header for the
    /// ordering contract; nothing is signed until the observed outcome,
    /// artifacts and teardown are verified.
    public static func emitAndAttest(into receiptDir: URL,
                                     observation: ControlAttestRunObservation,
                                     facts: HvFRunFacts,
                                     recorder: LifecycleRecorder,
                                     enroll: EnrollReceipt,
                                     keyPolicy: KeyPolicy,
                                     counterStore: AssertionCounterStore,
                                     producer: AssertionProducer,
                                     lockDeadline: ContinuousClock.Instant) async throws -> ControlAttestOutcome {
        // 0. Empty receipt directory.
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: receiptDir.path, isDirectory: &isDir),
              isDir.boolValue else {
            throw ControlAttestFlowError.receiptDirMissing(receiptDir.path)
        }
        let preExisting = try listFiles(in: receiptDir)
        guard preExisting.isEmpty else { throw ControlAttestFlowError.receiptDirNotEmpty(preExisting) }

        // 1. Observed outcome: stream shape, HMAC terminal record (app-internal
        //    authority), derived checker, single sealed result artifact.
        //    F4: the EMITTED terminal/identity/counts are derived from the
        //    authenticated transcript — caller-supplied duplicates are only
        //    accepted when they AGREE, never as a second unchecked source.
        let scan = try DSMX.scanGuestStream(facts.controlRecording)
        guard scan.terminalFrames == 1, scan.postTerminalBytes == 0 else {
            throw ControlAttestFlowError.controlStreamUnclean(terminalFrames: scan.terminalFrames,
                                                              postTerminalBytes: scan.postTerminalBytes)
        }
        let terminalPayload = try DSMX.terminalPayload(of: facts.controlRecording)
        if !facts.terminalPayload.isEmpty, facts.terminalPayload != terminalPayload {
            throw ControlAttestFlowError.duplicateFactsMismatch(
                "facts.terminalPayload != the transcript's authenticated terminal record")
        }
        if facts.controlFrames != 0, facts.controlFrames != scan.frames {
            throw ControlAttestFlowError.duplicateFactsMismatch(
                "facts.controlFrames \(facts.controlFrames) != scan.frames \(scan.frames)")
        }
        guard facts.runId == observation.runId, facts.nonceHex == observation.nonceHex else {
            throw ControlAttestFlowError.duplicateFactsMismatch(
                "facts run identity disagrees with the authenticated observation")
        }
        _ = try TerminalAuth.verify(payload: terminalPayload, hmacKey: observation.hmacKey,
                                    runId: observation.runId, nonce: observation.nonceHex,
                                    taskSHA256: SHA256.hex(facts.taskBytes),
                                    collectedStdout: facts.stdout,
                                    collectedStderr: facts.stderr,
                                    collectedTrace: facts.guestTrace,
                                    expectedProvider: observation.expectedProvider)
        guard observation.stopReason == "guest-requested" else {
            throw ControlAttestFlowError.stopReasonNotGuestRequested(observation.stopReason)
        }
        // The checker verdict is derived from the exact prompt bytes; a failed
        // or non-completed outcome is simply not admissible — never staged.
        let verdict = PublicTaskChecker.verify(taskBytes: facts.taskBytes, stdout: facts.stdout)
        guard verdict.verdict == "pass", let resultDoc = verdict.resultDocument else {
            throw ControlAttestFlowError.outcomeNotAdmissible("checker verdict \(verdict.verdict)")
        }
        guard let record = (try? PyJSON.parse(terminalPayload)) as? [String: Any],
              record["status"] as? String == "completed",
              record["exit_status"] as? Int == 0 else {
            throw ControlAttestFlowError.outcomeNotAdmissible("terminal outcome")
        }
        // field-by-field: JSON numbers bridge as NSNumber, never == on [Any]
        let rows = record["artifacts"] as? [[Any]]
        guard let row = rows?.first, rows?.count == 1,
              row[0] as? String == "result.json",
              row[1] as? String == SHA256.hex(resultDoc),
              (row[2] as? NSNumber)?.intValue == resultDoc.count else {
            throw ControlAttestFlowError.terminalArtifactMismatch(
                "sealed artifacts \(String(describing: record["artifacts"])) != the single result.json over the reconstructed document")
        }

        // 2-6. Serialized per-key critical section: predict → emit → assert →
        //      verify → advance (or rollback, store untouched).
        let lock = try counterStore.lock(keyId: enroll.keyId, deadline: lockDeadline)
        let predicted: Int
        switch keyPolicy {
        case .freshDedicatedKey:
            predicted = try AssertionCounterStore.predictedCounterForFreshKey(lock.state)
        case .existingKey:
            predicted = try AssertionCounterStore.predictedCounter(from: lock.state, keyId: enroll.keyId)
        }
        let observed = HvFRunFacts(
            runId: facts.runId, nonceHex: facts.nonceHex, counter: predicted,
            runChallenge: facts.runChallenge, taskBytes: facts.taskBytes,
            controlRecording: facts.controlRecording, controlFrames: scan.frames,
            terminalPayload: terminalPayload, stdout: facts.stdout, stderr: facts.stderr,
            guestTrace: facts.guestTrace, hostTraceLines: facts.hostTraceLines,
            hostTraceHead: facts.hostTraceHead, hostTraceEvents: facts.hostTraceEvents,
            framesIn: facts.framesIn, bytesIn: facts.bytesIn,
            manifestSHA256: facts.manifestSHA256, pins: facts.pins,
            ctlAbiVersion: facts.ctlAbiVersion)

        let statementBytes: Data
        do {
            // F7: the teardown stop reason is the CHECKED observation this
            // flow validated above (guest-requested), not a literal the
            // emitter invents.
            statementBytes = try HvFControlEmit.writeReceipt(into: receiptDir, recorder: recorder,
                                                             keyId: enroll.keyId, appId: enroll.appId,
                                                             facts: observed,
                                                             stopReason: observation.stopReason)
        } catch {
            try rollbackOrThrow(receiptDir, after: error)
        }

        let assertion: Data
        do {
            try Task.checkCancellation()          // no assertion after cancel
            let clientDataHash = Data(SHA256.digest(statementBytes))
            assertion = try await producer.generateAssertion(keyId: enroll.keyId,
                                                             clientDataHash: clientDataHash)
            guard !assertion.isEmpty else {
                throw ControlAttestFlowError.assertionProducerFailed("empty assertion bytes")
            }
        } catch {
            try rollbackOrThrow(receiptDir, after: error)
        }

        // Offline verification — the circularity enforcement point.
        let recovered: Int
        do {
            recovered = try AppAttestVerify.verifyAssertion(assertionCbor: assertion,
                                                            clientData: statementBytes,
                                                            publicPoint: enroll.publicPoint,
                                                            appId: enroll.appId,
                                                            expectedCounter: predicted)
        } catch {
            try rollbackOrThrow(receiptDir, after: error)
        }

        do {
            // keyId.txt with a trailing newline (the verifier .strip()s);
            // assertion.cbor exactly the producer bytes; the staged enroll
            // evidence completes the exactly-14-file set.
            try (Data(enroll.keyId.utf8) + Data([0x0a])).write(to: receiptDir.appendingPathComponent("keyId.txt"),
                                                               options: .atomic)
            try assertion.write(to: receiptDir.appendingPathComponent("assertion.cbor"), options: .atomic)
            try enroll.enrollClientData.write(to: receiptDir.appendingPathComponent("enroll-client-data.bin"),
                                              options: .atomic)
            try enroll.enrollmentCbor.write(to: receiptDir.appendingPathComponent("enrollment.cbor"),
                                            options: .atomic)
            let present: [String]
            do {
                present = try listFiles(in: receiptDir)
            } catch {
                // F10: an enumeration failure is explicit, never a silent skip.
                throw ControlAttestFlowError.receiptEnumerationFailed(
                    "\(error) (receipt dir: \(receiptDir.path))")
            }
            guard Set(present) == Set(controlFiles) else {
                throw ControlAttestFlowError.receiptFileSetWrong(present)
            }
        } catch {
            try rollbackOrThrow(receiptDir, after: error)
        }

        // F10: a failed counter advance must roll the receipt back too — a
        // receipt whose counter never committed is not evidence.
        let state: AssertionCounterState
        do {
            state = try lock.advance(verifiedCounter: recovered,
                                     assertionSHA256: SHA256.hex(assertion))
        } catch {
            try rollbackOrThrow(receiptDir, after: error)
        }
        return ControlAttestOutcome(receiptDirectory: receiptDir, controlStatement: statementBytes,
                                    assertionCbor: assertion, verifiedCounter: recovered,
                                    counterState: state, files: controlFiles)
    }

    // MARK: helpers

    static func listFiles(in dir: URL) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: dir.path)
    }

    /// Remove every file in the receipt dir (it was verified empty on entry,
    /// so everything present is this run's partial output), then re-throw the
    /// error that caused the rollback. If cleanup itself fails, the rollback
    /// failure REPLACES the original error — receipt-like bytes surviving on
    /// disk is the more urgent fact. F10: an ENUMERATION failure is not a
    /// successful cleanup either — we then cannot know what partial bytes
    /// survive — so it surfaces as `rollbackFailed`, never as a silent empty
    /// listing that would let the original error stand as "rolled back".
    static func rollbackOrThrow(_ dir: URL, after original: Error) throws -> Never {
        let names: [String]
        do {
            names = try listFiles(in: dir)
        } catch {
            throw ControlAttestFlowError.rollbackFailed(
                "enumeration failed: \(error) — original error: \(original) (operator must inspect the receipt dir: \(dir.path))")
        }
        var failures: [String] = []
        for name in names {
            do { try FileManager.default.removeItem(at: dir.appendingPathComponent(name)) }
            catch { failures.append(name) }
        }
        if !failures.isEmpty {
            throw ControlAttestFlowError.rollbackFailed(
                "could not remove \(failures.joined(separator: ", ")) — original error: \(original)")
        }
        throw original
    }
}
