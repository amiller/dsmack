// marAttest tests for the NEW HVF control profile: the observed-run →
// HvFControlEmit → genuine-assertion path, exercised end to end with synthetic
// P-256 keys (NO DeviceCheck, NO keychain — the injected AssertionProducer
// stands in for DCAppAttestService.generateAssertion and produces REAL ECDSA
// signatures over the exact control_statement bytes).
//
// Cross-language parity is pinned by committed goldens: verifier/
// test_hvf_control.py builds the SAME fixture from the SAME actual data path
// (bridge worker result doc, one-event guest trace, REAL terminal_auth seal,
// REAL protocol.encode_frame transcript) and writes
// Tests/marAttestTests/Fixtures/{hvf-fixture.json, hvf-control-statement.bin}.
// The Swift builder must reproduce those bytes exactly.
import CryptoKit
import XCTest

import marControl
import marAttest
@testable import marControl
@testable import marAttest

// MARK: - assertion producer bound to the committed enrollment snapshot
// The enrollment evidence (enrollment.cbor / enroll-client-data.bin / keyId)
// comes from the committed Python-rig fixture; the leaf PRIVATE key is the
// fixture's fixed scalar, so assertions produced here verify against the
// certified public point in the committed enrollment. NO DER/CBOR building.

// internal (was private): shared with AppAttestVerifyTests.swift (cycle-6 import)
func fixtureData(_ f: HvFFixture, _ key: String) -> Data {
    let hex = (f.json["enroll"] as! [String: Any])[key] as! String
    var d = Data(capacity: hex.count / 2)
    var i = hex.startIndex
    while i < hex.endIndex {
        d.append(UInt8(hex[i..<hex.index(i, offsetBy: 2)], radix: 16)!)
        i = hex.index(i, offsetBy: 2)
    }
    return d
}

/// The fixture leaf PRIVATE scalar, zero-padded to the 32-byte representation
/// CryptoKit's PrivateKey(rawRepresentation:) requires.
// internal (was private): shared with AppAttestVerifyTests.swift (cycle-6 import)
func fixtureScalar(_ f: HvFFixture) -> Data {
    var scalar = fixtureData(f, "leaf_private_scalar_hex")
    while scalar.count < 32 { scalar.insert(0x00, at: 0) }
    return scalar
}

private func sha256(_ d: Data) -> Data { Data(SHA256.hash(data: d)) }

private final class FixtureProducer: AssertionProducer, @unchecked Sendable {
    let key: P256.Signing.PrivateKey
    let appId: String
    private let lock = NSLock()
    private var counter: Int

    init(appId: String, scalar: Data, firstCounter: Int = 1) {
        self.key = try! P256.Signing.PrivateKey(rawRepresentation: scalar)
        self.appId = appId
        self.counter = firstCounter
    }

    func generateAssertion(keyId: String, clientDataHash: Data) async throws -> Data {
        lock.lock()
        let current = counter
        counter += 1
        lock.unlock()
        return assertion(clientDataHash: clientDataHash, counter: current)
    }

    func assertion(clientDataHash: Data, counter: Int) -> Data {
        var auth = Data(SHA256.hash(data: Data(appId.utf8)))
        auth.append(0x00)
        auth.append(contentsOf: [
            UInt8((counter >> 24) & 0xff), UInt8((counter >> 16) & 0xff),
            UInt8((counter >> 8) & 0xff), UInt8(counter & 0xff),
        ])
        var nonce = auth
        nonce.append(clientDataHash)
        // attest_core convention: the ECDSA data is the DIGEST
        // sha256(authData || sha256(clientData)); CryptoKit pre-hashes once.
        let signature = try! key.signature(for: Data(SHA256.digest(nonce)))
        var out = Data([0xa2])                                   // map(2)
        out.append(Data([0x71]))                                 // text(17)
        out.append(Data("authenticatorData".utf8))
        out.append(contentsOf: [0x58, UInt8(auth.count)])        // bytes(len)
        out.append(auth)
        out.append(Data([0x69]))                                 // text(9)
        out.append(Data("signature".utf8))
        let sig = signature.derRepresentation
        out.append(contentsOf: [0x59, UInt8(sig.count >> 8), UInt8(sig.count & 0xff)])
        out.append(sig)
        return out
    }
}

// MARK: - committed cross-language fixtures

// internal (was private): shared with AppAttestVerifyTests.swift (cycle-6 import)
struct HvFFixture {
    let json: [String: Any]
    let expectedStatement: Data

    init() throws {
        // Tests run from the source checkout: locate the committed goldens
        // relative to this file (no resource-bundle dependency).
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("Fixtures")
        self.json = try JSONSerialization.jsonObject(
            with: try Data(contentsOf: url.appendingPathComponent("hvf-fixture.json"))
        ) as! [String: Any]
        self.expectedStatement = try Data(contentsOf: url.appendingPathComponent("hvf-control-statement.bin"))
    }

    func hex(_ key: String) -> Data {
        let s = json[key] as! String
        var d = Data(capacity: s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let next = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<next], radix: 16)!)
            i = next
        }
        return d
    }
    var identity: [String: String] { json["identity"] as! [String: String] }
    var run: [String: Any] { json["run"] as! [String: Any] }
    var environment: [String: Any] { json["environment"] as! [String: Any] }
    var guest: [String: Any] { json["guest"] as! [String: Any] }
    var output: [String: Any] { json["output"] as! [String: Any] }
    var result: [String: Any] { json["result"] as! [String: Any] }
    var enroll: [String: Any] { json["enroll"] as! [String: Any] }
    var hostTrace: [String: Any] { json["host_trace"] as! [String: Any] }
    var lifecycle: [String: Any] { json["lifecycle"] as! [String: Any] }
}

private func makeTempDir(_ name: String) throws -> URL {
    let dir = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("marAttestTests-\(name)-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

// MARK: - checker + golden parity

final class HvFCheckerAndGoldenTests: XCTestCase {

    func testCheckerDerivesVerdictFromActualPromptBytes() throws {
        let fx = try HvFFixture()
        let task = fx.hex("task_hex")
        let stdout = fx.hex("stdout_hex")
        let verdict = PublicTaskChecker.verify(taskBytes: task, stdout: stdout)
        XCTAssertEqual(verdict.verdict, "pass")
        let prompt = (try JSONSerialization.jsonObject(with: task) as! [String: Any])["prompt"] as! String
        let promptData = Data(prompt.utf8)
        // the digest chain is recomputed, not echoed: a different prompt fails
        XCTAssertEqual(verdict.digest1, sha256(promptData).map { String(format: "%02x", $0) }.joined())
        var other = task
        other[other.count - 3] ^= 0x01
        XCTAssertEqual(PublicTaskChecker.verify(taskBytes: other, stdout: stdout).verdict, "fail")
        var badStdout = stdout
        badStdout[5] ^= 0x01
        XCTAssertEqual(PublicTaskChecker.verify(taskBytes: task, stdout: badStdout).verdict, "fail")
    }

    func testLifecycleStageParityWithCommittedFixture() throws {
        let fx = try HvFFixture()
        let recorder = LifecycleRecorder()
        let task = fx.hex("task_hex")
        let control = fx.hex("control_hex")
        let stdout = fx.hex("stdout_hex")
        let stderr = fx.hex("stderr_hex")
        let guestTrace = fx.hex("guest_trace_hex")
        try recorder.sessionStarted(runId: fx.run["run_id"] as! String)
        try recorder.taskInputCommitted(taskSHA256: fx.json["task_sha256"] as! String,
                                        taskBytes: fx.json["task_bytes"] as! Int)
        try recorder.channelClosed(framesIn: fx.json["frames_in"] as! Int,
                                   bytesIn: fx.json["bytes_in"] as! Int,
                                   framesOut: fx.json["control_frames"] as! Int,
                                   bytesOut: control.count, terminalFrames: 1,
                                   postTerminalBytes: 0)
        try recorder.artifactsCollected(files: [
            ("guest-trace.log", fx.guest["trace_sha256"] as! String, guestTrace.count),
            ("result.json", fx.result["sha256"] as! String, fx.result["bytes"] as! Int),
            ("stderr.bin", (fx.output["stderr"] as! [String: Any])["sha256"] as! String, stderr.count),
            ("stdout.bin", (fx.output["stdout"] as! [String: Any])["sha256"] as! String, stdout.count),
        ])
        try recorder.deviceClosed()
        try recorder.vmStopped(stopReason: "guest-requested")
        XCTAssertEqual(recorder.head, fx.lifecycle["head"] as! String,
                       "lifecycle chain must match the Python-built fixture exactly")
        XCTAssertEqual(recorder.events, fx.lifecycle["events"] as! Int)
        _ = task
    }

    func testSwiftBuilderReproducesCommittedStatementBytes() throws {
        let fx = try HvFFixture()
        let recorder = LifecycleRecorder()
        let control = fx.hex("control_hex")
        let stdout = fx.hex("stdout_hex")
        let stderr = fx.hex("stderr_hex")
        let guestTrace = fx.hex("guest_trace_hex")
        try recorder.sessionStarted(runId: fx.run["run_id"] as! String)
        try recorder.taskInputCommitted(taskSHA256: fx.json["task_sha256"] as! String,
                                        taskBytes: fx.json["task_bytes"] as! Int)
        try recorder.channelClosed(framesIn: fx.json["frames_in"] as! Int,
                                   bytesIn: fx.json["bytes_in"] as! Int,
                                   framesOut: fx.json["control_frames"] as! Int,
                                   bytesOut: control.count, terminalFrames: 1, postTerminalBytes: 0)
        try recorder.artifactsCollected(files: [
            ("guest-trace.log", fx.guest["trace_sha256"] as! String, guestTrace.count),
            ("result.json", fx.result["sha256"] as! String, fx.result["bytes"] as! Int),
            ("stderr.bin", (fx.output["stderr"] as! [String: Any])["sha256"] as! String, stderr.count),
            ("stdout.bin", (fx.output["stdout"] as! [String: Any])["sha256"] as! String, stdout.count),
        ])
        try recorder.deviceClosed()
        try recorder.vmStopped(stopReason: "guest-requested")
        let env = fx.environment
        let facts = HvFRunFacts(
            runId: fx.run["run_id"] as! String, nonceHex: fx.run["nonce"] as! String,
            counter: fx.run["counter"] as! Int,
            runChallenge: Data(),   // challenge bytes are not needed for the statement (sha is in the fixture)
            taskBytes: fx.hex("task_hex"),
            controlRecording: control, controlFrames: fx.json["control_frames"] as! Int,
            terminalPayload: Data((fx.json["terminal_record_canonical"] as! String).utf8),
            stdout: stdout, stderr: stderr, guestTrace: guestTrace,
            hostTraceLines: Data(), hostTraceHead: fx.hostTrace["head"] as! String,
            hostTraceEvents: fx.hostTrace["events"] as! Int,
            framesIn: fx.json["frames_in"] as! Int, bytesIn: fx.json["bytes_in"] as! Int,
            manifestSHA256: env["manifest_sha256"] as! String,
            pins: ["kernel_sha256": env["kernel_sha256"] as! String,
                   "initrd_sha256": env["initrd_sha256"] as! String,
                   "disk_sha256": env["disk_sha256"] as! String,
                   "cmdline_sha256": env["cmdline_sha256"] as! String,
                   "archive_sha256": env["archive_sha256"] as! String],
            ctlAbiVersion: env["ctl_abi_version"] as! Int)
        // The verifier's run_challenge_sha256 is committed; reproduce it by
        // giving the builder the challenge whose sha is pinned. The fixture
        // stores it (32 zero bytes in the Python fixture builder).
        let challenge = Data(count: 32)
        let factsWithChallenge = HvFRunFacts(
            runId: facts.runId, nonceHex: facts.nonceHex, counter: facts.counter,
            runChallenge: challenge, taskBytes: facts.taskBytes,
            controlRecording: facts.controlRecording, controlFrames: facts.controlFrames,
            terminalPayload: facts.terminalPayload, stdout: facts.stdout, stderr: facts.stderr,
            guestTrace: facts.guestTrace, hostTraceLines: facts.hostTraceLines,
            hostTraceHead: facts.hostTraceHead, hostTraceEvents: facts.hostTraceEvents,
            framesIn: facts.framesIn, bytesIn: facts.bytesIn,
            manifestSHA256: facts.manifestSHA256, pins: facts.pins,
            ctlAbiVersion: facts.ctlAbiVersion)
        let built = try HvFControlEmit.buildStatement(
            keyId: fx.identity["key_id"]!, appId: fx.identity["app_id"]!,
            facts: factsWithChallenge,
            verdict: PublicTaskChecker.verify(taskBytes: fx.hex("task_hex"), stdout: stdout),
            resultDoc: stdout.subdata(in: stdout.startIndex..<stdout.index(before: stdout.endIndex)),
            guestTraceEvents: 1, recorder: recorder)
        XCTAssertEqual(built, fx.expectedStatement,
                       "Swift builder must reproduce the Python builder's exact bytes")
        // the spliced record is the verbatim guest-sealed payload
        let recordString = fx.json["terminal_record_canonical"] as! String
        XCTAssertTrue(built.range(of: Data(recordString.utf8)) != nil)
    }
}

// MARK: - counter store

final class FixtureKeyProbeTests: XCTestCase {

    func testProducerKeyMatchesCommittedEnrollmentAndSignsVerifiably() throws {
        let fx = try HvFFixture()
        let appId = fx.identity["app_id"]!
        let scalar = fixtureScalar(fx)
        XCTAssertEqual(scalar.count, 32, "scalar hex: \(scalar.map { String(format: "%02x", $0) }.joined())")
        let key = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        // the committed enrollment's certified point must be THIS key's point
        let enrollDir = try makeTempDir("probe-enroll")
        try FileManager.default.createDirectory(at: enrollDir, withIntermediateDirectories: true)
        try (fx.enroll["key_id"] as! String + "\n").data(using: .utf8)!
            .write(to: enrollDir.appendingPathComponent("keyId.txt"))
        try fixtureData(fx, "client_data_hex")
            .write(to: enrollDir.appendingPathComponent("enroll-client-data.bin"))
        try fixtureData(fx, "enrollment_hex")
            .write(to: enrollDir.appendingPathComponent("enrollment.cbor"))
        let enroll = try EnrollReceipt.load(directory: enrollDir, appId: appId)
        XCTAssertEqual(enroll.publicPoint, key.publicKey.x963Representation,
                       "fixture leaf scalar does not derive the committed certified key")
        // an assertion from this key verifies over the exact client-data bytes
        let statement = Data("probe-statement".utf8)
        let producer = FixtureProducer(appId: appId, scalar: scalar)
        let clientHash = sha256(statement)
        let assertion = producer.assertion(clientDataHash: clientHash, counter: 5)
        // decode-level check: the CBOR must round-trip the produced bytes
        let decoded = try AttestCBOR.decode(assertion)
        guard case .map(let obj) = decoded else { return XCTFail("not a map") }
        guard case .bytes(let decodedAuth)? = obj[.str("authenticatorData")] else { return XCTFail("no authData") }
        guard case .bytes(let decodedSig)? = obj[.str("signature")] else { return XCTFail("no signature") }
        XCTAssertEqual(decodedAuth.count, 37, "authData \(decodedAuth.count) bytes")
        var expectedNonce = decodedAuth
        expectedNonce.append(clientHash)
        // signature-level check at BOTH hash levels
        let sig = try P256.Signing.ECDSASignature(derRepresentation: decodedSig)
        let level1 = key.publicKey.isValidSignature(sig, for: expectedNonce)
        let level2 = key.publicKey.isValidSignature(sig, for: Data(SHA256.hash(data: expectedNonce)))
        XCTAssertTrue(level1 || level2,
                      "signature verifies at neither level (authData \(decodedAuth.map { String(format: "%02x", $0) }.joined()))")
        let recovered = try AppAttestVerify.verifyAssertion(assertionCbor: assertion,
                                                            clientData: statement,
                                                            publicPoint: enroll.publicPoint,
                                                            appId: appId, expectedCounter: 5)
        XCTAssertEqual(recovered, 5)
    }
}

final class CounterStoreTests: XCTestCase {

    func testFreshKeyPredictsOneAndAdvanceEnforcesPlusOne() throws {
        let storeDir = try makeTempDir("store")
        let store = try AssertionCounterStore(directory: storeDir)
        let keyId = "k1"
        var lastState: AssertionCounterState?
        do {
            let lock = try store.lock(keyId: keyId, deadline: .now + .seconds(5))
            XCTAssertNil(lock.state)
            XCTAssertEqual(try AssertionCounterStore.predictedCounterForFreshKey(lock.state), 1)
            XCTAssertThrowsError(try AssertionCounterStore.predictedCounter(from: lock.state, keyId: keyId))
            lastState = try lock.advance(verifiedCounter: 1,
                                         assertionSHA256: String(repeating: "a", count: 64))
        }   // the per-key flock releases when the KeyLock deinits at block end
        XCTAssertEqual(lastState?.lastVerifiedCounter, 1)
        let lock2 = try store.lock(keyId: keyId, deadline: .now + .seconds(5))
        XCTAssertEqual(lock2.state?.lastVerifiedCounter, 1)
        XCTAssertEqual(try AssertionCounterStore.predictedCounter(from: lock2.state, keyId: keyId), 2)
        XCTAssertThrowsError(try lock2.advance(verifiedCounter: 1,
                                               assertionSHA256: String(repeating: "b", count: 64)))
    }

    func testCorruptStateIsRefusedNeverInvented() throws {
        let storeDir = try makeTempDir("store-corrupt")
        let store = try AssertionCounterStore(directory: storeDir)
        let keyId = "k2"
        let lock = try store.lock(keyId: keyId, deadline: .now + .seconds(5))
        _ = try lock.advance(verifiedCounter: 1, assertionSHA256: String(repeating: "c", count: 64))
        let stateURL = storeDir.appendingPathComponent(store.fileBase(for: keyId) + ".json")
        var corrupt = try Data(contentsOf: stateURL)
        corrupt[corrupt.count - 2] ^= 0xff
        try corrupt.write(to: stateURL)
        XCTAssertThrowsError(try store.lock(keyId: keyId, deadline: .now + .seconds(5)))
    }
}

// MARK: - end-to-end flow over the SAME fixture bytes

final class ControlAttestFlowTests: XCTestCase {

    private func flowFacts(fx: HvFFixture, counter: Int,
                           controlFrames: Int? = nil, terminalPayload: Data? = nil,
                           runId: String? = nil) throws -> HvFRunFacts {
        let env = fx.environment
        return HvFRunFacts(
            runId: runId ?? (fx.run["run_id"] as! String), nonceHex: fx.run["nonce"] as! String,
            counter: counter, runChallenge: Data(count: 32),
            taskBytes: fx.hex("task_hex"),
            controlRecording: fx.hex("control_hex"),
            controlFrames: controlFrames ?? (fx.json["control_frames"] as! Int),
            terminalPayload: terminalPayload ?? Data((fx.json["terminal_record_canonical"] as! String).utf8),
            stdout: fx.hex("stdout_hex"), stderr: fx.hex("stderr_hex"),
            guestTrace: fx.hex("guest_trace_hex"),
            hostTraceLines: fx.hex("host_trace_lines_hex"),
            hostTraceHead: fx.hostTrace["head"] as! String,
            hostTraceEvents: fx.hostTrace["events"] as! Int,
            framesIn: fx.json["frames_in"] as! Int, bytesIn: fx.json["bytes_in"] as! Int,
            manifestSHA256: env["manifest_sha256"] as! String,
            pins: ["kernel_sha256": env["kernel_sha256"] as! String,
                   "initrd_sha256": env["initrd_sha256"] as! String,
                   "disk_sha256": env["disk_sha256"] as! String,
                   "cmdline_sha256": env["cmdline_sha256"] as! String,
                   "archive_sha256": env["archive_sha256"] as! String],
            ctlAbiVersion: env["ctl_abi_version"] as! Int)
    }

    /// The Python-encoded transcript must feed cleanly through the REAL
    /// production retainer (CRC, framing, collection) and reproduce exactly
    /// the collected bytes — cross-language same-path parity.
    func testTranscriptFeedsProductionRetainerWithParity() throws {
        let fx = try HvFFixture()
        let retainer = ControlSessionRetainer()
        try retainer.feed(fx.hex("control_hex"))
        try retainer.close()
        XCTAssertEqual(retainer.stdout, fx.hex("stdout_hex"))
        XCTAssertEqual(retainer.stderr, fx.hex("stderr_hex"))
        XCTAssertEqual(retainer.trace, fx.hex("guest_trace_hex"))
        XCTAssertEqual(retainer.frames, fx.json["control_frames"] as! Int)
        XCTAssertEqual(retainer.terminalFrames, 1)
        XCTAssertEqual(retainer.terminalPayload,
                       Data((fx.json["terminal_record_canonical"] as! String).utf8))
        let scan = try DSMX.scanGuestStream(fx.hex("control_hex"))
        XCTAssertEqual(scan.terminalFrames, 1)
        XCTAssertEqual(scan.postTerminalBytes, 0)
    }

    func testFlowEndToEndCounterRecoveryAndRollbacks() async throws {
        let fx = try HvFFixture()
        let appId = fx.identity["app_id"]!
        let hmacKey = fx.hex("hmac_key_hex")
        let producer = FixtureProducer(appId: appId, scalar: fixtureScalar(fx))

        // enroll receipt from the COMMITTED fixture snapshot, verified offline
        let enrollDir = try makeTempDir("enroll")
        try FileManager.default.createDirectory(at: enrollDir, withIntermediateDirectories: true)
        try (fx.enroll["key_id"] as! String + "\n").data(using: .utf8)!
            .write(to: enrollDir.appendingPathComponent("keyId.txt"))
        try fixtureData(fx, "client_data_hex")
            .write(to: enrollDir.appendingPathComponent("enroll-client-data.bin"))
        try fixtureData(fx, "enrollment_hex")
            .write(to: enrollDir.appendingPathComponent("enrollment.cbor"))
        let enroll = try EnrollReceipt.load(directory: enrollDir, appId: appId)
        let store = try AssertionCounterStore(directory: try makeTempDir("store"))
        let deadline = ContinuousClock.now + .seconds(10)
        let observation = ControlAttestRunObservation(
            runId: fx.run["run_id"] as! String, nonceHex: fx.run["nonce"] as! String,
            hmacKey: hmacKey,
            expectedProvider: ["streams": 0, "bytes_up": 0, "bytes_down": 0],
            stopReason: "guest-requested")

        func recorder() throws -> LifecycleRecorder {
            let r = LifecycleRecorder()
            try r.sessionStarted(runId: fx.run["run_id"] as! String)
            try r.taskInputCommitted(taskSHA256: fx.json["task_sha256"] as! String,
                                     taskBytes: fx.json["task_bytes"] as! Int)
            return r
        }

        // RUN 1: fresh dedicated key, counter 1, verified over exact bytes.
        let receipt1 = try makeTempDir("receipt1")
        let outcome1 = try await ControlAttestFlow.emitAndAttest(
            into: receipt1, observation: observation, facts: try flowFacts(fx: fx, counter: 0),
            recorder: try recorder(), enroll: enroll, keyPolicy: .freshDedicatedKey,
            counterStore: store, producer: producer, lockDeadline: deadline)
        XCTAssertEqual(outcome1.verifiedCounter, 1)
        XCTAssertEqual(outcome1.files, ControlAttestFlow.controlFiles)
        XCTAssertEqual(outcome1.files.count, 14)
        XCTAssertEqual(try Data(contentsOf: receipt1.appendingPathComponent("assertion.cbor")),
                       outcome1.assertionCbor)
        XCTAssertEqual(try Data(contentsOf: receipt1.appendingPathComponent("control_statement.json")),
                       outcome1.controlStatement)
        XCTAssertEqual(try Data(contentsOf: receipt1.appendingPathComponent("terminal.json")),
                       Data((fx.json["terminal_record_canonical"] as! String).utf8))

        // RUN 2: counter recovery — the store's verified history predicts 2.
        let receipt2 = try makeTempDir("receipt2")
        let outcome2 = try await ControlAttestFlow.emitAndAttest(
            into: receipt2, observation: observation, facts: try flowFacts(fx: fx, counter: 0),
            recorder: try recorder(), enroll: enroll, keyPolicy: .freshDedicatedKey,
            counterStore: store, producer: producer, lockDeadline: deadline)
        XCTAssertEqual(outcome2.verifiedCounter, 2)

        // RUN 3: a producer replaying counter 1 is REFUSED: rollback to empty,
        // store does not advance.
        struct ReplayProducer: AssertionProducer {
            let base: FixtureProducer
            let counter: Int
            func generateAssertion(keyId: String, clientDataHash: Data) async throws -> Data {
                base.assertion(clientDataHash: clientDataHash, counter: counter)
            }
        }
        let receipt3 = try makeTempDir("receipt3")
        do {
            _ = try await ControlAttestFlow.emitAndAttest(
                into: receipt3, observation: observation, facts: try flowFacts(fx: fx, counter: 0),
                recorder: try recorder(), enroll: enroll, keyPolicy: .freshDedicatedKey,
                counterStore: store, producer: ReplayProducer(base: producer, counter: 1),
                lockDeadline: deadline)
            XCTFail("counter replay must be refused")
        } catch let error as AppAttestError {
            XCTAssertEqual(error, .counterBinding(predicted: 3, recovered: 1))
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: receipt3.path).count, 0)
        let lockAfter = try store.lock(keyId: enroll.keyId, deadline: deadline)
        XCTAssertEqual(lockAfter.state?.lastVerifiedCounter, 2)

        // RUN 4: a failing producer rolls back cleanly too.
        struct FailingProducer: AssertionProducer {
            func generateAssertion(keyId: String, clientDataHash: Data) async throws -> Data {
                throw ControlAttestFlowError.assertionProducerFailed("injected")
            }
        }
        let receipt4 = try makeTempDir("receipt4")
        do {
            _ = try await ControlAttestFlow.emitAndAttest(
                into: receipt4, observation: observation, facts: try flowFacts(fx: fx, counter: 0),
                recorder: try recorder(), enroll: enroll, keyPolicy: .freshDedicatedKey,
                counterStore: store, producer: FailingProducer(), lockDeadline: deadline)
            XCTFail("failing producer must be refused")
        } catch {}
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: receipt4.path).count, 0)
    }

    func testFlowRefusesHostHaltStopReason() async throws {
        let fx = try HvFFixture()
        let appId = fx.identity["app_id"]!
        let producer = FixtureProducer(appId: appId, scalar: fixtureScalar(fx))
        let enroll = try Self.commitEnroll(fx: fx, tag: "enroll2")
        let store = try AssertionCounterStore(directory: try makeTempDir("store2"))
        let observation = ControlAttestRunObservation(
            runId: fx.run["run_id"] as! String, nonceHex: fx.run["nonce"] as! String,
            hmacKey: fx.hex("hmac_key_hex"),
            expectedProvider: ["streams": 0, "bytes_up": 0, "bytes_down": 0],
            stopReason: "host-halt")
        let receipt = try makeTempDir("receipt5")
        do {
            _ = try await ControlAttestFlow.emitAndAttest(
                into: receipt, observation: observation, facts: try flowFacts(fx: fx, counter: 0),
                recorder: LifecycleRecorder(), enroll: enroll, keyPolicy: .freshDedicatedKey,
                counterStore: store, producer: producer,
                lockDeadline: .now + .seconds(10))
            XCTFail("host-halt must not be success authority")
        } catch let error as ControlAttestFlowError {
            XCTAssertEqual(error, .stopReasonNotGuestRequested("host-halt"))
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: receipt.path).count, 0)
    }

    // MARK: F4 — emitted terminal/identity/counts derive from the authenticated
    // transcript; caller-supplied duplicates are cross-checked, never trusted.

    /// F4 positive: with NO parallel duplicate facts supplied (empty
    /// terminalPayload, controlFrames 0), the flow derives everything emitted
    /// from the authenticated transcript — the receipt's terminal.json IS the
    /// transcript's terminal record and the statement is byte-identical to the
    /// Python builder's committed golden.
    func testFlowDerivesEmittedTerminalIdentityAndCountsFromTranscript() async throws {
        let fx = try HvFFixture()
        let producer = FixtureProducer(appId: fx.identity["app_id"]!, scalar: fixtureScalar(fx))
        let enroll = try Self.commitEnroll(fx: fx, tag: "enroll-f4")
        let store = try AssertionCounterStore(directory: try makeTempDir("store-f4"))
        let observation = ControlAttestRunObservation(
            runId: fx.run["run_id"] as! String, nonceHex: fx.run["nonce"] as! String,
            hmacKey: fx.hex("hmac_key_hex"),
            expectedProvider: ["streams": 0, "bytes_up": 0, "bytes_down": 0],
            stopReason: "guest-requested")
        let receipt = try makeTempDir("receipt-f4")
        let outcome = try await ControlAttestFlow.emitAndAttest(
            into: receipt, observation: observation,
            facts: try flowFacts(fx: fx, counter: 0, controlFrames: 0, terminalPayload: Data()),
            recorder: try Self.startedRecorder(fx: fx), enroll: enroll,
            keyPolicy: .freshDedicatedKey, counterStore: store, producer: producer,
            lockDeadline: .now + .seconds(10))
        XCTAssertEqual(outcome.verifiedCounter, 1)
        XCTAssertEqual(try Data(contentsOf: receipt.appendingPathComponent("terminal.json")),
                       Data((fx.json["terminal_record_canonical"] as! String).utf8),
                       "emitted terminal must be the transcript's authenticated record")
        XCTAssertEqual(outcome.controlStatement, fx.expectedStatement,
                       "derived-facts statement must equal the Python builder's exact bytes")
        if let dump = ProcessInfo.processInfo.environment["MAR_JOIN_DUMP_DIR"], !dump.isEmpty {
            // Join-evidence hook: hand the completed Swift-emitted receipt to
            // the REAL Python verifier/CLI on the integration host (genuine
            // cross-language interop, not a mocked builder).
            let dst = URL(fileURLWithPath: dump, isDirectory: true)
            try FileManager.default.createDirectory(at: dst, withIntermediateDirectories: true)
            for f in outcome.files {
                try Data(contentsOf: receipt.appendingPathComponent(f))
                    .write(to: dst.appendingPathComponent(f))
            }
        }
    }

    /// F4 negatives: a caller-supplied duplicate that DISAGREES with the
    /// authenticated source is refused — a valid transcript can never ride
    /// alongside a different emitted payload/identity/count.
    func testFlowRefusesDuplicateFactsDisagreeingWithAuthenticatedSource() async throws {
        let fx = try HvFFixture()
        let producer = FixtureProducer(appId: fx.identity["app_id"]!, scalar: fixtureScalar(fx))
        let enroll = try Self.commitEnroll(fx: fx, tag: "enroll-f4n")
        let store = try AssertionCounterStore(directory: try makeTempDir("store-f4n"))
        let observation = ControlAttestRunObservation(
            runId: fx.run["run_id"] as! String, nonceHex: fx.run["nonce"] as! String,
            hmacKey: fx.hex("hmac_key_hex"),
            expectedProvider: ["streams": 0, "bytes_up": 0, "bytes_down": 0],
            stopReason: "guest-requested")
        var wrongTerminal = Data((fx.json["terminal_record_canonical"] as! String).utf8)
        wrongTerminal[24] ^= 0x20
        let cases: [String: () throws -> HvFRunFacts] = [
            "terminal-payload": { try self.flowFacts(fx: fx, counter: 0, terminalPayload: wrongTerminal) },
            "frame-count": { try self.flowFacts(fx: fx, counter: 0,
                                                controlFrames: (fx.json["control_frames"] as! Int) + 1) },
            "run-identity": { try self.flowFacts(fx: fx, counter: 0, runId: "deadbeefdeadbeef") },
        ]
        for (name, facts) in cases {
            let receipt = try makeTempDir("receipt-f4n-\(name)")
            do {
                _ = try await ControlAttestFlow.emitAndAttest(
                    into: receipt, observation: observation, facts: try facts(),
                    recorder: try Self.startedRecorder(fx: fx), enroll: enroll,
                    keyPolicy: .freshDedicatedKey, counterStore: store, producer: producer,
                    lockDeadline: .now + .seconds(10))
                XCTFail("\(name) disagreement with the authenticated source must be refused")
            } catch let error as ControlAttestFlowError {
                guard case .duplicateFactsMismatch = error else {
                    return XCTFail("\(name): wrong error \(error)")
                }
            }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: receipt.path).count, 0,
                           "\(name): refusal must roll the receipt back to empty")
        }
    }

    // MARK: F10 — rollback must be real: counter-persistence failure rolls the
    // receipt back; an enumeration failure is rollbackFailed, never "clean".

    /// The F10 reproducer: `lock.advance` (counter persistence) fails AFTER a
    /// complete assertion-bearing receipt exists. The flow must roll the
    /// receipt back to empty and leave the store at its last VERIFIED state.
    func testFlowRollsBackReceiptWhenCounterPersistenceFails() async throws {
        let fx = try HvFFixture()
        let producer = FixtureProducer(appId: fx.identity["app_id"]!, scalar: fixtureScalar(fx),
                                       firstCounter: 2)   // the store's history predicts 2
        let enroll = try Self.commitEnroll(fx: fx, tag: "enroll-advfail")
        let storeDir = try makeTempDir("store-advfail")
        let store = try AssertionCounterStore(directory: storeDir)
        let deadline = ContinuousClock.now + .seconds(10)
        do {   // seed verified history: counter 1 committed
            let lock = try store.lock(keyId: enroll.keyId, deadline: deadline)
            _ = try lock.advance(verifiedCounter: 1, assertionSHA256: String(repeating: "d", count: 64))
        }
        // Injection: the store directory becomes unwritable, so the verified
        // advance's temp+rename persistence cannot commit.
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: storeDir.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: storeDir.path) }
        let receipt = try makeTempDir("receipt-advfail")
        var thrown: Error?
        do {
            _ = try await ControlAttestFlow.emitAndAttest(
                into: receipt,
                observation: ControlAttestRunObservation(
                    runId: fx.run["run_id"] as! String, nonceHex: fx.run["nonce"] as! String,
                    hmacKey: fx.hex("hmac_key_hex"),
                    expectedProvider: ["streams": 0, "bytes_up": 0, "bytes_down": 0],
                    stopReason: "guest-requested"),
                facts: try flowFacts(fx: fx, counter: 0),
                recorder: try Self.startedRecorder(fx: fx), enroll: enroll,
                keyPolicy: .freshDedicatedKey, counterStore: store, producer: producer,
                lockDeadline: deadline)
        } catch { thrown = error }
        XCTAssertNotNil(thrown, "counter persistence failure must fail the flow")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: receipt.path).count, 0,
                       "a receipt whose counter never committed must be rolled back")
        let lockAfter = try store.lock(keyId: enroll.keyId, deadline: deadline)
        XCTAssertEqual(lockAfter.state?.lastVerifiedCounter, 1,
                       "the store must keep only its last VERIFIED state")
    }

    // MARK: F7 — the emitter records the caller's CHECKED stop observation.

    func testWriteReceiptRefusesToManufactureStopReason() throws {
        let fx = try HvFFixture()
        XCTAssertThrowsError(try HvFControlEmit.writeReceipt(
            into: try makeTempDir("receipt-stop"),
            recorder: try Self.startedRecorder(fx: fx),
            keyId: fx.identity["key_id"]!, appId: fx.identity["app_id"]!,
            facts: try flowFacts(fx: fx, counter: 1),
            stopReason: "host-halt")) { error in
            XCTAssertEqual(error as? HvFControlEmitError,
                           .badFact("stop_reason host-halt is not guest-requested"))
        }
    }

    // MARK: shared setup helpers

    /// The committed-fixture enroll receipt: keyId + client data + enrollment
    /// CBOR staged exactly as the deployment would, then verified offline.
    private static func commitEnroll(fx: HvFFixture, tag: String) throws -> EnrollReceipt {
        let enrollDir = try makeTempDir(tag)
        try FileManager.default.createDirectory(at: enrollDir, withIntermediateDirectories: true)
        try (fx.enroll["key_id"] as! String + "\n").data(using: .utf8)!
            .write(to: enrollDir.appendingPathComponent("keyId.txt"))
        try fixtureData(fx, "client_data_hex")
            .write(to: enrollDir.appendingPathComponent("enroll-client-data.bin"))
        try fixtureData(fx, "enrollment_hex")
            .write(to: enrollDir.appendingPathComponent("enrollment.cbor"))
        return try EnrollReceipt.load(directory: enrollDir, appId: fx.identity["app_id"]!)
    }

    /// A recorder carrying the run's first two lifecycle stages (what the
    /// mode observed before the emitter appends teardown stages 3–6).
    private static func startedRecorder(fx: HvFFixture) throws -> LifecycleRecorder {
        let r = LifecycleRecorder()
        try r.sessionStarted(runId: fx.run["run_id"] as! String)
        try r.taskInputCommitted(taskSHA256: fx.json["task_sha256"] as! String,
                                 taskBytes: fx.json["task_bytes"] as! Int)
        return r
    }
}

// MARK: - F10 unit: rollback enumeration failure is explicit

final class RollbackEnumerationTests: XCTestCase {

    func testRollbackEnumerationFailureIsRollbackFailedNeverSilentCleanup() throws {
        let dir = try makeTempDir("rollback-enum")
        try Data("survivor".utf8).write(to: dir.appendingPathComponent("leftover.bin"))
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: dir.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path) }
        XCTAssertThrowsError(try ControlAttestFlow.rollbackOrThrow(
            dir, after: ControlAttestFlowError.assertionProducerFailed("injected"))) { error in
            guard case ControlAttestFlowError.rollbackFailed(let m) = error else {
                return XCTFail("expected rollbackFailed, got \(error)")
            }
            XCTAssertTrue(m.contains("enumeration failed"), m)
            XCTAssertTrue(m.contains("assertion producer failed: injected"), m)
        }
    }
}

// MARK: - repair2 executable-wiring repairs (R2-A5-STATE, R2-A2-CHALLENGE)

/// The counter store's STABLE per-key location: state written by one store
/// instance under the key's own staging directory must be visible to a LATER
/// store instance (the executable's next invocation), and the directory must
/// live beside the key, never inside a fresh per-run output directory.
final class StableCounterStateTests: XCTestCase {

    func testStatePersistsAcrossStoreInstancesAtTheStableDirectory() throws {
        let keyIdDir = try makeTempDir("keyid-stable")
        let keyId = "stability-probe-key"
        let stable = AssertionCounterStore.stableDirectory(forKeyIdDirectory: keyIdDir)
        // under the key's own directory, by construction
        XCTAssertTrue(stable.path.hasPrefix(keyIdDir.path), stable.path)

        let first = try AssertionCounterStore(directory: stable)
        let advanced: AssertionCounterState? = try first.withExclusiveKeyLock(
            keyId: keyId, deadline: .now + .seconds(5),
            body: { $0 },
            verifiedAdvance: { state, _ in
                if state != nil { XCTFail("expected fresh key") }
                return AssertionCounterState(keyId: keyId, lastVerifiedCounter: 1,
                                             lastAssertionSHA256: String(repeating: "a", count: 64),
                                             updates: 1)
            }).1
        XCTAssertEqual(advanced?.lastVerifiedCounter, 1)

        // A SECOND instance (the executable's next invocation) sees the history:
        // no re-prediction of counter 1 for a reused key.
        let second = try AssertionCounterStore(directory: stable)
        try second.withExclusiveKeyLock(
            keyId: keyId, deadline: .now + .seconds(5),
            body: { state in
                XCTAssertNotNil(state, "counter history was lost across store instances")
                XCTAssertEqual(state?.lastVerifiedCounter, 1)
                XCTAssertEqual(try AssertionCounterStore.predictedCounter(from: state, keyId: keyId), 2)
            },
            verifiedAdvance: { state, _ in
                AssertionCounterState(keyId: keyId, lastVerifiedCounter: 2,
                                      lastAssertionSHA256: String(repeating: "b", count: 64),
                                      updates: (state?.updates ?? 0) + 1)
            })
    }

    func testStableDirectoryIsNeverInsideARunOutputDirectory() {
        let keyIdDir = URL(fileURLWithPath: "/operator/enrollment-staging/key-xyz")
        let stable = AssertionCounterStore.stableDirectory(forKeyIdDirectory: keyIdDir)
        XCTAssertEqual(stable.lastPathComponent, "counter-state")
        XCTAssertEqual(stable.deletingLastPathComponent().standardizedFileURL.path,
                       keyIdDir.standardizedFileURL.path)
    }
}

/// The run-challenge input conversion: the validated bytes are the RAW file
/// bytes, and the statement's run_challenge_sha256 commits to THEM — the hex
/// rendering hashes differently and must never enter the facts (R2-A2-CHALLENGE).
final class RunChallengeBytesTests: XCTestCase {

    func testValidatedRunChallengeReadsTheRawBytes() throws {
        let raw = Data((0..<32).map { UInt8($0) })          // 32 raw bytes
        let dir = try makeTempDir("challenge")
        let path = dir.appendingPathComponent("challenge.bin").path
        try raw.write(to: URL(fileURLWithPath: path))
        let got = try HvFControlEmit.validatedRunChallenge(atPath: path)
        XCTAssertEqual(got, raw)
        // The commitment the verifier checks: sha256 over the RAW bytes.
        XCTAssertEqual(SHA256.hex(got), SHA256.hex(raw))
        // ...and provably NOT the hex rendering's digest.
        XCTAssertNotEqual(SHA256.hex(got), SHA256.hex(Data(hex(raw).utf8)))
    }

    func testValidatedRunChallengeRefusesWrongLength() throws {
        let dir = try makeTempDir("challenge-bad")
        for n in [0, 16, 31, 33] {
            let path = dir.appendingPathComponent("c\(n).bin").path
            try Data(repeating: 7, count: n).write(to: URL(fileURLWithPath: path))
            XCTAssertThrowsError(try HvFControlEmit.validatedRunChallenge(atPath: path)) { error in
                guard case HvFControlEmitError.badFact(let m) = error else {
                    return XCTFail("expected badFact, got \(error)")
                }
                XCTAssertTrue(m.contains("32 bytes"), m)
            }
        }
    }

    private func hex(_ d: Data) -> String {
        d.map { String(format: "%02x", $0) }.joined()
    }
}
