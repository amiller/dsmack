// Astra-gate R3/R4 tests for the ACTUAL Swift host adapter:
//   * the golden terminal (produced AND signed by the real channel-lane code)
//     verifies over the bytes the adapter collected — HMAC, run identity, task
//     commitment, output/trace commitments, provider counters, canonicality;
//   * every negative the reviewer demanded is refused by THIS adapter:
//     invalid terminal, replay (foreign nonce/run id), corruption (header and
//     payload CRC), tampered collected bytes, forged authenticator,
//     non-canonical record, excess frames (aggregate caps), and backpressure
//     (non-blocking, deadline-bounded socketpair I/O);
//   * descriptor accounting: the host endpoint closes exactly once.
// Golden bytes come from TerminalVectors.swift (generated from
// tests/golden/terminal-auth-vectors.json); if an assertion fails, the Swift
// side has drifted from the contract — fix the Swift side, never the golden.
import XCTest

@testable import marControl

struct TestIOError: Error, CustomStringConvertible { let description: String; init(_ s: String) { description = s } }

final class ControlSessionTests: XCTestCase {

    // MARK: positive — the real signed session verifies

    func testGoldenSessionCollectedAndTerminalAuthenticated() throws {
        let r = ControlSessionRetainer()
        try r.feed(TermVectors.guestStream)
        try r.close()
        XCTAssertEqual(r.frames, TermVectors.guestFrames)
        XCTAssertEqual(r.bytes, TermVectors.guestBytes)
        XCTAssertEqual(r.terminalFrames, 1)
        XCTAssertEqual(r.stdout, TermVectors.stdout)
        XCTAssertEqual(r.stderr, TermVectors.stderr)
        XCTAssertEqual(r.trace, TermVectors.trace)
        XCTAssertEqual(r.postTerminalBytes, 0)
        let rec = try r.verifyTerminal(hmacKey: TermVectors.hmacKey,
                                       runId: TermVectors.runId,
                                       nonce: TermVectors.nonce,
                                       taskSHA256: TermVectors.taskSHA256,
                                       expectedProvider: ["streams": 0, "bytes_up": 0, "bytes_down": 0])
        XCTAssertEqual(rec.status, "completed")
        XCTAssertEqual(rec.exitStatus, 0)
        XCTAssertEqual(rec.authenticatorHex, TermVectors.authenticator)
        XCTAssertEqual(try DSMX.terminalPayload(of: r.retained), TermVectors.terminalPayload)
        // the collected stdout commitment is the artifact the worker produced
        XCTAssertEqual(rec.artifacts.first?.first as? String, "result.json")
    }

    // MARK: split deliveries (chunk boundaries must not matter)

    func testFeedingByteByByteStillVerifies() throws {
        let r = ControlSessionRetainer()
        for b in TermVectors.guestStream { try r.feed(Data([b])) }
        try r.close()
        let rec = try r.verifyTerminal(hmacKey: TermVectors.hmacKey,
                                       runId: TermVectors.runId,
                                       nonce: TermVectors.nonce,
                                       taskSHA256: TermVectors.taskSHA256,
                                       expectedProvider: [:])
        XCTAssertEqual(rec.status, "completed")
    }

    // MARK: corruption — CRC must fail the feed

    func testPayloadCRCFlipRejected() {
        var stream = [UInt8](TermVectors.guestStream)
        stream[stream.count - 3] ^= 0x40   // payload area of the terminal frame
        let r = ControlSessionRetainer()
        XCTAssertThrowsError(try r.feed(Data(stream))) { error in
            XCTAssertTrue("\(error)".contains("crc"), "got \(error)")
        }
    }

    func testHeaderCRCFlipRejected() {
        var stream = [UInt8](TermVectors.guestStream)
        stream[12] ^= 0x01   // header CRC byte of the first frame
        let r = ControlSessionRetainer()
        XCTAssertThrowsError(try r.feed(Data(stream))) { error in
            XCTAssertTrue("\(error)".contains("crc"), "got \(error)")
        }
    }

    func testHeaderCRCFlipInLaterFrameRejectedAfterEarlierFramesAccepted() {
        var stream = [UInt8](TermVectors.guestStream)
        // flip the header CRC of the SECOND frame only
        var off = 0
        let first = Int(stream[8]) << 24 | Int(stream[9]) << 16 | Int(stream[10]) << 8 | Int(stream[11])
        off = 16 + first + 4 + 12
        stream[off] ^= 0x80
        let r = ControlSessionRetainer()
        XCTAssertThrowsError(try r.feed(Data(stream)))
        // feed must have processed the first frame before failing on the second
        XCTAssertEqual(r.frames, 1)
    }

    // MARK: authentication negatives

    func testWrongKeyIsForgery() throws {
        let r = ControlSessionRetainer()
        try r.feed(TermVectors.guestStream)
        var key = TermVectors.hmacKey
        key[0] ^= 1
        XCTAssertThrowsError(try r.verifyTerminal(hmacKey: key, runId: TermVectors.runId,
                                                  nonce: TermVectors.nonce,
                                                  taskSHA256: TermVectors.taskSHA256,
                                                  expectedProvider: [:])) { e in
            XCTAssertTrue("\(e)".contains("authenticator"), "got \(e)")
        }
    }

    func testReplayForeignNonceRejected() throws {
        let r = ControlSessionRetainer()
        try r.feed(TermVectors.guestStream)
        XCTAssertThrowsError(try r.verifyTerminal(hmacKey: TermVectors.hmacKey,
                                                  runId: TermVectors.runId,
                                                  nonce: String(repeating: "0", count: 32),
                                                  taskSHA256: TermVectors.taskSHA256,
                                                  expectedProvider: [:])) { e in
            XCTAssertTrue("\(e)".contains("nonce"), "got \(e)")
        }
    }

    func testReplayForeignRunIdRejected() throws {
        let r = ControlSessionRetainer()
        try r.feed(TermVectors.guestStream)
        XCTAssertThrowsError(try r.verifyTerminal(hmacKey: TermVectors.hmacKey,
                                                  runId: String(repeating: "a", count: 32),
                                                  nonce: TermVectors.nonce,
                                                  taskSHA256: TermVectors.taskSHA256,
                                                  expectedProvider: [:]))
    }

    func testTamperedCollectedStdoutBreaksCommitment() throws {
        let r = ControlSessionRetainer()
        var stream = [UInt8](TermVectors.guestStream)
        // flip one byte inside the stdout OUTPUT_CHUNK payload, then re-fix the
        // CRCs of that frame so the frame itself stays valid: only the COMMITTED
        // content changed — the commitment check (not the CRC) must catch it.
        var off = 0
        for _ in 0..<TermVectors.guestFrames {
            let len = Int(stream[off + 8]) << 24 | Int(stream[off + 9]) << 16
                | Int(stream[off + 10]) << 8 | Int(stream[off + 11])
            if stream[off + 7] == 5 {   // OUTPUT_CHUNK
                stream[off + 17] ^= 0x01
                var frame = Array(stream[off..<off + 16 + len + 4])
                let headerPrefix = Array(frame[0..<12])
                var hc = CRC32.checksum(Data(headerPrefix))
                frame[12] = UInt8((hc >> 24) & 0xff); frame[13] = UInt8((hc >> 16) & 0xff)
                frame[14] = UInt8((hc >> 8) & 0xff); frame[15] = UInt8(hc & 0xff)
                let payload = Array(frame[16..<16 + len])
                let pc = CRC32.checksum(Data(payload))
                frame[16 + len] = UInt8((pc >> 24) & 0xff); frame[16 + len + 1] = UInt8((pc >> 16) & 0xff)
                frame[16 + len + 2] = UInt8((pc >> 8) & 0xff); frame[16 + len + 3] = UInt8(pc & 0xff)
                stream.replaceSubrange(off..<off + 16 + len + 4, with: frame)
                break
            }
            off += 16 + len + 4
        }
        XCTAssertNoThrow(try r.feed(Data(stream)))   // CRC-valid frames
        XCTAssertThrowsError(try r.verifyTerminal(hmacKey: TermVectors.hmacKey,
                                                  runId: TermVectors.runId,
                                                  nonce: TermVectors.nonce,
                                                  taskSHA256: TermVectors.taskSHA256,
                                                  expectedProvider: [:])) { e in
            XCTAssertTrue("\(e)".contains("commitment") || "\(e)".contains("collected"), "got \(e)")
        }
    }

    func testTamperedTaskCommitmentRejected() throws {
        let r = ControlSessionRetainer()
        try r.feed(TermVectors.guestStream)
        XCTAssertThrowsError(try r.verifyTerminal(hmacKey: TermVectors.hmacKey,
                                                  runId: TermVectors.runId,
                                                  nonce: TermVectors.nonce,
                                                  taskSHA256: String(repeating: "0", count: 64),
                                                  expectedProvider: [:])) { e in
            XCTAssertTrue("\(e)".contains("task"), "got \(e)")
        }
    }

    func testProviderAccountingMismatchRejected() throws {
        let r = ControlSessionRetainer()
        try r.feed(TermVectors.guestStream)
        XCTAssertThrowsError(try r.verifyTerminal(hmacKey: TermVectors.hmacKey,
                                                  runId: TermVectors.runId,
                                                  nonce: TermVectors.nonce,
                                                  taskSHA256: TermVectors.taskSHA256,
                                                  expectedProvider: ["streams": 3, "bytes_up": 9, "bytes_down": 9]))
    }

    func testNonCanonicalRecordRejected() throws {
        // the golden terminal with one byte of pretty-print whitespace inserted:
        // same values, different byte string -> not canonical -> refused even
        // though the MAC would verify.
        let payload = TermVectors.terminalPayload
        let brace = Data("\"".utf8)
        guard let firstQuote = payload.range(of: brace) else { return XCTFail() }
        var mangled = payload.subdata(in: payload.startIndex..<firstQuote.lowerBound)
        mangled.append(Data(" ".utf8))
        mangled.append(payload.subdata(in: firstQuote.lowerBound..<payload.endIndex))
        XCTAssertThrowsError(try TerminalAuth.verify(payload: mangled, hmacKey: TermVectors.hmacKey,
                                                     runId: TermVectors.runId, nonce: TermVectors.nonce,
                                                     taskSHA256: TermVectors.taskSHA256,
                                                     collectedStdout: TermVectors.stdout,
                                                     collectedStderr: TermVectors.stderr,
                                                     collectedTrace: TermVectors.trace,
                                                     expectedProvider: [:])) { e in
            XCTAssertTrue("\(e)".contains("canonical") || "\(e)".contains("unparseable"), "got \(e)")
        }
    }

    func testStructurallyMalformedArtifactsRejectedEvenWithValidHMAC() throws {
        // a record the host itself builds (valid HMAC) but with a malformed
        // artifact digest: the structural check must refuse it regardless.
        // commitments are GENUINE (so the run reaches the artifact check);
        // only the artifact row is malformed.
        let stdout = Data("abc".utf8)
        var record: [String: Any] = [
            "schema": "dsmx-terminal-v1",
            "run_id": TermVectors.runId,
            "nonce": TermVectors.nonce,
            "task_sha256": TermVectors.taskSHA256,
            "status": "completed",
            "exit_status": 0,
            "started": 1760000000.125,
            "finished": 1760000000.5,
            "output": ["stdout": TerminalAuth.streamCommitment(stdout),
                       "stderr": TerminalAuth.streamCommitment(Data())],
            "trace": TerminalAuth.streamCommitment(Data()),
            "artifacts": [["result.json", "tooshort", 3]],
            "provider": ["streams": 0, "requests": 0, "bytes_up": 0, "bytes_down": 0],
        ]
        record["authenticator"] = HMACSHA256.hexDigest(
            key: TermVectors.hmacKey,
            message: try PyJSON.canonical(record.filter { $0.key != "authenticator" }))
        let signed = try PyJSON.canonical(record)
        XCTAssertThrowsError(try TerminalAuth.verify(
            payload: signed, hmacKey: TermVectors.hmacKey, runId: TermVectors.runId,
            nonce: TermVectors.nonce, taskSHA256: TermVectors.taskSHA256,
            collectedStdout: stdout, collectedStderr: Data(), collectedTrace: Data(),
            expectedProvider: [:])) { e in
            XCTAssertTrue("\(e)".contains("artifact"), "got \(e)")
        }
    }

    // MARK: structural stream negatives

    func testMissingTerminalAtEOFFailsClose() {
        let r = ControlSessionRetainer()
        // everything before the terminal: feed all but the last frame
        var off = 0
        let s = [UInt8](TermVectors.guestStream)
        for _ in 0..<(TermVectors.guestFrames - 1) {
            let len = Int(s[off + 8]) << 24 | Int(s[off + 9]) << 16 | Int(s[off + 10]) << 8 | Int(s[off + 11])
            off += 16 + len + 4
        }
        XCTAssertNoThrow(try r.feed(Data(s[..<off])))
        XCTAssertThrowsError(try r.close()) { e in
            XCTAssertTrue("\(e)".contains("terminal"), "got \(e)")
        }
    }

    func testTruncatedTailAtEOFFailsClose() throws {
        let s = [UInt8](TermVectors.guestStream)
        let r = ControlSessionRetainer()
        XCTAssertNoThrow(try r.feed(Data(s.dropLast(3))))
        XCTAssertThrowsError(try r.close())
    }

    func testBytesAfterTerminalAreFatal() throws {
        let r = ControlSessionRetainer()
        XCTAssertThrowsError(try r.feed(TermVectors.guestStream + Data(repeating: 0x41, count: 8))) { e in
            XCTAssertTrue("\(e)".contains("after terminal"), "got \(e)")
        }
        XCTAssertEqual(r.postTerminalBytes, 8)
    }

    func testSecondTerminalIsAPostTerminalViolation() throws {
        let s = [UInt8](TermVectors.guestStream)
        let r = ControlSessionRetainer()
        XCTAssertThrowsError(try r.feed(TermVectors.guestStream + TermVectors.guestStream))
        XCTAssertEqual(r.terminalFrames, 1)
        XCTAssertTrue(r.postTerminalBytes > 0)
    }

    // MARK: aggregate + per-stream caps

    func testAggregateFrameCapExceeded() {
        var limits = ControlSessionRetainer.Limits()
        limits.maxFrames = 3
        let r = ControlSessionRetainer(limits: limits)
        var s = [UInt8](TermVectors.guestStream)
        // strip the terminal (last frame) so only legal non-terminal frames remain
        var off = 0, cut = s.count
        for i in 0..<TermVectors.guestFrames {
            let len = Int(s[off + 8]) << 24 | Int(s[off + 9]) << 16 | Int(s[off + 10]) << 8 | Int(s[off + 11])
            if i == TermVectors.guestFrames - 1 { cut = off }
            off += 16 + len + 4
        }
        XCTAssertThrowsError(try r.feed(Data(s[..<cut]))) { e in
            XCTAssertTrue("\(e)".contains("frame cap"), "got \(e)")
        }
    }

    func testAggregateRetentionByteCapExceeded() {
        var limits = ControlSessionRetainer.Limits()
        limits.maxRetainedBytes = 400
        let r = ControlSessionRetainer(limits: limits)
        XCTAssertThrowsError(try r.feed(TermVectors.guestStream)) { e in
            XCTAssertTrue("\(e)".contains("retention cap"), "got \(e)")
        }
        // the retained stream never exceeded the cap
        XCTAssertLessThanOrEqual(r.retained.count, 400)
    }

    func testOutputStreamCapExceeded() throws {
        var limits = ControlSessionRetainer.Limits()
        limits.maxOutputBytesPerStream = 8
        let r = ControlSessionRetainer(limits: limits)
        var chunk = Data([0])
        chunk.append(Data(repeating: 0x61, count: 9))
        // OUTPUT_CHUNK is guest->host: build the frame bytes directly
        let guest = Self.guestFrame(kind: .outputChunk, payload: chunk)
        XCTAssertThrowsError(try r.feed(guest)) { e in
            XCTAssertTrue("\(e)".contains("cap"), "got \(e)")
        }
    }

    func testUnknownOutputSelectorRejected() {
        let payload = Data([7]) + Data(repeating: 0x62, count: 4)
        let frame = Self.guestFrame(kind: .outputChunk, payload: payload)
        let r = ControlSessionRetainer()
        XCTAssertThrowsError(try r.feed(frame)) { e in
            XCTAssertTrue("\(e)".contains("selector"), "got \(e)")
        }
    }

    static func guestFrame(kind: DSMXKind, payload: Data) -> Data {
        var header = Data("DSMX".utf8)
        header.appendBE(UInt16(1))
        header.appendBE(kind.rawValue)
        header.appendBE(UInt32(payload.count))
        var frame = header
        frame.appendBE(CRC32.checksum(header))
        frame.append(payload)
        frame.appendBE(CRC32.checksum(payload))
        return frame
    }

    // MARK: Python-canonical JSON parity

    func testCanonicalJSONMatchesPythonByteForByte() throws {
        for c in TermVectors.canonicalCases {
            // stderr is not captured by XCTest: the last CASE line before any
            // abnormal exit names the offending input directly in the log.
            FileHandle.standardError.write(Data("CASE \(c.json)\n".utf8))
            let value = try PyJSON.parse(Data(c.json.utf8))
            let encoded = try PyJSON.canonical(value)
            FileHandle.standardError.write(Data("  -> \(String(decoding: encoded, as: UTF8.self))\n".utf8))
            XCTAssertEqual(encoded, Data(c.python.utf8), c.json)
        }
    }

    func testStrictParseRejectsDuplicateKeysAndConstants() {
        XCTAssertThrowsError(try PyJSON.parse(Data("{\"a\":1,\"a\":2}".utf8)))
        XCTAssertThrowsError(try PyJSON.parse(Data("{\"a\":NaN}".utf8)))
        XCTAssertThrowsError(try PyJSON.parse(Data("{}".utf8) + Data("x".utf8)))
        XCTAssertThrowsError(try PyJSON.parse(Data("{\"a\":}".utf8)))
    }

    // MARK: non-blocking, deadline-bounded I/O over a real socketpair (R3)

    #if canImport(Darwin)
    func socketpair() throws -> (Int32, Int32) {
        var fds: [Int32] = [0, 0]
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            throw TestIOError("socketpair: \(String(cString: strerror(errno)))")
        }
        return (fds[0], fds[1])
    }

    func testSendUnderBackpressureCompletesWhenPeerDrains() throws {
        let (a, b) = try socketpair()
        try ControlIO.makeNonblocking(fd: a)
        let payload = Data(repeating: 0x5a, count: 256 * 1024)   // >> socket buffer
        let reader = Thread {
            var got = 0
            var buf = Data(count: 65536)
            while got < payload.count {
                let n = buf.withUnsafeMutableBytes { raw -> Int in
                    recv(b, raw.baseAddress, 4096, 0)   // deliberately small sips
                }
                if n > 0 { got += n }
                if n == 0 { break }
                usleep(200)   // slow reader: sustained backpressure
            }
        }
        reader.start()
        // a blocking socket would deadlock here on the buffer cap; non-blocking
        // + deadline-bounded poll must complete.
        try ControlIO.sendAll(fd: a, payload, deadline: ContinuousClock.now + .seconds(30))
        Thread.sleep(forTimeInterval: 0.3)   // let the reader finish its sips
        close(a); close(b)
    }

    func testSendToStalledPeerHitsDeadlineNotForever() throws {
        let (a, b) = try socketpair()
        try ControlIO.makeNonblocking(fd: a)
        let payload = Data(repeating: 0x5b, count: 512 * 1024)   // >> buffer, peer never reads
        XCTAssertThrowsError(try ControlIO.sendAll(fd: a, payload,
                                                   deadline: ContinuousClock.now + .milliseconds(400))) { e in
            XCTAssertTrue(e is ControlIO.Timeout, "got \(e)")
        }
        close(a); close(b)
    }

    func testRecvDeadlineAndEOF() throws {
        let (a, b) = try socketpair()
        try ControlIO.makeNonblocking(fd: a)
        XCTAssertNoThrow(try {
            let r = try ControlIO.recv(fd: a, deadline: ContinuousClock.now + .milliseconds(200))
            guard case .wouldBlock = r else { return XCTFail("expected wouldBlock") }
        }())
        try ControlIO.sendAll(fd: b, Data("hi".utf8), deadline: ContinuousClock.now + .seconds(5))
        let r = try ControlIO.recv(fd: a, deadline: ContinuousClock.now + .seconds(5))
        guard case .data(let d) = r else { return XCTFail("expected data") }
        XCTAssertEqual(d, Data("hi".utf8))
        close(b)   // peer closes -> EOF
        var gotEOF = false
        let deadline = ContinuousClock.now + .seconds(5)
        while ContinuousClock.now < deadline {
            if case .eof = try ControlIO.recv(fd: a, deadline: deadline) { gotEOF = true; break }
            usleep(1000)
        }
        XCTAssertTrue(gotEOF, "expected EOF after peer close")
        close(a)
    }

    // MARK: descriptor accounting (R4): the host endpoint closes exactly once

    func openFDCount() -> Int {
        (try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count) ?? -1
    }

    func testHostEndpointCloseRestoresFDCount() throws {
        let before = openFDCount()
        try (0..<16).forEach { _ in
            let (a, b) = try socketpair()
            let endpoint = ControlHostEndpoint(fd: a)
            endpoint.close()
            endpoint.close()   // idempotent
            Darwin.close(b)    // the test owns the peer; it must not count either
        }
        XCTAssertEqual(openFDCount(), before, "every endpoint close must free its descriptor")
    }

    func testHostEndpointDeinitClosesRemainder() throws {
        let before = openFDCount()
        try (0..<16).forEach { _ in
            let (a, b) = try socketpair()
            var endpoint: ControlHostEndpoint? = ControlHostEndpoint(fd: a)
            _ = endpoint
            endpoint = nil   // deinit must close the remainder now
            Darwin.close(b)  // the test-owned peer is released separately
        }
        XCTAssertEqual(openFDCount(), before, "deinit must close any remainder")
    }
    #endif
}
