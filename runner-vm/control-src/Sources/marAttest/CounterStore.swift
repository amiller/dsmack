// Serialized per-key App Attest assertion-counter state — the explicit
// resolution of the statement/assertion counter circularity.
//
// THE CIRCULARITY (stated plainly): the verifier requires
//   (a) assertion.counter == control_statement.run.counter  (counter_binding)
//   (b) assertion.counter >  verifier_prev_counter          (counter_replay)
// and the assertion itself signs sha256(exact control_statement bytes).
// DCAppAttestService exposes NO counter read API and no counter argument:
// the service assigns the next counter internally. The app therefore cannot
// observe the counter before building the statement it must sign.
//
// RESOLUTION (fail-closed, single-shot):
//   1. The counter in the statement is a PREDICTION:
//        fresh dedicated key (reviewed default): 1 — Apple sets the
//          enrollment authenticator's counter to 0 (attest_core requires
//          nonzero_initial_counter == refused), and the first production
//          vector in the verifier suite carries counter == 1;
//        existing key: lastVerifiedCounter + 1, where lastVerifiedCounter is
//          ONLY ever set from a locally signature-verified assertion (below).
//   2. After generateAssertion returns, the library verifies the assertion
//      offline (ECDSA P-256 by the enrollment-certified key over the exact
//      statement bytes) and requires recovered == predicted. A mismatch is a
//      REFUSAL: the receipt is rolled back, the store is NOT advanced, and
//      there is deliberately NO retry loop — re-emitting would append a
//      second lifecycle stage sequence (the verifier requires exactly the six
//      stages), so a mismatched run is over; the operator re-runs with a new
//      session or a fresh key. Bounded by construction.
//   3. The store advances only inside the same critical section, only to
//      (lastVerified + 1), only after that assertion verified. State is never
//      invented: a missing/corrupt record for a key that has already produced
//      assertions is a refusal (recover by verifier-verified evidence), never
//      a guess. An unsigned counter claim is never state.
//
// The verifier's authority is unchanged: it keeps its own prev_counter record
// and its own chain verification; if the two sides ever disagree, its
// counter_replay/counter_binding checks refuse — fail-closed everywhere.
//
// SERIALIZATION: one canonical-JSON file per key (name = sha256(keyId)),
// written temp+fsync+rename with the directory fsynced, under an exclusive
// flock held from prediction through verified advance, so concurrent runs on
// the same key serialize instead of racing the counter.
import Foundation
import marControl

public enum CounterStoreError: Error, Equatable, CustomStringConvertible {
    case badDirectory(String)
    case corrupt(String)
    case unknownKeyState(String)          // never invent state for a used key
    case lockTimeout(String)
    case ioFailure(String)
    case advanceViolation(from: Int, to: Int)

    public var description: String {
        switch self {
        case .badDirectory(let m): return "counter_store: bad directory: \(m)"
        case .corrupt(let m): return "counter_store: corrupt state: \(m)"
        case .unknownKeyState(let m):
            return "counter_store: \(m)"
        case .lockTimeout(let m): return "counter_store: lock deadline exceeded: \(m)"
        case .ioFailure(let m): return "counter_store: io: \(m)"
        case .advanceViolation(let f, let t):
            return "counter_store: advance from \(f) to \(t) is not exactly +1"
        }
    }
}

public struct AssertionCounterState: Equatable {
    public static let schema = "dsmack-attest-counter/1"
    public let keyId: String
    public let lastVerifiedCounter: Int
    public let lastAssertionSHA256: String
    public let updates: Int

    public init(keyId: String, lastVerifiedCounter: Int, lastAssertionSHA256: String, updates: Int) {
        self.keyId = keyId
        self.lastVerifiedCounter = lastVerifiedCounter
        self.lastAssertionSHA256 = lastAssertionSHA256
        self.updates = updates
    }

    public var canonicalBytes: Data {
        (try? ControlJSON.canonical([
            "schema": Self.schema,
            "key_id": keyId,
            "last_verified_counter": lastVerifiedCounter,
            "last_assertion_sha256": lastAssertionSHA256,
            "updates": updates,
        ] as [String: Any])) ?? Data()
    }

    /// Parse strictly: canonical bytes, exact field set, no booleans, exact types.
    public static func parse(_ raw: Data) throws -> AssertionCounterState {
        guard let obj = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any],
              Set(obj.keys) == ["schema", "key_id", "last_verified_counter",
                                "last_assertion_sha256", "updates"],
              obj["schema"] as? String == schema,
              let keyId = obj["key_id"] as? String, !keyId.isEmpty,
              let counter = obj["last_verified_counter"] as? Int,
              let sha = obj["last_assertion_sha256"] as? String,
              let updates = obj["updates"] as? Int,
              counter >= 0, counter <= 1 << 31, updates >= 1,
              (try? ControlJSON.canonical(obj)) == raw
        else { throw CounterStoreError.corrupt("state file is not canonical dsmack-attest-counter/1") }
        return AssertionCounterState(keyId: keyId, lastVerifiedCounter: counter,
                                     lastAssertionSHA256: sha, updates: updates)
    }
}

public final class AssertionCounterStore {
    public let directory: URL
    public let maxStateBytes = 4096

    public init(directory: URL) throws {
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDir) {
            guard isDir.boolValue else { throw CounterStoreError.badDirectory("not a directory") }
        } else {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
        self.directory = directory
    }

    // MARK: paths

    /// File name per key: sha256 of the keyId bytes — no keyId characters in paths.
    public func fileBase(for keyId: String) -> String {
        "key-" + marControl.SHA256.hex(Data(keyId.utf8))
    }

    private func stateURL(for keyId: String) -> URL {
        directory.appendingPathComponent(fileBase(for: keyId) + ".json")
    }

    private func lockURL(for keyId: String) -> URL {
        directory.appendingPathComponent(fileBase(for: keyId) + ".lock")
    }

    // MARK: locking

    /// Open (O_CREAT) the per-key lock file and take an exclusive flock,
    /// polling to a deadline. Returns the raw fd; caller closes it.
    private func acquireLock(keyId: String, deadline: ContinuousClock.Instant) throws -> Int32 {
        let path = lockURL(for: keyId).path
        let fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw CounterStoreError.ioFailure("open \(path): \(String(cString: strerror(errno)))") }
        while true {
            let rc = flock(fd, LOCK_EX | LOCK_NB)
            if rc == 0 { return fd }
            guard errno == EWOULDBLOCK else {
                close(fd)
                throw CounterStoreError.ioFailure("flock: \(String(cString: strerror(errno)))")
            }
            guard ContinuousClock.now < deadline else {
                close(fd)
                throw CounterStoreError.lockTimeout(path)
            }
            usleep(20_000)
        }
    }

    // MARK: state I/O

    private func readState(keyId: String) throws -> AssertionCounterState? {
        let url = stateURL(for: keyId)
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            if errno == ENOENT { return nil }
            throw CounterStoreError.ioFailure("open \(url.path): \(String(cString: strerror(errno)))")
        }
        defer { close(fd) }
        var buf = Data()
        let chunk = 512
        while buf.count <= maxStateBytes {
            var part = [UInt8](repeating: 0, count: chunk)
            let n = read(fd, &part, chunk)
            if n < 0 { throw CounterStoreError.ioFailure("read: \(String(cString: strerror(errno)))") }
            if n == 0 { break }
            buf.append(contentsOf: part[0..<n])
        }
        guard buf.count <= maxStateBytes else { throw CounterStoreError.corrupt("state over \(maxStateBytes) bytes") }
        guard !buf.isEmpty else { throw CounterStoreError.corrupt("state file empty") }
        return try AssertionCounterState.parse(buf)
    }

    /// Atomic durable write: temp file in the same directory, fsync, rename
    /// over the target, fsync the directory.
    private func writeState(_ state: AssertionCounterState, for keyId: String) throws {
        let target = stateURL(for: keyId)
        let temp = directory.appendingPathComponent(fileBase(for: keyId) + ".json.tmp.\(getpid())")
        let fd = open(temp.path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw CounterStoreError.ioFailure("open tmp: \(String(cString: strerror(errno)))") }
        let bytes = [UInt8](state.canonicalBytes)
        let ok = bytes.withUnsafeBufferPointer { ptr -> Bool in
            var written = 0
            while written < bytes.count {
                let n = write(fd, ptr.baseAddress! + written, bytes.count - written)
                if n <= 0 { return false }
                written += n
            }
            return true
        }
        guard ok, fsync(fd) == 0 else {
            close(fd); unlink(temp.path)
            throw CounterStoreError.ioFailure("write/fsync state")
        }
        close(fd)
        guard rename(temp.path, target.path) == 0 else {
            unlink(temp.path)
            throw CounterStoreError.ioFailure("rename: \(String(cString: strerror(errno)))")
        }
        let dirFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        if dirFD >= 0 { fsync(dirFD); close(dirFD) }
    }

    // MARK: the serialized critical section

    /// A held per-key exclusive lock. The assertion producer call is async
    /// (DCAppAttestService.generateAssertion is async), so the lock is held
    /// across suspension points on purpose: serialization must cover the
    /// whole predict → emit → assert → verify → advance window, or two
    /// concurrent runs on one key would both predict the same counter.
    public final class KeyLock {
        let store: AssertionCounterStore
        let keyId: String
        let fd: Int32
        /// State read under the held lock; nil = no verified history.
        public let state: AssertionCounterState?
        fileprivate var advanced = false

        fileprivate init(store: AssertionCounterStore, keyId: String, fd: Int32, state: AssertionCounterState?) {
            self.store = store; self.keyId = keyId; self.fd = fd; self.state = state
        }

        deinit { close(fd) }

        /// Persist the verified advance. Only legal once, only to exactly
        /// state.lastVerifiedCounter + 1 (or exactly 1 from no history), and
        /// only with a counter the CALLER obtained from a locally
        /// signature-verified assertion — this type cannot tell, so the flow
        /// passes only verified values (see ControlAttestFlow).
        public func advance(verifiedCounter: Int, assertionSHA256: String) throws -> AssertionCounterState {
            guard !advanced else { throw CounterStoreError.corrupt("advance called twice") }
            let next: AssertionCounterState
            if let c = state {
                guard verifiedCounter == c.lastVerifiedCounter + 1 else {
                    throw CounterStoreError.advanceViolation(from: c.lastVerifiedCounter, to: verifiedCounter)
                }
                next = AssertionCounterState(keyId: keyId, lastVerifiedCounter: verifiedCounter,
                                             lastAssertionSHA256: assertionSHA256, updates: c.updates + 1)
            } else {
                guard verifiedCounter == 1 else {
                    throw CounterStoreError.advanceViolation(from: 0, to: verifiedCounter)
                }
                next = AssertionCounterState(keyId: keyId, lastVerifiedCounter: verifiedCounter,
                                             lastAssertionSHA256: assertionSHA256, updates: 1)
            }
            try store.writeState(next, for: keyId)
            advanced = true
            return next
        }
    }

    /// Acquire the per-key exclusive lock and read state under it.
    public func lock(keyId: String, deadline: ContinuousClock.Instant) throws -> KeyLock {
        let fd = try acquireLock(keyId: keyId, deadline: deadline)
        do {
            let current = try readState(keyId: keyId)
            if let c = current, c.keyId != keyId {
                throw CounterStoreError.corrupt("state file belongs to \(c.keyId)")
            }
            return KeyLock(store: self, keyId: keyId, fd: fd, state: current)
        } catch {
            close(fd)
            throw error
        }
    }

    /// Run `body` under the per-key lock with the current state. The body
    /// receives the state (nil for a key with no history) and returns the
    /// verified new state to persist — persisted ONLY if it is exactly
    /// (lastVerified + 1), or exactly 1 when advancing from no history.
    public func withExclusiveKeyLock<T>(keyId: String, deadline: ContinuousClock.Instant,
                                        body: (AssertionCounterState?) throws -> T,
                                        verifiedAdvance: (AssertionCounterState?, T) throws -> AssertionCounterState) throws -> (T, AssertionCounterState?) {
        let lockFD = try acquireLock(keyId: keyId, deadline: deadline)
        defer { close(lockFD) }
        let current = try readState(keyId: keyId)
        if let c = current, c.keyId != keyId {
            throw CounterStoreError.corrupt("state file belongs to \(c.keyId)")
        }
        let result = try body(current)
        let next = try verifiedAdvance(current, result)
        if let c = current {
            guard next.lastVerifiedCounter == c.lastVerifiedCounter + 1 else {
                throw CounterStoreError.advanceViolation(from: c.lastVerifiedCounter,
                                                         to: next.lastVerifiedCounter)
            }
        } else {
            guard next.lastVerifiedCounter == 1 else {
                throw CounterStoreError.advanceViolation(from: 0, to: next.lastVerifiedCounter)
            }
        }
        try writeState(next, for: keyId)
        return (result, next)
    }

    /// The prediction rule, on its own: nil history + fresh allowed => 1;
    /// nil history + known-used key => refusal; else lastVerified + 1.
    public static func predictedCounter(from state: AssertionCounterState?, keyId: String) throws -> Int {
        if let s = state { return s.lastVerifiedCounter + 1 }
        throw CounterStoreError.unknownKeyState(
            "no counter state for key \(keyId): a fresh dedicated key predicts 1 at its first " +
            "assertion (enrollment counter is 0); a key with prior use must be recovered from " +
            "verifier-verified assertions — state is never invented")
    }

    /// The stable per-key state location for the hvf-control executable: under
    /// the key's OWN enrollment staging directory (which persists across
    /// invocations and is already owned by this profile's operator flow),
    /// NEVER inside a fresh per-run output directory. A store under OUT loses
    /// the counter history at every invocation and would predict counter 1
    /// again for a reused key (repair2 R2-A5-STATE).
    public static func stableDirectory(forKeyIdDirectory keyIdDir: URL) -> URL {
        keyIdDir.appendingPathComponent("counter-state", isDirectory: true)
    }

    /// Convenience for the reviewed default: a FRESH dedicated key (enrollment
    /// verified, no store history) predicts counter 1 for its first assertion.
    public static func predictedCounterForFreshKey(_ state: AssertionCounterState?) throws -> Int {
        if let s = state { return s.lastVerifiedCounter + 1 }
        return 1
    }
}
