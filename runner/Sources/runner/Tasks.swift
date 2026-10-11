import Containerization
import ContainerizationEXT4
import CryptoKit
import Foundation
import NIOCore
import SystemPackage

// Per-task guest VMs started by the peer compose (notes/abalone-node-interface.md item 8). Each task is its own
// Containerization VM: no NIC, no socket, /in read-only from the inputs tar, /out an empty ext4 volume read back on
// the host after the VM stops. Its receipt chain is signed under a key made for that task.
let maxTaskSeconds = 1800
let attachBufferBytes = 4 << 20

func checkTaskCompose(_ p: TasksPolicy, _ c: Compose, _ taskId: String) throws -> Resource {
    func refuse(_ s: String) -> Refusal { Refusal(status: 403, reason: s) }
    guard p.images.contains(c.service.image) else { throw refuse("task image \(c.service.image) is not in tasks.images") }
    guard c.egress.allow.isEmpty, c.egress.tcp?.isEmpty != false, c.egress.max_requests == 0, c.egress.max_tokens == 0 else {
        throw refuse("task egress must be empty")
    }
    guard c.volumes.isEmpty else { throw refuse("task compose may not declare volumes or binds") }
    guard c.top["kms_enabled"] as? Bool == false else { throw refuse("task compose must set kms_enabled false") }
    guard let t = c.top["task"] as? [String: Any], t.count == 1, let rid = t["resource"] as? String, let r = p.resources[rid] else {
        throw refuse("task must be {\"resource\": <one of \(p.resources.keys.sorted())>}")
    }
    let l = c.service.labels ?? [:]
    guard l["abalone.task_id"] == taskId, l["abalone.auth_hash"]?.isEmpty == false, l["abalone.inputs_root"]?.isEmpty == false else {
        throw refuse("task labels must carry abalone.task_id (= task_id), abalone.auth_hash and abalone.inputs_root")
    }
    return r
}

struct TarEntry { let name: String, mode: Int, data: Data? }  // data nil: directory

// ustar with entries sorted by UTF-8 name, uid/gid/mtime 0, empty uname/gname, no pax headers, so the same tree
// always gives the same bytes. kms/verify_receipts.py (det_tar) rebuilds it from an extracted out/ directory.
func detTar(_ entries: [TarEntry]) throws -> Data {
    var t = Data()
    for e in entries.sorted(by: { $0.name.utf8.lexicographicallyPrecedes($1.name.utf8) }) {
        let n = Array(e.name.utf8)
        var name = n, prefix: [UInt8] = []
        if n.count > 100 {
            guard let i = n.indices.first(where: { n[$0] == 0x2f && n.count - $0 - 1 <= 100 }), i <= 155, i < n.count - 1 else {
                throw Fail("path \(e.name) does not fit a ustar header")
            }
            (prefix, name) = (Array(n[..<i]), Array(n[(i + 1)...]))
        }
        var h = [UInt8](repeating: 0, count: 512)
        func put(_ off: Int, _ b: [UInt8]) { h.replaceSubrange(off ..< off + b.count, with: b) }
        func oct(_ v: Int, _ w: Int) throws -> [UInt8] {
            let s = String(v, radix: 8)
            guard s.count < w else { throw Fail("\(e.name): \(v) does not fit a ustar field") }
            return Array((String(repeating: "0", count: w - 1 - s.count) + s).utf8) + [0]
        }
        put(0, name); put(100, try oct(e.mode, 8)); put(108, try oct(0, 8)); put(116, try oct(0, 8))
        put(124, try oct(e.data?.count ?? 0, 12)); put(136, try oct(0, 12)); put(148, Array("        ".utf8))
        h[156] = e.data == nil ? 0x35 : 0x30
        put(257, Array("ustar\u{0}00".utf8)); put(345, prefix)
        put(148, try oct(h.reduce(0) { $0 + Int($1) }, 7) + [0x20])
        t += h
        if let d = e.data { t += d + Data(count: (512 - d.count % 512) % 512) }
    }
    return t + Data(count: 1024)
}

// The /out volume as tar entries under out/: directories 0755, files 0755 if any execute bit is set else 0644.
// Anything else (symlinks, devices, fifos) and short reads (sparse or preallocated files) are refused.
func outEntries(_ image: URL) throws -> [TarEntry] {
    let r = try EXT4.EXT4Reader(blockDevice: FilePath(image.path))
    var entries = [TarEntry(name: "out/", mode: 0o755, data: nil)]
    func walk(_ dir: String) throws {
        for n in try r.listDirectory(FilePath(dir.isEmpty ? "/" : dir)) {
            let p = dir + "/" + n, inode = try r.stat(FilePath(p), followSymlinks: false).inode
            switch inode.mode & 0xF000 {
            case 0x4000:
                entries.append(TarEntry(name: "out\(p)/", mode: 0o755, data: nil))
                try walk(p)
            case 0x8000:
                let d = try r.readFile(at: FilePath(p), followSymlinks: false), size = Int(inode.sizeHigh) << 32 | Int(inode.sizeLow)
                guard d.count == size else { throw Fail("/out\(p): read \(d.count) of \(size) bytes") }
                entries.append(TarEntry(name: "out\(p)", mode: inode.mode & 0o111 != 0 ? 0o755 : 0o644, data: d))
            default: throw Fail("/out\(p) is neither a regular file nor a directory")
            }
        }
    }
    try walk("")
    return entries
}

struct Stdin: ReaderStream { let s: AsyncStream<Data>; func stream() -> AsyncStream<Data> { s } }

final class TaskRun: Writer, @unchecked Sendable {
    let id: String, compose: Compose, composeBytes: Data, resource: Resource, answer: Data, dir: URL
    let stdinStream: AsyncStream<Data>, stdinInput: AsyncStream<Data>.Continuation
    let lock = NSLock()
    var state = "booting", startedAt: Date?, wall: Int?, exitCode: Int32?, reason: String?, stopReason: String?
    var container: LinuxContainer?, manager: ContainerManager?, cid: String?, chain: Chain?, done: Task<Void, Never>?
    // pendingAttach: an attachment opened while booting, before the task's receipt chain exists (the runner's App Attest
    // call for the task boot is still in flight); its attach receipt is signed right after task-start.
    var claimed = false, pendingAttach = false, live: Channel?, buffer = Data(), dropped = 0

    init(id: String, compose: Compose, composeBytes: Data, resource: Resource, answer: Data, dir: URL) {
        (self.id, self.compose, self.composeBytes, self.resource, self.answer, self.dir) = (id, compose, composeBytes, resource, answer, dir)
        (stdinStream, stdinInput) = AsyncStream.makeStream(of: Data.self)
    }

    var active: Bool { state == "booting" || state == "running" }

    // Entrypoint stdout: to the attached connection, else into a 4 MiB buffer that drops its oldest bytes.
    func write(_ d: Data) throws {
        lock.withLock {
            if let ch = live, ch.isActive { return ch.writeAndFlush(ByteBuffer(bytes: d), promise: nil) }
            buffer.append(d)
            if buffer.count > attachBufferBytes {
                dropped += buffer.count - attachBufferBytes
                buffer = Data(buffer.suffix(attachBufferBytes))
            }
        }
    }
    func close() throws {}

    func claim() throws {
        try lock.withLock {
            guard active else { throw Refusal(status: 409, reason: "task \(id) is \(state)") }
            guard !claimed else { throw Refusal(status: 409, reason: "task \(id) already has an attached connection") }
            claimed = true
        }
    }
    func release() { lock.withLock { claimed = false } }

    func activate(_ ch: Channel) throws {
        try lock.withLock {
            guard active else { throw Fail("task \(id) ended before the attachment opened") }
            if let chain { try chain.sign(["event": "attach"]) } else { pendingAttach = true }
            live = ch
            if !buffer.isEmpty { ch.writeAndFlush(ByteBuffer(bytes: buffer), promise: nil); buffer = Data() }
        }
    }

    func detach(_ ch: Channel) throws {
        try lock.withLock {
            guard live === ch else { return }
            (live, claimed) = (nil, false)
            if let chain { try chain.sign(["event": "detach"]) } else { pendingAttach = false }
        }
    }

    func status() throws -> Data {
        try lock.withLock {
            let w: Int = wall ?? startedAt.map { Int(Date().timeIntervalSince($0).rounded(.up)) } ?? 0
            let started: Any = startedAt.map { Int($0.timeIntervalSince1970 * 1000) } ?? NSNull()
            return try canonical(["task_id": id, "state": state, "started_at": started, "wall_seconds": w,
                                  "exit_code": exitCode ?? NSNull(), "reason": reason ?? NSNull(), "dropped_bytes": dropped])
        }
    }
}

final class Tasks: @unchecked Sendable {
    let policy: TasksPolicy, guest: Guest, attest: Bool, store: ImageStore, kernel: Kernel, out: URL, bootDelayMs: Int
    let lock = NSLock()
    var runs: [String: TaskRun] = [:]

    init(policy: TasksPolicy, guest: Guest, attest: Bool, store: ImageStore, kernel: Kernel, out: URL, bootDelayMs: Int) {
        (self.policy, self.guest, self.attest, self.store, self.kernel, self.out) = (policy, guest, attest, store, kernel, out)
        self.bootDelayMs = bootDelayMs
    }

    func run(_ id: String?) throws -> TaskRun {
        guard let id, let r = lock.withLock({ runs[id] }) else { throw Refusal(status: 404, reason: "no task \(id ?? "(no id)")") }
        return r
    }

    func claim(_ id: String) throws -> TaskRun { let r = try run(id); try r.claim(); return r }

    func handle(_ method: String, _ c: URLComponents, _ body: Data) async throws -> (Int, [(String, String)], Data) {
        let json = [("content-type", "application/json")]
        let query = c.queryItems?.first(where: { $0.name == "id" })?.value
        var req: [String: Any]?
        if method == "POST" {
            do { req = try JSONSerialization.jsonObject(with: body) as? [String: Any] } catch { throw Refusal(status: 400, reason: "body is not JSON: \(error)") }
        }
        switch (method, c.path) {
        case ("POST", "/task/start"): return (200, json, try start(req ?? [:]))
        case ("GET", "/task/status"): return (200, json, try run(query).status())
        case ("POST", "/task/stop"):
            guard let grace = req?["grace_seconds"] as? Int, (0 ... 300).contains(grace) else { throw Refusal(status: 400, reason: "/task/stop needs grace_seconds in 0...300") }
            let r = try run(req?["task_id"] as? String)
            try await stop(r, grace: grace, reason: "stop")
            return (200, json, try r.status())
        case ("GET", "/task/collect"):
            let r = try run(query)
            guard r.lock.withLock({ ["exited", "stopped"].contains(r.state) }) else { throw Refusal(status: 409, reason: "task \(r.id) is \(r.state); collect needs exited or stopped") }
            return (200, [("content-type", "application/x-tar")], try Data(contentsOf: r.dir.appendingPathComponent("collect.tar")))
        case ("POST", "/task/delete"):
            let r = try run(req?["task_id"] as? String)
            try lock.withLock {
                guard !r.lock.withLock({ r.active }) else { throw Refusal(status: 409, reason: "task \(r.id) is \(r.state); stop it first") }
                runs[r.id] = nil
            }
            if var m = r.manager, let cid = r.cid { try m.delete(cid) }
            try FileManager.default.removeItem(at: r.dir)
            log("task \(r.id) deleted")
            return (200, json, try canonical(["task_id": r.id, "deleted": true]))
        default: throw Refusal(status: 404, reason: "no runner.local endpoint \(method) \(c.path)")
        }
    }

    func start(_ req: [String: Any]) throws -> Data {
        guard let id = req["task_id"] as? String, id.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
              let obj = req["compose"] as? [String: Any], let b64 = req["inputs_tar_b64"] as? String else {
            throw Refusal(status: 400, reason: "/task/start body must be {task_id: 32 hex, compose: {...}, inputs_tar_b64}")
        }
        let bytes = try canonical(obj), hash = sha256hex(bytes)
        if let r = lock.withLock({ runs[id] }) {
            guard r.compose.hash == hash else { throw Refusal(status: 409, reason: "task \(id) was started with compose \(r.compose.hash), not \(hash)") }
            return r.answer
        }
        let compose: Compose
        do { compose = try parseCompose(bytes) } catch { throw Refusal(status: 403, reason: "task compose: \(error)") }
        let resource = try checkTaskCompose(policy, compose, id)
        guard let tar = Data(base64Encoded: b64) else { throw Refusal(status: 400, reason: "inputs_tar_b64 is not base64") }
        guard tar.count <= 20 << 20 else { throw Refusal(status: 413, reason: "inputs tar is \(tar.count) bytes, over 20 MiB") }
        let r = TaskRun(id: id, compose: compose, composeBytes: bytes, resource: resource,
                        answer: try canonical(["task_id": id, "compose_hash": hash, "state": "booting"]), dir: out.appendingPathComponent("tasks/\(id)"))
        try lock.withLock {
            if let other = runs[id] {  // a concurrent start of the same task_id won the race
                guard other.compose.hash == hash else { throw Refusal(status: 409, reason: "task \(id) was started with compose \(other.compose.hash), not \(hash)") }
                return
            }
            let n = runs.values.filter { r in r.lock.withLock { r.active } }.count
            guard n < policy.max_concurrent else { throw Refusal(status: 429, reason: "max_concurrent \(policy.max_concurrent) tasks already running") }
            runs[id] = r
            r.done = Task { [self] in await boot(r, tar) }
        }
        return lock.withLock { runs[id]!.answer }
    }

    func boot(_ r: TaskRun, _ tar: Data) async {
        do {
            let fm = FileManager.default, g = r.dir.appendingPathComponent("guest")
            func path(_ n: String) -> String { r.dir.appendingPathComponent(n).path }
            try fm.createDirectory(at: g, withIntermediateDirectories: true)
            try r.composeBytes.write(to: g.appendingPathComponent("app-compose.json"))
            let key = P256.Signing.PrivateKey()
            let clientData = try canonical(["attested": attest, "compose_hash": r.compose.hash, "domain": "mac-compose-task-boot/1",
                                            "nonce": hex(SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }),
                                            "receipt_pub": hex(key.publicKey.x963Representation)])
            try clientData.write(to: g.appendingPathComponent("clientData.bin"))
            try canonical(try await guest.evidence(clientData)).write(to: g.appendingPathComponent("attest.json"))
            if bootDelayMs > 0 { try await Task.sleep(for: .milliseconds(bootDelayMs)) }  // DEV-ONLY --dev-task-boot-delay-ms
            let chain = try Chain(signer: key, composeHash: r.compose.hash, file: g.appendingPathComponent("receipts.jsonl"))
            try chain.sign(["event": "task-start", "inputs_sha256": sha256hex(tar)])
            try r.lock.withLock {
                r.chain = chain
                if r.pendingAttach { r.pendingAttach = false; try chain.sign(["event": "attach"]) }
            }
            try tar.write(to: URL(fileURLWithPath: path("inputs.tar")))
            let inputs = try EXT4.Formatter(FilePath(path("in.ext4")), minDiskSize: 128.mib())
            try await inputs.unpack(source: URL(fileURLWithPath: path("inputs.tar")), format: .paxRestricted, compression: .none)
            try inputs.close()
            try EXT4.Formatter(FilePath(path("out.ext4")), minDiskSize: UInt64(r.resource.out_mb).mib()).close()
            let initfs = try await store.getInitImage(reference: initfsReference).initBlock(at: URL(fileURLWithPath: path("initfs.ext4")), for: .linuxArm)
            var manager = try ContainerManager(kernel: kernel, initfs: initfs, root: store.path)
            let cid = "task-\(r.id)-\(Int(Date().timeIntervalSince1970))"
            let stderr = try Capture(URL(fileURLWithPath: path("stderr.txt")))
            r.lock.withLock { (r.manager, r.cid) = (manager, cid) }
            let c = try await manager.create(cid, reference: r.compose.service.image, rootfsSizeInBytes: 2.gib(), networking: false) { c in
                c.cpus = r.resource.cpus
                c.memoryInBytes = UInt64(r.resource.mem_mb).mib()
                if let cmd = r.compose.service.command { c.process.arguments = cmd }
                c.process.environmentVariables += (r.compose.service.environment ?? [:]).sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }
                c.process.stdin = Stdin(s: r.stdinStream)
                c.process.stdout = r
                c.process.stderr = stderr
                c.mounts += [Mount.block(format: "ext4", source: path("in.ext4"), destination: "/in", options: ["ro"]),
                             Mount.block(format: "ext4", source: path("out.ext4"), destination: "/out")]
                guard c.interfaces.isEmpty, c.sockets.isEmpty else { throw Fail("task VM would get a network interface or socket") }
            }
            r.lock.withLock { r.container = c }
            try await c.create()
            try await c.start()
            let pending = r.lock.withLock { () -> String? in
                (r.state, r.startedAt) = ("running", Date())
                return r.stopReason
            }
            log("task \(r.id) running (\(cid), \(r.resource.cpus) vCPU, \(r.resource.mem_mb) MiB, cap \(r.resource.max_seconds) s)")
            if pending != nil { signal(r, c, grace: 0) }
            let cap = Task { [self] in
                do { try await Task.sleep(for: .seconds(r.resource.max_seconds)) } catch { return }
                do { try await stop(r, grace: 5, reason: "time_cap") } catch { log("task \(r.id) time_cap stop failed: \(error)") }
            }
            let status = try await c.wait()
            cap.cancel()
            try await finish(r, c, status.exitCode)
        } catch {
            log("task \(r.id) failed: \(error)")
            let c = r.lock.withLock { () -> LinuxContainer? in
                (r.state, r.reason) = ("failed", "\(error)")
                return r.container
            }
            r.stdinInput.finish()
            if let c { do { try await c.stop() } catch { log("task \(r.id) stop after failure: \(error)") } }
        }
    }

    // After the entrypoint exits: stop the VM (the agent syncs), read /out, close any attachment, sign exit, write collect.tar once.
    func finish(_ r: TaskRun, _ c: LinuxContainer, _ code: Int32) async throws {
        r.lock.withLock { r.container = nil }
        r.stdinInput.finish()
        try await c.stop()
        let ended = Date(), entries = try outEntries(r.dir.appendingPathComponent("out.ext4")), outTar = try detTar(entries)
        let ch = try r.lock.withLock { () -> Channel? in
            let ch = r.live
            if ch != nil { try r.chain!.sign(["event": "detach"]) }
            (r.live, r.claimed) = (nil, false)
            r.wall = Int(ended.timeIntervalSince(r.startedAt!).rounded(.up))
            try r.chain!.sign(["event": "exit", "exit_code": code, "wall_seconds": r.wall!, "out_sha256": sha256hex(outTar), "reason": r.stopReason ?? NSNull()])
            return ch
        }
        // Closing right after a write can lose bytes in the guest socket relay; give the last output a second.
        if let ch { ch.eventLoop.scheduleTask(in: .seconds(1)) { ch.close(promise: nil) } }
        let g = r.dir.appendingPathComponent("guest")
        let guestEntries = try [TarEntry(name: "guest/", mode: 0o755, data: nil)] + ["app-compose.json", "attest.json", "clientData.bin", "receipts.jsonl"].map {
            TarEntry(name: "guest/\($0)", mode: 0o644, data: try Data(contentsOf: g.appendingPathComponent($0)))
        }
        try outTar.write(to: r.dir.appendingPathComponent("out.tar"))
        try detTar(guestEntries + entries).write(to: r.dir.appendingPathComponent("collect.tar"))
        r.lock.withLock { (r.state, r.exitCode, r.reason) = (r.stopReason == nil ? "exited" : "stopped", code, r.stopReason) }
        log("task \(r.id) \(r.state) exit_code \(code) wall \(r.wall!) s\(r.reason.map { " (\($0))" } ?? ""), out sha256 \(sha256hex(outTar))")
    }

    // SIGTERM, then SIGKILL after the grace; the boot task's wait() then runs finish(). Idempotent.
    func stop(_ r: TaskRun, grace: Int, reason: String) async throws {
        let c = r.lock.withLock { () -> LinuxContainer? in
            guard r.active, r.stopReason == nil else { return nil }
            r.stopReason = reason
            return r.state == "running" ? r.container : nil
        }
        if let c { signal(r, c, grace: grace) }
    }

    func signal(_ r: TaskRun, _ c: LinuxContainer, grace: Int) {
        Task {
            do {
                if grace > 0 {
                    try await c.kill(.term)
                    try await Task.sleep(for: .seconds(grace))
                }
                if r.lock.withLock({ r.container != nil }) { try await c.kill(.kill) }
            } catch { log("task \(r.id) signal failed: \(error)") }
        }
    }

    func shutdown() async throws {
        let all = lock.withLock { Array(runs.values) }
        for r in all { try await stop(r, grace: 0, reason: "runner_exit") }
        for r in all { await r.done?.value }
    }
}
