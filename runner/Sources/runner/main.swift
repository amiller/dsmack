import Containerization
import ContainerizationArchive
import ContainerizationEXT4
import CryptoKit
import DeviceCheck
import Foundation
import SystemPackage

struct Fail: Error, CustomStringConvertible { let description: String; init(_ d: String) { description = d } }
func hex(_ d: some Sequence<UInt8>) -> String { d.map { String(format: "%02x", $0) }.joined() }
func sha256hex(_ d: Data) -> String { hex(SHA256.hash(data: d)) }
func log(_ s: String) { FileHandle.standardError.write(Data("runner: \(s)\n".utf8)) }

// Kata 3.17.0 vmlinux-6.12.28 (data/vz-spike-20261008/RESULTS.md). Any other kernel is refused.
let kernelSHA256 = "67bac9f416af4cdc9b151e4ba4962d6515e0ad7acc53816761cf964aa6af6ea0"
// vminit 0.33.4, version-matched to the Containerization library (0.26.5 cannot bind-mount relayed sockets).
let initfsReference = "ghcr.io/apple/containerization/vminit@sha256:4551a4627a8575ee625e139fa8a1fbdc5b09f06d03c8dc2c3863dcd2e33e98af"
let guestSocket = "/run/egress.sock"

struct Onchain: Codable, Equatable { let rpc: String; let apps: [String] }
struct ProviderQuote: Codable, Equatable { let kind, attestation_url: String; let compose_hashes: [String]?; let onchain: Onchain?; let model: String? }
struct Rule: Codable { let host, method, path_prefix: String; let auth_header, auth_prefix: String?; let metered: Bool?; let provider_quote: ProviderQuote?; let response_headers: [String]? }
struct TCPTarget: Codable, Hashable { let host: String; let port: Int }
struct EgressPolicy: Codable { let allow: [Rule]; let tcp: [TCPTarget]?; let max_requests, max_tokens: Int }
struct Service: Codable { let image: String; let command: [String]?; let environment, labels: [String: String]?; let volumes: [String]? }
struct Volume { let name, target: String }
struct Resource: Codable { let cpus, mem_mb, out_mb, max_seconds: Int }
struct TasksPolicy: Codable { let images: [String]; let max_concurrent: Int; let resources: [String: Resource] }
struct Compose { let hash: String; let top: [String: Any]; let service: Service; let volumes: [Volume]; let egress: EgressPolicy; let tasks: TasksPolicy? }

func object(_ data: Data, _ what: String) throws -> [String: Any] {
    guard let o = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw Fail("\(what) is not a JSON object") }
    return o
}
func decode<T: Decodable>(_ t: T.Type, _ any: Any) throws -> T {
    try JSONDecoder().decode(t, from: JSONSerialization.data(withJSONObject: any))
}

// compose_hash = sha256(exact app-compose.json bytes), as dstack-vmm (qemu.rs app_compose_hash) and
// dstack-util (system_setup.rs measure_app_info) compute it.
func pinned(_ image: String) -> Bool { image.range(of: "@sha256:[0-9a-f]{64}$", options: .regularExpression) != nil }
func loadCompose(_ path: String) throws -> Compose { try parseCompose(try Data(contentsOf: URL(fileURLWithPath: path))) }
func parseCompose(_ bytes: Data) throws -> Compose {
    let top = try object(bytes, "app-compose.json")
    guard top["runner"] as? String == "docker-compose" else { throw Fail("app-compose runner must be \"docker-compose\"") }
    for k in ["pre_launch_script", "bash_script", "docker_config"] where top[k] != nil { throw Fail("app-compose field \(k) is not supported") }
    guard let dcf = top["docker_compose_file"] as? String else { throw Fail("app-compose has no docker_compose_file") }
    let dc = try object(Data(dcf.utf8), "docker_compose_file (this prototype accepts only the JSON subset of YAML)")
    guard Set(dc.keys).subtracting(["volumes"]) == ["services"], let services = dc["services"] as? [String: Any], services.count == 1,
          let s = services.values.first as? [String: Any] else { throw Fail("docker_compose_file must be {\"services\": {<exactly one service>}, \"volumes\"?: {...}}") }
    let extra = Set(s.keys).subtracting(["image", "command", "environment", "labels", "volumes"])
    guard extra.isEmpty else { throw Fail("service keys not supported: \(extra.sorted())") }
    let svc = try decode(Service.self, s)
    guard pinned(svc.image) else {
        throw Fail("image \"\(svc.image)\" is not pinned by an @sha256: digest")
    }
    // Named volumes only ("<name>:/<path>"), each declared top-level as {} as docker compose requires. Host binds are refused.
    let volumes = try (svc.volumes ?? []).map { v in
        let p = v.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard p.count == 2, p[0].range(of: "^[a-zA-Z0-9][a-zA-Z0-9_.-]*$", options: .regularExpression) != nil, p[1].hasPrefix("/") else {
            throw Fail("volume \"\(v)\" is not <name>:/<path> (only named volumes; host binds and options are refused)")
        }
        return Volume(name: p[0], target: p[1])
    }
    let declared = dc["volumes"].map { $0 as? [String: Any] } ?? [:]
    guard let declared, Set(declared.keys) == Set(volumes.map(\.name)), declared.values.allSatisfy({ ($0 as? [String: Any])?.isEmpty == true }),
          Set(volumes.map(\.name)).count == volumes.count, Set(volumes.map(\.target)).count == volumes.count else {
        throw Fail("top-level volumes must declare each service volume exactly once as {}; names and targets must be unique")
    }
    guard let eg = top["egress"] else { throw Fail("app-compose has no egress policy") }
    let egress = try decode(EgressPolicy.self, eg)
    for r in egress.allow { if let pq = r.provider_quote {
        guard ["redpill", "phala", "nearai"].contains(pq.kind) else { throw Fail("provider_quote kind \"\(pq.kind)\" is not implemented (redpill, phala, nearai)") }
        guard (pq.compose_hashes != nil) != (pq.onchain != nil), pq.compose_hashes?.isEmpty != true else {
            throw Fail("provider_quote needs exactly one of a non-empty compose_hashes list and onchain")
        }
        if let o = pq.onchain, !o.rpc.hasPrefix("https://") || o.apps.isEmpty || !o.apps.allSatisfy({ $0.range(of: "^0x[0-9a-f]{40}$", options: .regularExpression) != nil }) {
            throw Fail("provider_quote onchain needs an https rpc and a non-empty list of lowercase 0x DstackApp addresses")
        }
        guard (pq.kind == "nearai") == (pq.model != nil) else { throw Fail("provider_quote model is required for nearai and only for nearai") }
        // One verified quote per host: every rule naming that host carries the same provider_quote.
        guard egress.allow.allSatisfy({ hostname($0.host) != hostname(r.host) || $0.provider_quote == pq }) else {
            throw Fail("rules for host \(hostname(r.host)) disagree on provider_quote")
        }
    } }
    // tasks: the per-task guests this (peer) compose may start; see Tasks.swift.
    var tasks: TasksPolicy?
    if let t = top["tasks"] {
        guard let o = t as? [String: Any], Set(o.keys) == ["images", "max_concurrent", "resources"], let rs = o["resources"] as? [String: Any], !rs.isEmpty,
              rs.values.allSatisfy({ ($0 as? [String: Any]).map { Set($0.keys) == ["cpus", "mem_mb", "out_mb", "max_seconds"] } == true }) else {
            throw Fail("tasks must be {images, max_concurrent, resources: {<id>: {cpus, mem_mb, out_mb, max_seconds}}}")
        }
        let p = try decode(TasksPolicy.self, o)
        guard !p.images.isEmpty, Set(p.images).count == p.images.count, p.images.allSatisfy(pinned) else { throw Fail("tasks.images must be distinct @sha256:-pinned images") }
        guard p.max_concurrent >= 1 else { throw Fail("tasks.max_concurrent must be >= 1") }
        for (id, r) in p.resources where !(r.cpus >= 1 && r.mem_mb >= 256 && r.out_mb >= 16 && (1 ... maxTaskSeconds).contains(r.max_seconds)) {
            throw Fail("tasks.resources.\(id) needs cpus >= 1, mem_mb >= 256, out_mb >= 16, 1 <= max_seconds <= \(maxTaskSeconds)")
        }
        tasks = p
    }
    return Compose(hash: sha256hex(bytes), top: top, service: svc, volumes: volumes, egress: egress, tasks: tasks)
}

let kmsSession = URLSession(configuration: { let c = URLSessionConfiguration.ephemeral; c.connectionProxyDictionary = [:]; return c }())
func kmsCall(_ url: String, _ body: [String: Any]?) async throws -> [String: Any] {
    guard let u = URL(string: url), u.scheme == "http", u.host == "127.0.0.1" else { throw Fail("--kms must be http://127.0.0.1:<port> (prototype: plaintext localhost only)") }
    var req = URLRequest(url: u)
    if let body { req.httpMethod = "POST"; req.httpBody = try JSONSerialization.data(withJSONObject: body) }
    let (data, resp) = try await kmsSession.data(for: req)
    let status = (resp as! HTTPURLResponse).statusCode
    guard status == 200 else { throw Fail("KMS \(u.path) -> \(status): \(String(decoding: data, as: UTF8.self))") }
    return try object(data, "KMS reply")
}

// Guest stdout/stderr, appended to <out>/guest_stdout.txt as it arrives (a long-running node is observable live).
final class Capture: Writer, @unchecked Sendable {
    let lock = NSLock(), file: FileHandle
    init(_ url: URL) throws { FileManager.default.createFile(atPath: url.path, contents: nil); file = try FileHandle(forWritingTo: url) }
    func write(_ d: Data) throws { try lock.withLock { try file.write(contentsOf: d) } }
    func close() throws {}
}

// Loads a local OCI layout tarball and tags it as the one of `images` with its root digest, refusing if none has it.
func loadArchive(_ flag: String, _ archive: URL, _ store: ImageStore, _ images: [String], _ out: URL) async throws {
    let layout = out.appendingPathComponent("oci-layout")
    _ = try ArchiveReader(file: archive).extractContents(to: layout)
    let loaded = try await store.load(from: layout)
    try FileManager.default.removeItem(at: layout)
    guard loaded.count == 1 else { throw Fail("\(flag) \(archive.path) holds \(loaded.count) images; expected 1") }
    let manifests = try await loaded[0].index().manifests
    guard manifests.count == 1 else { throw Fail("\(flag) \(archive.path) holds \(manifests.count) manifests; expected 1") }
    guard let image = images.first(where: { $0.hasSuffix("@" + manifests[0].digest) }) else {
        throw Fail("\(flag) manifest digest \(manifests[0].digest) != compose image digest \(images.map { String($0.split(separator: "@").last!) }.joined(separator: ", "))")
    }
    _ = try await store.tag(existing: loaded[0].reference, new: image)
    log("loaded \(archive.lastPathComponent) (\(loaded[0].reference), \(manifests[0].digest)) as \(image)")
}

// This binary's full SHA-256 CDHash, the value App Attest binds and the KMS keys app_key by. "cdhashes-full" is
// kSecCodeInfoCdHashesFull ({hash type: CDHash}; 2 = SHA-256), which the SDK does not export to Swift.
func selfCDHash() throws -> String {
    var code: SecCode?, st: SecStaticCode?, info: CFDictionary?
    guard SecCodeCopySelf([], &code) == errSecSuccess, SecCodeCopyStaticCode(code!, [], &st) == errSecSuccess,
          SecCodeCopySigningInformation(st!, [], &info) == errSecSuccess,
          let full = (info as NSDictionary?)?["cdhashes-full"] as? NSDictionary, let h = full[NSNumber(value: 2)] as? Data else { throw Fail("cannot read this binary's SHA-256 CDHash") }
    return hex(h)
}

let args = Array(CommandLine.arguments.dropFirst())
func opt(_ name: String) throws -> String {
    guard let i = args.firstIndex(of: name), i + 1 < args.count else { throw Fail("missing \(name) <value>") }
    return args[i + 1]
}

func run() async throws {
    let attest = args.contains("--attest")
    guard attest != args.contains("--no-attest") else { throw Fail("pass exactly one of --attest or --no-attest") }
    var anchors = anchorsDER.map { SecCertificateCreateWithData(nil, Data(base64Encoded: $0)! as CFData)! }
    if args.contains("--dev-test-anchor") {
        guard !attest else { throw Fail("--dev-test-anchor is DEV-ONLY and refused with --attest") }
        let path = try opt("--dev-test-anchor")
        guard let c = SecCertificateCreateWithData(nil, try Data(contentsOf: URL(fileURLWithPath: path)) as CFData) else { throw Fail("\(path) is not a DER certificate") }
        anchors.append(c)
        log("DEV-ONLY: --dev-test-anchor: upstream TLS also trusts \(path)")
    }
    // DEV-ONLY: holds each task boot this long before its receipt chain exists, as a slow App Attest assertion does.
    var bootDelayMs = 0
    if args.contains("--dev-task-boot-delay-ms") {
        guard !attest else { throw Fail("--dev-task-boot-delay-ms is DEV-ONLY and refused with --attest") }
        guard let n = Int(try opt("--dev-task-boot-delay-ms")), n > 0 else { throw Fail("--dev-task-boot-delay-ms needs a positive integer") }
        bootDelayMs = n
    }
    let compose = try loadCompose(try opt("--compose"))
    let out = URL(fileURLWithPath: try opt("--out")), base = URL(fileURLWithPath: try opt("--base")), kms = try opt("--kms")
    guard !FileManager.default.fileExists(atPath: out.path) else { throw Fail("--out \(out.path) already exists") }
    try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
    func save(_ name: String, _ d: Data) throws { try d.write(to: out.appendingPathComponent(name)) }
    let kernel = base.appendingPathComponent("vmlinux-arm64")
    let kh = sha256hex(try Data(contentsOf: kernel))
    guard kh == kernelSHA256 else { throw Fail("kernel \(kernel.path) sha256 \(kh) != compiled-in \(kernelSHA256)") }
    let measured = attest ? try selfCDHash() : "dev"
    let app = try opt("--app")
    guard !app.isEmpty else { throw Fail("--app needs a non-empty app id") }
    log("compose_hash \(compose.hash), cdhash \(measured), app \(app)")
    let quoteHelper = try compose.egress.allow.contains { $0.provider_quote != nil } ? {
        let h = QuoteHelper(node: URL(fileURLWithPath: try opt("--node")), script: URL(fileURLWithPath: try opt("--quote-helper")), out: out)
        try h.check()
        return h
    }() : nil

    let receiptKey = P256.Signing.PrivateKey(), releaseKey = P256.KeyAgreement.PrivateKey()
    guard let nonce = try await kmsCall(kms + "/nonce", nil)["nonce"] as? String else { throw Fail("KMS /nonce reply has no nonce") }
    let clientData = try canonical([
        "domain": "mac-compose-boot/1", "app": app, "compose_hash": compose.hash, "nonce": nonce, "attested": attest, "enrolled_at": Int(Date().timeIntervalSince1970),
        "receipt_pub": hex(receiptKey.publicKey.x963Representation), "eph_pub": hex(releaseKey.publicKey.x963Representation),
    ])
    try save("clientData.bin", clientData)
    var boot: Enrollment?
    var release: [String: Any] = ["mode": attest ? "attested" : "dev-unattested", "client_data": clientData.base64EncodedString()]
    if attest {
        let svc = DCAppAttestService.shared
        guard svc.isSupported else {
            throw Fail("--attest: DCAppAttestService.isSupported is false. This is not a signed, App Attest-entitled build (ad-hoc builds cannot attest). Use the signed build, or --no-attest for DEV-ONLY runs.")
        }
        let keyId = try await svc.generateKey()
        let attestation = try await svc.attestKey(keyId, clientDataHash: Data(SHA256.hash(data: clientData)))
        release["key_id"] = keyId
        release["attestation"] = attestation.base64EncodedString()
        boot = Enrollment(keyId: keyId, attestation: attestation, clientData: clientData)
    } else {
        log("DEV-ONLY: --no-attest. No App Attest; the key is released by a KMS in --dev-unattested mode.")
    }
    // The KMS seals canonical JSON {"api_key": str, "app": str, "app_key": 64 hex} to eph_pub: ECDH with its one-time key epk,
    // HKDF-SHA256, AES-256-GCM with AAD sha256(clientData).
    let parcel = try await kmsCall(kms + "/release", release)
    guard let epk = (parcel["epk"] as? String).flatMap({ Data(base64Encoded: $0) }),
          let sealed = (parcel["sealed"] as? String).flatMap({ Data(base64Encoded: $0) }) else { throw Fail("KMS /release reply has no epk/sealed parcel") }
    let aead = try releaseKey.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: epk))
        .hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data("mac-compose-key-release/1".utf8), outputByteCount: 32)
    let opened = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: aead, authenticating: Data(SHA256.hash(data: clientData)))
    let secrets = try object(opened, "KMS parcel")
    guard Set(secrets.keys) == ["api_key", "app", "app_key"], let apiKey = secrets["api_key"] as? String, let ak = secrets["app_key"] as? String,
          ak.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw Fail("KMS parcel must be {\"api_key\": str, \"app\": str, \"app_key\": 64 hex}, got keys \(secrets.keys.sorted())") }
    guard secrets["app"] as? String == app else { throw Fail("KMS parcel app \(secrets["app"] ?? "nil") != --app \(app)") }
    let appKey = SymmetricKey(data: Data((0 ..< 32).map { UInt8(ak.dropFirst($0 * 2).prefix(2), radix: 16)! }))
    log("API key and app key released by KMS (\(apiKey.utf8.count) + 32 bytes, held in memory only)")

    let guest = Guest(app: app, composeHash: compose.hash, receiptPub: hex(receiptKey.publicKey.x963Representation), appKey: appKey, boot: boot, bootClientData: clientData)
    var every = 6 * 3600
    if args.contains("--reenroll-seconds") {
        guard let n = Int(try opt("--reenroll-seconds")), n > 0 else { throw Fail("--reenroll-seconds needs a positive integer") }
        every = n
    }
    let reenroll = attest ? Task {
        do { try await guest.reenroll(every: every) } catch is CancellationError {} catch {
            log("error: App Attest re-enrollment failed: \(error)")
            exit(1)
        }
    } : nil
    let store = try ImageStore(path: base.appendingPathComponent("store"))
    if args.contains("--oci-archive") { try await loadArchive("--oci-archive", URL(fileURLWithPath: try opt("--oci-archive")), store, [compose.service.image], out) }
    let taskArchives = args.indices.filter { args[$0] == "--task-archive" }.map { $0 + 1 }
    guard compose.tasks != nil || taskArchives.isEmpty else { throw Fail("--task-archive needs a compose with tasks") }
    for i in taskArchives {
        guard i < args.count else { throw Fail("missing --task-archive <value>") }
        try await loadArchive("--task-archive", URL(fileURLWithPath: args[i]), store, compose.tasks!.images, out)
    }
    let tasks = compose.tasks.map { Tasks(policy: $0, guest: guest, attest: attest, store: store, kernel: Kernel(path: kernel, platform: .linuxArm), out: out, bootDelayMs: bootDelayMs) }
    let hostSocket = out.appendingPathComponent("egress.sock")
    let chain = try Chain(signer: receiptKey, composeHash: compose.hash, file: out.appendingPathComponent("receipts.jsonl"))
    let proxy = Proxy(policy: compose.egress, anchors: anchors, key: apiKey, chain: chain, guest: guest, quoteHelper: quoteHelper, tasks: tasks)
    let server = try await proxy.serve(unixSocket: hostSocket.path)

    // Fresh initfs per boot: ContainerManager(initfsReference:) silently reuses any existing store/initfs.ext4.
    let initfs = try await store.getInitImage(reference: initfsReference).initBlock(at: out.appendingPathComponent("initfs.ext4"), for: .linuxArm)
    // Each named volume is an unencrypted 256 MiB ext4 image keyed by app, volumes/<sha256(app)>/<name>.ext4, formatted on
    // first use. A genesis app id "<cdhash>|<compose_hash>" keeps the pre-app path volumes/<cdhash>/<compose_hash>/ if it
    // exists, whichever admitted build of the app boots, so an upgraded genesis build finds its ledger.
    // <target>/.abalone-persistent is a read-only file mount, rewritten each boot, holding the compose_hash.
    let genesis = app.range(of: "^([0-9a-f]{64}|dev)\\|[0-9a-f]{64}$", options: .regularExpression) != nil
    let legacyDir = base.appendingPathComponent("volumes/" + app.replacingOccurrences(of: "|", with: "/"))
    let volumeDir = genesis && FileManager.default.fileExists(atPath: legacyDir.path)
        ? legacyDir : base.appendingPathComponent("volumes/\(sha256hex(Data(app.utf8)))")
    if !compose.volumes.isEmpty { log("volumes of app \(app) at \(volumeDir.path)") }
    let volumeMounts = try compose.volumes.flatMap { v in
        let img = volumeDir.appendingPathComponent("\(v.name).ext4").path
        if !FileManager.default.fileExists(atPath: img) {
            try FileManager.default.createDirectory(at: volumeDir, withIntermediateDirectories: true)
            try EXT4.Formatter(FilePath(img), minDiskSize: 256.mib()).close()
            log("created volume \(v.name) at \(img)")
        }
        // One live build per app: an exclusive flock, never closed, so it is held until this runner exits. It is on a
        // sidecar <img>.lock: VZ refuses to attach an image this process holds a flock on ("storage device attachment is invalid").
        let fd = open(img + ".lock", O_RDWR | O_CREAT, 0o600)
        guard fd >= 0 else { throw Fail("cannot open \(img).lock: \(String(cString: strerror(errno)))") }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            throw Fail("volume \(v.name) at \(img) is locked (\(String(cString: strerror(errno)))): another runner of app \(app) is live; refusing to boot")
        }
        let marker = out.appendingPathComponent("volume-markers/\(v.name)")
        try FileManager.default.createDirectory(at: marker, withIntermediateDirectories: true)
        try Data("\(compose.hash)\n".utf8).write(to: marker.appendingPathComponent(".abalone-persistent"))
        // .full = F_FULLFSYNC on the host for each guest flush; Containerization's default .fsync is not flushed to the drive on macOS.
        return [Mount.block(format: "ext4", source: img, destination: v.target, runtimeOptions: ["vzDiskImageSynchronizationMode=full"]),
                Mount.share(source: marker.appendingPathComponent(".abalone-persistent").path, destination: v.target + "/.abalone-persistent", options: ["ro"])]
    }
    var manager = try ContainerManager(kernel: Kernel(path: kernel, platform: .linuxArm), initfs: initfs, root: store.path)
    let id = "runner-\(compose.hash.prefix(12))-\(Int(Date().timeIntervalSince1970))"
    try save("container_id.txt", Data(id.utf8))
    let output = try Capture(out.appendingPathComponent("guest_stdout.txt"))
    let container = try await manager.create(id, reference: compose.service.image, rootfsSizeInBytes: 512.mib(), networking: false) { c in
        c.cpus = 2
        c.memoryInBytes = 512.mib()
        if let cmd = compose.service.command { c.process.arguments = cmd }
        c.process.environmentVariables += (compose.service.environment ?? [:]).sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }
        c.process.stdout = output
        c.process.stderr = output
        c.mounts += volumeMounts
        c.sockets = [UnixSocketConfiguration(source: hostSocket, destination: URL(fileURLWithPath: guestSocket),
                                             permissions: FilePermissions(rawValue: 0o777))]
        guard c.interfaces.isEmpty else { throw Fail("guest would get a network interface: \(c.interfaces)") }
    }
    try await container.create()
    try await container.start()
    let status = try await container.wait()
    try await container.stop()
    try await tasks?.shutdown()
    reenroll?.cancel()
    try await server.close()
    try save("guest_exit.txt", Data(String(describing: status).utf8))
    log("guest exited \(status); rootfs kept at \(base.path)/store/containers/\(id)/rootfs.ext4")
}

// Containerization's socket relay writes with write(2) on sockets without SO_NOSIGPIPE; a guest that closes mid-transfer
// would otherwise kill the runner with SIGPIPE. Ignored, the write fails with EPIPE and the relay tears that connection down.
signal(SIGPIPE, SIG_IGN)
do {
    switch args.first {
    case "check" where args.count == 2: print(try loadCompose(args[1]).hash)
    case "run": try await run()
    default: throw Fail("usage: runner check <app-compose.json> | runner run --compose F --app APP --out DIR --base DIR --kms http://127.0.0.1:PORT (--attest | --no-attest) [--dev-test-anchor CA.der] [--oci-archive OCI.tar] [--task-archive OCI.tar ...] [--quote-helper verify/provider_quote.mjs --node NODE] [--reenroll-seconds N (default 21600)] [--dev-task-boot-delay-ms N]")
    }
} catch {
    log("error: \(error)")
    exit(1)
}
