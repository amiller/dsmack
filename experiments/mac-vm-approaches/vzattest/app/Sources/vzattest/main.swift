import Containerization
import CryptoKit
import DeviceCheck
import Foundation

// usage: vzattest enroll|assert|boot (boot = VM only, no App Attest) <out> <base> <challenge> <keyId>
let a = CommandLine.arguments
guard a.count == 6 else { exit(64) }
let mode = a[1], out = URL(fileURLWithPath: a[2]), base = URL(fileURLWithPath: a[3])
let keyURL = URL(fileURLWithPath: a[5])
try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
func save(_ name: String, _ d: Data) throws { try d.write(to: out.appendingPathComponent(name)) }
func hex(_ d: some Sequence<UInt8>) -> String { d.map { String(format: "%02x", $0) }.joined() }

let composeHash = hex(SHA256.hash(data: try Data(contentsOf: base.appendingPathComponent("compose.yaml"))))
let challenge = hex(try Data(contentsOf: URL(fileURLWithPath: a[4])))
let clientData = Data("{\"challenge\":\"\(challenge)\",\"compose_sha256\":\"\(composeHash)\"}".utf8)
try save("clientData.bin", clientData)
let digest = Data(SHA256.hash(data: clientData))
let svc = DCAppAttestService.shared
guard mode == "boot" || svc.isSupported else { throw NSError(domain: "appattest_unsupported", code: 1) }

if mode == "enroll" {
    let key = try await svc.generateKey()
    try key.write(to: keyURL, atomically: true, encoding: .utf8)
    try save("keyId.txt", Data(key.utf8))
    try save("attestation.cbor", try await svc.attestKey(key, clientDataHash: digest))
}
if mode == "assert" {
    let key = try String(contentsOf: keyURL, encoding: .utf8)
    try save("keyId.txt", Data(key.utf8))
    try save("assertion.cbor", try await svc.generateAssertion(key, clientDataHash: digest))
}
if mode != "enroll" {

    final class Capture: Writer, @unchecked Sendable {
        let lock = NSLock(); var data = Data()
        func write(_ d: Data) throws { lock.withLock { data.append(d) } }
        func close() throws {}
    }
    let output = Capture()
    var manager = try await ContainerManager(
        kernel: Kernel(path: base.appendingPathComponent("vmlinux-arm64"), platform: .linuxArm),
        initfsReference: "ghcr.io/apple/containerization/vminit:0.26.5",
        root: base.appendingPathComponent("store"))
    let id = "vzspike-\(Int(Date().timeIntervalSince1970))"
    let container = try await manager.create(id, reference: "docker.io/library/alpine:3.16", rootfsSizeInBytes: 512.mib()) { @Sendable c in
        c.cpus = 2
        c.memoryInBytes = 512.mib()
        c.process.arguments = ["/bin/sh", "-c", "uname -a; cat /etc/alpine-release; echo compose_sha256=\(composeHash)"]
        c.process.stdout = output
    }
    try await container.create()
    try await container.start()
    let status = try await container.wait()
    try await container.stop()
    try manager.delete(id)
    try save("vm_stdout.txt", output.data)
    try save("vm_exit.txt", Data(String(describing: status).utf8))
}
try save("done.txt", Data("complete\n".utf8))
