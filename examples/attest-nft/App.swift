import Foundation
import DeviceCheck
import CryptoKit
import IOKit

// attest-nft enroll DIR                  new App Attest key; DIR gets keyId.txt, clientData.bin, attestation.cbor
// attest-nft claim DIR CHAINID NFT TO    assertion over AttestNFT.context(TO, chip, chipId, device); DIR gets assertion.cbor, claim.json
// The app signs nothing else, so its key can only ever claim a token. chip is macOS's CPU name, chipId and the
// ECID come from the device tree iBoot hands the kernel; only device = sha256(domain || NFT || ECID) leaves the app.
let args = CommandLine.arguments
guard args.count >= 3 else { exit(64) }
let dir = URL(fileURLWithPath: args[2], isDirectory: true)
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
func path(_ name: String) -> URL { dir.appendingPathComponent(name) }
func fail(_ what: String) -> Never {
    try! Data(what.utf8).write(to: path("error.txt"))
    exit(1)
}
func hex(_ s: String, _ n: Int) -> Data {
    let t = s.hasPrefix("0x") ? String(s.dropFirst(2)) : s
    guard t.count == 2 * n else { fail("expected \(n) bytes: \(s)") }
    return Data((0..<n).map { UInt8(t.dropFirst(2 * $0).prefix(2), radix: 16)! })
}
func wait(_ start: (@escaping (Data?, Error?) -> Void) -> Void) -> Data {
    let done = DispatchSemaphore(value: 0)
    var out: Data?, err: Error?
    start { out = $0; err = $1; done.signal() }
    guard done.wait(timeout: .now() + 90) == .success else { fail("App Attest timed out") }
    guard let data = out else { fail("App Attest: \(String(describing: err))") }
    return data
}
let service = DCAppAttestService.shared
guard service.isSupported else { fail("App Attest is not supported here") }

switch (args[1], args.count) {
case ("enroll", 3):
    guard !FileManager.default.fileExists(atPath: path("keyId.txt").path) else { fail("DIR already has a key") }
    let key = String(data: wait { cb in service.generateKey { k, e in cb(k.map { Data($0.utf8) }, e) } }, encoding: .utf8)!
    try key.write(to: path("keyId.txt"), atomically: true, encoding: .utf8)
    let clientData = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    try clientData.write(to: path("clientData.bin"))
    try wait { service.attestKey(key, clientDataHash: Data(SHA256.hash(data: clientData)), completionHandler: $0) }
        .write(to: path("attestation.cbor"))
case ("claim", 6):
    let key = try String(contentsOf: path("keyId.txt"), encoding: .utf8)
    let nft = hex(args[4], 20)
    var chain = Data(count: 24)
    chain.append(contentsOf: withUnsafeBytes(of: UInt64(args[3])!.bigEndian, Array.init))
    var size = 0
    sysctlbyname("machdep.cpu.brand_string", nil, &size, nil, 0)
    var brand = [CChar](repeating: 0, count: size)
    guard sysctlbyname("machdep.cpu.brand_string", &brand, &size, nil, 0) == 0 else { fail("machdep.cpu.brand_string") }
    let name = Data(String(cString: brand).utf8)
    guard name.count <= 32 else { fail("chip name longer than 32 bytes") }
    let chip = name + Data(count: 32 - name.count)
    let chosen = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen")
    guard chosen != 0 else { fail("IODeviceTree:/chosen") }
    func prop(_ k: String, _ n: Int) -> Data {
        guard let d = IORegistryEntryCreateCFProperty(chosen, k as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? Data, d.count == n else { fail(k) }
        return d
    }
    let chipId = Data(prop("chip-id", 4).reversed())
    let device = Data(SHA256.hash(data: Data("dsmack.example.attest-nft/device/1".utf8) + nft + prop("unique-chip-id", 8)))
    let context = Data(SHA256.hash(data: Data("dsmack.example.attest-nft/2".utf8) + chain + nft + hex(args[5], 20) + chip + chipId + device))
    try wait { service.generateAssertion(key, clientDataHash: context, completionHandler: $0) }
        .write(to: path("assertion.cbor"))
    let h = { (d: Data) in "0x" + d.map { String(format: "%02x", $0) }.joined() }
    try JSONSerialization.data(withJSONObject: ["chainid": args[3], "nft": args[4], "to": args[5], "chip": h(chip), "chipId": h(chipId), "device": h(device), "context": h(context)])
        .write(to: path("claim.json"))
default:
    fail("usage: attest-nft enroll DIR | attest-nft claim DIR CHAINID NFT TO")
}
