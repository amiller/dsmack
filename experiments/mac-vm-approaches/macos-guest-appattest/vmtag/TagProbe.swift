import Foundation
import IOKit
import DeviceCheck
import CryptoKit

// args: enroll|assert <outdir> <nonce-hex> <keyId-file>. The serial has no input path.
let args = CommandLine.arguments
precondition(args.count == 5, "usage: enroll|assert outdir nonce keyfile")
let (mode, out, nonce, keyFile) = (args[1], URL(fileURLWithPath: args[2]), args[3], URL(fileURLWithPath: args[4]))
try! FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
func save(_ name: String, _ d: Data) { try! d.write(to: out.appendingPathComponent(name)) }
func fail(_ s: String, _ e: Error?) -> Never { save("error.txt", Data("\(s): \(String(describing: e))".utf8)); exit(1) }
func hex(_ d: some Sequence<UInt8>) -> String { d.map { String(format: "%02x", $0) }.joined() }

func serial() -> String {
#if FAKE
    return "FAKESERIAL"
#else
    let svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
    precondition(svc != 0, "no IOPlatformExpertDevice")
    defer { IOObjectRelease(svc) }
    return IORegistryEntryCreateCFProperty(svc, kIOPlatformSerialNumberKey as CFString, kCFAllocatorDefault, 0)!.takeRetainedValue() as! String
#endif
}
let tag = hex(SHA256.hash(data: Data(("dsmack.device.v1" + "genesis-placeholder" + serial()).utf8)))
let clientData = try! JSONSerialization.data(withJSONObject: [
    "v": "dsmack.device.v1", "tag": tag, "nonce": nonce, "node_pubkey": "placeholder-node-pubkey"], options: [.sortedKeys])
save("clientData.json", clientData)
let svc = DCAppAttestService.shared
guard svc.isSupported else { fail("appattest_unsupported", nil) }
let digest = Data(SHA256.hash(data: clientData))
let sem = DispatchSemaphore(value: 0)
var keyID = ""
if mode == "enroll" {
    svc.generateKey { k, e in guard let k else { fail("generateKey", e) }; keyID = k; sem.signal() }
    sem.wait()
    try! keyID.write(to: keyFile, atomically: true, encoding: .utf8)
    svc.attestKey(keyID, clientDataHash: digest) { d, e in guard let d else { fail("attestKey", e) }; save("attestation.cbor", d); sem.signal() }
} else {
    keyID = try! String(contentsOf: keyFile, encoding: .utf8)
    svc.generateAssertion(keyID, clientDataHash: digest) { d, e in guard let d else { fail("generateAssertion", e) }; save("assertion.cbor", d); sem.signal() }
}
sem.wait()
save("keyId.txt", Data(keyID.utf8))
print("tag=\(tag) mode=\(mode)")
