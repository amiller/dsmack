import Foundation
import IOKit
import DeviceCheck
import CryptoKit

func h(_ s: String) -> String { String(SHA256.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined().prefix(16)) }
func prop(_ k: String) -> String {
    let svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
    precondition(svc != 0, "no IOPlatformExpertDevice")
    defer { IOObjectRelease(svc) }
    return IORegistryEntryCreateCFProperty(svc, k as CFString, kCFAllocatorDefault, 0)!.takeRetainedValue() as! String
}
func out(_ s: String) { print(s); fflush(stdout) }
out("serial_sha256_16=\(h(prop(kIOPlatformSerialNumberKey)))")
out("uuid_sha256_16=\(h(prop(kIOPlatformUUIDKey)))")
out("appattest_supported=\(DCAppAttestService.shared.isSupported)")
out("devicecheck_supported=\(DCDevice.current.isSupported)")
let sem = DispatchSemaphore(value: 0)
DCDevice.current.generateToken { tok, err in
    out(tok.map { "devicecheck_token_bytes=\($0.count)" } ?? "devicecheck_error=\(err!)")
    sem.signal()
}
sem.wait()
DCAppAttestService.shared.generateKey { kid, err in
    guard let kid else { out("appattest_generatekey_error=\(err!)"); sem.signal(); return }
    out("appattest_generatekey=ok")
    DCAppAttestService.shared.attestKey(kid, clientDataHash: Data(SHA256.hash(data: Data("vm-probe".utf8)))) { att, err in
        out(att.map { "appattest_attest_bytes=\($0.count)" } ?? "appattest_attest_error=\(err!)")
        sem.signal()
    }
}
sem.wait()
