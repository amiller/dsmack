import Foundation
import DeviceCheck
import CryptoKit

// Isolated evidence client. Never deletes keys or changes platform security.
#if MODIFIED
let operationResult = 5
#else
let operationResult = 4
#endif
let args = CommandLine.arguments
guard args.count == 5 else { exit(64) }
let mode = args[1], output = URL(fileURLWithPath: args[2], isDirectory: true)
let challengeURL = URL(fileURLWithPath: args[3])
let keyURL = URL(fileURLWithPath: args[4])
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
func save(_ name: String, _ data: Data) {
    do { try data.write(to: output.appendingPathComponent(name), options: .atomic) }
    catch { exit(70) }
}
func fail(_ stage: String, _ error: Error?) -> Never {
    save("error.txt", Data("\(stage): \(String(describing: error))".utf8)); exit(1)
}
let service = DCAppAttestService.shared
save("runtime.json", try JSONSerialization.data(withJSONObject: [
    "supported": service.isSupported, "operation_result": operationResult,
    "mode": mode, "os": ProcessInfo.processInfo.operatingSystemVersionString,
    "bundle": Bundle.main.bundleIdentifier ?? "", "executable": args[0]
], options: [.prettyPrinted, .sortedKeys]))
guard service.isSupported else { fail("unsupported", nil) }
let clientData = try Data(contentsOf: challengeURL)
save("clientData.bin", clientData)
let digest = Data(SHA256.hash(data: clientData))
let semaphore = DispatchSemaphore(value: 0)
var keyID = ""
if mode == "enroll" {
    guard !FileManager.default.fileExists(atPath: keyURL.path) else { fail("key_file_exists", nil) }
    service.generateKey { key, error in
        guard let key = key, error == nil else { fail("generateKey", error) }
        keyID = key
        do { try key.write(to: keyURL, atomically: true, encoding: .utf8) }
        catch { fail("save_key_id", error) }
        semaphore.signal()
    }
    guard semaphore.wait(timeout: .now() + 60) == .success else { fail("generate_timeout", nil) }
} else {
    keyID = try String(contentsOf: keyURL, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
}
save("keyId.txt", Data(keyID.utf8))
if mode == "enroll" {
    service.attestKey(keyID, clientDataHash: digest) { data, error in
        guard let data = data, error == nil else { fail("attestKey", error) }
        save("attestation.cbor", data); semaphore.signal()
    }
} else if mode == "assert" {
    service.generateAssertion(keyID, clientDataHash: digest) { data, error in
        guard let data = data, error == nil else { fail("generateAssertion", error) }
        save("assertion.cbor", data); semaphore.signal()
    }
} else { fail("invalid_mode", nil) }
guard semaphore.wait(timeout: .now() + 90) == .success else { fail("operation_timeout", nil) }
save("done.txt", Data("complete".utf8))
